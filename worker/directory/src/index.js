// GFC node directory: a Cloudflare Worker (docs/node-directory.md).
//
// Nodes POST a signed announcement every few minutes and GET the list of every node.
// The directory only relays: each node re-checks every signature, certificate and
// revocation list itself (node_certs.py). The checks here just keep junk out.
//
//   POST /announce      {body, signature, cert?}  signed by the node's own key
//   GET  /nodes         {nodes: [{address, announcement}], revocations}
//   POST /revocations   {body, signature}         signed by a federation key, seq must increase
//   GET  /revocations
//
// Bindings (wrangler.toml): KV namespace NODES; vars NETWORK, FEDERATION_PUBKEYS.

const DOMAIN = "GFC-NODE-SIG-v1:";
const VERSION = 1;
const NODE_TTL_S = 1800;        // a node that stops announcing drops out after 30 min
const MAX_AGE_S = 600;
const MAX_SKEW_S = 120;
const MAX_KEYS_PER_IP = 4;
const MAX_NODES = 1000;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*", ...extra },
  });

const hexBytes = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));

async function verifySigned(kind, signed, signerField) {
  if (!signed || typeof signed.body !== "string" || typeof signed.signature !== "string") return null;
  if (signed.body.length > 8192 || !HEX128.test(signed.signature)) return null;
  let body;
  try { body = JSON.parse(signed.body); } catch { return null; }
  if (!body || body.v !== VERSION || body.kind !== kind) return null;
  const signer = body[signerField];
  if (typeof signer !== "string" || !HEX64.test(signer)) return null;
  try {
    const key = await crypto.subtle.importKey("raw", hexBytes(signer), { name: "Ed25519" }, false, ["verify"]);
    const msg = new TextEncoder().encode(DOMAIN + kind + ":" + signed.body);
    return (await crypto.subtle.verify({ name: "Ed25519" }, key, hexBytes(signed.signature), msg)) ? body : null;
  } catch {
    return null;
  }
}

const pins = (env) => new Set((env.FEDERATION_PUBKEYS || "").split(",").map((k) => k.trim().toLowerCase()).filter(Boolean));

async function revocations(env) {
  const stored = await env.NODES.get("revocations", "json");
  return stored || null;
}

async function revokedSet(env) {
  const r = await revocations(env);
  if (!r) return new Set();
  try { return new Set(JSON.parse(r.body).revoked || []); } catch { return new Set(); }
}

async function isOfficial(env, cert, nodeKey, revoked) {
  const body = await verifySigned("node-cert", cert, "issuer");
  if (!body || !pins(env).has(body.issuer) || body.role !== "official") return false;
  if (body.node_key !== nodeKey || revoked.has(nodeKey)) return false;
  const now = Date.now(), issued = Date.parse(body.issued_at), expires = Date.parse(body.expires_at);
  return !Number.isNaN(issued) && !Number.isNaN(expires) && issued - MAX_SKEW_S * 1000 <= now && now < expires;
}

async function announce(request, env) {
  let signed;
  try { signed = await request.json(); } catch { return json({ error: "not JSON" }, 400); }
  const body = await verifySigned("node-announce", signed, "node_key");
  if (!body) return json({ error: "bad signature" }, 400);
  if (body.network !== env.NETWORK) return json({ error: `this directory is for ${env.NETWORK}` }, 400);
  if (!Number.isInteger(body.port) || body.port <= 0 || body.port >= 65536) return json({ error: "bad port" }, 400);
  const age = (Date.now() - Date.parse(body.time)) / 1000;
  if (Number.isNaN(age) || age > MAX_AGE_S || age < -MAX_SKEW_S) return json({ error: "stale or future time" }, 400);

  const revoked = await revokedSet(env);
  if (revoked.has(body.node_key)) return json({ error: "revoked" }, 403);
  const address = request.headers.get("cf-connecting-ip") || "";
  if (!address) return json({ error: "no address" }, 400);

  // A few node keys per address, so one machine can't flood the list
  const ipKey = `ip:${address}`;
  const keys = new Set((await env.NODES.get(ipKey, "json")) || []);
  if (!keys.has(body.node_key) && keys.size >= MAX_KEYS_PER_IP) return json({ error: "too many nodes from this address" }, 429);
  keys.add(body.node_key);
  await env.NODES.put(ipKey, JSON.stringify([...keys]), { expirationTtl: NODE_TTL_S });

  const official = signed.cert ? await isOfficial(env, signed.cert, body.node_key, revoked) : false;
  const announcement = { body: signed.body, signature: signed.signature, ...(official ? { cert: signed.cert } : {}) };
  await env.NODES.put(`node:${body.node_key}`, JSON.stringify({ address, announcement }), {
    expirationTtl: NODE_TTL_S,
    metadata: { official },
  });
  return json({ ok: true, address, official });
}

async function listNodes(env) {
  const nodes = [];
  let cursor;
  do {
    const page = await env.NODES.list({ prefix: "node:", cursor, limit: 1000 });
    for (const k of page.keys) {
      const v = await env.NODES.get(k.name, "json");
      if (v) nodes.push(v);
      if (nodes.length >= MAX_NODES) break;
    }
    cursor = page.list_complete || nodes.length >= MAX_NODES ? undefined : page.cursor;
  } while (cursor);
  return json({ nodes, revocations: await revocations(env) }, 200, { "cache-control": "public, max-age=60" });
}

async function postRevocations(request, env) {
  let signed;
  try { signed = await request.json(); } catch { return json({ error: "not JSON" }, 400); }
  const body = await verifySigned("node-revocations", signed, "issuer");
  if (!body || !pins(env).has(body.issuer) || !Number.isInteger(body.seq) || !Array.isArray(body.revoked)) {
    return json({ error: "not a revocation list signed by a federation key" }, 403);
  }
  const current = await revocations(env);
  const currentSeq = current ? JSON.parse(current.body).seq : -1;
  if (body.seq <= currentSeq) return json({ error: `seq must be above ${currentSeq}` }, 409);
  await env.NODES.put("revocations", JSON.stringify({ body: signed.body, signature: signed.signature }));
  for (const key of body.revoked) await env.NODES.delete(`node:${key}`);
  return json({ ok: true, seq: body.seq, revoked: body.revoked.length });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type" } });
    }
    if (pathname === "/announce" && request.method === "POST") return announce(request, env);
    if (pathname === "/nodes" && request.method === "GET") return listNodes(env);
    if (pathname === "/revocations" && request.method === "POST") return postRevocations(request, env);
    if (pathname === "/revocations" && request.method === "GET") return json(await revocations(env));
    if (pathname === "/" && request.method === "GET") {
      return json({ service: "GFC node directory", network: env.NETWORK, endpoints: ["/nodes", "/announce", "/revocations"] });
    }
    return json({ error: "not found" }, 404);
  },
};
