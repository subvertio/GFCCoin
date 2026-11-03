// Runs the Worker against Python-signed fixtures with an in-memory KV (no Cloudflare needed):
//   python worker/directory/test/make_fixture.py && node worker/directory/test/worker.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker from "../src/index.js";

const fx = JSON.parse(readFileSync(new URL("./fixture.json", import.meta.url)));

function memoryKV() {
  const m = new Map();
  return {
    async get(k, type) { const v = m.get(k); return v === undefined ? null : type === "json" ? JSON.parse(v.value) : v.value; },
    async put(k, value, opts = {}) { m.set(k, { value, metadata: opts.metadata }); },
    async delete(k) { m.delete(k); },
    async list({ prefix }) { return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }; },
  };
}

const env = { NODES: memoryKV(), NETWORK: fx.network, FEDERATION_PUBKEYS: fx.federation_pubkey };
const call = (method, path, body, ip = "203.0.113.5") =>
  worker.fetch(new Request(`https://dir.test${path}`, {
    method, headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }), env).then(async (r) => ({ status: r.status, data: await r.json() }));

let r = await call("POST", "/announce", fx.official);
assert.equal(r.status, 200); assert.equal(r.data.official, true); assert.equal(r.data.address, "203.0.113.5");

r = await call("POST", "/announce", fx.community, "198.51.100.9");
assert.equal(r.status, 200); assert.equal(r.data.official, false);

r = await call("POST", "/announce", fx.forged_cert, "203.0.113.5");
assert.equal(r.data.official, false, "a cert from an unpinned key is not official");
await call("POST", "/announce", fx.official);  // back to official

r = await call("POST", "/announce", { ...fx.community, signature: "00".repeat(64) });
assert.equal(r.status, 400, "bad signature refused");

r = await call("GET", "/nodes");
assert.equal(r.data.nodes.length, 2);
assert.ok(r.data.nodes.some((n) => n.announcement.cert), "the official node's cert is listed");

r = await call("POST", "/revocations", fx.revocations);
assert.equal(r.status, 200);
r = await call("POST", "/revocations", fx.revocations);
assert.equal(r.status, 409, "seq must increase");
r = await call("POST", "/announce", fx.official);
assert.equal(r.status, 403, "a revoked node can't announce");
r = await call("GET", "/nodes");
assert.equal(r.data.nodes.length, 1);

console.log("worker tests passed");
