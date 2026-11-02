"""
Attesters on their own machines (audit F14): a small signing endpoint for each attester,
and the relayer's client for it.

Each attester runs `python -m bridge attest-serve` next to its own ledger node, with its own
key. The relayer asks it to sign a MintRequest; the attester checks the deposit against its
own ledger (bridge/attester.py) and signs only what that ledger shows. So the relayer, or
anyone who breaks into it, gets signatures for real deposits only: a quorum needs two
attester machines to agree.

Protocol (JSON over HTTP):
  GET  /info    {"address", "chain_id", "bridge", "policy"}: public, for the relayer to check
                it's talking to the attester it expects, with the same relay fee and mint TTL
  POST /attest  {"tx_hash", "evm_to", "mint_cents", "deadline"} ->
                {"signer", "signature" (0x hex or null), "refusal", "retry"}
  Requests to /attest carry X-GFC-Time (unix seconds) and X-GFC-Auth: an HMAC-SHA256, with
  a secret shared by that attester and the relayer, over "<time>\\n<body>". The secret never
  travels; a request older than 60 seconds is refused. A replayed request can only get the
  same kind of signature again, for a deposit that's real.

The relayer records each deposit's deadline before it asks for signatures
(relayer.relay), so a deposit is never refunded while a signature someone may hold could
still mint it, even one that was overheard. Attesters refuse deadlines further out than
the mint TTL (Attester.attest).

The server listens on 127.0.0.1 by default. To reach it from the relayer, put it behind
TLS (a reverse proxy such as Caddy) or a private network (WireGuard, Tailscale, an SSH
tunnel); mainnet refuses a plain-HTTP attester URL unless it's this machine or a Tailscale
address (100.64.0.0/10, which WireGuard already encrypts and authenticates).
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from bridge import eip712
from bridge.attester import Attestation, Attester

logger = logging.getLogger("gfc.bridge.attester_http")

MAX_SKEW_SECONDS = 60
MAX_BODY_BYTES = 4096


def new_secret() -> str:
    return secrets.token_hex(32)


def read_secret(path: str) -> bytes:
    text = Path(path).read_text().strip()
    if len(text) < 64:
        raise SystemExit(f"{Path(path).name} is too short to be an attester secret (python -m bridge "
                         "new-attester-secret FILE)")
    return text.encode()


def auth_header(secret: bytes, timestamp: int, body: bytes) -> str:
    return hmac.new(secret, str(timestamp).encode() + b"\n" + body, hashlib.sha256).hexdigest()


TAILSCALE = ipaddress.ip_network("100.64.0.0/10")  # Tailscale's addresses: WireGuard-encrypted, authenticated


def is_private_url(url: str) -> bool:
    """https, or plain HTTP to this machine or to a Tailscale address (100.64.0.0/10)."""
    u = urlparse(url)
    if u.scheme == "https":
        return True
    if u.scheme != "http" or not u.hostname:
        return False
    if u.hostname in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(u.hostname)
    except ValueError:
        return False  # a name (MagicDNS or not) could resolve anywhere: use the 100.x address
    return ip.is_loopback or ip in TAILSCALE


# Policy both sides must share. A different relay fee means every request's amount differs from
# what the attester computes; a shorter mint TTL means it refuses every deadline; a different
# deposit cutoff means the two judge different deposits mintable. The relayer refuses such an
# attester at startup instead.
# The deposit cutoff too: attesters with different cutoffs disagree on which deposits are this
# bridge's to mint (found on attester #2)
MUST_MATCH = ("relay_fee_cents", "deposits_from")
SHOULD_MATCH = ("min_deposit_cents", "finality_seconds", "faucet_hold_days", "manual_review_cents",
                "checkpoint_url")


def policy(cfg) -> dict:
    out = {k: getattr(cfg, k) for k in MUST_MATCH + SHOULD_MATCH + ("mint_ttl_seconds",)}
    out["deposits_from"] = cfg.deposits_from.isoformat() if cfg.deposits_from else None
    return out


def policy_problems(ours: dict, theirs: dict) -> tuple:
    """(fatal, warnings) comparing this relayer's policy with an attester's."""
    if not theirs:
        return [], ["it doesn't publish its policy (an older version): check it matches by hand"]
    fatal = [f"{k} is {theirs.get(k)!r} there, {ours[k]!r} here" for k in MUST_MATCH if theirs.get(k) != ours[k]]
    if (theirs.get("mint_ttl_seconds") or 0) < ours["mint_ttl_seconds"]:
        fatal.append(f"its mint TTL {theirs.get('mint_ttl_seconds')} s is shorter than ours "
                     f"{ours['mint_ttl_seconds']} s: it would refuse every deadline")
    warnings = [f"{k} is {theirs.get(k)!r} there, {ours[k]!r} here" for k in SHOULD_MATCH if theirs.get(k) != ours[k]]
    return fatal, warnings


# ----------------------------------------------------------------------- server

def make_server(attester: Attester, secret: bytes, host: str = "127.0.0.1", port: int = 8300) -> HTTPServer:
    """One request at a time: the attester reads its ledger and signs, nothing else."""
    info = json.dumps({"address": attester.address, "chain_id": attester.cfg.chain_id,
                       "bridge": attester.cfg.bridge_address.lower(), "policy": policy(attester.cfg)}).encode()

    class Handler(BaseHTTPRequestHandler):
        timeout = 10  # a slow client can't hold the attester

        def log_message(self, fmt, *args):  # no per-request access log noise
            pass

        def _send(self, status: int, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/info":
                self._send(200, info)
            else:
                self._send(404, b'{"error": "not found"}')

        def do_POST(self):
            if self.path != "/attest":
                return self._send(404, b'{"error": "not found"}')
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY_BYTES:
                return self._send(400, b'{"error": "bad length"}')
            body = self.rfile.read(length)
            try:
                ts = int(self.headers.get("X-GFC-Time", ""))
            except ValueError:
                return self._send(401, b'{"error": "unauthenticated"}')
            given = self.headers.get("X-GFC-Auth", "")
            if abs(time.time() - ts) > MAX_SKEW_SECONDS or \
                    not hmac.compare_digest(given, auth_header(secret, ts, body)):
                logger.warning(f"Refused an unauthenticated attest request from {self.client_address[0]}")
                return self._send(401, b'{"error": "unauthenticated"}')
            try:
                req = json.loads(body)
                tx_hash, evm_to = str(req["tx_hash"]).lower(), str(req["evm_to"])
                mint_cents, deadline = int(req["mint_cents"]), int(req["deadline"])
                bytes.fromhex(tx_hash)
                if len(tx_hash) != 64:
                    raise ValueError("tx_hash")
            except (ValueError, KeyError, TypeError):
                return self._send(400, b'{"error": "bad request"}')
            try:
                result = attester.attest(tx_hash, evm_to, mint_cents, deadline)
            except Exception as e:  # a locked ledger, say: the relayer retries
                logger.error(f"Attest failed for {tx_hash[:16]}: {type(e).__name__}: {e}")
                result = Attestation(attester.address, None, "attester error", retry=True)
            if result.signature:
                logger.info(f"Signed {mint_cents / 100:.2f} GFC to {evm_to} for {tx_hash[:16]}, deadline {deadline}")
            else:
                logger.info(f"Refused {tx_hash[:16]}: {result.refusal}")
            self._send(200, json.dumps({
                "signer": result.signer,
                "signature": "0x" + result.signature.hex() if result.signature else None,
                "refusal": result.refusal, "retry": result.retry}).encode())

    return HTTPServer((host, port), Handler)


# ----------------------------------------------------------------------- client

class RemoteAttester:
    """The relayer's view of one attester machine: the same attest() as a local Attester."""

    def __init__(self, cfg, url: str, secret: bytes, timeout: float = 20.0, label: Optional[str] = None):
        self.cfg, self.url, self._secret = cfg, url.rstrip("/"), secret
        self.label = label or "remote attester"
        self._http = httpx.Client(timeout=timeout)
        try:
            info = self._http.get(self.url + "/info").json()
        except (httpx.HTTPError, ValueError) as e:
            raise SystemExit(f"{self.label} can't be reached: {type(e).__name__}") from None
        if info.get("chain_id") != cfg.chain_id or str(info.get("bridge", "")).lower() != cfg.bridge_address.lower():
            raise SystemExit(f"{self.label} signs for chain {info.get('chain_id')} bridge {info.get('bridge')}, "
                             f"not this bridge")
        fatal, warnings = policy_problems(policy(cfg), info.get("policy") or {})
        for w in warnings:
            logger.warning(f"{self.label}: {w}")
        if fatal:
            raise SystemExit(f"{self.label}'s policy doesn't match this relayer's, so it would refuse every mint: "
                             + "; ".join(fatal))
        self.address = info["address"]

    def attest(self, tx_hash: str, evm_to: str, mint_cents: int, deadline: int, now=None) -> Attestation:
        body = json.dumps({"tx_hash": tx_hash, "evm_to": evm_to, "mint_cents": mint_cents,
                           "deadline": deadline}).encode()
        ts = int(time.time())
        try:
            resp = self._http.post(self.url + "/attest", content=body, headers={
                "Content-Type": "application/json", "X-GFC-Time": str(ts),
                "X-GFC-Auth": auth_header(self._secret, ts, body)})
            resp.raise_for_status()
            out = resp.json()
        except httpx.HTTPStatusError as e:  # httpx's own message holds the URL
            return Attestation(self.address, None, f"{self.label}: HTTP {e.response.status_code}", retry=True)
        except (httpx.HTTPError, ValueError) as e:
            return Attestation(self.address, None, f"{self.label} unreachable: {type(e).__name__}", retry=True)
        if not out.get("signature"):
            return Attestation(self.address, None, f"{self.label}: {out.get('refusal', '')}", bool(out.get("retry")))
        # Trust the signature only if it's that attester's, over exactly this request
        try:
            sig = bytes.fromhex(out["signature"][2:])
            req = eip712.mint_request(tx_hash, evm_to, mint_cents, deadline)
            signer = eip712.recover_signer(self.cfg.chain_id, self.cfg.bridge_address, req, sig)
        except Exception:
            signer = None
        if signer != self.address:
            logger.error(f"{self.label} returned a signature that isn't its own for this request")
            return Attestation(self.address, None, f"{self.label}: bad signature")
        return Attestation(self.address, sig)
