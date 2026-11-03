"""
GFC node identity, official-node certificates and the signed node directory
(docs/node-directory.md).

Anyone can run a GFC node. A node is "official" only while it holds a certificate signed by
a federation key (config.FEDERATION_PUBKEYS): a key the network operator keeps offline,
separate from the treasury and checkpoint keys.

- Node key: every node has its own Ed25519 key (GFC_NODE_KEY_FILE, default
  DATA_DIR/node_key.hex), made on first start. Its public key is the node's identity.
- Certificate: {node_key, label, role: "official", issued_at, expires_at, issuer}, signed by
  a federation key. It binds the node *key*, not an address, so it is useless without that
  node's private key. Installed on the node at GFC_NODE_CERT_FILE (default
  DATA_DIR/node_cert.json).
- Announcement: {node_key, port, api_url, version, time, cert}, signed by the node key. The
  directory (a Cloudflare Worker, worker/directory) stores each node's latest one and records
  the address it came from; nodes fetch the list and connect to each other.
- Revocations: a list of revoked node keys with an increasing sequence number, signed by a
  federation key and published through the directory. A revoked node is no longer official.

Nodes never trust the directory itself: they check every announcement, certificate and
revocation list against the pinned keys. The directory checks them too, to keep junk out.

Signed message: NODE_SIGNATURE_DOMAIN + kind + ":" + body, where body is the canonical JSON
string that travels with the signature (so other languages verify the exact bytes).

CLI (run on your own PC for the federation key; on a node for its key):
    python node_certs.py new-federation-key FILE        an encrypted federation key; prints its public key
    python node_certs.py certify FILE NODE_KEY LABEL [--days N]   print a certificate for a node
    python node_certs.py revoke FILE SEQ NODE_KEY...    print a signed revocation list
    python node_certs.py node-key                       this node's public key (makes it if missing)
    python node_certs.py install-cert CERT_FILE         check a certificate and install it on this node
    python node_certs.py publish-revocations FILE       send a revocation list to the directory
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

import config
import signing

VERSION = 1
NODE_SIGNATURE_DOMAIN = b"GFC-NODE-SIG-v1:"  # never confused with a transaction or seed signature
KIND_CERT = "node-cert"
KIND_ANNOUNCE = "node-announce"
KIND_REVOCATIONS = "node-revocations"
ANNOUNCE_MAX_AGE_S = 600     # an announcement older than this is stale
ANNOUNCE_MAX_SKEW_S = 120    # or this far in the future
DEFAULT_CERT_DAYS = 365


# ----------------------------------------------------------------------- signing

def canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _message(kind: str, body_str: str) -> bytes:
    return NODE_SIGNATURE_DOMAIN + kind.encode() + b":" + body_str.encode()


def sign(private_key: str, kind: str, body: dict) -> dict:
    """{body: <canonical JSON string>, signature: <hex>}."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    body_str = canonical(body)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    return {"body": body_str, "signature": key.sign(_message(kind, body_str)).hex()}


def open_signed(kind: str, signed: dict, signer_field: str) -> Optional[dict]:
    """The body of a signed object if its signature by body[signer_field] is valid, else None."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(signed, dict):
        return None
    body_str, sig = signed.get("body"), signed.get("signature")
    if not isinstance(body_str, str) or not isinstance(sig, str) or len(body_str) > 8192:
        return None
    try:
        body = json.loads(body_str)
        signer = body[signer_field]
        if not isinstance(body, dict) or body.get("v") != VERSION or body.get("kind") != kind \
                or not signing.is_public_key(signer):
            return None
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(bytes.fromhex(sig), _message(kind, body_str))
        return body
    except (ValueError, KeyError, TypeError, InvalidSignature):
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value) -> Optional[datetime]:
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return t if t.tzinfo else None
    except ValueError:
        return None


# ----------------------------------------------------------------------- certificates

def make_cert(federation_key: str, node_key: str, label: str, days: int = DEFAULT_CERT_DAYS,
              now: Optional[datetime] = None) -> dict:
    if not signing.is_public_key(node_key):
        raise ValueError("NODE_KEY must be a node's 64-hex public key (`python node_certs.py node-key` on it)")
    now = now or _now()
    body = {"v": VERSION, "kind": KIND_CERT, "node_key": node_key.lower(), "label": label[:80],
            "role": "official", "issuer": signing.public_key_of(federation_key),
            "issued_at": now.replace(microsecond=0).isoformat(),
            "expires_at": (now + timedelta(days=days)).replace(microsecond=0).isoformat()}
    return sign(federation_key, KIND_CERT, body)


def check_cert(cert: dict, node_key: str, federation_pubkeys: Iterable[str] = None,
               revoked: Iterable[str] = (), now: Optional[datetime] = None) -> Optional[dict]:
    """The certificate body if it makes node_key official right now, else None."""
    pins = {k.lower() for k in (config.FEDERATION_PUBKEYS if federation_pubkeys is None else federation_pubkeys)}
    body = open_signed(KIND_CERT, cert, "issuer")
    if not body or body["issuer"] not in pins or body.get("role") != "official":
        return None
    if body.get("node_key") != (node_key or "").lower() or body["node_key"] in set(revoked):
        return None
    issued, expires, now = _parse_time(body.get("issued_at")), _parse_time(body.get("expires_at")), now or _now()
    if not issued or not expires or not issued - timedelta(seconds=ANNOUNCE_MAX_SKEW_S) <= now < expires:
        return None
    return body


# ----------------------------------------------------------------------- revocations

def make_revocations(federation_key: str, seq: int, node_keys: Iterable[str],
                     now: Optional[datetime] = None) -> dict:
    keys = sorted({k.lower() for k in node_keys})
    if not all(signing.is_public_key(k) for k in keys):
        raise ValueError("every revoked key must be a 64-hex node public key")
    body = {"v": VERSION, "kind": KIND_REVOCATIONS, "seq": int(seq), "revoked": keys,
            "issuer": signing.public_key_of(federation_key),
            "time": (now or _now()).replace(microsecond=0).isoformat()}
    return sign(federation_key, KIND_REVOCATIONS, body)


def check_revocations(signed: dict, federation_pubkeys: Iterable[str] = None) -> Optional[dict]:
    pins = {k.lower() for k in (config.FEDERATION_PUBKEYS if federation_pubkeys is None else federation_pubkeys)}
    body = open_signed(KIND_REVOCATIONS, signed, "issuer")
    if not body or body["issuer"] not in pins or not isinstance(body.get("seq"), int) \
            or not isinstance(body.get("revoked"), list):
        return None
    return body


# ----------------------------------------------------------------------- announcements

def make_announcement(node_key_priv: str, port: int, api_url: str = "", version: str = "",
                      cert: Optional[dict] = None, now: Optional[datetime] = None) -> dict:
    body = {"v": VERSION, "kind": KIND_ANNOUNCE, "node_key": signing.public_key_of(node_key_priv),
            "port": int(port), "api_url": api_url[:200], "version": version[:40],
            "time": (now or _now()).replace(microsecond=0).isoformat(), "network": config.NETWORK}
    signed = sign(node_key_priv, KIND_ANNOUNCE, body)
    if cert:
        signed["cert"] = cert
    return signed


def check_announcement(signed: dict, now: Optional[datetime] = None, max_age_s: float = ANNOUNCE_MAX_AGE_S
                       ) -> Optional[dict]:
    """The announcement body if it is signed by its node key, fresh and on our network."""
    body = open_signed(KIND_ANNOUNCE, signed, "node_key")
    if not body or body.get("network") != config.NETWORK:
        return None
    port, t = body.get("port"), _parse_time(body.get("time"))
    if not isinstance(port, int) or not 0 < port < 65536 or not t:
        return None
    age = ((now or _now()) - t).total_seconds()
    if age > max_age_s or age < -ANNOUNCE_MAX_SKEW_S:
        return None
    return body


def directory_entries(listing: dict, federation_pubkeys: Iterable[str] = None, now: Optional[datetime] = None,
                      max_age_s: float = 3600) -> list:
    """
    Checked entries from a directory listing {nodes: [{address, announcement}], revocations}:
    [{address, port, node_key, api_url, official, label}]. Anything that fails a check is dropped.
    """
    revoked = set()
    rev = check_revocations(listing.get("revocations"), federation_pubkeys) if isinstance(listing, dict) else None
    if rev:
        revoked = set(rev["revoked"])
    out, seen = [], set()
    for item in (listing.get("nodes") or [])[:1000] if isinstance(listing, dict) else []:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            continue
        ann = item.get("announcement") or {}
        body = check_announcement(ann, now=now, max_age_s=max_age_s)
        if not body or body["node_key"] in seen or body["node_key"] in revoked:
            continue
        seen.add(body["node_key"])
        cert = check_cert(ann.get("cert"), body["node_key"], federation_pubkeys, revoked, now) if ann.get("cert") else None
        out.append({"address": item["address"][:64], "port": body["port"], "node_key": body["node_key"],
                    "api_url": body.get("api_url", ""), "official": bool(cert),
                    "label": cert.get("label", "") if cert else ""})
    return out


# ----------------------------------------------------------------------- this node

def node_key_path() -> Path:
    return Path(os.environ.get("GFC_NODE_KEY_FILE", str(config.DATA_DIR / "node_key.hex")))


def cert_path() -> Path:
    return Path(os.environ.get("GFC_NODE_CERT_FILE", str(config.DATA_DIR / "node_cert.json")))


def load_or_create_node_key() -> str:
    """This node's identity key. It only names the node in the directory; it holds no funds."""
    path = node_key_path()
    if path.exists():
        return path.read_text().strip()
    priv, _ = signing.generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    signing._write_secret(path, priv)
    return priv


def load_cert(node_key_pub: str) -> Optional[dict]:
    """The installed certificate, if it is valid for this node right now."""
    path = cert_path()
    if not path.exists():
        return None
    try:
        cert = json.loads(path.read_text())
    except (ValueError, OSError):
        return None
    return cert if check_cert(cert, node_key_pub) else None


def _load_federation_key(path: Path) -> str:
    priv = signing._read_treasury_key_file(path, os.environ.get("GFC_FEDERATION_PASSPHRASE")
                                           or signing._passphrase("Federation key passphrase: ", False))
    if signing.public_key_of(priv) not in config.FEDERATION_PUBKEYS:
        print("warning: this federation key isn't pinned in config.FEDERATION_PUBKEYS; "
              "nodes won't accept what it signs", file=sys.stderr)
    return priv


def _cli(argv: list) -> int:
    if len(argv) == 2 and argv[0] == "new-federation-key":
        path = Path(argv[1])
        if path.exists():
            print(f"{path} already exists; not overwriting it", file=sys.stderr)
            return 1
        import keystore
        priv, pub = signing.generate_keypair()  # never written to disk in plaintext
        passphrase = os.environ.get("GFC_FEDERATION_PASSPHRASE") or \
            signing._passphrase("Passphrase for the federation key file (12+ chars): ", True)
        sealed = keystore.seal_backup(passphrase, {"private_key": priv, "public_key": pub}, "treasury")
        signing._write_secret(path, json.dumps(sealed, indent=2))
        print(f"Encrypted federation key written to {path}. Keep it offline, with a backup.")
        print(f"Pin this public key in config.PINNED_FEDERATION_PUBKEYS and the directory Worker's FEDERATION_PUBKEYS:\n"
              f"  {pub}")
        return 0
    if len(argv) >= 4 and argv[0] == "certify":
        days = DEFAULT_CERT_DAYS
        if "--days" in argv:
            i = argv.index("--days")
            days = int(argv[i + 1])
            argv = argv[:i] + argv[i + 2:]
        cert = make_cert(_load_federation_key(Path(argv[1])), argv[2], " ".join(argv[3:]), days)
        print(json.dumps(cert, indent=2))
        return 0
    if len(argv) >= 3 and argv[0] == "revoke":
        print(json.dumps(make_revocations(_load_federation_key(Path(argv[1])), int(argv[2]), argv[3:]), indent=2))
        return 0
    if argv == ["node-key"]:
        print(signing.public_key_of(load_or_create_node_key()))
        return 0
    if len(argv) == 2 and argv[0] == "install-cert":
        cert = json.loads(Path(argv[1]).read_text())
        pub = signing.public_key_of(load_or_create_node_key())
        body = check_cert(cert, pub)
        if not body:
            print("that certificate isn't valid for this node (wrong node key, unpinned issuer, revoked or expired)",
                  file=sys.stderr)
            return 1
        cert_path().write_text(json.dumps(cert, indent=2))
        print(f"installed: official node \"{body['label']}\" until {body['expires_at']}. Restart the node to announce it.")
        return 0
    if len(argv) == 2 and argv[0] == "publish-revocations":
        import httpx
        signed = json.loads(Path(argv[1]).read_text())
        if not check_revocations(signed):
            print("not a revocation list signed by a pinned federation key", file=sys.stderr)
            return 1
        for url in config.DIRECTORY_URLS:
            r = httpx.post(url.rstrip("/") + "/revocations", json=signed, timeout=15)
            print(f"{url}: HTTP {r.status_code} {r.text[:200]}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
