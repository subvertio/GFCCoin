"""Write fixture.json for worker.test.mjs: Python-signed objects the Worker must accept or refuse."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("GFC_DATA_DIR", str(Path(__file__).parent / ".data"))

import node_certs  # noqa: E402
import signing  # noqa: E402

fed_priv, fed_pub = signing.generate_keypair()
other_priv, _ = signing.generate_keypair()
node_priv, node_pub = signing.generate_keypair()
cert = node_certs.make_cert(fed_priv, node_pub, "test node")
fixture = {
    "network": node_certs.config.NETWORK,
    "federation_pubkey": fed_pub,
    "node_pub": node_pub,
    "official": node_certs.make_announcement(node_priv, 6881, cert=cert),
    "community": node_certs.make_announcement(signing.generate_keypair()[0], 6881),
    "forged_cert": node_certs.make_announcement(node_priv, 6881, cert=node_certs.make_cert(other_priv, node_pub, "x")),
    "revocations": node_certs.make_revocations(fed_priv, 1, [node_pub]),
}
(Path(__file__).parent / "fixture.json").write_text(json.dumps(fixture, indent=2))
print("fixture written")
