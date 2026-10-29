"""
The EIP-712 MintRequest that attesters sign. Must match GFCBridge.MINT_TYPEHASH
and its EIP712("GFC Bridge", "1") domain; tests check the digest against the
contract's own mintDigest().
"""

from typing import Tuple

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

DOMAIN_NAME = "GFC Bridge"
DOMAIN_VERSION = "1"

MINT_TYPES = {
    "Mint": [
        {"name": "ledgerTxHash", "type": "bytes32"},
        {"name": "to", "type": "address"},
        {"name": "amountCents", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ]
}


def mint_request(ledger_tx_hash_hex: str, to: str, amount_cents: int, deadline: int) -> tuple:
    """The MintRequest tuple as GFCBridge takes it."""
    return (bytes.fromhex(ledger_tx_hash_hex), to_checksum_address(to), amount_cents, deadline)


def _message(chain_id: int, bridge: str, req: tuple):
    return encode_typed_data(full_message={
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            **MINT_TYPES,
        },
        "primaryType": "Mint",
        "domain": {"name": DOMAIN_NAME, "version": DOMAIN_VERSION, "chainId": chain_id,
                   "verifyingContract": to_checksum_address(bridge)},
        "message": {"ledgerTxHash": req[0], "to": req[1], "amountCents": req[2], "deadline": req[3]},
    })


def sign_mint(key: str, chain_id: int, bridge: str, req: tuple) -> Tuple[str, bytes]:
    """(signer address, 65-byte r||s||v signature)."""
    signed = Account.sign_message(_message(chain_id, bridge, req), private_key=key)
    return Account.from_key(key).address, bytes(signed.signature)


def recover_signer(chain_id: int, bridge: str, req: tuple, signature: bytes) -> str:
    return Account.recover_message(_message(chain_id, bridge, req), signature=signature)
