"""
Minimal EVM access for the bridge: JSON-RPC over httpx, ABI encoding with
eth_abi, and EIP-1559 transactions signed with eth_account. Only the calls the
bridge needs; no web3.py.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Sequence

import httpx
from eth_abi import decode, encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

# httpx logs every request URL at INFO; RPC URLs often carry an API key
logging.getLogger("httpx").setLevel(logging.WARNING)

MINT_REQUEST_TUPLE = "(bytes32,address,uint256,uint256)"
TOPIC_BRIDGED_OUT = "0x" + keccak(text="BridgedOut(uint256,address,bytes32,uint256)").hex()
TOPIC_MINTED = "0x" + keccak(text="MintedFromLedger(bytes32,address,uint256)").hex()

# Custom errors of GFCBridge / GFCToken / OpenZeppelin, to name reverts in logs
_ERRORS = [
    "AlreadyProcessed(bytes32)", "Expired(uint256)", "ZeroAddress()", "ZeroAmount()",
    "MintTooLarge(uint256,uint256)", "WindowLimitExceeded(uint256,uint256)",
    "NotEnoughSignatures(uint256,uint256)", "BadSignerOrder()", "NotAttester(address)",
    "BadThreshold()", "BadLimits()", "NotWholeCents(uint256)", "BelowMinimum(uint256,uint256)",
    "ZeroLedgerWallet()", "SupplyCapExceeded(uint256,uint256)", "EnforcedPause()",
    "AccessControlUnauthorizedAccount(address,bytes32)", "ECDSAInvalidSignature()",
    "ECDSAInvalidSignatureLength(uint256)", "ECDSAInvalidSignatureS(bytes32)",
    "ERC20InsufficientAllowance(address,uint256,uint256)", "ERC20InsufficientBalance(address,uint256,uint256)",
]
ERROR_NAMES = {"0x" + keccak(text=sig)[:4].hex(): sig.split("(")[0] for sig in _ERRORS}


class RPCError(Exception):
    def __init__(self, message: str, data: Optional[str] = None):
        name = ERROR_NAMES.get((data or "")[:10])
        super().__init__(f"{message} ({name})" if name else message)
        self.data = data
        self.error_name = name


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def calldata(signature: str, types: Sequence[str] = (), args: Sequence[Any] = ()) -> str:
    return "0x" + (selector(signature) + encode(list(types), list(args))).hex()


class Chain:
    def __init__(self, rpc_url: str, timeout: float = 30.0):
        self._http = httpx.Client(timeout=timeout)
        self._url = rpc_url
        self._id = 0

    def close(self):
        self._http.close()

    def rpc(self, method: str, params: list) -> Any:
        self._id += 1
        resp = self._http.post(self._url, json={"jsonrpc": "2.0", "id": self._id, "method": method,
                                                "params": params})
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            err = body["error"]
            data = err.get("data")
            if isinstance(data, dict):
                data = data.get("data")
            raise RPCError(f"{method}: {err.get('message')}", data if isinstance(data, str) else None)
        return body["result"]

    # ----------------------------------------------------------------- reads

    def chain_id(self) -> int:
        return int(self.rpc("eth_chainId", []), 16)

    def block_number(self, tag: str = "latest") -> int:
        if tag == "latest":
            return int(self.rpc("eth_blockNumber", []), 16)
        return int(self.rpc("eth_getBlockByNumber", [tag, False])["number"], 16)

    def final_block(self, chain_finality: str) -> int:
        """Highest block we treat as final: a tag ("finalized"/"safe") or N confirmations."""
        if chain_finality.isdigit():
            return max(self.block_number() - int(chain_finality), -1)
        return self.block_number(chain_finality)

    def call(self, to: str, signature: str, types: Sequence[str] = (), args: Sequence[Any] = (),
             returns: Sequence[str] = ("uint256",)) -> Any:
        out = self.rpc("eth_call", [{"to": to, "data": calldata(signature, types, args)}, "latest"])
        values = decode(list(returns), bytes.fromhex(out[2:]))
        return values[0] if len(values) == 1 else values

    def code(self, address: str) -> bytes:
        """The code at an address: empty for a plain wallet, 0xef0100 + target for an EIP-7702 delegation."""
        return bytes.fromhex(self.rpc("eth_getCode", [address, "latest"])[2:])

    def logs(self, address: str, topic0: str, from_block: int, to_block: int, chunk: int = 5_000) -> List[dict]:
        out = []
        start = from_block
        while start <= to_block:
            end = min(start + chunk - 1, to_block)
            out += self.rpc("eth_getLogs", [{"address": address, "topics": [topic0],
                                             "fromBlock": hex(start), "toBlock": hex(end)}])
            start = end + 1
        return out

    # ----------------------------------------------------------------- writes

    def send(self, key: str, to: Optional[str], data: str, value: int = 0, gas: Optional[int] = None,
             wait: float = 60.0) -> Dict[str, Any]:
        """Sign and send an EIP-1559 tx, wait for the receipt, raise RPCError on revert."""
        acct = Account.from_key(key)
        tx = {"from": acct.address, "data": data, "value": hex(value)}
        if to:
            tx["to"] = to_checksum_address(to)
        if gas is None:
            gas = int(int(self.rpc("eth_estimateGas", [tx]), 16) * 1.25)  # raises with the revert reason
        base_fee = int(self.rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
        tip = int(self.rpc("eth_maxPriorityFeePerGas", []), 16)
        unsigned = {
            "chainId": self.chain_id(),
            "nonce": int(self.rpc("eth_getTransactionCount", [acct.address, "pending"]), 16),
            "data": data, "value": value, "gas": gas,
            "maxFeePerGas": 2 * base_fee + tip, "maxPriorityFeePerGas": tip, "type": 2,
        }
        if to:
            unsigned["to"] = tx["to"]
        signed = acct.sign_transaction(unsigned)
        tx_hash = self.rpc("eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex().removeprefix("0x")])
        deadline = time.monotonic() + wait
        while True:
            receipt = self.rpc("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                break
            if time.monotonic() > deadline:
                raise RPCError(f"timed out waiting for {tx_hash}")
            time.sleep(0.2)
        if int(receipt["status"], 16) != 1:
            raise RPCError(f"transaction {tx_hash} reverted")
        return receipt


class BridgeContract:
    """The GFCBridge calls the service uses (see evm/src/GFCBridge.sol)."""

    def __init__(self, chain: Chain, address: str):
        self.chain = chain
        self.address = to_checksum_address(address)

    def _u(self, sig: str) -> int:
        return self.chain.call(self.address, sig)

    def token(self) -> str:
        return to_checksum_address(self.chain.call(self.address, "token()", returns=("address",)))

    def threshold(self) -> int:
        return self._u("threshold()")

    def max_mint_cents(self) -> int:
        return self._u("maxMintCents()")

    def remaining_in_window_cents(self) -> int:
        return self._u("remainingInWindowCents()")

    def total_minted_cents(self) -> int:
        return self._u("totalMintedCents()")

    def total_bridged_out_cents(self) -> int:
        return self._u("totalBridgedOutCents()")

    def paused(self) -> bool:
        return self.chain.call(self.address, "paused()", returns=("bool",))

    def processed(self, ledger_tx_hash: bytes) -> bool:
        return self.chain.call(self.address, "processed(bytes32)", ["bytes32"], [ledger_tx_hash], ("bool",))

    def is_attester(self, address: str) -> bool:
        role = keccak(text="ATTESTER_ROLE")
        return self.chain.call(self.address, "hasRole(bytes32,address)", ["bytes32", "address"],
                               [role, to_checksum_address(address)], ("bool",))

    def mint_digest(self, req: tuple) -> bytes:
        return self.chain.call(self.address, f"mintDigest({MINT_REQUEST_TUPLE})", [MINT_REQUEST_TUPLE],
                               [req], ("bytes32",))

    def mint_from_ledger(self, key: str, req: tuple, signatures: List[bytes]) -> Dict[str, Any]:
        data = calldata(f"mintFromLedger({MINT_REQUEST_TUPLE},bytes[])", [MINT_REQUEST_TUPLE, "bytes[]"],
                        [req, signatures])
        return self.chain.send(key, self.address, data)

    def pause(self, key: str) -> Dict[str, Any]:
        return self.chain.send(key, self.address, calldata("pause()"))

    def bridged_out_logs(self, from_block: int, to_block: int, chunk: int) -> List[dict]:
        """BridgedOut events as dicts: nonce, from, ledger_wallet (hex), amount_cents, block, evm_tx."""
        out = []
        for log in self.chain.logs(self.address, TOPIC_BRIDGED_OUT, from_block, to_block, chunk):
            t = log["topics"]
            out.append({
                "nonce": int(t[1], 16),
                "from": to_checksum_address("0x" + t[2][-40:]),
                "ledger_wallet": t[3][2:].lower(),
                "amount_cents": int(log["data"], 16),
                "block": int(log["blockNumber"], 16),
                "evm_tx": log["transactionHash"],
            })
        return out

    def minted_logs(self, from_block: int, to_block: int, chunk: int) -> List[dict]:
        out = []
        for log in self.chain.logs(self.address, TOPIC_MINTED, from_block, to_block, chunk):
            t = log["topics"]
            out.append({
                "ledger_tx_hash": t[1][2:].lower(),
                "to": to_checksum_address("0x" + t[2][-40:]),
                "amount_cents": int(log["data"], 16),
                "block": int(log["blockNumber"], 16),
                "evm_tx": log["transactionHash"],
            })
        return out


def token_total_supply(chain: Chain, token: str) -> int:
    return chain.call(token, "totalSupply()")
