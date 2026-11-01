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
    """
    An RPC failure. Never carries the RPC URL (it often holds an API key). A transaction that
    was sent carries tx_hash, and receipt when it reverted: its gas was spent all the same.
    """
    def __init__(self, message: str, data: Optional[str] = None, tx_hash: Optional[str] = None,
                 receipt: Optional[dict] = None):
        name = ERROR_NAMES.get((data or "")[:10])
        super().__init__(f"{message} ({name})" if name else message)
        self.data = data
        self.error_name = name
        self.tx_hash = tx_hash
        self.receipt = receipt


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def calldata(signature: str, types: Sequence[str] = (), args: Sequence[Any] = ()) -> str:
    return "0x" + (selector(signature) + encode(list(types), list(args))).hex()


class Chain:
    def __init__(self, rpc_url: str, timeout: float = 30.0, label: str = "rpc"):
        self._http = httpx.Client(timeout=timeout)
        self._url = rpc_url
        self._id = 0
        self.label = label  # how logs and errors name this provider: never its URL

    def close(self):
        self._http.close()

    def rpc(self, method: str, params: list) -> Any:
        self._id += 1
        try:
            resp = self._http.post(self._url, json={"jsonrpc": "2.0", "id": self._id, "method": method,
                                                    "params": params})
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPStatusError as e:  # httpx's own message holds the URL
            raise RPCError(f"{self.label} {method}: HTTP {e.response.status_code}") from None
        except (httpx.HTTPError, ValueError) as e:
            raise RPCError(f"{self.label} {method}: {type(e).__name__}") from None
        if not isinstance(body, dict):
            raise RPCError(f"{self.label} {method}: malformed response")
        if "error" in body:
            err = body["error"]
            data = err.get("data")
            if isinstance(data, dict):
                data = data.get("data")
            raise RPCError(f"{method}: {err.get('message')}", data if isinstance(data, str) else None)
        if "result" not in body:
            raise RPCError(f"{self.label} {method}: malformed response")
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
             returns: Sequence[str] = ("uint256",), block: Any = "latest") -> Any:
        tag = hex(block) if isinstance(block, int) else block
        out = self.rpc("eth_call", [{"to": to, "data": calldata(signature, types, args)}, tag])
        values = decode(list(returns), bytes.fromhex(out[2:]))
        return values[0] if len(values) == 1 else values

    def code(self, address: str) -> bytes:
        """The code at an address: empty for a plain wallet, 0xef0100 + target for an EIP-7702 delegation."""
        return bytes.fromhex(self.rpc("eth_getCode", [address, "latest"])[2:])

    def nonce(self, address: str, block: Any = "latest") -> int:
        """Transactions sent from an address. An EIP-7702 authorization raises it too."""
        tag = hex(block) if isinstance(block, int) else block
        return int(self.rpc("eth_getTransactionCount", [address, tag]), 16)

    def block_hash(self, number: int) -> Optional[str]:
        block = self.rpc("eth_getBlockByNumber", [hex(number), False])
        return block["hash"].lower() if block else None

    def receipt(self, tx_hash: str) -> Optional[dict]:
        return self.rpc("eth_getTransactionReceipt", [tx_hash])

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
             wait: float = 60.0, max_gas: Optional[int] = None,
             max_fee_per_gas: Optional[int] = None) -> Dict[str, Any]:
        """
        Sign and send an EIP-1559 tx, wait for the receipt, raise RPCError on revert (with the
        receipt: a reverted tx still pays gas) or timeout (with the tx hash: it may still land).
        max_gas / max_fee_per_gas cap what the RPC's estimates may spend (audit F12): over a cap,
        nothing is sent.
        """
        acct = Account.from_key(key)
        tx = {"from": acct.address, "data": data, "value": hex(value)}
        if to:
            tx["to"] = to_checksum_address(to)
        if gas is None:
            gas = int(int(self.rpc("eth_estimateGas", [tx]), 16) * 1.25)  # raises with the revert reason
        if max_gas is not None and gas > max_gas:
            raise RPCError(f"needs {gas} gas, above the {max_gas} cap: not sent")
        base_fee = int(self.rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
        tip = int(self.rpc("eth_maxPriorityFeePerGas", []), 16)
        max_fee = 2 * base_fee + tip
        if max_fee_per_gas is not None:
            if base_fee >= max_fee_per_gas:
                raise RPCError(f"base fee {base_fee} wei is at or above the {max_fee_per_gas} wei cap: not sent")
            max_fee = min(max_fee, max_fee_per_gas)
            tip = min(tip, max_fee - base_fee)
        unsigned = {
            "chainId": self.chain_id(),
            "nonce": int(self.rpc("eth_getTransactionCount", [acct.address, "pending"]), 16),
            "data": data, "value": value, "gas": gas,
            "maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip, "type": 2,
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
                raise RPCError(f"timed out waiting for {tx_hash}", tx_hash=tx_hash)
            time.sleep(0.2)
        if int(receipt["status"], 16) != 1:
            raise RPCError(f"transaction {tx_hash} reverted", tx_hash=tx_hash, receipt=receipt)
        return receipt


class BridgeContract:
    """The GFCBridge calls the service uses (see evm/src/GFCBridge.sol)."""

    def __init__(self, chain: Chain, address: str):
        self.chain = chain
        self.address = to_checksum_address(address)

    def _u(self, sig: str, block: Any = "latest") -> int:
        return self.chain.call(self.address, sig, block=block)

    def token(self, block: Any = "latest") -> str:
        return to_checksum_address(self.chain.call(self.address, "token()", returns=("address",), block=block))

    def threshold(self) -> int:
        return self._u("threshold()")

    def max_mint_cents(self) -> int:
        return self._u("maxMintCents()")

    def remaining_in_window_cents(self) -> int:
        return self._u("remainingInWindowCents()")

    def total_minted_cents(self, block: Any = "latest") -> int:
        return self._u("totalMintedCents()", block)

    def total_bridged_out_cents(self, block: Any = "latest") -> int:
        return self._u("totalBridgedOutCents()", block)

    def paused(self) -> bool:
        return self.chain.call(self.address, "paused()", returns=("bool",))

    def processed(self, ledger_tx_hash: bytes, block: Any = "latest") -> bool:
        return self.chain.call(self.address, "processed(bytes32)", ["bytes32"], [ledger_tx_hash], ("bool",), block)

    def is_attester(self, address: str) -> bool:
        role = keccak(text="ATTESTER_ROLE")
        return self.chain.call(self.address, "hasRole(bytes32,address)", ["bytes32", "address"],
                               [role, to_checksum_address(address)], ("bool",))

    def mint_digest(self, req: tuple) -> bytes:
        return self.chain.call(self.address, f"mintDigest({MINT_REQUEST_TUPLE})", [MINT_REQUEST_TUPLE],
                               [req], ("bytes32",))

    def mint_from_ledger(self, key: str, req: tuple, signatures: List[bytes], max_gas: Optional[int] = None,
                         max_fee_per_gas: Optional[int] = None) -> Dict[str, Any]:
        data = calldata(f"mintFromLedger({MINT_REQUEST_TUPLE},bytes[])", [MINT_REQUEST_TUPLE, "bytes[]"],
                        [req, signatures])
        return self.chain.send(key, self.address, data, max_gas=max_gas, max_fee_per_gas=max_fee_per_gas)

    def pause(self, key: str) -> Dict[str, Any]:
        return self.chain.send(key, self.address, calldata("pause()"))

    def bridged_out_logs(self, from_block: int, to_block: int, chunk: int) -> List[dict]:
        """
        BridgedOut events as dicts: nonce, from, ledger_wallet (hex), amount_cents, block,
        evm_tx, block_hash, log_index. A log that isn't exactly a BridgedOut of this bridge in
        the asked range raises RPCError: the provider is wrong or lying (audit F09).
        """
        out = []
        for log in self.chain.logs(self.address, TOPIC_BRIDGED_OUT, from_block, to_block, chunk):
            ev = decode_bridged_out(log, self.address)
            if not from_block <= ev["block"] <= to_block:
                raise RPCError(f"{self.chain.label}: BridgedOut log from block {ev['block']}, outside "
                               f"{from_block}..{to_block}")
            out.append(ev)
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


def _word(value: Any) -> int:
    """A 32-byte hex word as an int; anything else raises ValueError."""
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise ValueError(f"not a 32-byte word: {value!r}")
    return int(value, 16)


def decode_bridged_out(log: dict, bridge_address: str) -> dict:
    """One BridgedOut log, checked field by field; RPCError if it isn't exactly one."""
    try:
        if log.get("removed"):
            raise ValueError("removed (reorged out)")
        if (log.get("address") or "").lower() != bridge_address.lower():
            raise ValueError(f"from {log.get('address')}, not the bridge")
        t = log.get("topics") or []
        if len(t) != 4 or t[0].lower() != TOPIC_BRIDGED_OUT:
            raise ValueError("not a BridgedOut event")
        nonce, sender, wallet, amount = _word(t[1]), _word(t[2]), _word(t[3]), _word(log.get("data"))
        if sender >> 160:
            raise ValueError("sender isn't an address")
        tx_hash, block_hash = log.get("transactionHash"), log.get("blockHash")
        _word(tx_hash), _word(block_hash)
        return {
            "nonce": nonce,
            "from": to_checksum_address("0x" + format(sender, "040x")),
            "ledger_wallet": format(wallet, "064x"),
            "amount_cents": amount,
            "block": int(log["blockNumber"], 16),
            "evm_tx": tx_hash.lower(),
            "block_hash": block_hash.lower(),
            "log_index": int(log["logIndex"], 16),
        }
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise RPCError(f"malformed BridgedOut log: {e}") from None


def token_total_supply(chain: Chain, token: str, block: Any = "latest") -> int:
    return chain.call(token, "totalSupply()", block=block)
