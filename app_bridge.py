"""
GFC Bridge API - move GFC from the ledger to its ERC-20 on Base ("Bridge to Base").

- GET  /bridge/info                        chains with a pinned escrow, the token address once
                                           deployed, and the deposit policy (min, fee, hold)
- GET  /bridge/quote?wallet_id=W           W's balance and how much of it can be bridged now
- POST /bridge/deposit (Bearer, spend)     {wallet_id, chain_id, evm_address, amount}: a signed
                                           TRANSFER to that chain's escrow with the exact reason
                                           bridge:v1:<chainId>:<address> the bridge service mints for

The node refuses deposits the bridge service would never mint (under the minimum, or paid
with fresh free credit), so users don't strand GFC waiting for a manual refund. The rules
every node enforces on escrow wallets are in blockchain.bridge_rule_violation(); the
service is bridge/ (docs/bridge-service.md).
"""

import re
import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import blockchain
import config
from bridge import deposits
from config import DB_PATH
from security import Caller, bearer_token, release_spend, reserve_spend, resolve_caller

router = APIRouter()

EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class BridgeDepositRequest(BaseModel):
    wallet_id: str
    chain_id: int
    evm_address: str
    amount: float
    api_token: str = ""  # Legacy: prefer the Authorization: Bearer header


def _escrows() -> frozenset:
    return frozenset(config.BRIDGE_ESCROWS.values())


def _bridgeable(wallet_id: str) -> tuple:
    """(balance_cents, bridgeable_cents) for a wallet, as the attesters will judge it now."""
    conn = sqlite3.connect(DB_PATH)
    try:
        return deposits.clean_cents(conn, wallet_id, datetime.now(timezone.utc), config.BRIDGE_FAUCET_HOLD_DAYS,
                                    exclude=_escrows())
    finally:
        conn.close()


@router.get("/bridge/info")
def bridge_info():
    chains = [{
        "chain_id": chain_id,
        "name": config.CHAIN_NAMES.get(chain_id, f"Chain {chain_id}"),
        "escrow_wallet": escrow,
        "token_address": config.BRIDGE_TOKENS.get(chain_id),  # None until the token is deployed
    } for chain_id, escrow in sorted(config.BRIDGE_ESCROWS.items())]
    return {
        "enabled": bool(chains),
        "chains": chains,
        "min_deposit_cents": config.BRIDGE_MIN_DEPOSIT_CENTS,
        "relay_fee_cents": config.BRIDGE_RELAY_FEE_CENTS,
        "faucet_hold_days": config.BRIDGE_FAUCET_HOLD_DAYS,
        "notice": "Wrapped GFC is an in-app credit, not an investment. Bridging is new, unaudited code: "
                  "start small. Deposits are minted after a finality wait and attester checks.",
    }


@router.get("/bridge/quote")
def bridge_quote(wallet_id: str):
    balance, bridgeable = _bridgeable(wallet_id)
    return {
        "wallet_id": wallet_id,
        "balance_cents": balance,
        "bridgeable_cents": bridgeable,
        "held_cents": balance - bridgeable,
        "faucet_hold_days": config.BRIDGE_FAUCET_HOLD_DAYS,
        "min_deposit_cents": config.BRIDGE_MIN_DEPOSIT_CENTS,
        "relay_fee_cents": config.BRIDGE_RELAY_FEE_CENTS,
    }


@router.post("/bridge/deposit")
def bridge_deposit(req: BridgeDepositRequest, bearer: str = Depends(bearer_token)):
    caller: Caller = resolve_caller(bearer, req.api_token)
    username = caller.require("spend")

    escrow = config.BRIDGE_ESCROWS.get(req.chain_id)
    if not escrow:
        raise HTTPException(status_code=400, detail="bridging to that chain isn't available")
    if not EVM_ADDRESS_RE.match(req.evm_address) or int(req.evm_address, 16) == 0:
        raise HTTPException(status_code=400, detail="evm_address must be a 0x address (40 hex characters)")

    conn = sqlite3.connect(DB_PATH)
    wallet = conn.execute("SELECT owner FROM wallets WHERE id = ?", (req.wallet_id,)).fetchone()
    conn.close()
    if not wallet or not wallet[0] or wallet[0].lower() != username.lower():
        raise HTTPException(status_code=403, detail="wallet does not belong to this user")

    amount_cents = round(req.amount * 100)
    if amount_cents < config.BRIDGE_MIN_DEPOSIT_CENTS or amount_cents <= config.BRIDGE_RELAY_FEE_CENTS:
        raise HTTPException(status_code=400, detail=f"the minimum deposit is "
                                                    f"{config.BRIDGE_MIN_DEPOSIT_CENTS / 100:.2f} GFC")
    balance, bridgeable = _bridgeable(req.wallet_id)
    if amount_cents > balance:
        raise HTTPException(status_code=400, detail=f"insufficient balance: {balance / 100:.2f} GFC available")
    if amount_cents > bridgeable:
        raise HTTPException(status_code=400, detail=(
            f"only {bridgeable / 100:.2f} GFC can be bridged now: free credit (welcome grant, invite and "
            f"post bonuses) can be bridged {config.BRIDGE_FAUCET_HOLD_DAYS:g} days after it arrives"))

    reserve_spend(caller, amount_cents)  # Per-token daily limit, if the token has one
    try:
        tx = blockchain.process_transfer(
            db_path=DB_PATH, sender_wallet=req.wallet_id, recipient_wallet=escrow, amount_cents=amount_cents,
            reason=f"bridge:v1:{req.chain_id}:{req.evm_address}", data_key=caller.data_key())
    except ValueError as e:
        release_spend(caller, amount_cents)
        raise HTTPException(status_code=400, detail=str(e))
    if not tx.get("signature"):
        # Can't happen for keyed wallets; a legacy unsigned deposit would never be minted
        raise HTTPException(status_code=500, detail="deposit was not signed")
    return {
        "ok": True,
        "tx_id": tx["id"],
        "tx_hash": tx["tx_hash"],
        "chain_id": req.chain_id,
        "evm_address": req.evm_address,
        "amount_cents": amount_cents,
        "mint_cents": amount_cents - config.BRIDGE_RELAY_FEE_CENTS,
        "status": "deposited: tokens are minted after the finality wait and attester checks",
    }
