"""
GFC PoDT (Proof-of-Data-Transfer) API Endpoints
Lightweight router integrated with the blockchain — no libtorrent dependency.

Replaces the old podt_api.py which required libtorrent (broken/excluded).
Uses blockchain.process_podt_reward() to create REWARD transactions from Treasury.
"""

import hashlib
import os
import sqlite3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from config import DB_PATH
from blockchain import (
    process_podt_reward,
    get_balance_cents,
    TREASURY_WALLET_ID,
    CREDITS_PER_MB_CENTS,
    MIN_TRANSFER_BYTES,
)


# Create router
podt_router = APIRouter(prefix="/podt", tags=["Proof-of-Data-Transfer"])


# ============================================================================
# REQUEST MODELS
# ============================================================================

class TransferReportRequest(BaseModel):
    seeder_wallet: str
    receiver_wallet: str = ""
    file_hash: str
    file_size_bytes: int


# ============================================================================
# ENDPOINTS
# ============================================================================

@podt_router.post("/report_transfer")
async def report_transfer(request: TransferReportRequest):
    """
    Report a completed file transfer for PoDT credit.

    Called by the sync engine after a seed file is successfully transferred.
    Creates a REWARD transaction from Treasury to the seeder's wallet.

    Disabled unless GFC_ENABLE_PODT_REPORT=1: the claim is self-reported and
    unauthenticated, so anyone could mint Treasury rewards. The sync engine
    awards PoDT credits directly and does not need this endpoint.
    """
    if os.environ.get("GFC_ENABLE_PODT_REPORT") != "1":
        raise HTTPException(status_code=403, detail="report_transfer is disabled on this node")
    if not request.seeder_wallet:
        raise HTTPException(status_code=400, detail="seeder_wallet is required")
    if not request.file_hash:
        raise HTTPException(status_code=400, detail="file_hash is required")
    if request.file_size_bytes < MIN_TRANSFER_BYTES:
        return {
            "ok": False,
            "reason": f"Transfer too small (min {MIN_TRANSFER_BYTES} bytes)",
            "credits_earned": 0.0,
        }

    # Compute proof ID from transfer details
    proof_string = f"{request.seeder_wallet}:{request.receiver_wallet}:{request.file_hash}:{request.file_size_bytes}"
    proof_id = hashlib.sha256(proof_string.encode()).hexdigest()

    try:
        result = process_podt_reward(
            db_path=DB_PATH,
            seeder_wallet=request.seeder_wallet,
            proof_id=proof_id,
            bytes_transferred=request.file_size_bytes,
            file_hash=request.file_hash,
            receiver_wallet=request.receiver_wallet,
        )

        if result:
            return {
                "ok": True,
                "proof_id": proof_id,
                "credits_earned": result["amount"],
                "credits_earned_cents": result["amount_cents"],
                "tx_id": result["id"],
                "tx_hash": result["tx_hash"],
                "block_index": result.get("block_index"),
                "mb_transferred": request.file_size_bytes / (1024 * 1024),
            }
        else:
            return {
                "ok": False,
                "reason": "Transfer already claimed or reward too small",
                "proof_id": proof_id,
                "credits_earned": 0.0,
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@podt_router.get("/stats")
async def podt_stats():
    """Get network-wide PoDT statistics."""
    try:
        conn = sqlite3.connect(DB_PATH)

        total_proofs = conn.execute("SELECT COUNT(*) FROM podt_proofs").fetchone()[0]
        total_bytes = conn.execute(
            "SELECT COALESCE(SUM(file_size_bytes), 0) FROM podt_proofs"
        ).fetchone()[0]
        total_reward_cents = conn.execute(
            "SELECT COALESCE(SUM(reward_cents), 0) FROM podt_proofs"
        ).fetchone()[0]

        # Top 10 seeders by total reward
        top_seeders = conn.execute(
            "SELECT seeder_wallet, SUM(reward_cents) as total_reward, COUNT(*) as transfer_count, "
            "SUM(file_size_bytes) as total_bytes "
            "FROM podt_proofs GROUP BY seeder_wallet ORDER BY total_reward DESC LIMIT 10"
        ).fetchall()

        conn.close()

        return {
            "ok": True,
            "total_transfers": total_proofs,
            "total_bytes": total_bytes,
            "total_bytes_mb": total_bytes / (1024 * 1024) if total_bytes else 0.0,
            "total_bytes_gb": total_bytes / (1024 * 1024 * 1024) if total_bytes else 0.0,
            "total_reward_gfc": total_reward_cents / 100.0 if total_reward_cents else 0.0,
            "rate_gfc_per_mb": CREDITS_PER_MB_CENTS / 100.0,
            "top_seeders": [
                {
                    "wallet": row[0],
                    "total_earned_gfc": row[1] / 100.0,
                    "transfer_count": row[2],
                    "total_bytes_mb": row[3] / (1024 * 1024) if row[3] else 0.0,
                }
                for row in top_seeders
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@podt_router.get("/wallet/{wallet_id}")
async def podt_wallet_stats(wallet_id: str):
    """Get PoDT earnings for a specific wallet."""
    try:
        conn = sqlite3.connect(DB_PATH)

        # Wallet-specific PoDT stats
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(reward_cents), 0), COALESCE(SUM(file_size_bytes), 0) "
            "FROM podt_proofs WHERE seeder_wallet = ?",
            (wallet_id,)
        ).fetchone()

        # Recent transfers
        recent = conn.execute(
            "SELECT proof_id, file_hash, file_size_bytes, reward_cents, receiver_wallet, created_at "
            "FROM podt_proofs WHERE seeder_wallet = ? ORDER BY created_at DESC LIMIT 20",
            (wallet_id,)
        ).fetchall()

        conn.close()

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "transfer_count": row[0],
            "total_earned_gfc": row[1] / 100.0,
            "total_earned_cents": row[1],
            "total_bytes_seeded": row[2],
            "total_bytes_seeded_mb": row[2] / (1024 * 1024) if row[2] else 0.0,
            "recent_transfers": [
                {
                    "proof_id": r[0],
                    "file_hash": r[1][:16] + "...",
                    "file_size_bytes": r[2],
                    "reward_gfc": r[3] / 100.0,
                    "receiver_wallet": r[4][:16] + "..." if r[4] else "",
                    "timestamp": r[5],
                }
                for r in recent
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
