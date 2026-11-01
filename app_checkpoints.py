"""
Ledger checkpoints API (ledger_checkpoints.py): what bridge attesters read from the canonical node.

- GET /ledger/checkpoint                         the latest signed checkpoint {body, signature}
- GET /ledger/checkpoint/log?start=N&limit=L     log rows N.. (1-based) up to the latest checkpoint:
                                                 [{position, tx_hash}], at most 2,000 per call
"""

from fastapi import APIRouter, HTTPException, Query

import ledger_checkpoints
from config import DB_PATH

router = APIRouter()

MAX_LOG_ROWS = 2000


@router.get("/ledger/checkpoint")
def latest_checkpoint():
    cp = ledger_checkpoints.latest(DB_PATH)
    if cp is None:
        raise HTTPException(404, "this node doesn't sign checkpoints")
    return cp


@router.get("/ledger/checkpoint/log")
def checkpoint_log(start: int = Query(1, ge=1), limit: int = Query(MAX_LOG_ROWS, ge=1, le=MAX_LOG_ROWS)):
    cp = ledger_checkpoints.latest(DB_PATH)
    if cp is None:
        raise HTTPException(404, "this node doesn't sign checkpoints")
    return {"count": cp["body"]["count"],
            "rows": ledger_checkpoints.log_rows(DB_PATH, start, limit, cp["body"]["count"])}
