"""
GFC Backend - Main Application
Galactic Federation Coin - Backend API

Features: wallets, transactions, seeds, feed, search, profiles, engagement,
          blockchain (hybrid SQLite chain), PoDT rewards, P2P sync.
"""

from fastapi import FastAPI, HTTPException, Form, File, UploadFile, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json
import sqlite3
import os
import uuid
import hashlib
import datetime

import config
from config import DB_PATH, DATA_DIR, SEEDS_ORIG_DIR, SEEDS_THUMB_DIR, AVATAR_DIR

from app_seeds import router as seeds_router
from app_engagement import router as engagement_router
from app_profile import router as profile_router
from app_podt import podt_router
from app_verify import router as verify_router
from app_share import router as share_router
from app_referrals import router as referrals_router
from app_echohunt import router as echohunt_router
from app_tokens import router as tokens_router
from app_web import router as web_router, feed_html_response, wants_html
from app_moderation import router as moderation_router
from app_webverify import router as webverify_router
from app_treasury import router as treasury_router
from app_release import router as release_router
from app_recovery import router as recovery_router
import audio_stream
import blockchain
import logredact
import moderation
import keystore
import first_post
import seed_edits
import verified_wallets
import referrals
import reposts
import signing
from security import (
    hash_password, verify_password, migrate_plaintext_passwords,
    init_sessions_table, create_session, Caller, caller_from_form, caller_from_query,
    bearer_token, resolve_caller, reserve_spend, release_spend, NodeCORSMiddleware,
)

# ============================================================================
# APP INITIALIZATION
# ============================================================================

app = FastAPI(
    title="Galactic Federation Coin API",
    description="Complete GFC backend with P2P sync",
    version="4.0.0"
)

# CORS: only the origins in GFC_CORS_ORIGINS (none by default, i.e. same-origin only)
app.add_middleware(NodeCORSMiddleware)

# Include routers
app.include_router(seeds_router)
app.include_router(engagement_router)
app.include_router(profile_router)
app.include_router(podt_router)
app.include_router(verify_router)
app.include_router(share_router)
app.include_router(referrals_router)
app.include_router(echohunt_router)
app.include_router(tokens_router)
app.include_router(web_router)
app.include_router(moderation_router)
app.include_router(webverify_router)
app.include_router(treasury_router)
app.include_router(release_router)
app.include_router(recovery_router)

# Static file serving (using absolute paths from config)
# follow_symlink=True is required on Windows because files created by different
# processes (e.g., MSIX AppContainer sandboxes) may resolve through NTFS reparse
# points, causing os.path.realpath() to return a different base path than the
# directory itself. Using abspath (follow_symlink) avoids this mismatch.
app.mount("/originals", StaticFiles(directory=str(SEEDS_ORIG_DIR), follow_symlink=True), name="originals")
app.mount("/thumbs", StaticFiles(directory=str(SEEDS_THUMB_DIR), follow_symlink=True), name="thumbs")
app.mount("/avatars", StaticFiles(directory=str(AVATAR_DIR), follow_symlink=True), name="avatars")
# Compressed streaming copies of big/lossless audio (audio_stream.py)
app.mount("/streams", StaticFiles(directory=str(audio_stream.STREAMS_DIR), follow_symlink=True), name="streams")

# ============================================================================
# MODELS
# ============================================================================

class WalletCreateResponse(BaseModel):
    id: str
    name: str
    gfc_balance: float = 0.0


class TransactionRequest(BaseModel):
    sender: str
    recipient: str
    amount: float
    reason: str
    api_token: str = ""  # Legacy: prefer the Authorization: Bearer header


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Ensure all tables exist in the ledger database"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT DEFAULT '',
        last_name TEXT DEFAULT '',
        email TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS wallets
                    (id TEXT PRIMARY KEY, name TEXT, owner TEXT DEFAULT '', gfc_balance REAL DEFAULT 100, created_at TEXT DEFAULT '')''')
    # Migration: add columns if they don't exist (safe to re-run)
    for col, coldef in [("owner", "TEXT DEFAULT ''"), ("gfc_balance", "REAL DEFAULT 100"), ("created_at", "TEXT DEFAULT ''")]:
        try:
            conn.execute(f"ALTER TABLE wallets ADD COLUMN {col} {coldef}")
        except Exception:
            pass  # Column already exists
    conn.execute('''CREATE TABLE IF NOT EXISTS transactions
                    (id TEXT PRIMARY KEY, sender TEXT, recipient TEXT,
                     amount REAL, reason TEXT, timestamp TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS seeds (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        title TEXT DEFAULT '',
        description TEXT DEFAULT '',
        tags TEXT DEFAULT '',
        filename TEXT NOT NULL,
        thumb_filename TEXT DEFAULT '',
        content_type TEXT DEFAULT '',
        file_size INTEGER DEFAULT 0,
        gfc_earned REAL DEFAULT 0.0,
        likes INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        seed_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS likes (
        id TEXT PRIMARY KEY,
        seed_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(seed_id, owner)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS bookmarks (
        id TEXT PRIMARY KEY,
        seed_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(seed_id, owner)
    )''')
    # Migration: add profile columns to users table (safe to re-run)
    try:
        conn.execute("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''")
    except Exception:
        pass  # column already exists
    try:
        conn.execute("ALTER TABLE users ADD COLUMN avatar_filename TEXT DEFAULT ''")
    except Exception:
        pass  # column already exists
    try:
        conn.execute("ALTER TABLE seeds ADD COLUMN reward_wallet TEXT DEFAULT ''")
    except Exception:
        pass  # column already exists
    try:
        # Signature by reward_wallet over the seed's identity (see signing.sign_seed)
        conn.execute("ALTER TABLE seeds ADD COLUMN signature TEXT DEFAULT ''")
    except Exception:
        pass  # column already exists

    init_sessions_table(conn)
    keystore.init_keystore(conn)
    reposts.init_repost_tables(conn)
    first_post.init_first_post_tables(conn)
    seed_edits.init_seed_edit_tables(conn)
    verified_wallets.init_tables(conn)
    migrate_plaintext_passwords(conn)

    conn.commit()
    conn.close()

    # Initialize blockchain tables and genesis block (idempotent)
    blockchain.init_blockchain_tables(DB_PATH)
    blockchain.create_genesis_block(DB_PATH)

init_db()


# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

@app.post("/auth/register")
async def auth_register(
    username: str = Form(...),
    password: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    phone: str = Form(""),
    ref: str = Form("")
):
    """Register a new user account. `ref` is the username of whoever invited them (optional)."""
    if not username.strip() or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    username = username.strip()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO users (id, username, password, first_name, last_name, email, phone, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), username, hash_password(password), first_name.strip(), last_name.strip(), email.strip(), phone.strip(),
             datetime.datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="username already exists")
    finally:
        conn.close()

    token = create_session(username)
    data_key = keystore.unlock_user_keys(username, password)
    keystore.attach_to_session(token, data_key)
    invited_by = referrals.record_invite(DB_PATH, username, ref)
    # Shown to the user once: with their phone or email it restores the account AND its wallets
    # if they forget the password (account_recovery.py)
    recovery_code = keystore.new_recovery_code(username, data_key)
    return {"ok": True, "token": token, "user": username, "invited_by": invited_by, "recovery_code": recovery_code}


@app.post("/auth/login")
async def auth_login(
    username: str = Form(...),
    password: str = Form(...)
):
    """Login with username and password"""
    if not username.strip() or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    username = username.strip()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, password FROM users WHERE LOWER(username) = LOWER(?)",
        (username,)
    ).fetchone()
    conn.close()

    if not row or not verify_password(password, row[1]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    # Return the canonical username from the database, not the user input
    canonical_username = row[0]
    token = create_session(canonical_username)
    # Unwrap the user's data key with the password and re-wrap it for this session
    keystore.attach_to_session(token, keystore.unlock_user_keys(canonical_username, password))
    return {"ok": True, "token": token, "user": canonical_username}


# ============================================================================
# CORE ENDPOINTS
# ============================================================================

@app.get("/")
def root(request: Request):
    """API root - service info; browsers (Accept: text/html) get the web feed instead."""
    if wants_html(request):
        return feed_html_response(request)
    return JSONResponse({
        "service": "Galactic Federation Coin API",
        "version": "4.0.0",
        "features": [
            "Wallet Management",
            "Seed Sharing",
            "Transaction Ledger",
            "Feed System",
            "P2P Sync",
            "Blockchain (Hybrid SQLite Chain)",
            "Proof-of-Data-Transfer (PoDT)"
        ],
        "documentation": "/docs",
    }, headers={"Vary": "Accept"})


@app.get("/health")
def health():
    """Health check"""
    return {
        "ok": True,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        # Lets apps ask for phone verification before someone writes a post
        "network": config.NETWORK,
        "phone_required_to_post": config.REQUIRE_PHONE_TO_POST,
    }


@app.get("/ready")
def ready():
    """Readiness probe - returns 200 when the server can serve requests."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("SELECT 1")
        conn.close()
        return {"ready": True}
    except Exception:
        raise HTTPException(status_code=503, detail="not ready")


# ============================================================================
# WALLET ENDPOINTS
# ============================================================================

@app.post("/wallets/create", response_model=WalletCreateResponse)
async def create_wallet(name: str = Form("Default Wallet"), caller: Caller = Depends(caller_from_form)):
    """Create a new GFC wallet"""
    owner = caller.require("post")

    try:
        conn = sqlite3.connect(DB_PATH)
        # Wallet ID is the Ed25519 public key; the private key stays in this node's wallet_keys
        wallet_id = signing.create_wallet_key(conn, caller.data_key())
        conn.execute(
            "INSERT INTO wallets (id, name, owner, gfc_balance, created_at, gfc_balance_cents) VALUES (?, ?, ?, ?, ?, ?)",
            (wallet_id, name, owner, 0.0, datetime.datetime.utcnow().isoformat(), 0)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    # First-wallet grant (100 GFC from Treasury), only once the owner's phone is verified.
    # Unverified owners get it when they verify (POST /verify/web/fb/check) instead.
    grant_balance = 0.0
    if owner:
        verified_wallets.attest(DB_PATH, owner)  # treasury node: proof for peers, if verified
        grant_result = blockchain.process_user_grant(DB_PATH, owner, wallet_id)
        if grant_result:
            grant_balance = grant_result["amount"]  # 100.0
        # A first post made before the account had a wallet is paid now
        bonus = first_post.pay_pending(DB_PATH, owner)
        if bonus:
            grant_balance += bonus["amount"]

    return WalletCreateResponse(id=wallet_id, name=name, gfc_balance=grant_balance)


@app.get("/wallets/{wallet_id}")
async def get_wallet(wallet_id: str):
    """Get wallet information with blockchain-calculated balance"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("SELECT id, name FROM wallets WHERE id = ?", (wallet_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Wallet not found")

        # Calculate balance from blockchain (confirmed transactions only)
        balance_cents = blockchain.get_balance_cents(DB_PATH, wallet_id)
        balance = balance_cents / 100.0

        return {
            "id": row[0],
            "name": row[1],
            "balance": balance,
            "balance_cents": balance_cents,
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/wallets/export")
async def export_wallet_keys(password: str = Form(...), backup_passphrase: str = Form(...),
                             caller: Caller = Depends(caller_from_form)):
    """
    Download an encrypted backup of your wallet keys on this node. Keep it (and
    the passphrase) somewhere safe: it is the only way to recover your wallets
    if this node's data is lost or you forget your password.
    """
    username = caller.require("spend")
    _require_password(username, password)
    data_key = caller.data_key()
    if not data_key:
        raise HTTPException(status_code=401, detail="log in again to unlock your keys")
    try:
        return keystore.export_wallets(username, data_key, backup_passphrase)
    except keystore.KeystoreError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/wallets/import")
async def import_wallet_keys(backup_passphrase: str = Form(...), backup: str = Form(...),
                             caller: Caller = Depends(caller_from_form)):
    """Restore wallet keys from a backup made by /wallets/export (on this or another node)."""
    username = caller.require("spend")
    data_key = caller.data_key()
    if not data_key:
        raise HTTPException(status_code=401, detail="log in again to unlock your keys")
    try:
        imported = keystore.import_wallets(username, data_key, backup_passphrase, json.loads(backup))
    except (keystore.KeystoreError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "imported": imported}


def _require_password(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row[0]):
        raise HTTPException(status_code=401, detail="invalid credentials")


# ============================================================================
# TRANSACTION ENDPOINTS
# ============================================================================

@app.post("/transactions/create")
async def create_transaction(transaction: TransactionRequest, bearer: str = Depends(bearer_token)):
    """Create a blockchain-validated transaction (sender wallet must belong to the caller)"""
    caller = resolve_caller(bearer, transaction.api_token)
    username = caller.require("spend")
    conn = sqlite3.connect(DB_PATH)
    wallet = conn.execute("SELECT owner FROM wallets WHERE id = ?", (transaction.sender,)).fetchone()
    conn.close()
    if not wallet or not wallet[0] or wallet[0].lower() != username.lower():
        raise HTTPException(status_code=403, detail="sender wallet does not belong to this user")

    # Convert amount to cents
    amount_cents = int(transaction.amount * 100)

    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    reserve_spend(caller, amount_cents)  # Per-token daily limit, if the token has one
    try:
        tx = blockchain.process_transfer(
            db_path=DB_PATH,
            sender_wallet=transaction.sender,
            recipient_wallet=transaction.recipient,
            amount_cents=amount_cents,
            reason=transaction.reason,
            data_key=caller.data_key(),
        )

        return {
            "id": tx["id"],
            "sender": tx["sender"],
            "recipient": tx["recipient"],
            "amount": tx["amount"],
            "amount_cents": tx["amount_cents"],
            "reason": tx["reason"],
            "timestamp": tx["timestamp"],
            "tx_hash": tx["tx_hash"],
            "tx_type": tx["tx_type"],
            "block_index": tx.get("block_index"),
            # False for legacy wallets without a key: the transfer is valid on this node only
            "signed": bool(tx.get("signature")),
        }
    except ValueError as e:
        # Insufficient balance or validation error
        release_spend(caller, amount_cents)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        release_spend(caller, amount_cents)
        raise HTTPException(status_code=500, detail=f"Transaction error: {str(e)}")


@app.get("/transactions/history")
async def transaction_history(wallet_id: str = None):
    """Get transaction history with blockchain metadata"""
    try:
        conn = sqlite3.connect(DB_PATH)

        select_cols = "id, sender, recipient, amount, reason, timestamp, amount_cents, tx_hash, block_index, tx_type"

        if wallet_id:
            cursor = conn.execute(
                f"SELECT {select_cols} FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC",
                (wallet_id, wallet_id)
            )
        else:
            cursor = conn.execute(f"SELECT {select_cols} FROM transactions ORDER BY timestamp DESC")

        transactions = []
        for row in cursor.fetchall():
            amount_cents = row[6] if row[6] else int((row[3] or 0) * 100)
            transactions.append({
                "id": row[0],
                "sender": row[1],
                "recipient": row[2],
                "amount": amount_cents / 100.0 if amount_cents else (row[3] or 0),
                "reason": row[4],
                "timestamp": row[5],
                "amount_cents": amount_cents,
                "tx_hash": row[7] or "",
                "block_index": row[8],
                "tx_type": row[9] or "TRANSFER",
            })

        conn.close()
        return {"transactions": transactions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# ============================================================================
# FEED ENDPOINT
# ============================================================================

@app.get("/feed")
def feed(caller: Caller = Depends(caller_from_query)):
    """Get feed - all seeds with per-user engagement state"""
    from app_engagement import get_feed_items
    return get_feed_items(caller.owner("read"))


# ============================================================================
# SEARCH ENDPOINT
# ============================================================================

@app.get("/search")
def search(q: str = "", caller: Caller = Depends(caller_from_query)):
    """Search seeds and transactions by keyword."""
    from app_engagement import SEED_SELECT, seed_row_to_dict

    result = {"seeds": [], "transactions": [], "seed_count": 0, "transaction_count": 0}

    if not q.strip():
        return result

    keywords = q.strip().split()
    owner = caller.owner("read")

    conn = sqlite3.connect(DB_PATH)

    # --- Search seeds ---
    seed_conditions = []
    seed_params = []
    for kw in keywords:
        pattern = f"%{kw}%"
        seed_conditions.append(
            "(LOWER(title) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?) "
            "OR LOWER(tags) LIKE LOWER(?) OR LOWER(owner) LIKE LOWER(?))"
        )
        seed_params.extend([pattern, pattern, pattern, pattern])

    seed_where = " AND ".join(seed_conditions)
    rows = conn.execute(
        f"{SEED_SELECT} WHERE {seed_where} ORDER BY live_likes DESC, seeds.views DESC LIMIT 50",
        seed_params
    ).fetchall()

    seed_items = [seed_row_to_dict(r) for r in rows]

    # Add per-user engagement state if authenticated
    if owner != "anonymous":
        liked_set = {r[0] for r in conn.execute(
            "SELECT seed_id FROM likes WHERE owner = ?", (owner,)).fetchall()}
        bookmarked_set = {r[0] for r in conn.execute(
            "SELECT seed_id FROM bookmarks WHERE owner = ?", (owner,)).fetchall()}
        for item in seed_items:
            item["liked"] = item["id"] in liked_set
            item["bookmarked"] = item["id"] in bookmarked_set

    seed_items = moderation.visible_items(conn, seed_items, owner)
    result["seeds"] = seed_items
    result["seed_count"] = len(seed_items)

    # --- Search transactions ---
    tx_conditions = []
    tx_params = []
    for kw in keywords:
        pattern = f"%{kw}%"
        tx_conditions.append(
            "(LOWER(sender) LIKE LOWER(?) OR LOWER(recipient) LIKE LOWER(?) "
            "OR LOWER(reason) LIKE LOWER(?))"
        )
        tx_params.extend([pattern, pattern, pattern])

    tx_where = " AND ".join(tx_conditions)
    tx_rows = conn.execute(
        "SELECT id, sender, recipient, amount, reason, timestamp, amount_cents, tx_hash, block_index, tx_type FROM transactions "
        f"WHERE {tx_where} ORDER BY timestamp DESC LIMIT 50",
        tx_params
    ).fetchall()

    tx_items = []
    for r in tx_rows:
        amount_cents = r[6] if r[6] else int((r[3] or 0) * 100)
        tx_items.append({
            "id": r[0], "sender": r[1], "recipient": r[2],
            "amount": amount_cents / 100.0 if amount_cents else (r[3] or 0),
            "reason": r[4], "timestamp": r[5],
            "tx_hash": r[7] or "", "block_index": r[8],
            "tx_type": r[9] or "TRANSFER",
        })

    result["transactions"] = tx_items
    result["transaction_count"] = len(tx_items)

    conn.close()
    return result


# ============================================================================
# BLOCKCHAIN ENDPOINTS
# ============================================================================

@app.get("/blockchain/stats")
def blockchain_stats():
    """Get blockchain statistics: blocks, transactions, treasury, circulation."""
    try:
        return blockchain.get_blockchain_stats(DB_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/blockchain/validate")
def blockchain_validate():
    """Validate the entire blockchain (prev_hash linkage + Merkle roots)."""
    try:
        is_valid, msg = blockchain.validate_chain(DB_PATH)
        return {
            "valid": is_valid,
            "message": msg,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# P2P INTEGRATION
# ============================================================================

from p2p_service import start_p2p, stop_p2p, p2p_status

@app.on_event("startup")
async def startup_event():
    """Start P2P services when the server starts."""
    logredact.install()  # no phone numbers or verify link codes in the logs
    # Treasury node: proof of verification for verified accounts that don't have one yet
    try:
        issued = verified_wallets.backfill(DB_PATH)
        if issued:
            print(f"[Verified] Issued {issued} verified wallet records")
    except Exception as e:
        print(f"[Verified] Backfill failed: {e}")
    # Ensure firewall rules exist for P2P ports (best-effort, requires admin)
    _ensure_firewall_rules()
    # Fingerprint seeds stored before the repost check existed (a treasury node also
    # notarises them, oldest first). In the background: images and models take a while.
    import threading
    threading.Thread(target=_backfill_fingerprints, daemon=True).start()
    try:
        await start_p2p()
    except Exception as e:
        print(f"[P2P] ERROR: Failed to start P2P services: {e}")
        import traceback
        traceback.print_exc()


def _backfill_fingerprints():
    try:
        done = reposts.backfill(DB_PATH)
        if done:
            print(f"[Reposts] Fingerprinted {done} existing seeds")
    except Exception as e:
        print(f"[Reposts] Backfill failed: {e}")
    try:
        queued = audio_stream.backfill(DB_PATH)
        if queued:
            print(f"[AudioStream] Queued streaming copies for {queued} existing audio seeds")
    except Exception as e:
        print(f"[AudioStream] Backfill failed: {e}")


def _ensure_firewall_rules():
    """Try to add firewall rules for P2P ports if they don't exist yet.
    Also adds an application-allow rule for gfc_backend.exe itself.
    Silently fails if not running as admin (installer handles this case)."""
    import subprocess
    import sys
    import os
    if sys.platform != "win32":
        return

    # Port-based rules (each param is a separate list item to avoid .split() issues with paths)
    rules = [
        ('GFC Coin P2P Sync', ['dir=in', 'action=allow', 'protocol=TCP', 'localport=6881']),
        ('GFC Coin LAN Discovery', ['dir=in', 'action=allow', 'protocol=UDP', 'localport=6882']),
    ]

    # Application-based rule — allows gfc_backend.exe through firewall regardless of port rules.
    # Windows Firewall often auto-blocks new executables; this ensures the backend can accept connections.
    exe_path = os.path.abspath(sys.executable)
    rules.append((
        'GFC Coin Backend',
        ['dir=in', 'action=allow', f'program={exe_path}', 'enable=yes']
    ))

    for name, params in rules:
        try:
            # Check if rule already exists
            check = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={name}'],
                capture_output=True, text=True, timeout=5
            )
            if 'No rules match' in check.stdout or check.returncode != 0:
                # Rule doesn't exist, try to add it
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={name}'] + params
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                print(f"[P2P] Added firewall rule: {name} (rc={result.returncode})")
                if result.stderr:
                    print(f"[P2P]   stderr: {result.stderr.strip()}")
            else:
                print(f"[P2P] Firewall rule already exists: {name}")
        except Exception as e:
            print(f"[P2P] Firewall rule check/add failed for {name}: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop P2P services when the server shuts down."""
    await stop_p2p()

@app.get("/p2p/status")
def get_p2p_status():
    """Get P2P network status - peer count, connections, sync state."""
    return p2p_status()

@app.get("/p2p/diagnose")
async def diagnose_p2p():
    """Diagnose P2P connectivity issues - tests firewall, port binding, peer reachability."""
    import subprocess, socket, sys
    results = {"platform": sys.platform, "checks": []}

    # Check 1: Is port 6881 listening?
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        err = s.connect_ex(("127.0.0.1", 6881))
        s.close()
        results["checks"].append({
            "test": "TCP port 6881 listening locally",
            "pass": err == 0,
            "detail": "OK" if err == 0 else f"connect_ex returned {err}"
        })
    except Exception as e:
        results["checks"].append({"test": "TCP port 6881 listening", "pass": False, "detail": str(e)})

    # Check 2: Firewall rules exist?
    if sys.platform == "win32":
        for rule_name in ["GFC Coin P2P Sync", "GFC Coin LAN Discovery"]:
            try:
                check = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
                    capture_output=True, text=True, timeout=5
                )
                exists = 'No rules match' not in check.stdout and check.returncode == 0
                results["checks"].append({
                    "test": f"Firewall rule '{rule_name}'",
                    "pass": exists,
                    "detail": "Rule exists and enabled" if exists else "Rule NOT found"
                })
            except Exception as e:
                results["checks"].append({"test": f"Firewall rule '{rule_name}'", "pass": False, "detail": str(e)})

    # Check 3: Can we reach known peers on port 6881?
    from p2p_service import discovery
    for key, peer_info in list(discovery.known_peers.items()):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            err = s.connect_ex((peer_info.address, peer_info.port))
            s.close()
            results["checks"].append({
                "test": f"TCP to peer {key}",
                "pass": err == 0,
                "detail": "Reachable" if err == 0 else f"UNREACHABLE (error {err} - firewall or peer down)"
            })
        except Exception as e:
            results["checks"].append({"test": f"TCP to peer {key}", "pass": False, "detail": str(e)})

    # Check 4: Local IPs
    results["local_ips"] = list(discovery._local_ips)
    results["known_peers"] = discovery.get_peer_list(20)

    # Check 5: What broadcast addresses are being used?
    results["broadcast_targets"] = discovery._get_broadcast_addresses()

    return results


@app.get("/p2p/add_peer")
@app.post("/p2p/add_peer")
async def add_peer_manually(address: str, port: int = 6881):
    """Manually add a peer by IP address. Use when UDP discovery fails.
    Works with both GET and POST so you can use the browser URL bar.
    Example: http://localhost:8000/p2p/add_peer?address=192.168.1.100&port=6881
    """
    from p2p_service import discovery
    if not address:
        return {"ok": False, "error": "address is required"}
    is_new = discovery._add_peer(address, port)
    return {
        "ok": True,
        "added": is_new,
        "peer_key": f"{address}:{port}",
        "known_peers": discovery.peer_count,
        "message": f"Peer {address}:{port} {'added (new)' if is_new else 'already known (updated last_seen)'}. Sync will connect within 10 seconds."
    }


@app.get("/p2p/force_sync")
async def force_sync():
    """Force an immediate sync with all connected peers.
    Returns what was synced. Use to debug sync issues."""
    from p2p_service import sync_engine
    if not sync_engine:
        return {"ok": False, "error": "Sync engine not running"}

    connections = list(sync_engine.connections.items())
    if not connections:
        return {"ok": False, "error": "No connected peers", "known_peers": discovery.peer_count}

    results = []
    for key, peer in connections:
        if peer.is_connected:
            try:
                await sync_engine._sync_one_peer(peer)
                results.append({"peer": key, "status": "sync_requests_sent"})
            except Exception as e:
                results.append({"peer": key, "status": f"error: {e}"})
        else:
            results.append({"peer": key, "status": "not_connected"})

    return {
        "ok": True,
        "synced_peers": results,
        "last_sync_timestamps": dict(sync_engine.last_sync_timestamps),
        "total_connections": len(sync_engine.connections),
    }


@app.get("/p2p/sync_debug")
async def sync_debug():
    """Debug endpoint - shows detailed sync engine state."""
    from p2p_service import sync_engine, discovery
    import sqlite3 as _sqlite3

    if not sync_engine:
        return {"ok": False, "error": "Sync engine not running"}

    # Count rows in each table
    table_counts = {}
    try:
        conn = _sqlite3.connect(DB_PATH)
        for table in ["users", "seeds", "transactions", "likes", "comments", "bookmarks", "wallets", "blocks", "user_grants", "podt_proofs", "pending_sync_tx"]:
            try:
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                table_counts[table] = count
            except Exception:
                table_counts[table] = "error"
        conn.close()
    except Exception as e:
        table_counts["error"] = str(e)

    return {
        "ok": True,
        "local_table_counts": table_counts,
        "connections": {
            key: {
                "is_connected": peer.is_connected,
                "version": peer.peer_version,
            }
            for key, peer in sync_engine.connections.items()
        },
        "last_sync_timestamps": dict(sync_engine.last_sync_timestamps),
        "per_peer_sync_ts": dict(sync_engine._per_peer_sync_ts),
        "pending_file_chunks": list(sync_engine._pending_file_chunks.keys()),
        "known_peers": discovery.peer_count,
        "connected_peers": len(discovery.connected_peers),
    }


# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("GFC Backend Server Starting...")
    print(f"Data directory: {DATA_DIR}")
    print(f"Database: {DB_PATH}")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8000)
