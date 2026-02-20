"""
GFC Backend - User Profile Router
Handles profile viewing, editing, and avatar uploads.
"""

import re
import sqlite3
import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from config import DB_PATH, AVATAR_DIR

router = APIRouter()

SAFE_RE = re.compile(r"[^A-Za-z0-9._+-]")

# ---------- helpers ----------

def owner_from_token(token: str) -> str:
    """Extract username from API token format 'local-{username}-token'."""
    if token.startswith("local-") and token.endswith("-token"):
        return token[6:-6]
    return "anonymous"


def safe_ext(filename: str) -> str:
    """Return the sanitized file extension (e.g. '.jpg')."""
    if not filename or "." not in filename:
        return ".jpg"
    ext = filename.rsplit(".", 1)[-1]
    ext = SAFE_RE.sub("", ext).lower()
    return f".{ext}" if ext else ".jpg"


def profile_dict(row) -> dict:
    """Convert a DB row (tuple) to a profile response dict."""
    # row order: username, first_name, last_name, bio, email, phone, avatar_filename, created_at
    avatar_filename = row[6] or ""
    avatar_url = f"/avatars/{avatar_filename}" if avatar_filename else None
    return {
        "ok": True,
        "username":   row[0],
        "first_name": row[1] or "",
        "last_name":  row[2] or "",
        "bio":        row[3] or "",
        "email":      row[4] or "",
        "phone":      row[5] or "",
        "avatar":     avatar_url,
        "created_at": row[7] or "",
    }


# ---------- routes ----------

# IMPORTANT: /users/me MUST be defined BEFORE /users/{username}
# otherwise FastAPI will match "me" as a username parameter.

@router.get("/users/me")
def get_my_profile(api_token: str = ""):
    """Return the authenticated user's full profile."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="authentication required")

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, first_name, last_name, bio, email, phone, avatar_filename, created_at "
        "FROM users WHERE LOWER(username) = LOWER(?)",
        (owner,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    return profile_dict(row)


@router.post("/users/me")
async def update_my_profile(
    api_token: str = Form(""),
    first_name: Optional[str] = Form(None),
    last_name: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
):
    """Update the authenticated user's profile fields."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="authentication required")

    conn = sqlite3.connect(DB_PATH)

    # Build dynamic UPDATE with only provided fields
    updates = []
    values = []
    if first_name is not None:
        updates.append("first_name = ?")
        values.append(first_name.strip())
    if last_name is not None:
        updates.append("last_name = ?")
        values.append(last_name.strip())
    if bio is not None:
        updates.append("bio = ?")
        values.append(bio.strip())

    if not updates:
        conn.close()
        raise HTTPException(status_code=400, detail="no fields to update")

    values.append(owner)  # WHERE clause
    conn.execute(
        f"UPDATE users SET {', '.join(updates)} WHERE LOWER(username) = LOWER(?)",
        values
    )
    conn.commit()

    # Return updated profile
    row = conn.execute(
        "SELECT username, first_name, last_name, bio, email, phone, avatar_filename, created_at "
        "FROM users WHERE LOWER(username) = LOWER(?)",
        (owner,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    return profile_dict(row)


@router.post("/users/me/avatar")
async def upload_avatar(
    avatar: UploadFile = File(...),
    api_token: str = Form(""),
):
    """Upload or replace the user's avatar image."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="authentication required")

    # Read file
    try:
        raw = await avatar.read()
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"failed to read avatar: {ex}")

    if len(raw) == 0:
        raise HTTPException(status_code=400, detail="empty file")

    # Determine extension and filename
    ext = safe_ext(avatar.filename or "avatar.jpg")
    avatar_filename = f"{owner.lower()}_avatar{ext}"
    avatar_path = AVATAR_DIR / avatar_filename

    # Delete any previous avatar for this user (different extension)
    for old in AVATAR_DIR.glob(f"{owner.lower()}_avatar.*"):
        try:
            old.unlink()
        except Exception:
            pass

    # Save new avatar
    try:
        avatar_path.write_bytes(raw)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"failed to save avatar: {ex}")

    # Update database
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE users SET avatar_filename = ? WHERE LOWER(username) = LOWER(?)",
        (avatar_filename, owner)
    )
    conn.commit()
    conn.close()

    avatar_url = f"/avatars/{avatar_filename}"
    return {"ok": True, "avatar": avatar_url}


@router.get("/users/{username}")
def get_public_profile(username: str):
    """Return a user's public profile (no email/phone for privacy)."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT username, first_name, last_name, bio, email, phone, avatar_filename, created_at "
        "FROM users WHERE LOWER(username) = LOWER(?)",
        (username,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    # Return public fields only (no email/phone)
    avatar_filename = row[6] or ""
    avatar_url = f"/avatars/{avatar_filename}" if avatar_filename else None
    return {
        "ok": True,
        "username":   row[0],
        "first_name": row[1] or "",
        "last_name":  row[2] or "",
        "bio":        row[3] or "",
        "avatar":     avatar_url,
        "created_at": row[7] or "",
    }
