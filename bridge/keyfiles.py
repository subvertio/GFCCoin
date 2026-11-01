"""
Key files for the bridge service, and the checks mainnet requires of them (audit F14).

- EVM keys are encrypted keystore files (the standard Ethereum JSON, made by
  `python -m bridge new-evm-key FILE`), unlocked with a passphrase typed when the service
  starts (or GFC_BRIDGE_KEY_PASSPHRASE). Plain hex key files still work on testnets only.
- The escrow key is the encrypted treasury-format file from `python -m bridge new-escrow-key`.
- A key file must be readable by its owner only. On Windows that's the file's ACL, not its
  mode bits: no Everyone, Users or Authenticated Users entry.

Encryption protects a file at rest, not a running service: a compromised service account can
read the keys out of memory. That's why mainnet also refuses a quorum of attester keys in one
process (see bridge/__main__.py).
"""

import getpass
import json
import os
import subprocess
from pathlib import Path
from typing import Optional

# Principals that mean "other people on this machine" in an icacls listing
_BROAD_PRINCIPALS = ("everyone", "builtin\\users", "nt authority\\authenticated users")


def is_keystore(path: str) -> bool:
    """An encrypted file: an Ethereum keystore or a sealed treasury-format file (JSON)."""
    return Path(path).read_text().lstrip().startswith("{")


def read_evm_keystore(path: str) -> str:
    """Decrypt an Ethereum keystore file; returns the key as 0x-hex. Never logs it."""
    from eth_account import Account
    passphrase = os.environ.get("GFC_BRIDGE_KEY_PASSPHRASE") or \
        getpass.getpass(f"Passphrase for {Path(path).name}: ")
    try:
        return "0x" + bytes(Account.decrypt(json.loads(Path(path).read_text()), passphrase)).hex()
    except ValueError:
        raise SystemExit(f"wrong passphrase for {Path(path).name}") from None


def write_evm_keystore(path: str, passphrase: str) -> str:
    """Create a new key in an encrypted keystore file readable by its owner only; returns its address."""
    from eth_account import Account
    import signing
    acct = Account.create()
    signing._write_secret(Path(path), json.dumps(Account.encrypt(acct.key, passphrase)))
    restrict_to_owner(path)
    return acct.address


def restrict_to_owner(path: str):
    """On Windows, replace the file's inherited ACL with one entry for the current user."""
    if os.name != "nt":
        return  # signing._write_secret already set 0600
    user = os.environ.get("USERNAME")
    if user:
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                       check=True, capture_output=True)


def access_problem(path: str) -> Optional[str]:
    """Why other accounts on this machine could read the key file, or None."""
    if os.name == "nt":
        try:
            out = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True).stdout
        except (OSError, subprocess.CalledProcessError):
            return "couldn't read its permissions"
        broad = sorted({p for p in _BROAD_PRINCIPALS if p + ":" in out.lower()})
        return f"readable by {', '.join(broad)}" if broad else None
    mode = os.stat(path).st_mode & 0o077
    return f"mode {oct(os.stat(path).st_mode & 0o777)}: readable by other accounts" if mode else None
