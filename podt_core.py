"""
Proof-of-Data-Transfer (PoDT) Core Module
Galactic Federation Coin - Data Transfer Verification & Credit System

This module implements the core consensus mechanism for GFC:
- Verifies file transfers between peers
- Calculates credits based on bytes transferred
- Manages transfer records and proofs
"""

import hashlib
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import sqlite3

# Configuration
CREDITS_PER_MB = 0.1  # Base credits earned per MB transferred
MIN_TRANSFER_SIZE = 1024  # Minimum 1KB for credit eligibility

try:
    from config import PODT_DB_PATH as DB_PATH
except ImportError:
    DB_PATH = "data/podt.db"  # Fallback for standalone usage


class TransferProof:
    """
    Represents cryptographic proof of a file transfer
    """
    def __init__(
        self,
        sender_wallet: str,
        receiver_wallet: str,
        file_hash: str,
        file_size: int,
        timestamp: float = None
    ):
        self.sender_wallet = sender_wallet
        self.receiver_wallet = receiver_wallet
        self.file_hash = file_hash
        self.file_size = file_size
        self.timestamp = timestamp or time.time()
        self.proof_id = self._generate_proof_id()
        
    def _generate_proof_id(self) -> str:
        """Generate unique proof ID from transfer parameters"""
        proof_string = f"{self.sender_wallet}{self.receiver_wallet}{self.file_hash}{self.timestamp}"
        return hashlib.sha256(proof_string.encode()).hexdigest()
    
    def calculate_credits(self) -> float:
        """Calculate GFC credits earned from this transfer"""
        if self.file_size < MIN_TRANSFER_SIZE:
            return 0.0
        
        mb_transferred = self.file_size / (1024 * 1024)
        credits = mb_transferred * CREDITS_PER_MB
        return round(credits, 6)
    
    def to_dict(self) -> dict:
        """Serialize proof to dictionary"""
        return {
            "proof_id": self.proof_id,
            "sender_wallet": self.sender_wallet,
            "receiver_wallet": self.receiver_wallet,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "timestamp": self.timestamp,
            "credits": self.calculate_credits(),
            "iso_timestamp": datetime.fromtimestamp(self.timestamp).isoformat()
        }
    
    def to_json(self) -> str:
        """Serialize proof to JSON"""
        return json.dumps(self.to_dict(), indent=2)


class PoDTEngine:
    """
    Main Proof-of-Data-Transfer Engine
    Handles verification, validation, and credit assignment
    """
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize PoDT database schema"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Transfer proofs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transfer_proofs (
                proof_id TEXT PRIMARY KEY,
                sender_wallet TEXT NOT NULL,
                receiver_wallet TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                credits REAL NOT NULL,
                timestamp REAL NOT NULL,
                verified INTEGER DEFAULT 0,
                verification_timestamp REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Wallet balances table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallet_balances (
                wallet_id TEXT PRIMARY KEY,
                balance REAL DEFAULT 0.0,
                total_earned REAL DEFAULT 0.0,
                total_sent REAL DEFAULT 0.0,
                bytes_transferred INTEGER DEFAULT 0,
                last_updated REAL
            )
        ''')
        
        # File registry (prevents duplicate credit claims)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_registry (
                file_hash TEXT PRIMARY KEY,
                first_seeder TEXT NOT NULL,
                total_transfers INTEGER DEFAULT 0,
                total_bytes_served INTEGER DEFAULT 0,
                registered_at REAL NOT NULL
            )
        ''')
        
        # Transfer history for audit
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transfer_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proof_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp REAL NOT NULL,
                details TEXT,
                FOREIGN KEY (proof_id) REFERENCES transfer_proofs(proof_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_file(self, file_path: str) -> Tuple[str, int]:
        """
        Calculate SHA-256 hash of a file
        Returns: (hash, file_size)
        """
        sha256_hash = hashlib.sha256()
        file_size = 0
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                file_size += len(byte_block)
        
        return sha256_hash.hexdigest(), file_size
    
    def register_file(self, file_hash: str, seeder_wallet: str) -> bool:
        """
        Register a file in the network (first seeder)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO file_registry (file_hash, first_seeder, registered_at)
                VALUES (?, ?, ?)
            ''', (file_hash, seeder_wallet, time.time()))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # File already registered
            return False
        finally:
            conn.close()
    
    def create_transfer_proof(
        self,
        sender_wallet: str,
        receiver_wallet: str,
        file_hash: str,
        file_size: int
    ) -> TransferProof:
        """
        Create a new transfer proof
        """
        proof = TransferProof(
            sender_wallet=sender_wallet,
            receiver_wallet=receiver_wallet,
            file_hash=file_hash,
            file_size=file_size
        )
        
        # Store proof in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO transfer_proofs 
            (proof_id, sender_wallet, receiver_wallet, file_hash, file_size, credits, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            proof.proof_id,
            proof.sender_wallet,
            proof.receiver_wallet,
            proof.file_hash,
            proof.file_size,
            proof.calculate_credits(),
            proof.timestamp
        ))
        
        # Log history
        cursor.execute('''
            INSERT INTO transfer_history (proof_id, action, timestamp, details)
            VALUES (?, 'CREATED', ?, ?)
        ''', (proof.proof_id, time.time(), json.dumps(proof.to_dict())))
        
        conn.commit()
        conn.close()
        
        return proof
    
    def verify_transfer(self, proof_id: str, actual_file_hash: str) -> bool:
        """
        Verify a transfer proof by comparing file hashes
        If verified, credits are awarded to sender
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get proof details
        cursor.execute('''
            SELECT sender_wallet, file_hash, file_size, credits, verified
            FROM transfer_proofs
            WHERE proof_id = ?
        ''', (proof_id,))
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return False
        
        sender_wallet, claimed_hash, file_size, credits, already_verified = result
        
        # Check if already verified
        if already_verified:
            conn.close()
            return True
        
        # Verify hash matches
        if claimed_hash != actual_file_hash:
            conn.close()
            return False
        
        # Mark as verified
        verification_time = time.time()
        cursor.execute('''
            UPDATE transfer_proofs
            SET verified = 1, verification_timestamp = ?
            WHERE proof_id = ?
        ''', (verification_time, proof_id))
        
        # Award credits to sender
        self._update_wallet_balance(cursor, sender_wallet, credits, file_size, 'EARN')
        
        # Update file registry
        cursor.execute('''
            UPDATE file_registry
            SET total_transfers = total_transfers + 1,
                total_bytes_served = total_bytes_served + ?
            WHERE file_hash = ?
        ''', (file_size, claimed_hash))
        
        # Log history
        cursor.execute('''
            INSERT INTO transfer_history (proof_id, action, timestamp, details)
            VALUES (?, 'VERIFIED', ?, ?)
        ''', (proof_id, verification_time, json.dumps({
            "verified_hash": actual_file_hash,
            "credits_awarded": credits
        })))
        
        conn.commit()
        conn.close()
        
        return True
    
    def _update_wallet_balance(
        self,
        cursor,
        wallet_id: str,
        amount: float,
        bytes_transferred: int,
        action: str
    ):
        """
        Update wallet balance (internal helper)
        action: 'EARN' or 'SPEND'
        """
        # Get current balance
        cursor.execute('SELECT balance, total_earned, total_sent, bytes_transferred FROM wallet_balances WHERE wallet_id = ?', (wallet_id,))
        result = cursor.fetchone()
        
        if result:
            current_balance, total_earned, total_sent, total_bytes = result
        else:
            current_balance = 0.0
            total_earned = 0.0
            total_sent = 0.0
            total_bytes = 0
        
        # Calculate new values
        if action == 'EARN':
            new_balance = current_balance + amount
            new_total_earned = total_earned + amount
            new_total_sent = total_sent
        else:  # SPEND
            new_balance = current_balance - amount
            new_total_earned = total_earned
            new_total_sent = total_sent + amount
        
        new_total_bytes = total_bytes + bytes_transferred
        
        # Update or insert
        cursor.execute('''
            INSERT INTO wallet_balances (wallet_id, balance, total_earned, total_sent, bytes_transferred, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(wallet_id) DO UPDATE SET
                balance = ?,
                total_earned = ?,
                total_sent = ?,
                bytes_transferred = ?,
                last_updated = ?
        ''', (
            wallet_id, new_balance, new_total_earned, new_total_sent, new_total_bytes, time.time(),
            new_balance, new_total_earned, new_total_sent, new_total_bytes, time.time()
        ))
    
    def get_wallet_balance(self, wallet_id: str) -> Dict:
        """Get wallet balance and statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT balance, total_earned, total_sent, bytes_transferred, last_updated
            FROM wallet_balances
            WHERE wallet_id = ?
        ''', (wallet_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                "wallet_id": wallet_id,
                "balance": result[0],
                "total_earned": result[1],
                "total_sent": result[2],
                "bytes_transferred": result[3],
                "last_updated": result[4],
                "mb_transferred": result[3] / (1024 * 1024) if result[3] else 0
            }
        else:
            return {
                "wallet_id": wallet_id,
                "balance": 0.0,
                "total_earned": 0.0,
                "total_sent": 0.0,
                "bytes_transferred": 0,
                "last_updated": None,
                "mb_transferred": 0.0
            }
    
    def get_transfer_stats(self, wallet_id: str = None) -> Dict:
        """Get transfer statistics for a wallet or entire network"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if wallet_id:
            # Wallet-specific stats
            cursor.execute('''
                SELECT COUNT(*), SUM(file_size), SUM(credits)
                FROM transfer_proofs
                WHERE sender_wallet = ? AND verified = 1
            ''', (wallet_id,))
            sent_result = cursor.fetchone()
            
            cursor.execute('''
                SELECT COUNT(*), SUM(file_size)
                FROM transfer_proofs
                WHERE receiver_wallet = ? AND verified = 1
            ''', (wallet_id,))
            received_result = cursor.fetchone()
            
            stats = {
                "wallet_id": wallet_id,
                "transfers_sent": sent_result[0] or 0,
                "bytes_sent": sent_result[1] or 0,
                "credits_earned": sent_result[2] or 0.0,
                "transfers_received": received_result[0] or 0,
                "bytes_received": received_result[1] or 0
            }
        else:
            # Network-wide stats
            cursor.execute('SELECT COUNT(*), SUM(file_size), SUM(credits) FROM transfer_proofs WHERE verified = 1')
            result = cursor.fetchone()
            
            cursor.execute('SELECT COUNT(*) FROM file_registry')
            file_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT SUM(balance) FROM wallet_balances')
            total_balance = cursor.fetchone()[0] or 0.0
            
            stats = {
                "total_verified_transfers": result[0] or 0,
                "total_bytes_transferred": result[1] or 0,
                "total_credits_issued": result[2] or 0.0,
                "unique_files": file_count or 0,
                "total_gfc_in_circulation": total_balance
            }
        
        conn.close()
        return stats
    
    def get_recent_transfers(self, wallet_id: str = None, limit: int = 20) -> List[Dict]:
        """Get recent transfer proofs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if wallet_id:
            cursor.execute('''
                SELECT proof_id, sender_wallet, receiver_wallet, file_hash, 
                       file_size, credits, timestamp, verified
                FROM transfer_proofs
                WHERE sender_wallet = ? OR receiver_wallet = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (wallet_id, wallet_id, limit))
        else:
            cursor.execute('''
                SELECT proof_id, sender_wallet, receiver_wallet, file_hash, 
                       file_size, credits, timestamp, verified
                FROM transfer_proofs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        transfers = []
        for row in cursor.fetchall():
            transfers.append({
                "proof_id": row[0],
                "sender_wallet": row[1],
                "receiver_wallet": row[2],
                "file_hash": row[3],
                "file_size": row[4],
                "credits": row[5],
                "timestamp": row[6],
                "iso_timestamp": datetime.fromtimestamp(row[6]).isoformat(),
                "verified": bool(row[7])
            })
        
        conn.close()
        return transfers


# Utility functions for easy integration
def quick_transfer_verification(sender: str, receiver: str, file_path: str) -> Dict:
    """
    Quick helper to create and return transfer proof for a file
    """
    engine = PoDTEngine()
    file_hash, file_size = engine.hash_file(file_path)
    
    # Register file if first time
    engine.register_file(file_hash, sender)
    
    # Create proof
    proof = engine.create_transfer_proof(sender, receiver, file_hash, file_size)
    
    return {
        "proof": proof.to_dict(),
        "file_hash": file_hash,
        "file_size": file_size,
        "credits_pending": proof.calculate_credits()
    }


if __name__ == "__main__":
    # Example usage
    print("Galactic Federation Coin - PoDT Engine Test")
    print("=" * 50)
    
    engine = PoDTEngine()
    
    # Simulate a transfer
    sender_wallet = "wallet_sender_123abc"
    receiver_wallet = "wallet_receiver_456def"
    test_file_hash = hashlib.sha256(b"test_file_content").hexdigest()
    test_file_size = 5 * 1024 * 1024  # 5 MB
    
    # Create transfer proof
    proof = engine.create_transfer_proof(sender_wallet, receiver_wallet, test_file_hash, test_file_size)
    print(f"\nTransfer Proof Created:")
    print(proof.to_json())
    
    # Verify transfer
    verified = engine.verify_transfer(proof.proof_id, test_file_hash)
    print(f"\nTransfer Verified: {verified}")
    
    # Check balance
    balance = engine.get_wallet_balance(sender_wallet)
    print(f"\nSender Balance:")
    print(json.dumps(balance, indent=2))
    
    # Network stats
    stats = engine.get_transfer_stats()
    print(f"\nNetwork Stats:")
    print(json.dumps(stats, indent=2))
