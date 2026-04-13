import sqlite3
import os

DB_PATH = "data/guardian_vault.db"

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Existing assets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            path TEXT PRIMARY KEY,
            sha256 TEXT,
            entropy REAL,
            magic TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # NEW: Volume tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS volumes (
            uuid TEXT PRIMARY KEY,
            tree_hash TEXT,
            last_scanned DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_volume_state(uuid):
    """Retrieves the last known tree hash for a specific hardware UUID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT tree_hash FROM volumes WHERE uuid = ?", (uuid,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def update_volume_state(uuid, tree_hash):
    """Saves the current hardware/tree state."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO volumes (uuid, tree_hash, last_scanned)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (uuid, tree_hash))
    conn.commit()
    conn.close()


def check_asset_state(path, current_hash):
    """
    Compares current file state against the database.
    Returns: 'NEW', 'UNCHANGED', or 'MODIFIED'
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT sha256 FROM assets WHERE path = ?", (path,))
    row = cursor.fetchone()
    
    state = "NEW"
    if row:
        stored_hash = row[0]
        state = "UNCHANGED" if stored_hash == current_hash else "MODIFIED"
    
    conn.close()
    return state

def update_asset(asset_dict):
    """Upserts (updates or inserts) an asset into the vault."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO assets (path, sha256, entropy, magic, last_seen)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (asset_dict['path'], asset_dict['sha256'], asset_dict['entropy'], asset_dict['magic']))
    
    conn.commit()
    conn.close()