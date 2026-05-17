"""
Persistent SQLite storage — users, transfers, chunks, logs.
DB path is anchored to this file's directory.
"""
import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "data" / "secure_transfer.db"


def _conn():
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    return c


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY,
                public_key_pem  TEXT NOT NULL,
                session_token   TEXT NOT NULL,
                registered_at   TEXT NOT NULL,
                last_seen       TEXT
            );
            CREATE TABLE IF NOT EXISTS transfers (
                transfer_id     TEXT PRIMARY KEY,
                sender          TEXT NOT NULL,
                recipient       TEXT NOT NULL,
                filename        TEXT NOT NULL,
                file_size       INTEGER NOT NULL DEFAULT 0,
                total_chunks    INTEGER NOT NULL DEFAULT 1,
                enc_aes_key     TEXT NOT NULL DEFAULT '',
                enc_hmac_key    TEXT NOT NULL DEFAULT '',
                meta_signature  TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'pending',
                created_at      TEXT NOT NULL,
                completed_at    TEXT
            );
            CREATE TABLE IF NOT EXISTS chunks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_id  TEXT    NOT NULL,
                chunk_index  INTEGER NOT NULL,
                data_b64     TEXT    NOT NULL,
                nonce        TEXT    NOT NULL,
                hmac         TEXT    NOT NULL,
                sig          TEXT    NOT NULL,
                UNIQUE(transfer_id, chunk_index)
            );
            CREATE TABLE IF NOT EXISTS logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level     TEXT NOT NULL,
                event     TEXT NOT NULL,
                actor     TEXT NOT NULL,
                message   TEXT NOT NULL
            );
        """)
    print(f"[DB] Ready at {DB_PATH}")


# ── Users ──────────────────────────────────────────────────────────────────────

def add_user(username, public_key_pem, session_token):
    now = datetime.now().isoformat()
    with _conn() as c:
        c.execute(
            "INSERT INTO users (username,public_key_pem,session_token,registered_at,last_seen) VALUES(?,?,?,?,?)",
            (username, public_key_pem, session_token, now, now))

def get_user(username):
    c   = _conn()
    row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    c.close()
    return dict(row) if row else None

def get_all_users():
    c    = _conn()
    rows = c.execute("SELECT username FROM users").fetchall()
    c.close()
    return [r["username"] for r in rows]

def update_user_last_seen(username):
    with _conn() as c:
        c.execute("UPDATE users SET last_seen=? WHERE username=?",
                  (datetime.now().isoformat(), username))

def update_user_keys(username, public_key_pem, session_token):
    """Replace public key + session token on re-login."""
    with _conn() as c:
        c.execute(
            "UPDATE users SET public_key_pem=?, session_token=?, last_seen=? WHERE username=?",
            (public_key_pem, session_token, datetime.now().isoformat(), username))

def invalidate_session(username):
    """Set session token to empty string — makes any stored token invalid."""
    with _conn() as c:
        c.execute("UPDATE users SET session_token='' WHERE username=?", (username,))

def mark_stale_transfers(recipient):
    """
    When a user re-logs in with new keys, pending transfers addressed to them
    were encrypted with their old public key and can no longer be decrypted.
    Mark them as 'stale' so they don't clutter the inbox.
    Returns count of transfers marked.
    """
    with _conn() as c:
        cur = c.execute(
            "UPDATE transfers SET status='stale' WHERE recipient=? AND status='ready'",
            (recipient,))
        return cur.rowcount


# ── Transfers ──────────────────────────────────────────────────────────────────

def add_transfer(transfer_id, sender, recipient, filename, file_size,
                 total_chunks, enc_aes_key, enc_hmac_key, meta_signature):
    with _conn() as c:
        c.execute("""
            INSERT INTO transfers
              (transfer_id,sender,recipient,filename,file_size,total_chunks,
               enc_aes_key,enc_hmac_key,meta_signature,status,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,'pending',?)
        """, (transfer_id, sender, recipient, filename, file_size, total_chunks,
              enc_aes_key or '', enc_hmac_key or '', meta_signature or '',
              datetime.now().isoformat()))

def get_transfer(transfer_id):
    c   = _conn()
    row = c.execute("SELECT * FROM transfers WHERE transfer_id=?", (transfer_id,)).fetchone()
    c.close()
    return dict(row) if row else None

def get_pending_transfers(recipient):
    c    = _conn()
    rows = c.execute(
        "SELECT * FROM transfers WHERE recipient=? AND status='ready'", (recipient,)).fetchall()
    c.close()
    return [dict(r) for r in rows]

def update_transfer_status(transfer_id, status):
    with _conn() as c:
        if status == "completed":
            c.execute("UPDATE transfers SET status=?,completed_at=? WHERE transfer_id=?",
                      (status, datetime.now().isoformat(), transfer_id))
        else:
            c.execute("UPDATE transfers SET status=? WHERE transfer_id=?", (status, transfer_id))

def get_transfer_chunk_count(transfer_id):
    c = _conn()
    n = c.execute("SELECT COUNT(*) FROM chunks WHERE transfer_id=?", (transfer_id,)).fetchone()[0]
    c.close()
    return n


# ── Chunks ─────────────────────────────────────────────────────────────────────

def add_chunk(transfer_id, chunk_index, data_b64, nonce, hmac, sig):
    with _conn() as c:
        c.execute(
            "INSERT INTO chunks(transfer_id,chunk_index,data_b64,nonce,hmac,sig) VALUES(?,?,?,?,?,?)",
            (transfer_id, chunk_index, data_b64, nonce or '', hmac or '', sig or ''))

def get_chunk(transfer_id, chunk_index):
    c   = _conn()
    row = c.execute(
        "SELECT * FROM chunks WHERE transfer_id=? AND chunk_index=?",
        (transfer_id, chunk_index)).fetchone()
    c.close()
    return dict(row) if row else None


# ── Logs ───────────────────────────────────────────────────────────────────────

def add_log(level, event, actor, message):
    with _conn() as c:
        c.execute(
            "INSERT INTO logs(timestamp,level,event,actor,message) VALUES(?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], level, event, actor, message))

def get_recent_logs(limit=200):
    c    = _conn()
    rows = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [{"timestamp": r["timestamp"], "level": r["level"],
             "event": r["event"], "actor": r["actor"], "message": r["message"]}
            for r in rows]

def clear_logs():
    with _conn() as c:
        c.execute("DELETE FROM logs")


# ── Status ─────────────────────────────────────────────────────────────────────

def get_status():
    c         = _conn()
    users     = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    pending   = c.execute("SELECT COUNT(*) FROM transfers WHERE status='ready'").fetchone()[0]
    completed = c.execute("SELECT COUNT(*) FROM transfers WHERE status='completed'").fetchone()[0]
    c.close()
    return {"registered_users": users, "pending_transfers": pending, "completed_transfers": completed}
