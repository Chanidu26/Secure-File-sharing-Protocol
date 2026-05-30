"""
Database — Session-based key model.

Design:
- Private keys NEVER stored. Generated fresh each login, live in browser memory only.
- Public keys stored only while user is actively logged in (online=1).
- On logout / session expiry → public key cleared, user goes offline.
- Only online users can receive files (they have a live public key).
- Transfers created while recipient is online; encrypted chunks persist for pickup.
- Sessions table: one row per active login, tied to Cognito sub + session_id.
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
            -- Permanent user identity (display name persists across logins)
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY,   -- Cognito sub UUID
                display_name    TEXT NOT NULL,
                registered_at   TEXT NOT NULL
            );

            -- Active session: public key present only while logged in
            CREATE TABLE IF NOT EXISTS sessions (
                username        TEXT PRIMARY KEY,   -- one active session per user
                session_id      TEXT NOT NULL,      -- random token tied to Flask session
                public_key_pem  TEXT NOT NULL,      -- RSA public key bundle (OAEP + PSS)
                logged_in_at    TEXT NOT NULL,
                last_ping       TEXT NOT NULL        -- updated on every API call
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


# ── Users (permanent identity) ─────────────────────────────────────────────────

def get_user(username):
    c   = _conn()
    row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    c.close()
    return dict(row) if row else None

def upsert_user(username, display_name):
    """Create user identity if new; never overwrite display_name once set."""
    now = datetime.now().isoformat()
    with _conn() as c:
        existing = c.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
        if not existing:
            c.execute("INSERT INTO users(username,display_name,registered_at) VALUES(?,?,?)",
                      (username, display_name, now))
            return True   # is_new
    return False


# ── Sessions (ephemeral, online state) ────────────────────────────────────────

def create_session(username, session_id, public_key_pem):
    """Register a fresh login with new public keys."""
    now = datetime.now().isoformat()
    with _conn() as c:
        c.execute("""
            INSERT INTO sessions(username, session_id, public_key_pem, logged_in_at, last_ping)
            VALUES(?,?,?,?,?)
            ON CONFLICT(username) DO UPDATE SET
                session_id=excluded.session_id,
                public_key_pem=excluded.public_key_pem,
                logged_in_at=excluded.logged_in_at,
                last_ping=excluded.last_ping
        """, (username, session_id, public_key_pem, now, now))

def delete_session(username):
    """Mark user offline — public key removed from DB."""
    with _conn() as c:
        c.execute("DELETE FROM sessions WHERE username=?", (username,))

def ping_session(username):
    """Update last_ping on every API call — keeps user 'online'."""
    with _conn() as c:
        c.execute("UPDATE sessions SET last_ping=? WHERE username=?",
                  (datetime.now().isoformat(), username))

def get_session(username):
    c   = _conn()
    row = c.execute("SELECT * FROM sessions WHERE username=?", (username,)).fetchone()
    c.close()
    return dict(row) if row else None

def get_online_users():
    """Return all users with an active session (logged in right now)."""
    c    = _conn()
    rows = c.execute("""
        SELECT u.username, u.display_name, s.logged_in_at
        FROM sessions s
        JOIN users u ON u.username = s.username
        ORDER BY s.logged_in_at DESC
    """).fetchall()
    c.close()
    return [{"username": r["username"], "display_name": r["display_name"],
             "logged_in_at": r["logged_in_at"]} for r in rows]

def get_public_key(username):
    """Returns public_key_pem only if user is currently online."""
    c   = _conn()
    row = c.execute("SELECT public_key_pem FROM sessions WHERE username=?", (username,)).fetchone()
    c.close()
    return row["public_key_pem"] if row else None

def validate_session(username, session_id):
    """Check that the session_id in JWT matches what we stored."""
    c   = _conn()
    row = c.execute("SELECT session_id FROM sessions WHERE username=?", (username,)).fetchone()
    c.close()
    return row and row["session_id"] == session_id


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
    online    = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    pending   = c.execute("SELECT COUNT(*) FROM transfers WHERE status='ready'").fetchone()[0]
    completed = c.execute("SELECT COUNT(*) FROM transfers WHERE status='completed'").fetchone()[0]
    c.close()
    return {"registered_users": users, "online_users": online,
            "pending_transfers": pending, "completed_transfers": completed}
