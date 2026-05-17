"""
Secure File Transfer Server
- Private keys NEVER leave the client browser
- Server stores only public keys, relays encrypted chunks
- All crypto happens in the browser via Web Crypto API
"""
import os, json, secrets, base64, datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import database

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "server.log"
LOG_FILE.parent.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
CORS(app)
app.secret_key = secrets.token_hex(32)

database.init_db()


@app.after_request
def add_headers(response):
    response.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    return response


def log_event(event, actor, message, level="INFO"):
    ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    entry = {"timestamp": ts, "level": level, "event": event,
             "actor": actor, "message": message}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    database.add_log(level, event, actor, message)
    print(f"[{ts}] [{level}] [{actor}] {message}")
    return entry


def check_auth():
    u   = request.headers.get("X-Username", "").strip().lower()
    t   = request.headers.get("X-Session-Token", "")
    rec = database.get_user(u)
    if rec:
        database.update_user_last_seen(u)
    return u, rec is not None and rec["session_token"] == t


def validate_bundle(pub_pem):
    """Return True if pub_pem is a valid JSON bundle with oaep + pss keys."""
    try:
        bundle = json.loads(pub_pem)
        assert "oaep" in bundle and "pss" in bundle
        assert bundle["oaep"].startswith("-----BEGIN PUBLIC KEY-----")
        assert bundle["pss"].startswith("-----BEGIN PUBLIC KEY-----")
        return True
    except Exception:
        return False


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("client.html")

@app.route("/monitor")
def monitor():
    return render_template("monitor.html")


# ── Auth ───────────────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    """Register a brand-new username. Fails if username already exists."""
    data     = request.get_json(force=True) or {}
    username = data.get("username", "").strip().lower()
    pub_pem  = data.get("public_key_pem", "")

    if not username or not pub_pem:
        return jsonify({"error": "Missing fields"}), 400
    if not validate_bundle(pub_pem):
        return jsonify({"error": "Invalid public key format"}), 400
    if database.get_user(username):
        return jsonify({"error": "Username already taken", "exists": True}), 400

    token = secrets.token_hex(32)
    database.add_user(username, pub_pem, token)
    log_event("REGISTER", "SERVER",
        f"'{username}' registered. Public key stored. Private key stays in client.")
    return jsonify({"success": True, "session_token": token})


@app.route("/api/login", methods=["POST"])
def login():
    """
    Re-login for a returning user whose private key was lost on page refresh.
    Generates fresh keys in the browser, updates the stored public key,
    and issues a new session token.
    Any pending transfers addressed to this user that were encrypted with
    the old public key will be marked as stale (they cannot be decrypted
    with the new private key — this is by design: Perfect Forward Secrecy).
    """
    data     = request.get_json(force=True) or {}
    username = data.get("username", "").strip().lower()
    pub_pem  = data.get("public_key_pem", "")

    if not username or not pub_pem:
        return jsonify({"error": "Missing fields"}), 400
    if not validate_bundle(pub_pem):
        return jsonify({"error": "Invalid public key format"}), 400

    existing = database.get_user(username)
    if not existing:
        return jsonify({"error": "Username not found. Please register first."}), 404

    # Issue new token and update stored public key
    token = secrets.token_hex(32)
    database.update_user_keys(username, pub_pem, token)

    # Mark any old pending transfers as stale — they were encrypted with the
    # previous public key and can no longer be decrypted
    stale = database.mark_stale_transfers(username)
    log_event("LOGIN", "SERVER",
        f"'{username}' logged in. New keys registered. "
        f"{stale} stale transfer(s) cleared (encrypted with old key).")
    return jsonify({"success": True, "session_token": token, "stale_cleared": stale})


@app.route("/api/logout", methods=["POST"])
def logout():
    """Invalidate the session token for a user."""
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    database.invalidate_session(u)
    log_event("LOGOUT", "SERVER", f"'{u}' logged out.")
    return jsonify({"success": True})


@app.route("/api/check_username", methods=["GET"])
def check_username():
    """Returns whether a username is already registered."""
    username = request.args.get("username", "").strip().lower()
    if not username:
        return jsonify({"error": "Missing username"}), 400
    exists = database.get_user(username) is not None
    return jsonify({"exists": exists, "username": username})


# ── Users ──────────────────────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
def list_users():
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"users": [n for n in database.get_all_users() if n != u]})


@app.route("/api/get_public_key/<username>", methods=["GET"])
def get_public_key(username):
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    user = database.get_user(username.lower())
    if not user:
        return jsonify({"error": "User not found"}), 404
    log_event("KEY_FETCH", "SERVER",
        f"'{u}' fetched public key of '{username}' for client-side encryption")
    return jsonify({"username": username.lower(), "public_key_pem": user["public_key_pem"]})


# ── Transfers ──────────────────────────────────────────────────────────────────

@app.route("/api/initiate_transfer", methods=["POST"])
def initiate_transfer():
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401

    data      = request.get_json(force=True) or {}
    recipient = data.get("recipient", "").lower()
    if not database.get_user(recipient):
        return jsonify({"error": f"'{recipient}' is not registered"}), 404

    tid = secrets.token_hex(16)
    database.add_transfer(
        tid, u, recipient,
        data.get("filename", "unknown"),
        data.get("file_size", 0),
        data.get("total_chunks", 1),
        data.get("enc_aes_key", ""),
        data.get("enc_hmac_key", ""),
        data.get("meta_signature", ""),
    )
    log_event("TRANSFER_INIT", "SERVER",
        f"Transfer {tid[:8]}… | '{u}' → '{recipient}' | '{data.get('filename')}'")
    return jsonify({"success": True, "transfer_id": tid})


@app.route("/api/upload_chunk", methods=["POST"])
def upload_chunk():
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401

    tid = request.form.get("transfer_id", "")
    tr  = database.get_transfer(tid)
    if not tr:
        return jsonify({"error": "Transfer not found"}), 404
    if tr["sender"] != u:
        return jsonify({"error": "Not your transfer"}), 403

    idx   = int(request.form.get("chunk_index", 0))
    total = int(request.form.get("total_chunks", 1))
    nonce = request.form.get("nonce", "")
    hmac  = request.form.get("hmac_tag", "")
    sig   = request.form.get("signature", "")
    fdata = request.files.get("chunk")
    if not fdata:
        return jsonify({"error": "No chunk data"}), 400

    chunk_bytes = fdata.read()
    database.add_chunk(tid, idx, base64.b64encode(chunk_bytes).decode(), nonce, hmac, sig)
    log_event("CHUNK_RECV", "SERVER",
        f"Transfer {tid[:8]}… | Chunk {idx+1}/{total} | {len(chunk_bytes)} bytes")

    if database.get_transfer_chunk_count(tid) >= total:
        database.update_transfer_status(tid, "ready")
        log_event("TRANSFER_READY", "SERVER",
            f"Transfer {tid[:8]}… | All {total} chunk(s) ready for '{tr['recipient']}'")

    return jsonify({"success": True})


@app.route("/api/inbox", methods=["GET"])
def inbox():
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"transfers": database.get_pending_transfers(u)})


@app.route("/api/get_chunk", methods=["GET"])
def get_chunk():
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401

    tid = request.args.get("transfer_id", "")
    idx = int(request.args.get("chunk_index", 0))
    tr  = database.get_transfer(tid)
    if not tr:
        return jsonify({"error": "Transfer not found"}), 404
    if tr["recipient"] != u:
        return jsonify({"error": "Not your transfer"}), 403

    chunk = database.get_chunk(tid, idx)
    if not chunk:
        return jsonify({"error": "Chunk not found"}), 404

    log_event("CHUNK_SENT", "SERVER",
        f"Transfer {tid[:8]}… | Chunk {idx+1}/{tr['total_chunks']} → '{u}'")
    return jsonify({
        "data_b64": chunk["data_b64"],
        "nonce":    chunk["nonce"],
        "hmac":     chunk["hmac"],
        "sig":      chunk["sig"],
        "index":    idx,
    })


@app.route("/api/complete_transfer", methods=["POST"])
def complete_transfer():
    u, ok = check_auth()
    if not ok:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True) or {}
    tid  = data.get("transfer_id", "")
    tr   = database.get_transfer(tid)
    if not tr:
        return jsonify({"error": "Not found"}), 404
    database.update_transfer_status(tid, "completed")
    log_event("COMPLETE", "SERVER",
        f"Transfer {tid[:8]}… | '{tr['sender']}' → '{u}' | '{tr['filename']}'", "SUCCESS")
    return jsonify({"success": True})


# ── Logs & status ──────────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
def get_logs():
    return jsonify({"logs": database.get_recent_logs(200)})

@app.route("/api/clear_logs", methods=["POST"])
def clear_logs():
    database.clear_logs()
    return jsonify({"success": True})

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify(database.get_status())


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log_event("SERVER_START", "SERVER",
        "Secure File Transfer Server started — open http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
