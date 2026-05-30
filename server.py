"""
Secure File Transfer — Session-Key Model
=========================================
Design principles:
  - Private keys NEVER leave the browser. Generated fresh on every login.
  - Public keys stored in DB only while user is actively logged in (sessions table).
  - On logout → session deleted → public key gone from DB → user offline.
  - Only online users appear in the UI and can receive files.
  - No enc_private_key stored anywhere on server.
  - Transfers encrypted with recipient's current-session public key.
    If recipient logs out before downloading, those transfers become unreadable
    (their private key is gone). This is intentional — session-bound security.
"""
import os, json, secrets, base64, datetime, urllib.request
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, session
from flask_cors import CORS
import database

# ── Config ─────────────────────────────────────────────────────────────────────
COGNITO_REGION       = os.environ.get("COGNITO_REGION",       "us-east-1")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_xxxxxxxx")
COGNITO_CLIENT_ID    = os.environ.get("COGNITO_CLIENT_ID",    "xxxxxxxxxxxxxxxxxxxxxxxxxxx")
COGNITO_CLIENT_SECRET= os.environ.get("COGNITO_CLIENT_SECRET","")
COGNITO_DOMAIN       = os.environ.get("COGNITO_DOMAIN",       "your domain address from Cognito console")
APP_BASE_URL         = os.environ.get("APP_BASE_URL",         "http://localhost:5000")

REDIRECT_URI = f"{APP_BASE_URL}/callback"
JWKS_URL     = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "server.log"
LOG_FILE.parent.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
CORS(app)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
database.init_db()

# ── JWKS ───────────────────────────────────────────────────────────────────────
_jwks_cache = None

def get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        try:
            with urllib.request.urlopen(JWKS_URL, timeout=5) as r:
                _jwks_cache = json.loads(r.read())
        except Exception as e:
            print(f"[JWKS] {e}")
            return {"keys": []}
    return _jwks_cache

# ── JWT ────────────────────────────────────────────────────────────────────────
import base64 as _b64

def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return _b64.urlsafe_b64decode(s)

def verify_cognito_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None

    expected_iss = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
    if payload.get("iss") != expected_iss:
        return None
    if payload.get("exp", 0) < datetime.datetime.utcnow().timestamp():
        return None

    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        kid      = header.get("kid")
        key_data = next((k for k in get_jwks().get("keys", []) if k.get("kid") == kid), None)
        if key_data:
            def b64i(s):
                s += "=" * (-len(s) % 4)
                return int.from_bytes(_b64.urlsafe_b64decode(s), "big")
            pub = RSAPublicNumbers(e=b64i(key_data["e"]), n=b64i(key_data["n"])).public_key(default_backend())
            pub.verify(_b64url_decode(parts[2]),
                       f"{parts[0]}.{parts[1]}".encode(),
                       padding.PKCS1v15(), hashes.SHA256())
    except ImportError:
        pass
    except Exception:
        return None
    return payload

def extract_identity(payload):
    """Returns (sub, suggested_display_name, email)."""
    sub       = payload.get("sub", "")
    preferred = payload.get("preferred_username", "") or payload.get("cognito:username", "")
    email     = payload.get("email", "")
    suggested = preferred or (email.split("@")[0] if email else sub[:8])
    return sub.lower(), suggested, email

# ── Auth decorator ─────────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        payload = verify_cognito_token(auth[7:])
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        sub, suggested, email      = extract_identity(payload)
        request.cognito_sub        = sub
        request.cognito_suggested  = suggested
        request.cognito_email      = email
        # Ping session on every authenticated call
        database.ping_session(sub)
        return f(*args, **kwargs)
    return wrapper

# ── Logging ────────────────────────────────────────────────────────────────────
def log_event(event, actor, message, level="INFO"):
    ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    entry = {"timestamp": ts, "level": level, "event": event, "actor": actor, "message": message}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    database.add_log(level, event, actor, message)
    print(f"[{ts}] [{level}] [{event}] {message}")
    return entry

# ── Pages ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("client.html",
        cognito_domain=COGNITO_DOMAIN,
        client_id=COGNITO_CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        app_base_url=APP_BASE_URL)

@app.route("/monitor")
def monitor():
    return render_template("monitor.html")

# ── OAuth2 ─────────────────────────────────────────────────────────────────────
@app.route("/login")
def login():
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    params = (f"response_type=code&client_id={COGNITO_CLIENT_ID}"
              f"&redirect_uri={REDIRECT_URI}&scope=openid+email+profile&state={state}")
    return redirect(f"https://{COGNITO_DOMAIN}/oauth2/authorize?{params}")

@app.route("/callback")
def callback():
    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    if state != session.pop("oauth_state", None):
        return "State mismatch", 400
    if not code:
        return "No code", 400

    token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"
    body      = (f"grant_type=authorization_code&code={code}"
                 f"&redirect_uri={REDIRECT_URI}&client_id={COGNITO_CLIENT_ID}")
    if COGNITO_CLIENT_SECRET:
        import base64 as b64
        creds   = b64.b64encode(f"{COGNITO_CLIENT_ID}:{COGNITO_CLIENT_SECRET}".encode()).decode()
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Authorization": f"Basic {creds}"}
    else:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        req = urllib.request.Request(token_url, body.encode(), headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            tokens = json.loads(r.read())
    except Exception as e:
        return f"Token exchange failed: {e}", 500

    session["id_token"]     = tokens.get("id_token", "")
    session["access_token"] = tokens.get("access_token", "")
    return redirect("/")

@app.route("/logout")
def logout_page():
    # Delete session from DB → user goes offline, public key cleared
    id_token = session.get("id_token", "")
    if id_token:
        try:
            payload = json.loads(_b64url_decode(id_token.split(".")[1]))
            sub = payload.get("sub", "").lower()
            if sub:
                database.delete_session(sub)
                log_event("LOGOUT", "SERVER", f"Session ended for sub={sub[:8]}…")
        except Exception:
            pass
    session.clear()
    return redirect(f"https://{COGNITO_DOMAIN}/logout?client_id={COGNITO_CLIENT_ID}&logout_uri={APP_BASE_URL}")

# ── Session info ───────────────────────────────────────────────────────────────
@app.route("/api/me")
def me():
    return jsonify({
        "id_token":     session.get("id_token", ""),
        "access_token": session.get("access_token", ""),
        "logged_in":    bool(session.get("access_token")),
    })

# ── Key registration (called once per login with fresh public keys) ─────────────
@app.route("/api/register_keys", methods=["POST"])
@require_auth
def register_keys():
    """
    Called by browser right after login with freshly generated public keys.
    - Probe { probe: true } → check if user has a display_name already
    - Register { public_key_pem, display_name? } → create session + store public key
    Private keys are NEVER sent here.
    """
    sub       = request.cognito_sub
    suggested = request.cognito_suggested
    data      = request.get_json(force=True) or {}

    # Probe: is this user known? (has display_name from a previous login?)
    if data.get("probe"):
        user = database.get_user(sub)
        if user:
            return jsonify({"action": "known", "display_name": user["display_name"]})
        return jsonify({"action": "new_user", "suggested_name": suggested})

    # Register fresh public keys for this session
    pub_pem      = data.get("public_key_pem", "")
    display_name = data.get("display_name", "").strip()

    if not pub_pem:
        return jsonify({"error": "Missing public_key_pem"}), 400

    try:
        bundle = json.loads(pub_pem)
        assert "oaep" in bundle and "pss" in bundle
    except Exception:
        return jsonify({"error": "Invalid public key bundle"}), 400

    # First-ever login needs a display_name
    user = database.get_user(sub)
    if not user:
        if not display_name or len(display_name) < 3:
            return jsonify({"error": "display_name required (min 3 chars)"}), 400
        database.upsert_user(sub, display_name)
        is_new = True
    else:
        display_name = user["display_name"]   # always use the original chosen name
        is_new = False

    # Create/replace session with fresh public key (private key stays in browser)
    session_id = secrets.token_hex(24)
    database.create_session(sub, session_id, pub_pem)

    log_event("LOGIN", "SERVER",
        f"'{display_name}' logged in. Fresh RSA keys registered. Private key stays in browser.",
        "SUCCESS")

    return jsonify({"success": True, "display_name": display_name, "is_new": is_new,
                    "session_id": session_id})

# ── Explicit logout API (called by browser on Sign out / tab close) ────────────
@app.route("/api/session_end", methods=["POST"])
@require_auth
def session_end():
    sub = request.cognito_sub
    database.delete_session(sub)
    user = database.get_user(sub)
    name = user["display_name"] if user else sub[:8]
    log_event("SESSION_END", "SERVER",
        f"'{name}' session ended — public key cleared, user offline.")
    return jsonify({"success": True})

# ── Users (online only) ────────────────────────────────────────────────────────
@app.route("/api/users")
@require_auth
def list_users():
    sub   = request.cognito_sub
    users = database.get_online_users()
    return jsonify({"users": [u for u in users if u["username"] != sub]})

@app.route("/api/get_public_key/<username>")
@require_auth
def get_public_key(username):
    pub = database.get_public_key(username.lower())
    if not pub:
        return jsonify({"error": f"'{username}' is not online or not found"}), 404
    user = database.get_user(username.lower())
    log_event("KEY_FETCH", "SERVER",
        f"'{request.cognito_sub[:8]}…' fetched public key of '{user['display_name'] if user else username}'")
    return jsonify({"username": username.lower(), "public_key_pem": pub,
                    "display_name": user["display_name"] if user else username})

# ── Transfers ──────────────────────────────────────────────────────────────────
@app.route("/api/initiate_transfer", methods=["POST"])
@require_auth
def initiate_transfer():
    sub       = request.cognito_sub
    data      = request.get_json(force=True) or {}
    recipient = data.get("recipient", "").lower()

    # Recipient must be online (public key must exist)
    if not database.get_public_key(recipient):
        return jsonify({"error": f"'{recipient}' is not currently online"}), 404

    tid = secrets.token_hex(16)
    database.add_transfer(
        tid, sub, recipient,
        data.get("filename", "unknown"),
        data.get("file_size", 0),
        data.get("total_chunks", 1),
        data.get("enc_aes_key", ""),
        data.get("enc_hmac_key", ""),
        data.get("meta_signature", ""),
    )
    sender = database.get_user(sub)
    sname  = sender["display_name"] if sender else sub[:8]
    recip  = database.get_user(recipient)
    rname  = recip["display_name"] if recip else recipient[:8]
    log_event("TRANSFER_INIT", "SERVER",
        f"'{sname}' → '{rname}' | '{data.get('filename')}'")
    return jsonify({"success": True, "transfer_id": tid})

@app.route("/api/upload_chunk", methods=["POST"])
@require_auth
def upload_chunk():
    sub = request.cognito_sub
    tid = request.form.get("transfer_id", "")
    tr  = database.get_transfer(tid)
    if not tr:
        return jsonify({"error": "Transfer not found"}), 404
    if tr["sender"] != sub:
        return jsonify({"error": "Not your transfer"}), 403

    idx   = int(request.form.get("chunk_index", 0))
    total = int(request.form.get("total_chunks", 1))
    fdata = request.files.get("chunk")
    if not fdata:
        return jsonify({"error": "No chunk data"}), 400

    chunk_bytes = fdata.read()
    database.add_chunk(tid, idx,
        base64.b64encode(chunk_bytes).decode(),
        request.form.get("nonce", ""),
        request.form.get("hmac_tag", ""),
        request.form.get("signature", ""))

    if database.get_transfer_chunk_count(tid) >= total:
        database.update_transfer_status(tid, "ready")
        log_event("TRANSFER_READY", "SERVER",
            f"Transfer {tid[:8]}… all {total} chunk(s) ready")

    return jsonify({"success": True})

@app.route("/api/inbox")
@require_auth
def inbox():
    sub       = request.cognito_sub
    transfers = database.get_pending_transfers(sub)
    for t in transfers:
        s = database.get_user(t["sender"])
        t["sender_display"] = s["display_name"] if s else t["sender"][:8]
    return jsonify({"transfers": transfers})

@app.route("/api/get_chunk")
@require_auth
def get_chunk():
    sub = request.cognito_sub
    tid = request.args.get("transfer_id", "")
    idx = int(request.args.get("chunk_index", 0))
    tr  = database.get_transfer(tid)
    if not tr:
        return jsonify({"error": "Not found"}), 404
    if tr["recipient"] != sub:
        return jsonify({"error": "Not your transfer"}), 403
    chunk = database.get_chunk(tid, idx)
    if not chunk:
        return jsonify({"error": "Chunk not found"}), 404
    return jsonify({"data_b64": chunk["data_b64"], "nonce": chunk["nonce"],
                    "hmac": chunk["hmac"], "sig": chunk["sig"], "index": idx})

@app.route("/api/complete_transfer", methods=["POST"])
@require_auth
def complete_transfer():
    sub  = request.cognito_sub
    data = request.get_json(force=True) or {}
    tid  = data.get("transfer_id", "")
    tr   = database.get_transfer(tid)
    if not tr:
        return jsonify({"error": "Not found"}), 404
    database.update_transfer_status(tid, "completed")
    r = database.get_user(sub)
    s = database.get_user(tr["sender"])
    log_event("COMPLETE", "SERVER",
        f"'{s['display_name'] if s else '?'}' → '{r['display_name'] if r else '?'}' | '{tr['filename']}'",
        "SUCCESS")
    return jsonify({"success": True})

# ── Logs / status ──────────────────────────────────────────────────────────────
@app.route("/api/logs")
def get_logs():   return jsonify({"logs": database.get_recent_logs(200)})

@app.route("/api/clear_logs", methods=["POST"])
def clear_logs(): database.clear_logs(); return jsonify({"success": True})

@app.route("/api/status")
def status():     return jsonify(database.get_status())

@app.after_request
def add_headers(r):
    r.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
    r.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    return r

if __name__ == "__main__":
    log_event("SERVER_START", "SERVER", "SecureTransfer (session-key model) started")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
