"""
Start the Secure File Transfer server with .env loading.
Usage:  python start.py
"""
import os, pathlib

# Load .env if present
env_path = pathlib.Path(__file__).parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from server import app, log_event

if __name__ == "__main__":
    base = os.environ.get("APP_BASE_URL", "http://localhost:5000")
    log_event("SERVER_START", "SERVER",
        f"Secure File Transfer (Cognito Edition) — open {base}")
    print(f"\n  🛡  SecureTransfer (Cognito Edition)")
    print(f"  Open: {base}\n")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
