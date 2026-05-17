#!/usr/bin/env python3
"""
start.py — launches server.py
Open http://localhost:5000 in your browser after running this.
"""
import subprocess, sys, os, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    print("\n╔══════════════════════════════════════════════╗")
    print("║        Secure File Transfer — Ready          ║")
    print("╠══════════════════════════════════════════════╣")
    print("║  Open:    http://localhost:5000              ║")
    print("║  Monitor: http://localhost:5000/monitor      ║")
    print("╚══════════════════════════════════════════════╝")
    print("\nPress Ctrl+C to stop.\n")

    env = {**os.environ, "PYTHONPATH": BASE_DIR}
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=BASE_DIR, env=env)

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down…")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    main()
