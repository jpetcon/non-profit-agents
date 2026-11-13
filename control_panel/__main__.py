"""Launch with `uv run python -m control_panel`."""
import argparse
import os
import secrets
import socket
import threading
import time
import webbrowser

import uvicorn


def main():
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    parser = argparse.ArgumentParser(description="Your local agent studio")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    token = secrets.token_urlsafe(32)
    from .app import create_app
    app = create_app(pairing_token=token)
    url = f"http://127.0.0.1:{args.port}/#pair={token}"
    def open_browser():
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", args.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        if not args.no_browser:
            webbrowser.open(url)
    print("Agent studio is local to this computer. Ctrl+C stops the app and its owned gateways.")
    print("Browser pairing link (keep private): " + url)
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
