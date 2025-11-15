# desktop.py — main entry for standalone Early Access app

import threading
import time

import uvicorn
import webview

from server import app
from beta_access import assert_beta_or_exit


def start_api() -> None:
    """
    Run FastAPI app in a background thread.

    Note:
    - Host/port must match what the desktop window loads.
    - reload=False is required for PyInstaller builds.
    """
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8765,
        log_level="info",
        reload=False,
    )


def main() -> None:
    # Terminal splash + beta gate (will exit(1) if invalid/expired)
    assert_beta_or_exit()

    # Start API in background
    t = threading.Thread(target=start_api, daemon=True)
    t.start()

    # Give server a moment to come up before opening the window
    time.sleep(1.5)

    # IMPORTANT: load from http://127.0.0.1, not file://
    webview.create_window(
        "Curator Finder – Early Access Preview",
        "http://127.0.0.1:8765/dashboard.html",
        width=1200,
        height=800,
        confirm_close=True,
    )
    webview.start()
    # To show a dev console on Windows, you can instead use:
    # webview.start(debug=True)


if __name__ == "__main__":
    main()
