# desktop.py — main entry for standalone app
import threading
import time
import webview
import uvicorn
from server import app


def start_api():
    """Run FastAPI app in background thread."""
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8765,
        log_level="info",
        reload=False,
    )


if __name__ == "__main__":
    # Start API in background
    t = threading.Thread(target=start_api, daemon=True)
    t.start()
    time.sleep(1.5)  # give server a moment

    # IMPORTANT: load from http://127.0.0.1, not file://
    webview.create_window(
        "Curator Finder",
        "http://127.0.0.1:8765/dashboard.html",
        width=1200,
        height=800,
        confirm_close=True,
    )
    webview.start()
#(debug=True)  # show console on Windows