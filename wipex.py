"""
WipeX launcher - runs the whole application offline as one local process.

    python wipex.py              start on http://127.0.0.1:8000 and open the UI
    python wipex.py --window     open in a native window (needs: pip install pywebview)
    python wipex.py --no-browser --port 8100

The backend serves the built UI from dist/ (run `npm run build` once). Nothing is
fetched from the network. Erasing physical disks needs Administrator / root rights.
"""

import argparse
import os
import socket
import sys
import threading
import time
import webbrowser


def _free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("No free local port")


def _wait_ready(port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="WipeX secure erasure and forensic recovery workstation")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--window", action="store_true", help="open in a native window (pywebview)")
    parser.add_argument("--no-browser", action="store_true", help="only start the server")
    args = parser.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import uvicorn
    import paths
    from main import app

    if not os.path.isfile(os.path.join(paths.ui_dir(), "index.html")):
        print("The UI is not built yet: run `npm install` and `npm run build` once, then start WipeX again.")
        print("(For development you can instead run `npm run dev` and open http://localhost:5173.)")

    port = _free_port(args.port)
    url = f"http://127.0.0.1:{port}/"
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    if not _wait_ready(port):
        print("WipeX engine did not start")
        return 1
    print(f"WipeX is running at {url}  (data: {paths.data_dir()})")

    if args.window:
        try:
            import webview
            webview.create_window("WipeX", url, width=1360, height=880, min_size=(900, 600))
            webview.start()
            server.should_exit = True
            return 0
        except ImportError:
            print("pywebview is not installed; opening the default browser instead")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        while thread.is_alive():
            thread.join(1.0)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


if __name__ == "__main__":
    sys.exit(main())
