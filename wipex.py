"""
WipeX launcher - runs the whole application offline as one local process.

    python wipex.py              start on http://127.0.0.1:8000 and open the UI
    python wipex.py --window     open in a native window (needs: pip install pywebview)
    python wipex.py --no-browser --port 8100
    python wipex.py --install    once, as Administrator / with sudo: WipeX then starts with those
                                 rights automatically and is opened from http://127.0.0.1:8000/
    python wipex.py --uninstall  remove that automatic start

The backend serves the built UI from dist/ (run `npm run build` once). Nothing is fetched
from the network. Reading and erasing drives needs Administrator / root rights: WipeX asks for
them once at start (UAC on Windows, sudo in a terminal on macOS / Linux) unless --no-admin is given.
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("No free local port")


def _running_wipex(port: int) -> bool:
    """True when a WipeX engine already answers on this port (then we just open it)."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1.5) as r:
            return json.loads(r.read().decode()).get("service") == "WipeX"
    except (OSError, ValueError):
        return False


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
    parser.add_argument("--no-admin", action="store_true", help="do not ask for Administrator / root rights")
    parser.add_argument("--install", action="store_true", help="start WipeX with Administrator / root rights automatically")
    parser.add_argument("--uninstall", action="store_true", help="remove the automatic start")
    parser.add_argument("--replace", action="store_true", help=argparse.SUPPRESS)   # take over a WipeX that is restarting
    args = parser.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(here, "engine"))
    import elevation

    if args.install or args.uninstall:
        if not elevation.is_admin():
            if args.no_admin:
                print("Installing needs Administrator rights (Windows) or sudo (macOS, Linux).")
                return 1
            if os.name != "nt" and sys.stdin.isatty():
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
            res = elevation.relaunch(sys.argv[1:] + ["--no-admin"])
            print(res["message"])
            return 0 if res["started"] else 1
        try:
            res = elevation.install(args.port) if args.install else elevation.uninstall()
        except Exception as exc:  # noqa: BLE001
            print(f"Failed: {exc}")
            return 1
        if args.install:
            print(f"Installed: WipeX {res['how']}.")
            print(f"Open it at {res['link']}" + (f"  (desktop link: {res['shortcut']})" if res["shortcut"] else ""))
            if os.name == "nt":
                import subprocess
                subprocess.run(["schtasks", "/Run", "/TN", elevation.TASK], capture_output=True)
        else:
            print("Removed the automatic start.")
        return 0

    if not args.replace and _running_wipex(args.port):
        url = f"http://127.0.0.1:{args.port}/"
        print(f"WipeX is already running at {url}")
        if not args.no_browser:
            webbrowser.open(url)
        return 0

    if not args.no_admin and not args.replace and not elevation.is_admin():
        if os.name != "nt" and sys.stdin.isatty():
            print("WipeX needs root to read and erase drives; enter your password (Ctrl+C to continue without).")
            try:
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
            except (OSError, KeyboardInterrupt):
                pass
        elif os.name == "nt":
            res = elevation.relaunch(sys.argv[1:])
            if res["started"]:
                return 0                                   # the elevated copy takes over
            print("Continuing without Administrator rights: drives cannot be read or erased directly.")

    import uvicorn
    import paths
    from main import app

    if not os.path.isfile(os.path.join(paths.ui_dir(), "index.html")):
        print("The UI is not built yet: run `npm install` and `npm run build` once, then start WipeX again.")
        print("(For development you can instead run `npm run dev` and open http://localhost:5173.)")

    if args.replace:                                       # the old engine is shutting down: take its port
        with open(elevation.takeover_marker(args.port), "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        deadline = time.time() + 30
        while not _port_free(args.port) and time.time() < deadline:
            time.sleep(0.3)
        port = args.port
    else:
        port = _free_port(args.port)
    url = f"http://127.0.0.1:{port}/"
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    if not _wait_ready(port):
        print("WipeX engine did not start")
        return 1
    print(f"WipeX is running at {url}  (data: {paths.data_dir()}, "
          f"{'with' if elevation.is_admin() else 'without'} Administrator / root rights)")

    if args.window:
        try:
            import webview
            webview.create_window("WipeX", url, width=1360, height=880, min_size=(900, 600))
            webview.start()
            server.should_exit = True
            return 0
        except ImportError:
            print("pywebview is not installed; opening the default browser instead")
    if not args.no_browser and not args.replace:
        webbrowser.open(url)
    try:
        while thread.is_alive():
            thread.join(1.0)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


if __name__ == "__main__":
    sys.exit(main())
