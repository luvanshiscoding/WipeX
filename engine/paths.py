"""
WipeX - where code, bundled resources and per-workstation data live.

Development (running from the repository): data sits in the repository folder (git-ignored).
Packaged desktop build (PyInstaller, sys.frozen): data goes to the per-user
application-data folder so the install directory can stay read-only:
    Windows  %LOCALAPPDATA%\\WipeX
    macOS    ~/Library/Application Support/WipeX
    Linux    $XDG_DATA_HOME/wipex (default ~/.local/share/wipex)
WIPEX_HOME overrides both.
"""

import os
import platform
import sys

FROZEN = bool(getattr(sys, "frozen", False))
CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repository root (engine/..)
# PyInstaller unpacks bundled files (the built UI) into sys._MEIPASS
RESOURCE_DIR = getattr(sys, "_MEIPASS", CODE_DIR)


def data_dir() -> str:
    env = os.environ.get("WIPEX_HOME")
    if env:
        path = env
    elif not FROZEN:
        path = CODE_DIR
    elif platform.system() == "Windows":
        path = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local"), "WipeX")
    elif platform.system() == "Darwin":
        path = os.path.expanduser("~/Library/Application Support/WipeX")
    else:
        path = os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "wipex")
    os.makedirs(path, exist_ok=True)
    return path


def ui_dir() -> str:
    """Built web UI (vite build output), served by the backend for offline use."""
    return os.path.join(RESOURCE_DIR, "dist")
