"""
WipeX - Administrator / root rights.

Reading and erasing drives directly needs Administrator rights on Windows and root on Linux and
macOS. WipeX asks for them once, when it starts, instead of failing later in a module:

  * start:    wipex.py relaunches itself with the rights (Windows: the UAC prompt; macOS / Linux in a
              terminal: sudo). Declining keeps WipeX running without them.
  * restart:  a WipeX that runs without them can restart itself with them (Restart as Administrator
              in the UI); the page reconnects to the new engine on the same port.
  * install:  one-time, with the rights: WipeX then starts with them at sign-in (Windows scheduled
              task "run with highest privileges"), at boot (macOS LaunchDaemon, Linux systemd), and
              is opened from a link (http://127.0.0.1:8000/) with no prompt at all.
"""

import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

SYSTEM = platform.system()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # the WipeX folder
LAUNCHER = os.path.join(ROOT, "wipex.py")
TASK = "WipeX"                                                          # Windows scheduled task
MAC_PLIST = "/Library/LaunchDaemons/in.wipex.engine.plist"
LINUX_UNIT = "/etc/systemd/system/wipex.service"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin()) if SYSTEM == "Windows" else os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def _python(windowless: bool = False) -> str:
    """This interpreter; on Windows optionally pythonw.exe, which opens no console window."""
    exe = sys.executable
    if windowless and SYSTEM == "Windows":
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(w):
            return w
    return exe


def relaunch(args: List[str], wait_for_port: bool = False) -> Dict[str, Any]:
    """Start another WipeX with Administrator / root rights. With wait_for_port the new one takes over
    this one's port once it is free (this process then has to exit)."""
    argv = [LAUNCHER] + [a for a in args if a != "--replace"] + (["--replace"] if wait_for_port else [])
    if SYSTEM == "Windows":
        params = subprocess.list2cmdline(argv)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", _python(), params, ROOT, 1)
        if rc > 32:
            return {"started": True, "message": "Approve the Windows prompt to continue with Administrator rights"}
        return {"started": False, "message": "The Administrator prompt was declined or could not be shown"}
    cmd = " ".join(_sh(a) for a in [_python()] + argv)
    if SYSTEM == "Darwin":
        script = f"cd {_sh(ROOT)} && nohup {cmd} > /tmp/wipex-engine.log 2>&1 &"
        osa = f'do shell script "{script.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}" with administrator privileges'
        try:
            subprocess.Popen(["osascript", "-e", osa], start_new_session=True)
            return {"started": True, "message": "Enter your Mac password in the dialog to continue with root rights"}
        except OSError as exc:
            return {"started": False, "message": f"Could not ask for the password: {exc}"}
    if shutil.which("pkexec"):
        env = [f"{k}={os.environ[k]}" for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY") if os.environ.get(k)]
        subprocess.Popen(["pkexec", "env", *env, _python()] + argv, cwd=ROOT, start_new_session=True)
        return {"started": True, "message": "Enter your password in the system dialog to continue with root rights"}
    return {"started": False, "message": "Start WipeX from a terminal with: sudo python3 wipex.py"}


def takeover_marker(port: int) -> str:
    """File the new (elevated) engine creates when it starts, telling the old one to exit.
    In a folder both users see: the same user's TEMP on Windows, /tmp elsewhere."""
    folder = tempfile.gettempdir() if SYSTEM == "Windows" else "/tmp"
    return os.path.join(folder, f"wipex-takeover-{port}")


def _xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sh(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ── Start with the rights at sign-in / boot ─────────────────────────────────

def _task_xml(port: int) -> str:
    """Scheduled task: at sign-in of any user in this session, highest privileges, no time limit,
    also on battery (schtasks' own defaults stop a task after 72 h and skip it on battery)."""
    args = subprocess.list2cmdline([LAUNCHER, "--no-browser", "--no-admin", "--port", str(port)])
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")  # noqa: E731
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts the WipeX engine with Administrator rights so it can read and erase drives.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{esc(_python(windowless=True))}</Command><Arguments>{esc(args)}</Arguments><WorkingDirectory>{esc(ROOT)}</WorkingDirectory></Exec></Actions>
</Task>
"""


def _user_home() -> str:
    """Home of the person at the keyboard, also when WipeX runs through sudo (then HOME may be root's)."""
    user = os.environ.get("SUDO_USER")
    return os.path.expanduser(f"~{user}") if user and SYSTEM != "Windows" else os.path.expanduser("~")


def _shortcut(port: int) -> str:
    """A desktop link to WipeX (the way users open it after the install)."""
    desktop = os.path.join(_user_home(), "Desktop")
    if not os.path.isdir(desktop):
        return ""
    if SYSTEM == "Darwin":
        path = os.path.join(desktop, "WipeX.webloc")
        body = ('<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>URL</key>'
                f'<string>http://127.0.0.1:{port}/</string></dict></plist>\n')
    else:
        path = os.path.join(desktop, "WipeX.url" if SYSTEM == "Windows" else "WipeX.desktop")
        body = (f"[InternetShortcut]\nURL=http://127.0.0.1:{port}/\n" if SYSTEM == "Windows" else
                f"[Desktop Entry]\nType=Link\nName=WipeX\nURL=http://127.0.0.1:{port}/\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    if SYSTEM == "Linux":
        os.chmod(path, 0o755)                          # desktop launchers must be executable
    if os.environ.get("SUDO_UID") and hasattr(os, "chown"):
        os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", "-1")))   # not owned by root
    return path


def install(port: int = 8000) -> Dict[str, Any]:
    """Make WipeX start with Administrator / root rights automatically. Needs those rights once."""
    if not is_admin():
        raise PermissionError("Installing needs Administrator rights (Windows) or sudo (macOS, Linux) once")
    if SYSTEM == "Windows":
        xml = os.path.join(tempfile.gettempdir(), "wipex-task.xml")
        with open(xml, "w", encoding="utf-16") as f:
            f.write(_task_xml(port))
        res = subprocess.run(["schtasks", "/Create", "/TN", TASK, "/XML", xml, "/F"], capture_output=True, text=True)
        os.remove(xml)
        if res.returncode:
            raise RuntimeError((res.stderr or res.stdout).strip() or "schtasks failed")
        how = "starts with Administrator rights every time you sign in to Windows"
    elif SYSTEM == "Darwin":
        with open(MAC_PLIST, "w", encoding="utf-8") as f:
            f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>in.wipex.engine</string>
  <key>ProgramArguments</key><array><string>{_xml(_python())}</string><string>{_xml(LAUNCHER)}</string><string>--no-browser</string><string>--no-admin</string><string>--port</string><string>{port}</string></array>
  <key>WorkingDirectory</key><string>{_xml(ROOT)}</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/wipex-engine.log</string><key>StandardErrorPath</key><string>/tmp/wipex-engine.log</string>
</dict></plist>
""")
        subprocess.run(["launchctl", "bootout", "system", MAC_PLIST], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", "system", MAC_PLIST], capture_output=True, check=True)
        how = "runs with root rights from startup (LaunchDaemon)"
    else:
        with open(LINUX_UNIT, "w", encoding="utf-8") as f:
            f.write(f"""[Unit]
Description=WipeX engine (secure erasure and forensic recovery)
After=local-fs.target

[Service]
WorkingDirectory={ROOT}
ExecStart="{_python()}" "{LAUNCHER}" --no-browser --no-admin --port {port}
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "--now", "wipex.service"], capture_output=True, check=True)
        how = "runs with root rights from startup (systemd service wipex)"
    return {"installed": True, "link": f"http://127.0.0.1:{port}/", "shortcut": _shortcut(port), "how": how}


def uninstall() -> Dict[str, Any]:
    if not is_admin():
        raise PermissionError("Removing the automatic start needs Administrator rights (Windows) or sudo (macOS, Linux)")
    if SYSTEM == "Windows":
        subprocess.run(["schtasks", "/Delete", "/TN", TASK, "/F"], capture_output=True)
    elif SYSTEM == "Darwin":
        subprocess.run(["launchctl", "bootout", "system", MAC_PLIST], capture_output=True)
        if os.path.exists(MAC_PLIST):
            os.remove(MAC_PLIST)
    else:
        subprocess.run(["systemctl", "disable", "--now", "wipex.service"], capture_output=True)
        if os.path.exists(LINUX_UNIT):
            os.remove(LINUX_UNIT)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    return {"installed": False}


def installed() -> bool:
    try:
        if SYSTEM == "Windows":
            return subprocess.run(["schtasks", "/Query", "/TN", TASK], capture_output=True).returncode == 0
        return os.path.exists(MAC_PLIST if SYSTEM == "Darwin" else LINUX_UNIT)
    except OSError:
        return False
