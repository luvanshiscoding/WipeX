# WipeX Desktop — Offline Application Plan

**Goal:** ship WipeX as an installable desktop application for Windows, Linux and macOS that works on an air-gapped workstation, plus a bootable Linux live USB for erasing system disks and firmware-frozen drives.

## 1. Starting point (already in the codebase)

| Requirement | Status | Where |
|---|---|---|
| Runs as one local process: the backend serves the built UI | ✅ | `engine/main.py` (serves `dist/`), `wipex.py` launcher |
| No network at runtime: fonts bundled, no CDN, no telemetry | ✅ | `@fontsource` packages, `vite build` |
| Local storage: single SQLite file, workspace folder, signing keys | ✅ | `store.py`, `database.py` |
| Per-user data folder when packaged (install folder stays read-only) | ✅ | `paths.py` (`%LOCALAPPDATA%\WipeX`, `~/Library/Application Support/WipeX`, `~/.local/share/wipex`) |
| API reachable only from this machine (host check, localhost bind) | ✅ | `TrustedHostMiddleware`, `127.0.0.1` |
| Sign-in, roles and per-user signing keys (no external identity server) | ✅ | `users.py` |
| Native window instead of a browser tab | ✅ optional | `python wipex.py --window` (pywebview) |
| Cross-platform test run (Windows, Linux, macOS) | ✅ | `.github/workflows/tests.yml` |

## 2. Shell technology — decision

| Option | How it works | Installer size | Effort | Verdict |
|---|---|---|---|---|
| **pywebview + PyInstaller** | Python process hosts the FastAPI engine and opens the OS web view (WebView2 / WebKitGTK / WKWebView) | ~60–90 MB | Low: one language, launcher already exists | **Chosen for the prototype and finale** |
| Tauri + Python sidecar | Rust shell with the OS web view; the frozen engine runs as a sidecar | ~70 MB | Medium: Rust toolchain, sidecar lifecycle | Later, if a smaller or more locked-down shell is needed |
| Electron + Python sidecar | Bundled Chromium plus the frozen engine | ~180 MB | Medium | Rejected: size, second runtime |

The UI stays the same web UI in every option, so the shell can be swapped later without touching the modules.

## 3. Packaging per operating system

| | Windows 10/11 | Linux (Ubuntu/Debian, Fedora) | macOS 13+ |
|---|---|---|---|
| Build | PyInstaller `--onedir` (UI `dist/` added as data) | PyInstaller `--onedir` | PyInstaller `.app` bundle |
| Installer | Inno Setup `.exe` (per-machine), MSIX later | AppImage + `.deb` | `.dmg` |
| Web view | WebView2 (built into Windows 11; bundled Evergreen installer for Windows 10) | WebKitGTK (`gir1.2-webkit2-4.1`, declared as a `.deb` dependency) | WKWebView (built in) |
| Raw-disk rights | Two Start-menu entries: *WipeX* and *WipeX (Administrator)*; the admin entry uses a `requireAdministrator` manifest | `.desktop` entry that starts the engine via `pkexec` | Engine started through an authorization prompt (`osascript … with administrator privileges`) |
| Firmware sanitize tools | Built in (NVMe through the Windows storage driver); optional `sedutil-cli.exe` next to the app | `nvme-cli`, `hdparm` as package dependencies; optional `sedutil-cli` | Not available (overwrite methods only) |
| Code signing | Authenticode certificate | Detached GPG signature + SHA-256 sums | Developer ID + notarization |

Native Python dependencies (`pytsk3`, `cryptography`, `Pillow`, `reportlab`) are frozen into the bundle, so the target machine needs no Python or Node.js. GPL tools (`nvme-cli`, `hdparm`, `sedutil-cli`) stay separate programs that WipeX calls; they are never linked into the application.

## 4. Bootable live USB (for what an installed app cannot do)

An installed application must refuse to erase the disk it is running from, and many laptops freeze ATA security at boot. For these cases WipeX ships a **Debian live image**:

- built with `live-build`; boots to a kiosk session that starts `wipex.py --window` full screen;
- includes `nvme-cli`, `hdparm`, `sedutil-cli`, `smartmontools`; networking disabled by default;
- every internal disk is a normal (non-boot) target, and suspend/resume is offered to unfreeze ATA drives;
- certificates, reports and the audit log are exported to a second USB stick; the workstation's signing key can be imported so certificates verify at the office.

## 5. Privilege separation (hardening step)

Today the whole engine runs elevated when raw disks are needed. The target design splits it:

1. **UI + engine** run as the normal user: cases, recovery from images, reports, audit log.
2. **Privileged worker**: a small helper started elevated only for raw-device jobs. It accepts one signed job description (device, method, wipe id) over a local pipe and refuses anything else. The boot-disk check and the legal-hold check run again inside the worker.

This limits what a compromised UI session could do with administrator rights.

## 6. Offline updates and data safety

- **No internet update channel.** Releases are distributed as signed bundles (USB or internal file share); the installer verifies the release signature and SHA-256 before installing.
- **Data folder backup:** one-click export of `wipex.db`, `keys/` (password-protected archive) and reports; restore on a replacement workstation.
- **Integrity self-check at start-up:** the engine verifies the audit chain and warns if it is broken.
- **SBOM** (CycloneDX) generated at build time and shipped with each release.

## 7. Milestones

| # | Milestone | Deliverable | Target |
|---|---|---|---|
| D1 | Single offline process | `wipex.py`, backend serves the UI, local fonts, per-user data folder | ✅ Done |
| D2 | Frozen builds in CI | PyInstaller spec; GitHub Actions uploads Windows / Linux / macOS artifacts; smoke test starts each build and calls `/api/health` | Oct 2026 |
| D3 | Installers | Inno Setup `.exe`, AppImage + `.deb`, `.dmg`; Start-menu / desktop entries incl. elevated launch | Oct 2026 |
| D4 | Live USB | `live-build` configuration, kiosk session, export to second USB; tested on two laptops and one desktop | Nov 2026 |
| D5 | Privilege separation | Elevated worker for raw-device jobs, signed job hand-off | Nov 2026 |
| D6 | Signing and release | Authenticode, Apple notarization, GPG-signed checksums, SBOM | Dec 2026 (finale) |

## 8. How each milestone is verified

- **Air-gap test:** install on a machine with all outbound traffic blocked by the firewall; run the full demo (erase a lab image, issue a certificate, recover from the evidence image, run the benchmark, verify the audit chain). Nothing may fail or wait for the network.
- **Clean-machine test:** fresh Windows 11, Ubuntu 24.04 and macOS VMs with no Python or Node.js installed.
- **Upgrade test:** install release N, create cases and certificates, upgrade to N+1, confirm every certificate and the audit chain still verify.
- **Least-privilege test:** as a normal user, raw-disk actions are refused with a clear message; as administrator (or from the live USB) they work.
- **Automated UI test:** the Playwright flow used during development (sign-in, two-person approval, erasure, certificate, E01 acquisition, auditor read-only) runs against each frozen build.

## 9. Risks

| Risk | Mitigation |
|---|---|
| `pytsk3` has no prebuilt wheel for a platform/Python pair | Build wheels in CI once and cache them; pin the Python version used for freezing |
| WebView2 missing on older Windows 10 | Bundle the Evergreen bootstrapper in the installer |
| Antivirus flags raw-disk access by an unsigned tool | Authenticode signing; publish hashes; document the exclusion |
| macOS blocks raw disk access even as root for internal disks (SIP / T2 / Apple silicon) | Offer overwrite of external disks only on macOS; use the live USB (on Intel Macs) or macOS *Erase All Content and Settings* for internal disks, recorded as an operator-confirmed step |
