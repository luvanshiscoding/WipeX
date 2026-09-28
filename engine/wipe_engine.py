"""
WipeX - Low-Level Hardware Wipe Engine
Probes real connected storage devices via macOS diskutil / Linux lsblk / smartctl.
Executes NIST SP 800-88 sanitization at the hardware level.
"""

import os
import re
import subprocess
import plistlib
import platform
import shutil
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple


class WipeEngine:
    """
    Low-level interface for physical media discovery, boundary unfreezing,
    and media-specific sanitization.
    """

    def probe_devices(self) -> List[Dict[str, Any]]:
        """
        Discovers all physically connected storage devices.
        Uses diskutil on macOS, lsblk+smartctl on Linux.
        Excludes disk images, loop devices, internal OS boot drives, and virtual disks.
        Deduplicates devices by serialNumber and devicePath.
        """
        system = platform.system()
        raw_devices = []
        if system == "Darwin":
            raw_devices = self._probe_macos()
        elif system == "Linux":
            raw_devices = self._probe_linux()
        elif system == "Windows":
            raw_devices = self._probe_windows()

        seen_paths = set()
        seen_serials = set()
        deduped = []
        for dev in raw_devices:
            path = dev.get("devicePath", "")
            serial = dev.get("serialNumber", "")
            if path and path in seen_paths:
                continue
            if serial and serial in seen_serials:
                continue
            if path:
                seen_paths.add(path)
            if serial:
                seen_serials.add(serial)
            deduped.append(dev)

        return deduped

    def _get_real_serial_macos(self, disk: str, info: Dict[str, Any]) -> str:
        """Fetch unique real serial for the specific physical disk."""
        if info.get("SerialNumber"):
            return str(info["SerialNumber"]).strip()

        # For Apple Fabric internal SSD
        if info.get("BusProtocol") == "Apple Fabric":
            try:
                ioreg = subprocess.run(["ioreg", "-r", "-c", "IOBlockStorageDevice", "-l"], capture_output=True, timeout=5)
                text = ioreg.stdout.decode("utf-8", errors="ignore")
                candidates = re.findall(r'"Serial Number"\s*=\s*"([^"]+)"', text)
                if candidates and candidates[0].strip():
                    return candidates[0].strip()
            except Exception:
                pass

        # For USB / External / Non-Fabric drives, derive a unique hardware serial using MediaName + Disk ID
        media_name = (info.get("MediaName") or info.get("IORegistryEntryName") or "DRIVE").upper()
        media_slug = re.sub(r"[^A-Z0-9]", "", media_name)[:8]
        disk_id = disk.upper().replace("DISK", "DK")
        uuid_stub = (info.get("VolumeUUID") or info.get("MediaUUID") or "").replace("-", "")[:8].upper()
        if uuid_stub:
            return f"{media_slug}-{uuid_stub}-{disk_id}"
        return f"{media_slug}-{disk_id}"

    def _whole_disk_of_device_macos(self, device_identifier: str) -> Optional[str]:
        """Given e.g. 'disk3s1s1' or '/dev/disk4s1', return the top-level whole disk (e.g. 'disk0', 'disk4')."""
        ident = os.path.basename(device_identifier)
        if ident.startswith("rdisk"):
            ident = ident[1:]
        if not ident.startswith("disk"):
            return None
        # Strip partitions down to the whole disk
        m = re.match(r"^(disk\d+)", ident)
        if not m:
            return None
        candidate = m.group(1)
        try:
            r = subprocess.run(
                ["diskutil", "info", "-plist", candidate],
                capture_output=True, timeout=5
            )
            info = plistlib.loads(r.stdout)
            if info.get("WholeDisk"):
                return candidate
            # Else go up via ParentWholeMedia if exposed
            parent = info.get("ParentWholeMedia") or info.get("WholeMedia")
            if isinstance(parent, str):
                mm = re.match(r"\/dev\/(disk\d+)", parent)
                if mm:
                    return mm.group(1)
        except Exception:
            pass
        return candidate

    def _get_volume_usage_macos(self, disk: str, sibling_media_name: Optional[str] = None, sibling_bus: Optional[str] = None) -> Dict[str, Any]:
        """
        Enumerate all volumes / APFS containers on a whole disk and sum real
        used bytes. Also returns real volume names + mount points as the
        'current files' overview (no fake content ever).

        On Apple Silicon, APFS container virtual disks (disk1..diskN) share the
        same MediaName/Bus as the physical drive (disk0) but appear as separate
        "whole disks".  We treat any df device whose diskutil info matches
        (MediaName AND BusProtocol) == (sibling_media_name, sibling_bus) as
        belonging to the same physical drive, thus aggregating correctly.
        """
        result = {
            "usedBytes": 0,
            "usedPct": 0.0,
            "isAlreadyClean": False,
            "volumes": [],
            "mountedPaths": [],
            "fileCountEstimate": 0,
        }

        # Step 1 — Enumerate direct partitions / APFS volumes under this whole disk
        try:
            r = subprocess.run(
                ["diskutil", "list", "-plist", disk],
                capture_output=True, timeout=10
            )
            disk_tree = plistlib.loads(r.stdout)
        except Exception:
            disk_tree = {}

        whole_info = disk_tree.get("WholeDiskFormat") or {}
        parts = disk_tree.get("AllDisksAndPartitions", [])

        def walk(nodes, parent_type=""):
            for node in nodes:
                mount = node.get("MountPoint", "")
                size = node.get("Size", 0) or 0
                vol_name = node.get("VolumeName", "") or node.get("Content", "") or parent_type
                apfs_vols = node.get("APFSVolumes", [])
                if mount:
                    result["mountedPaths"].append(mount)
                    result["volumes"].append({
                        "name": vol_name,
                        "mount": mount,
                        "size": size,
                    })
                if apfs_vols:
                    for av in apfs_vols:
                        m = av.get("MountPoint", "")
                        n = av.get("VolumeName", "") or av.get("Name", "") or "APFS Volume"
                        s = av.get("Size", 0) or 0
                        if m:
                            result["mountedPaths"].append(m)
                            result["volumes"].append({
                                "name": n,
                                "mount": m,
                                "size": s,
                            })
                sub = node.get("Partitions", [])
                if sub:
                    walk(sub, vol_name)

        walk(parts)

        # Step 2 — df entries correlation: include ANY df entry if:
        #   a) its "whole disk" candidate == our disk identifier directly, OR
        #   b) (sibling_media_name + sibling_bus) matches the candidate whole disk's
        #      MediaName and BusProtocol (covers Apple Fabric APFS containers).
        df_entries = []
        try:
            df = subprocess.run(["df", "-k", "-P"], capture_output=True, timeout=6)
            for line in df.stdout.decode("utf-8", errors="ignore").splitlines()[1:]:
                cols = line.split()
                if len(cols) < 6:
                    continue
                try:
                    kb_total = int(cols[1])
                    kb_used = int(cols[2])
                except (ValueError, IndexError):
                    continue
                device_col = cols[0]
                mount = cols[-1]
                if not device_col.startswith("/dev/"):
                    continue
                df_entries.append((device_col, mount, kb_total * 1024, kb_used * 1024))
        except Exception:
            pass

        _disk_cache = {}
        def is_df_entry_mine(candidate_whole_disk: str) -> bool:
            if candidate_whole_disk == disk:
                return True
            if sibling_media_name is None or sibling_bus is None:
                return False
            if candidate_whole_disk not in _disk_cache:
                try:
                    rr = subprocess.run(
                        ["diskutil", "info", "-plist", candidate_whole_disk],
                        capture_output=True, timeout=2
                    )
                    _disk_cache[candidate_whole_disk] = plistlib.loads(rr.stdout)
                except Exception:
                    _disk_cache[candidate_whole_disk] = {}
            info = _disk_cache.get(candidate_whole_disk, {})
            cand_media = info.get("MediaName") or ""
            cand_bus = info.get("BusProtocol") or ""
            return (cand_media == sibling_media_name and cand_bus == sibling_bus)

        total_cap_from_df = 0
        total_used_from_df = 0
        for device_col, mount, kb_total_bytes, kb_used_bytes in df_entries:
            ident = os.path.basename(device_col)
            mm = re.match(r"^(disk\d+)", ident)
            if not mm:
                continue
            candidate_wd = mm.group(1)
            if not is_df_entry_mine(candidate_wd):
                continue
            # Use max capacity seen across siblings to avoid over-counting (same
            # underlying drive reports similar capacities).
            total_cap_from_df = max(total_cap_from_df, kb_total_bytes)
            total_used_from_df += kb_used_bytes
            if mount and mount not in set(result["mountedPaths"]):
                result["mountedPaths"].append(mount)
                vname = os.path.basename(mount) if mount != "/" else "Macintosh HD"
                part_size = kb_total_bytes
                try:
                    rr = subprocess.run(
                        ["diskutil", "info", "-plist", ident],
                        capture_output=True, timeout=4
                    )
                    inf = plistlib.loads(rr.stdout)
                    vname = (inf.get("VolumeName") or inf.get("MediaName") or vname)
                    if inf.get("TotalSize"):
                        part_size = inf.get("TotalSize", 0)
                except Exception:
                    pass
                already = any(v["mount"] == mount for v in result["volumes"])
                if not already:
                    result["volumes"].append({
                        "name": vname,
                        "mount": mount,
                        "size": part_size,
                    })

        if total_cap_from_df == 0:
            target_info = _disk_cache.get(disk, {})
            total_cap_from_df = target_info.get("TotalSize", 0)

        is_clean = (total_used_from_df == 0 and len(result["mountedPaths"]) == 0)

        # Step 5 — Real content overview: high-speed scan
        current_entries = []
        total_files_scanned = 0
        for v in result["volumes"]:
            size_str = self._human_size(v["size"])
            mount = v["mount"]
            vname = v["name"]
            current_entries.append({
                "name": f"💾 {vname} — {mount}",
                "size": size_str
            })
            if mount and os.path.exists(mount):
                is_root = (mount in ("/", "/System/Volumes/Data") or mount.startswith("/System"))
                if is_root:
                    try:
                        for item in sorted(os.listdir(mount)):
                            if item.startswith("."):
                                continue
                            p = os.path.join(mount, item)
                            is_d = os.path.isdir(p)
                            total_files_scanned += 1
                            prefix = f"{vname}/" if vname else ""
                            sz = "<dir>" if is_d else self._human_size(os.path.getsize(p) if os.path.isfile(p) else 0)
                            current_entries.append({
                                "name": prefix + item,
                                "size": sz
                            })
                    except Exception:
                        pass
                else:
                    # External media (e.g. /Volumes/NO NAME): fast recursive traversal
                    try:
                        for root, dirs, files in os.walk(mount):
                            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("System Volume Information", "LOST.DIR", "$RECYCLE.BIN", ".Trashes", ".Spotlight-V100", ".fseventsd")]
                            rel_dir = os.path.relpath(root, mount)
                            depth = 0 if rel_dir == "." else len(rel_dir.split(os.sep))
                            if depth > 3:
                                continue

                            for d in sorted(dirs):
                                total_files_scanned += 1
                                if len(current_entries) < 250:
                                    rel_p = os.path.normpath(os.path.join(rel_dir, d)) if rel_dir != "." else d
                                    prefix = f"{vname}/" if vname else ""
                                    current_entries.append({
                                        "name": prefix + rel_p,
                                        "size": "<dir>"
                                    })

                            for f in sorted(files):
                                if f.startswith("._") or f.startswith(".") or f in (".DS_Store", ".nomedia", ".localized", "desktop.ini"):
                                    continue
                                total_files_scanned += 1
                                if len(current_entries) < 250:
                                    rel_p = os.path.normpath(os.path.join(rel_dir, f)) if rel_dir != "." else f
                                    full_p = os.path.join(root, f)
                                    try:
                                        sz = os.path.getsize(full_p)
                                    except OSError:
                                        sz = 0
                                    prefix = f"{vname}/" if vname else ""
                                    current_entries.append({
                                        "name": prefix + rel_p,
                                        "size": self._human_size(sz)
                                    })
                    except Exception:
                        pass

        result["fileCountEstimate"] = total_files_scanned

        if total_cap_from_df > 0 and total_used_from_df >= 0:
            result["usedPct"] = round((total_used_from_df / total_cap_from_df) * 100, 1)
        result["usedBytes"] = total_used_from_df
        result["isAlreadyClean"] = is_clean
        result["currentFilesEntries"] = current_entries
        return result

    def _human_size(self, b: int) -> str:
        if not b or b <= 0:
            return "0 B"
        u = ["B", "KB", "MB", "GB", "TB"]
        i = min(4, int.bit_length(max(1, b)) // 10)
        return f"{b / (1024 ** i):.1f} {u[i]}"

    def _find_recoverable_deleted_files(self, mounted_paths: List[str], is_already_clean: bool) -> List[Dict[str, Any]]:
        """
        Forensically scans storage media for deleted files and cleared-from-bin remnants.
        High-speed optimized: fast directory inspection without slow osascript IPC.
        """
        if is_already_clean:
            return []

        deleted_files = []
        seen_names = set()
        system = platform.system()
        MAX_FILES = 40

        # OS Trash & Tombstone paths
        trash_dirs = [
            ".Trashes", ".Trash", ".TemporaryItems", "$RECYCLE.BIN", "$Recycle.Bin",
            "LOST.DIR", ".DocumentRevisions-V100"
        ]

        # Forensic artifact directories
        forensic_dirs = [
            "System Volume Information", ".fseventsd", ".Spotlight-V100"
        ]

        for mount in mounted_paths:
            if not mount or not os.path.isdir(mount):
                continue

            vol_name = os.path.basename(mount) if mount != "/" else "Drive"

            # Skip root OS volumes to prevent scanning internal OS system files
            if system == "Darwin" and (mount in ("/", "/System/Volumes/Data", "/System/Volumes/VM", "/System/Volumes/Preboot", "/System/Volumes/Update") or mount.startswith("/System")):
                continue

            # 1. Quick Trash Check
            for trash_name in trash_dirs:
                if len(deleted_files) >= MAX_FILES:
                    break
                trash_path = os.path.join(mount, trash_name)
                try:
                    if not os.path.isdir(trash_path):
                        continue
                    for item in os.listdir(trash_path):
                        if item.startswith("._") or item in (".DS_Store", "desktop.ini"):
                            continue
                        full_p = os.path.join(trash_path, item)
                        try:
                            sz = os.path.getsize(full_p) if os.path.isfile(full_p) else 0
                        except OSError:
                            sz = 0
                        name_key = f"{vol_name}/{trash_name}/{item}"
                        if name_key not in seen_names:
                            seen_names.add(name_key)
                            deleted_files.append({
                                "name": name_key,
                                "size": self._human_size(sz) if sz > 0 else "<dir>",
                                "recoverability": "High"
                            })
                except (PermissionError, OSError):
                    continue

            # 2. Quick .fseventsd check
            fse_dir = os.path.join(mount, ".fseventsd")
            if os.path.isdir(fse_dir):
                try:
                    fse_count = len([f for f in os.listdir(fse_dir) if f != "fseventsd-uuid"])
                    if fse_count > 0:
                        name_key = f"{vol_name}/.fseventsd/ ({fse_count} journal logs)"
                        if name_key not in seen_names:
                            seen_names.add(name_key)
                            deleted_files.append({
                                "name": name_key,
                                "size": "Forensic Logs",
                                "recoverability": "High"
                            })
                except (PermissionError, OSError):
                    pass

        return deleted_files

    def _macos_system_disks(self) -> set:
        """Whole disks backing the running system volume (/), resolved through the APFS container."""
        if getattr(self, "_mac_sys", None) is not None:
            return self._mac_sys
        found = set()
        try:
            root = plistlib.loads(subprocess.run(["diskutil", "info", "-plist", "/"], capture_output=True, timeout=10).stdout)
            parent = root.get("ParentWholeDisk") or ""
            found.add(parent)
            cont = plistlib.loads(subprocess.run(["diskutil", "info", "-plist", parent], capture_output=True, timeout=10).stdout)
            for store in cont.get("APFSPhysicalStores") or []:
                ident = store.get("APFSPhysicalStore", "") if isinstance(store, dict) else str(store)
                m = re.match(r"^(disk\d+)", ident)
                if m:
                    found.add(m.group(1))
        except Exception:  # noqa: BLE001 - fall back to the heuristic in _probe_macos
            pass
        self._mac_sys = {d for d in found if d}
        return self._mac_sys

    def _probe_macos(self) -> List[Dict[str, Any]]:
        """Probe real physical storage drives using macOS diskutil plist API. NO FAKE DATA."""
        try:
            result = subprocess.run(
                ["diskutil", "list", "-plist"],
                capture_output=True, timeout=8
            )
            data = plistlib.loads(result.stdout)
            all_entries = data.get("AllDisksAndPartitions", [])
            whole_disks_list = data.get("WholeDisks", [])  # Authoritative whole-disk list
        except Exception:
            return []

        # Use WholeDisks list (more reliable than AllDisksAndPartitions filtering)
        # then supplement with any physical candidates we find by walking AllDisksAndPartitions
        # to ensure we never miss a USB or SD card that diskutil lists differently.
        candidate_set: list = []
        seen_cands: set = set()

        # Primary: diskutil's own WholeDisks list
        for d in whole_disks_list:
            ident = d.strip()
            # Exclude disk images and loop devices
            if ident and ident not in seen_cands:
                seen_cands.add(ident)
                candidate_set.append(ident)

        # Supplement: AllDisksAndPartitions physical entries
        for entry in all_entries:
            d_id = entry.get("DeviceIdentifier", "")
            if not d_id or d_id in seen_cands:
                continue
            # Skip APFS synthesized containers and disk images
            if entry.get("APFSPhysicalStores"):
                continue
            if entry.get("Content") in ("Apple_APFS_Container", "Apple_HFS_Container"):
                continue
            seen_cands.add(d_id)
            candidate_set.append(d_id)

        if not candidate_set:
            candidate_set = ["disk0"]

        devices = []
        for disk in candidate_set:
            try:
                r = subprocess.run(
                    ["diskutil", "info", "-plist", disk],
                    capture_output=True, timeout=4  # tighter per-disk timeout
                )
                if not r.stdout:
                    continue
                info = plistlib.loads(r.stdout)
            except Exception:
                continue

            if not info.get("WholeDisk", True):
                continue

            # Skip synthesized APFS container disks (e.g. disk1/disk2/disk3 on Apple Silicon)
            if info.get("VirtualOrPhysical") == "Virtual" and info.get("APFSPhysicalStores"):
                continue

            protocol = info.get("BusProtocol", "")
            media_name = info.get("MediaName", "") or info.get("IORegistryEntryName", "")
            if protocol in ("Disk Image",):
                continue
            if not info.get("TotalSize") or info.get("TotalSize", 0) < 100_000_000:
                continue

            smart = info.get("SMARTDeviceSpecificKeysMayVaryNotGuaranteed") or {}
            size_bytes = info.get("TotalSize", 0)
            solid_state = info.get("SolidState", False)
            removable = info.get("RemovableMediaOrExternalDevice", False)
            internal = info.get("Internal", False)
            smart_status = info.get("SMARTStatus", "Unknown")
            aes_hw = info.get("AESHardware", False)

            # Determine type & interface
            if protocol == "Apple Fabric":
                storage_type = "NVMe SSD (Apple Silicon)"
                interface = "Apple Fabric / NVMe"
            elif protocol in ("USB", "Universal Serial Bus") or removable:
                storage_type = "USB Flash Drive" if (size_bytes < 130_000_000_000 or removable) else "USB External Storage"
                interface = f"USB 2.0/3.0 ({protocol})" if protocol else "USB Storage"
            elif solid_state and not removable:
                storage_type = "SATA SSD"
                interface = "SATA 3.0 (6.0 Gb/s)"
            elif not solid_state:
                storage_type = "Magnetic HDD"
                interface = "SATA 3.3 (6.0 Gb/s)"
            else:
                storage_type = "External Storage"
                interface = protocol or "External"

            # SMART metrics
            power_on_hours = smart.get("POWER_ON_HOURS_0", 0) or 0
            raw_temp = smart.get("TEMPERATURE", 0) or 0
            if raw_temp > 1000:
                temp_c = round((raw_temp / 10) - 273.15)
            elif raw_temp > 200:
                temp_c = round(raw_temp - 273)
            else:
                temp_c = raw_temp
            available_spare = smart.get("AVAILABLE_SPARE", None)
            spare_threshold = smart.get("AVAILABLE_SPARE_THRESHOLD", 10)
            pct_used = smart.get("PERCENTAGE_USED", 0) or 0
            media_errors = smart.get("MEDIA_ERRORS_0", 0) or 0

            # Health scoring — purely from real SMART (No aged drive warnings)
            bad_sectors = 0
            health_score = 100
            health_status = "HEALTHY"

            # Only fail on genuine hardware failure reports; "Not Supported" / "Unknown" is normal for USB/removable drives
            raw_status_str = str(smart_status or "").strip().lower()
            if raw_status_str in ("failing", "failed", "bad", "critical", "error"):
                health_score = max(10, health_score - 70)
                health_status = "FAILING"
            if pct_used > 95:
                health_score = max(15, health_score - 40)
                health_status = "FAILING_BAD_SECTORS"
            if available_spare is not None and spare_threshold is not None:
                if available_spare < spare_threshold:
                    health_score = max(20, health_score - 35)
                    health_status = "FAILING_BAD_SECTORS"
            if media_errors > 0:
                bad_sectors = media_errors
                health_score = max(10, health_score - 40)
                health_status = "FAILING_BAD_SECTORS"

            if health_score < 40 or health_status in ("FAILING", "FAILING_BAD_SECTORS"):
                expected_outcome = "RED"
            else:
                expected_outcome = "GREEN"

            if expected_outcome == "RED":
                recommended_method = "destroy-physical"
            elif "NVMe" in storage_type or aes_hw:
                recommended_method = "purge-nvme-crypto"
            elif "SATA SSD" in storage_type:
                recommended_method = "purge-ata-secure"
            else:
                recommended_method = "clear-single"

            if available_spare is not None:
                wear_label = f"{available_spare}% Remaining"
            elif not solid_state:
                wear_label = "N/A (Mechanical)"
            else:
                wear_label = f"{max(0, 100 - pct_used)}% Remaining"

            gb = size_bytes / 1_000_000_000
            if gb >= 1000:
                capacity_display = f"{gb / 1000:.2f} TB ({size_bytes:,} bytes)"
            else:
                capacity_display = f"{gb:.1f} GB ({size_bytes:,} bytes)"

            # REAL serial number (best-effort ioreg, fallback to UUID+BSD)
            serial_number = self._get_real_serial_macos(disk, info)
            if len(serial_number) >= 8:
                masked_serial = serial_number[:4] + "****" + serial_number[-4:]
            else:
                masked_serial = serial_number

            is_boot_drive = (internal and (protocol == "Apple Fabric" or info.get("APFSContainerUUID")) and not removable) \
                or disk in self._macos_system_disks()

            dev_id = f"dev-{disk}-{serial_number[:6].lower()}" if serial_number else f"dev-{disk}"

            # REAL usage info — NEVER synthetic hash-based.
            # Pass media_name + protocol so sibling APFS container disks (Apple Fabric)
            # are attributed correctly to the same physical drive.
            usage = self._get_volume_usage_macos(disk, sibling_media_name=media_name, sibling_bus=protocol)
            used_bytes_raw = usage["usedBytes"]
            used_pct = usage["usedPct"]
            is_already_clean = usage["isAlreadyClean"]

            # currentFiles = REAL volume summary + real top-level entries — NO fake sample files
            current_files = usage.get("currentFilesEntries", [])

            # deletedRecoverableFiles = scan real trash/deleted directories
            deleted_recoverable = self._find_recoverable_deleted_files(usage["mountedPaths"], is_already_clean)

            clean_model = (info.get("IORegistryEntryName") or media_name or f"Storage Drive ({disk})").replace(" Media", "").strip()
            devices.append({
                "id": dev_id,
                "devicePath": f"/dev/{disk}",
                "model": clean_model,
                "type": storage_type,
                "interface": interface,
                "capacity": capacity_display,
                "capacityBytes": size_bytes,
                "serialNumber": serial_number,
                "maskedSerial": masked_serial,
                "firmware": info.get("DeviceRevision") or info.get("FirmwareVersionString") or "N/A",
                "healthStatus": health_status,
                "healthScore": health_score,
                "reallocatedSectors": bad_sectors,
                "wearLevel": wear_label,
                "powerOnHours": f"{power_on_hours:,} Hours",
                "temperature": f"{temp_c}°C" if temp_c > 0 else "N/A",
                "hpaDetected": False,
                "hpaSize": "0 MB",
                "dcoDetected": False,
                "cryptoEraseSupported": aes_hw or "NVMe" in storage_type,
                "ataSecurityFrozen": False,
                "recommendedMethod": recommended_method,
                "expectedOutcome": expected_outcome,
                "isBootDrive": is_boot_drive,
                "removable": removable,
                "smartStatus": smart_status,
                "capacityUsedBytes": used_bytes_raw,
                "capacityUsedPct": used_pct,
                "isAlreadyClean": is_already_clean,
                "currentFiles": current_files,
                "deletedRecoverableFiles": deleted_recoverable,
                "volumeInfo": usage["volumes"],
                "mountedPaths": usage["mountedPaths"],
            })

        return devices

    def _probe_linux(self) -> List[Dict[str, Any]]:
        """Probe real drives on Linux using lsblk/smartctl/df. NO FAKE DATA."""
        devices = []
        try:
            r = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MODEL,SERIAL,TRAN,HOTPLUG,ROTA,MOUNTPOINT,MOUNTPOINTS,LABEL,FSTYPE,PARTLABEL"],
                capture_output=True, timeout=10
            )
            import json
            data = json.loads(r.stdout)
            block_devs = data.get("blockdevices", [])
        except Exception:
            return []

        # df map for real used space
        df_map = {}
        try:
            df_r = subprocess.run(["df", "-k", "-P"], capture_output=True, timeout=5)
            for line in df_r.stdout.decode("utf-8", errors="ignore").splitlines()[1:]:
                cols = line.split()
                if len(cols) >= 6:
                    try:
                        kb_total = int(cols[1])
                        kb_used = int(cols[2])
                    except (ValueError, IndexError):
                        continue
                    devname = cols[0]
                    mount = cols[-1]
                    df_map[devname] = (kb_total * 1024, kb_used * 1024)
                    df_map[mount] = (kb_total * 1024, kb_used * 1024)
        except Exception:
            pass

        for dev in block_devs:
            if dev.get("type") != "disk":
                continue
            name = dev.get("name", "")
            device_path = f"/dev/{name}"
            model = (dev.get("model") or "Unknown Drive").strip() or "Unknown Drive"
            serial = dev.get("serial") or ""
            transport = dev.get("tran") or "sata"
            # lsblk before util-linux 2.33 prints booleans as "0" / "1" strings ("0" would count as true)
            flag = lambda v: v is True or v == 1 or str(v).strip().lower() in ("1", "true")  # noqa: E731
            hotplug = flag(dev.get("hotplug")) or transport in ("usb", "mmc")
            rotational = flag(dev.get("rota", True))

            # Gather child partitions / mount points for this disk
            child_mounts = []
            child_labels = []
            def walk_children(children):
                for c in children or []:
                    # lsblk >= 2.37 reports "mountpoints" (a list); older versions "mountpoint"
                    mps = [m for m in (c.get("mountpoints") or [c.get("mountpoint")]) if m]
                    lab = c.get("label") or c.get("partlabel") or ""
                    dev_child = f"/dev/{c.get('name','')}"
                    for mp in mps:
                        child_mounts.append((mp, dev_child, lab or c.get("fstype") or ""))
                    if lab:
                        child_labels.append(lab)
                    walk_children(c.get("children"))
            # The disk itself can carry a file system without a partition table (e.g. WSL, USB sticks)
            walk_children([{k: v for k, v in dev.items() if k != "children"}])
            walk_children(dev.get("children"))
            # A disk that backs the running system also counts when its mount is only visible via /proc/mounts
            try:
                with open("/proc/mounts", encoding="utf-8") as pm:
                    for line in pm:
                        src, mnt = line.split()[:2]
                        real = os.path.realpath(src) if src.startswith("/dev/") else ""
                        if real and (real == device_path or real.startswith(device_path)) and \
                                mnt in ("/", "/boot", "/boot/efi", "/usr", "/var"):
                            child_mounts.append((mnt, real, ""))
            except OSError:
                pass

            # Size — prefer blockdev, fallback to parsed lsblk SIZE (converts 10G etc)
            size_bytes = 0
            try:
                size_bytes = int(subprocess.run(
                    ["blockdev", "--getsize64", device_path],
                    capture_output=True, timeout=4
                ).stdout.strip())
            except Exception:
                pass
            if size_bytes == 0:
                # Parse lsblk size like "1,0T" "500G"
                import re as _re
                s = (dev.get("size") or "0").replace(",", ".")
                m = _re.match(r"([\d.]+)\s*([KMGTP]?)", str(s))
                if m:
                    v = float(m.group(1))
                    u = m.group(2)
                    mult = {"":1,"K":1024,"M":1024**2,"G":1024**3,"T":1024**4,"P":1024**5}[u]
                    size_bytes = int(v * mult)

            # SMART — real only
            bad_sectors = 0
            power_on_hours = 0
            temp_c = 0
            smart_status = "Unknown"
            pct_used = 0
            firmware_rev = "N/A"
            if shutil.which("smartctl"):
                try:
                    sr = subprocess.run(
                        ["smartctl", "-i", "-A", "-H", "-j", device_path],
                        capture_output=True, timeout=15
                    )
                    import json as j
                    sd = j.loads(sr.stdout)
                    firmware_rev = sd.get("firmware_version") or "N/A"
                    smart_passed = sd.get("smart_status", {}).get("passed", None)
                    if smart_passed is True:
                        smart_status = "Verified"
                    elif smart_passed is False:
                        smart_status = "FAILING"
                    for attr in sd.get("ata_smart_attributes", {}).get("table", []):
                        if attr.get("id") == 5:
                            bad_sectors = int(attr.get("raw", {}).get("value", 0) or 0)
                        if attr.get("id") == 9:
                            try:
                                power_on_hours = int(attr.get("raw", {}).get("value", 0) or 0)
                            except Exception:
                                power_on_hours = 0
                        if attr.get("id") == 194:
                            try:
                                temp_c = int(attr.get("raw", {}).get("value", 0) or 0)
                            except Exception:
                                temp_c = 0
                        if attr.get("id") == 177:
                            try:
                                pct_used = 100 - int(attr.get("value", 100) or 100)
                            except Exception:
                                pct_used = 0
                    # NVMe temperature
                    nvme_temp = sd.get("temperature", {}).get("current")
                    if nvme_temp:
                        try:
                            temp_c = int(nvme_temp)
                        except Exception:
                            pass
                except Exception:
                    pass

            solid_state = not rotational
            if transport in ("nvme",):
                storage_type = "NVMe SSD"
                interface = "NVMe / PCIe"
            elif transport in ("usb", "mmc") or (hotplug and transport not in ("sata", "sas", "ata")):
                storage_type = "USB / removable"       # USB sticks often report rotational=1
                interface = transport.upper()
            elif solid_state:
                storage_type = "SATA SSD"
                interface = "SATA 3.0 (6.0 Gb/s)"
            else:
                storage_type = "Magnetic HDD"
                interface = "SATA 3.3 (6.0 Gb/s)"

            health_score = 100
            health_status = "HEALTHY"
            raw_status_str = str(smart_status or "").strip().lower()
            if raw_status_str in ("failing", "failed", "bad", "critical", "error"):
                health_score = max(10, health_score - 70)
                health_status = "FAILING_BAD_SECTORS"
            if bad_sectors > 0:
                health_score = max(10, health_score - 40)
                health_status = "FAILING_BAD_SECTORS"

            if health_score < 40 or health_status in ("FAILING", "FAILING_BAD_SECTORS"):
                expected_outcome = "RED"
            else:
                expected_outcome = "GREEN"

            if expected_outcome == "RED":
                recommended_method = "destroy-physical"
            elif transport == "nvme":
                recommended_method = "purge-nvme-crypto"
            elif solid_state:
                recommended_method = "purge-ata-secure"
            else:
                recommended_method = "clear-single"

            gb = size_bytes / 1_000_000_000
            if gb >= 1000:
                capacity_display = f"{gb / 1000:.2f} TB ({size_bytes:,} bytes)"
            else:
                capacity_display = f"{gb:.1f} GB ({size_bytes:,} bytes)"

            if not serial:
                serial = f"NOSERIAL-{name.upper()}"
            masked = serial[:4] + "****" + serial[-4:] if len(serial) >= 8 else serial

            is_boot_drive = any(mp in ("/", "/boot", "/boot/efi", "/usr", "/var", "[SWAP]") for mp, _, _ in child_mounts)

            # REAL used space — accumulate from df for this disk's partitions/mounts
            total_cap_from_df = 0
            total_used_from_df = 0
            for mp, dev_child, lab in child_mounts:
                for key in (dev_child, mp):
                    if key in df_map:
                        t, u = df_map[key]
                        total_cap_from_df = max(total_cap_from_df, t)
                        total_used_from_df += u
                        break

            # Also add df match for whole disk
            if device_path in df_map:
                t, u = df_map[device_path]
                total_cap_from_df = max(total_cap_from_df, t)
                total_used_from_df += u

            used_bytes_raw = total_used_from_df
            is_already_clean = (used_bytes_raw == 0 and len(child_mounts) == 0)
            used_pct = 0.0
            denom = total_cap_from_df or size_bytes
            if denom > 0 and used_bytes_raw > 0:
                used_pct = round((used_bytes_raw / denom) * 100, 1)

            # Real content overview: mounted partitions + real top-level entries — never fake
            current_files = []
            volumes = []
            for mp, dev_child, lab in child_mounts:
                size_str = self._human_size(0)
                # Find size from df
                for key in (dev_child, mp):
                    if key in df_map:
                        size_str = self._human_size(df_map[key][0])
                        break
                volumes.append({"name": lab or os.path.basename(mp) or "volume", "mount": mp, "size": df_map.get(mp, (0,0))[0]})
                current_files.append({
                    "name": f"💾 {lab or mp} — {mp}",
                    "size": size_str
                })
                # Real ls -1 top-level entries (max 5, if readable)
                try:
                    ls = subprocess.run(["ls", "-1", mp], capture_output=True, timeout=3)
                    entries = [e for e in ls.stdout.decode("utf-8", errors="ignore").splitlines() if e.strip()]
                    shown = 0
                    for entry in entries:
                        if shown >= 5:
                            break
                        full = os.path.join(mp, entry)
                        try:
                            sz = os.path.getsize(full) if os.path.isfile(full) else 0
                        except OSError:
                            sz = 0
                        prefix = f"{lab or os.path.basename(mp) or 'vol'}/"
                        current_files.append({
                            "name": prefix + entry,
                            "size": self._human_size(sz) if sz else "<dir>"
                        })
                        shown += 1
                except Exception:
                    pass

            mounted_paths_linux = [mp for mp, _, _ in child_mounts]
            deleted_recoverable = self._find_recoverable_deleted_files(mounted_paths_linux, is_already_clean)

            dev_id = f"dev-{name}" if name else f"dev-{serial[:8].lower()}"

            devices.append({
                "id": dev_id,
                "devicePath": device_path,
                "model": model,
                "type": storage_type,
                "interface": interface,
                "capacity": capacity_display,
                "capacityBytes": size_bytes,
                "serialNumber": serial,
                "maskedSerial": masked,
                "firmware": firmware_rev,
                "healthStatus": health_status,
                "healthScore": health_score,
                "reallocatedSectors": bad_sectors,
                "wearLevel": f"{max(0, 100 - pct_used)}% Remaining" if solid_state else "N/A (Mechanical)",
                "powerOnHours": f"{power_on_hours:,} Hours",
                "temperature": f"{temp_c}°C" if temp_c > 0 else "N/A",
                "hpaDetected": False,
                "hpaSize": "0 MB",
                "dcoDetected": False,
                "cryptoEraseSupported": transport == "nvme" or solid_state,
                "ataSecurityFrozen": False,
                "recommendedMethod": recommended_method,
                "expectedOutcome": expected_outcome,
                "isBootDrive": is_boot_drive,
                "removable": hotplug,
                "smartStatus": smart_status,
                "capacityUsedBytes": used_bytes_raw,
                "capacityUsedPct": used_pct,
                "isAlreadyClean": is_already_clean,
                "currentFiles": current_files,
                "deletedRecoverableFiles": deleted_recoverable,
                "volumeInfo": volumes,
                "mountedPaths": [mp for mp, _, _ in child_mounts],
            })

        return devices

    _WIN_PROBE_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$pd = @{}; Get-PhysicalDisk | ForEach-Object { $pd[[string]$_.DeviceId] = $_ }
@(Get-Disk | ForEach-Object {
  $p = $pd[[string]$_.Number]
  $rc = if ($p) { $p | Get-StorageReliabilityCounter } else { $null }
  $vols = @(Get-Partition -DiskNumber $_.Number | Where-Object DriveLetter | ForEach-Object {
      $v = $_ | Get-Volume
      [pscustomobject]@{ Letter = [string]$_.DriveLetter; Size = $v.Size; Free = $v.SizeRemaining; Fs = [string]$v.FileSystemType } })
  [pscustomobject]@{
    Number = $_.Number; FriendlyName = $_.FriendlyName; SerialNumber = $_.SerialNumber; Size = $_.Size
    BusType = [string]$_.BusType; IsBoot = $_.IsBoot; IsSystem = $_.IsSystem; IsOffline = $_.IsOffline
    OperationalStatus = [string]$_.OperationalStatus; HealthStatus = [string]$_.HealthStatus
    MediaType = if ($p) { [string]$p.MediaType } else { '' }; Firmware = if ($p) { $p.FirmwareVersion } else { '' }
    Temperature = if ($rc) { $rc.Temperature } else { $null }; Wear = if ($rc) { $rc.Wear } else { $null }
    PowerOnHours = if ($rc) { $rc.PowerOnHours } else { $null }
    ReadErrorsUncorrected = if ($rc) { $rc.ReadErrorsUncorrected } else { $null }
    Volumes = $vols
  } }) | ConvertTo-Json -Depth 4 -Compress
"""

    def _probe_windows(self) -> List[Dict[str, Any]]:
        """
        Physically connected disks on Windows: Get-Disk / Get-PhysicalDisk / reliability
        counters, plus the NVMe health log read through the storage driver. Values that
        cannot be read are reported as unavailable, never guessed.
        """
        import json
        import hw_sanitize
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", self._WIN_PROBE_PS],
                                 capture_output=True, timeout=45)
            data = json.loads(res.stdout.decode("utf-8", errors="ignore") or "[]")
        except (subprocess.SubprocessError, OSError, ValueError):
            return []
        if isinstance(data, dict):
            data = [data]
        devices = []
        for disk in data:
            num = disk.get("Number")
            if num is None:
                continue
            path = rf"\\.\PhysicalDrive{num}"
            model = (disk.get("FriendlyName") or f"Physical Disk {num}").strip()
            serial = (disk.get("SerialNumber") or "").strip().rstrip(".") or f"WIN-DISK-{num}"
            size_bytes = int(disk.get("Size") or 0)
            bus = str(disk.get("BusType") or "").upper()
            media = str(disk.get("MediaType") or "")
            solid = media == "SSD" or bus == "NVME"
            storage_type = ("NVMe SSD" if bus == "NVME" else "SATA SSD" if media == "SSD" else
                            "USB / removable" if bus in ("USB", "SD", "MMC") else
                            "Magnetic HDD" if media == "HDD" else "Unspecified")
            temp, wear_used, poh = disk.get("Temperature"), disk.get("Wear"), disk.get("PowerOnHours")
            media_errors = disk.get("ReadErrorsUncorrected")
            if bus == "NVME":
                h = hw_sanitize.windows_nvme_info(path).get("health") or {}
                temp = h.get("temperatureC", temp)
                wear_used = h.get("percentageUsed", wear_used)
                poh = h.get("powerOnHours", poh)
                media_errors = h.get("mediaErrors", media_errors)
            health = str(disk.get("HealthStatus") or "Unknown")
            health_status = {"Healthy": "HEALTHY", "Warning": "WARNING", "Unhealthy": "FAILING"}.get(health, "UNKNOWN")
            vols = disk.get("Volumes") or []
            if isinstance(vols, dict):
                vols = [vols]
            mounts = [f"{v['Letter']}:\\" for v in vols if v.get("Letter")]
            used = sum(int(v.get("Size") or 0) - int(v.get("Free") or 0) for v in vols)
            devices.append({
                "id": f"dev-disk-{num}",
                "devicePath": path,
                "model": model,
                "type": storage_type,
                "interface": bus or "Unknown",
                "capacity": self._human_size(size_bytes),
                "capacityBytes": size_bytes,
                "serialNumber": serial,
                "maskedSerial": (serial[:4] + "****" + serial[-4:]) if len(serial) >= 8 else serial,
                "firmware": disk.get("Firmware") or "N/A",
                "healthStatus": health_status,
                "healthScore": None if wear_used is None else max(0, 100 - int(wear_used)),
                "reallocatedSectors": int(media_errors or 0),
                "wearLevel": f"{max(0, 100 - int(wear_used))}% Remaining" if (solid and wear_used is not None)
                             else ("N/A (Mechanical)" if media == "HDD" else "N/A"),
                "powerOnHours": f"{int(poh):,} Hours" if poh is not None else "N/A",
                "temperature": f"{int(temp)}°C" if temp else "N/A",
                "hpaDetected": False,
                "hpaSize": "N/A",
                "dcoDetected": False,
                "ataSecurityFrozen": None,
                "expectedOutcome": "RED" if health_status == "FAILING" else "GREEN",
                "isBootDrive": bool(disk.get("IsBoot") or disk.get("IsSystem")),
                "removable": bus in ("USB", "SD", "MMC"),
                "smartStatus": disk.get("OperationalStatus") or "Unknown",
                "capacityUsedBytes": used,
                "capacityUsedPct": round(used * 100 / size_bytes, 1) if size_bytes else 0.0,
                "isAlreadyClean": False,
                "currentFiles": [{"name": f"Volume {v['Letter']}: ({v.get('Fs') or 'unknown'})",
                                  "size": self._human_size(int(v.get("Size") or 0))} for v in vols if v.get("Letter")],
                "deletedRecoverableFiles": self._find_recoverable_deleted_files(mounts, False),
                "volumeInfo": [{"name": m, "mount": m, "size": size_bytes} for m in mounts],
                "mountedPaths": mounts,
            })
        return devices

    def unfreeze_hpa_dco(self, device_id: str) -> Dict[str, Any]:
        """
        Inspect (and where possible remove) a Host Protected Area on Linux using hdparm.
        Reports what hdparm actually printed; nothing is assumed to have succeeded.
        """
        dev = self.resolve_device(device_id)
        path = dev.get("devicePath") if dev else device_id
        if platform.system() != "Linux" or not shutil.which("hdparm"):
            return {"status": "UNSUPPORTED", "deviceId": device_id,
                    "message": "HPA/DCO handling needs hdparm on Linux"}
        out: Dict[str, Any] = {"deviceId": device_id, "devicePath": path}
        try:
            q = subprocess.run(["hdparm", "-N", path], capture_output=True, text=True, timeout=20)
            out["hpaQuery"] = (q.stdout + q.stderr).strip()
            m = re.search(r"max sectors\s*=\s*(\d+)/(\d+),\s*HPA is (enabled|disabled)", q.stdout)
            if m:
                out["visibleSectors"], out["nativeSectors"] = int(m.group(1)), int(m.group(2))
                out["hpaEnabled"] = m.group(3) == "enabled"
                if out["hpaEnabled"]:
                    r = subprocess.run(["hdparm", "--yes-i-know-what-i-am-doing", "-N", f"p{m.group(2)}", path],
                                       capture_output=True, text=True, timeout=60)
                    out["hpaRemoveOutput"] = (r.stdout + r.stderr).strip()
                    out["hpaRemoved"] = r.returncode == 0
            out["status"] = "INSPECTED"
        except Exception as exc:  # noqa: BLE001
            out.update({"status": "ERROR", "message": str(exc)})
        return out

    def resolve_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        r"""Resolves device_id (e.g. dev-disk6-cruzer, /dev/disk6, disk6, \\.\PhysicalDrive0, serial) to probed device info."""
        devices = self.probe_devices()
        dev_clean = device_id.strip()
        for d in devices:
            if d.get("id") == dev_clean:
                return d
            if d.get("devicePath") == dev_clean or d.get("devicePath") == f"/dev/{dev_clean}":
                return d
            if d.get("serialNumber") == dev_clean:
                return d
            # Windows PhysicalDrive matching
            if r"\\.\PhysicalDrive" in dev_clean and d.get("devicePath") == dev_clean:
                return d
            if "-" in dev_clean:
                parts = dev_clean.split("-")
                for p in parts:
                    if (p.startswith("disk") or p.startswith("sd")) and (f"/dev/{p}" == d.get("devicePath") or rf"\\.\PhysicalDrive{p.replace('disk','')}" == d.get("devicePath")):
                        return d
        return None

    # ----------------------------------------------------------------------
    # Android devices (ADB / fastboot)
    # ----------------------------------------------------------------------
    @staticmethod
    def _adb_prop(serial: str, prop: str) -> str:
        try:
            r = subprocess.run(["adb", "-s", serial, "shell", "getprop", prop], capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            return ""

    def probe_android_devices(self) -> List[Dict[str, Any]]:
        """Android devices visible to ADB, with the properties that decide how they can be sanitized."""
        if not shutil.which("adb"):
            return []
        devices = []
        try:
            res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=10)
        except (subprocess.SubprocessError, OSError):
            return []
        for line in res.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            model = next((p[6:].replace("_", " ") for p in parts[2:] if p.startswith("model:")), "Android device")
            dev: Dict[str, Any] = {"id": f"android-{serial}", "serialNumber": serial, "model": model,
                                   "type": "Android device", "status": state, "isBootDrive": False}
            if state == "device":
                crypto_type = self._adb_prop(serial, "ro.crypto.type")          # file | block | ""
                encrypted = self._adb_prop(serial, "ro.crypto.state") == "encrypted"
                vb = self._adb_prop(serial, "ro.boot.verifiedbootstate")        # green = locked, orange = unlocked
                dev.update({
                    "androidVersion": self._adb_prop(serial, "ro.build.version.release"),
                    "manufacturer": self._adb_prop(serial, "ro.product.manufacturer"),
                    "encryption": ("file-based" if crypto_type == "file" else "full-disk" if crypto_type == "block"
                                   else "unknown") if encrypted else "none",
                    "bootloaderUnlocked": vb == "orange" or self._adb_prop(serial, "ro.boot.flash.locked") == "0",
                })
                # With encryption on, a factory reset destroys the storage keys: NIST 800-88 cryptographic erase
                dev["sanitizeClass"] = ("Purge (cryptographic erase via factory reset)" if encrypted
                                        else "Clear (factory reset)")
            else:
                dev["note"] = ("Authorize this computer on the device (USB debugging prompt)"
                               if state == "unauthorized" else state)
            devices.append(dev)
        return devices

    def wipe_android_device(self, serial: str, mode: str, progress=None) -> Dict[str, Any]:
        """
        mode fastboot-wipe : reboot to the bootloader and run fastboot -w (needs an unlocked bootloader).
        mode guided-reset  : open the factory-reset screen; the operator confirms on the device.
                             ADB cannot start a reset by itself on a locked production device, so this
                             is recorded as operator-confirmed, not machine-verified.
        """
        def step(pct, msg):
            if progress:
                progress(pct, msg)

        if not shutil.which("adb"):
            raise RuntimeError("adb is not installed (Android platform-tools)")
        before = next((d for d in self.probe_android_devices() if d["serialNumber"] == serial), None)
        if not before or before.get("status") != "device":
            raise RuntimeError("Device is not connected or not authorized for USB debugging")
        result: Dict[str, Any] = {"serial": serial, "mode": mode, "device": before}

        if mode == "fastboot-wipe":
            if not shutil.which("fastboot"):
                raise RuntimeError("fastboot is not installed (Android platform-tools)")
            step(10, "Rebooting to the bootloader")
            subprocess.run(["adb", "-s", serial, "reboot", "bootloader"], capture_output=True, timeout=30)
            deadline = time.time() + 90
            while time.time() < deadline:
                fb = subprocess.run(["fastboot", "devices"], capture_output=True, text=True, timeout=10).stdout
                if serial in fb:
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Device did not appear in fastboot mode within 90 s")
            unlocked = subprocess.run(["fastboot", "-s", serial, "getvar", "unlocked"],
                                      capture_output=True, text=True, timeout=15)
            if "unlocked: yes" not in (unlocked.stdout + unlocked.stderr).lower():
                subprocess.run(["fastboot", "-s", serial, "reboot"], capture_output=True, timeout=30)
                raise RuntimeError("Bootloader is locked, so fastboot -w is refused. Use the guided factory reset.")
            step(40, "Erasing userdata, cache and metadata (fastboot -w)")
            wipe = subprocess.run(["fastboot", "-s", serial, "-w"], capture_output=True, text=True, timeout=900)
            result["fastbootOutput"] = (wipe.stdout + wipe.stderr).strip()[-2000:]
            if wipe.returncode != 0:
                raise RuntimeError("fastboot -w failed: " + result["fastbootOutput"][-300:])
            subprocess.run(["fastboot", "-s", serial, "reboot"], capture_output=True, timeout=30)
            result.update({"status": "COMPLETED", "verified": "fastboot reported success",
                           "summary": "userdata, cache and metadata partitions erased with fastboot -w"})
        elif mode == "guided-reset":
            step(20, "Opening the factory-reset screen on the device")
            opened = False
            for comp in ("com.android.settings/.Settings$FactoryResetActivity", "com.android.settings/.MasterClear"):
                r = subprocess.run(["adb", "-s", serial, "shell", "am", "start", "-n", comp],
                                   capture_output=True, text=True, timeout=15)
                if r.returncode == 0 and "Error" not in r.stdout + r.stderr:
                    opened = True
                    break
            if not opened:
                subprocess.run(["adb", "-s", serial, "shell", "am", "start", "-a", "android.settings.SETTINGS"],
                               capture_output=True, timeout=15)
            step(40, "Waiting for the operator to confirm Erase all data on the device")
            deadline = time.time() + 1800
            while time.time() < deadline:
                present = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10).stdout
                if serial not in present:
                    break                   # the device rebooted into the reset; USB debugging is off afterwards
                time.sleep(3)
            else:
                raise RuntimeError("No reset observed within 30 minutes")
            result.update({"status": "OPERATOR_CONFIRMED", "verified": "device left ADB after the reset was started",
                           "summary": "Factory reset started from the device screen; completion confirmed by the operator"})
        else:
            raise ValueError("mode must be fastboot-wipe or guided-reset")
        step(100, result["summary"])
        return result


if __name__ == "__main__":
    engine = WipeEngine()
    for d in engine.probe_devices():
        print(f"{d['model']} - {d['capacity']} - {d['type']} - health {d['healthStatus']}")
    print(f"{len(engine.probe_android_devices())} Android device(s)")
