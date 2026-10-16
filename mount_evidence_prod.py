#!/usr/bin/env python3
"""
mount_evidence.py - Forensic Evidence Mass Mounter (v2)
=======================================================
Recursively discovers forensic disk images under an evidence directory and
exposes every partition read-only: filesystems are mounted, everything else
(swap, reserved, encrypted, unknown) is identified and left as a read-only
block device. Each subdirectory of the evidence root is one host.

Supported image formats
-----------------------
  .E01 .Ex01 .L01 .S01   EWF           ewfmount (FUSE) -> read-only loop -> kpartx -r
  .raw .img .dd .bin     raw           read-only loop -> kpartx -r
  .vmdk .qcow2 .vhdx .vhd VMware/QEMU/Hyper-V qemu-nbd --read-only -> kernel or kpartx partitions
  .aff .afd .afm         AFF           affuse (FUSE) -> read-only loop -> kpartx -r

Layout (depth matches yarax-scanner --host-from-path: host/image/partition/)
------------------------------------------------------------------------------
  /mnt/IOC_SCAN/<host>/<image>/
      mount_manifest.json        machine-readable record of everything found
      image_info.txt             the same, for people
      p01_vfat_efi_SYSTEM/       mounted filesystems only: pNN_<fs>[_<role>][_<label>]
      p03_ntfs_OS/
      p08_evvg-root_ext4_root/   LVM logical volume on partition 8
      p03_ntfs_OS_vss01/         shadow copy 1 of p03 (--vss)
  /mnt/IOC_SCAN_dev/<host>/<image>/
      disk -> /dev/loop5         read-only whole-disk device (unallocated space)
      p02_msr -> /dev/mapper/loop5p2, p05_swap_swap -> ...   every partition
  Block devices live outside the scan tree so a --follow-links scan never
  reads a whole disk as one file.

Teardown
--------
  Every loop device, mapping, NBD connection, FUSE helper, mount, folder and
  symlink is journaled in <image>/.mount_state.json the moment it is created.
  --unmount releases exactly those, newest first, and nothing else. A busy
  mount stops that image's teardown (the processes holding it are listed)
  instead of pulling devices out from under it. Run --unmount again after
  closing them. --status shows what is currently attached.

Usage
-----
  sudo python3 mount_evidence.py [OPTIONS] EVIDENCE_ROOT|IMAGE
  sudo python3 mount_evidence.py --dry-run EVIDENCE_ROOT      # identify only, nothing left attached
  sudo python3 mount_evidence.py --block-only EVIDENCE_ROOT   # devices + manifest, no mounts
  sudo python3 mount_evidence.py --status
  sudo python3 mount_evidence.py --unmount

Dependencies
------------
  required: util-linux (losetup, sfdisk, blkid, mount), kpartx, dmsetup
  optional: ewf-tools (E01), qemu-utils (VMDK/QCOW2/VHDX), afflib-tools (AFF),
            ntfs-3g (NTFS), lvm2 (reading LVM metadata), libvshadow-utils (VSS),
            psmisc (fuser: who is holding a busy mount)
  apt install ewf-tools qemu-utils kpartx ntfs-3g util-linux afflib-tools lvm2 libvshadow-utils psmisc
"""

from __future__ import annotations

import argparse
import fcntl
import glob
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "2.0"

# ── Colours ───────────────────────────────────────────────────────────────────
RESET  = "\033[0m";  BOLD  = "\033[1m"
RED    = "\033[0;31m"; GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"; CYAN  = "\033[0;36m"

# ── Supported extensions ───────────────────────────────────────────────────────
EWF_FIRST_EXTS  = {".e01", ".ex01", ".l01", ".s01"}
EWF_SEG_PAT     = re.compile(r"^\.(e|ex|l|s)\d{2,}$", re.IGNORECASE)
RAW_EXTS        = {".raw", ".img", ".dd", ".bin"}
VMDK_EXTS       = {".vmdk"}
QCOW_EXTS       = {".qcow2", ".qcow"}
VHD_EXTS        = {".vhdx", ".vhd"}
AFF_EXTS        = {".aff", ".afd", ".afm"}
ALL_EXTS        = EWF_FIRST_EXTS | RAW_EXTS | VMDK_EXTS | QCOW_EXTS | VHD_EXTS | AFF_EXTS

STATE_FILE    = ".mount_state.json"
MANIFEST_FILE = "mount_manifest.json"
INFO_FILE     = "image_info.txt"
LOCK_FILE     = "/run/lock/mount_evidence.lock"
DRY_ROOT      = Path("/run/mount_evidence/dry")   # journals + helper mounts of --dry-run
DM_PREFIX     = "mev-"                            # device-mapper names this tool creates itself

# ── Partition types (sfdisk prints GPT GUIDs upper-case, MBR ids as bare hex) ─
GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": ("efi", "EFI System"),
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": ("msr", "Microsoft Reserved"),
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": ("basic", "Microsoft basic data"),
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": ("recovery", "Windows Recovery"),
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": ("ldm", "Windows LDM metadata"),
    "af9b60a0-1431-4f62-bc68-3311714a69ad": ("ldm", "Windows LDM data"),
    "e75caf8f-f680-4cee-afa3-b001e56efc2d": ("storage_spaces", "Windows Storage Spaces"),
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": ("swap", "Linux swap"),
    "0fc63daf-8483-4772-8e79-3d69d8477de4": ("linux", "Linux filesystem"),
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": ("linux", "Linux root (x86-64)"),
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": ("linux", "Linux /home"),
    "bc13c2ff-59e6-4262-a352-b275fd6f7172": ("linux", "Linux extended boot"),
    "e6d6d379-f507-44c2-a23c-238f2a3df928": ("lvm", "Linux LVM"),
    "a19d880f-05fc-4d3b-a006-743f0f84911e": ("raid", "Linux RAID"),
    "ca7d7ccb-63ed-4c53-861c-1742536059cc": ("luks", "Linux LUKS"),
    "21686148-6449-6e6f-744e-656564454649": ("bios_boot", "BIOS boot"),
    "48465300-0000-11aa-aa11-00306543ecac": ("apple", "Apple HFS+"),
    "7c3457ef-0000-11aa-aa11-00306543ecac": ("apple", "Apple APFS"),
    "aa31e02a-400f-11db-9590-000c2911d1b8": ("vmfs", "VMware VMFS"),
    "9d275380-40ad-11db-bf97-000c2911d1b8": ("vmware", "VMware reserved"),
}
MBR_TYPES = {
    "1": ("basic", "FAT12"), "4": ("basic", "FAT16 <32M"), "6": ("basic", "FAT16"),
    "7": ("basic", "NTFS / exFAT / HPFS"), "b": ("basic", "FAT32"), "c": ("basic", "FAT32 (LBA)"),
    "e": ("basic", "FAT16 (LBA)"), "17": ("basic", "Hidden NTFS"), "1c": ("basic", "Hidden FAT32"),
    "5": ("extended", "Extended"), "f": ("extended", "Extended (LBA)"), "85": ("extended", "Linux extended"),
    "27": ("recovery", "Hidden NTFS (Windows RE)"), "12": ("recovery", "OEM diagnostics"),
    "de": ("recovery", "Dell utility"), "42": ("ldm", "Windows dynamic disk (LDM)"),
    "82": ("swap", "Linux swap"), "83": ("linux", "Linux"), "8e": ("lvm", "Linux LVM"),
    "fd": ("raid", "Linux RAID autodetect"), "ef": ("efi", "EFI System"), "ee": ("protective", "GPT protective"),
    "fb": ("vmfs", "VMware VMFS"), "fc": ("vmware", "VMware swap"), "af": ("apple", "HFS / HFS+"),
}
# What a partition type normally holds; anything else is recorded as a discrepancy.
EXPECTED_FS = {"efi": {"vfat"}, "msr": set(), "swap": {"swap"}, "lvm": {"lvm2_member"},
               "raid": {"linux_raid_member"}, "luks": {"crypto_luks"}, "recovery": {"ntfs", "vfat"},
               "bios_boot": set()}

# ── Read-only mount options, tried in order. Every chain keeps "ro" and the
#    driver's no-journal-replay option, so a dirty volume is never "repaired".
NTFS_3G = [["-t", "ntfs-3g", "-o", "ro,noatime,windows_names,show_sys_files,streams_interface=windows"],
           ["-t", "ntfs-3g", "-o", "ro,noatime"]]
NTFS3   = [["-t", "ntfs3", "-o", "ro,noatime"]]      # kernel driver; --ntfs-driver ntfs3
FS_OPTS_RO: dict[str, list[list[str]]] = {
    "vfat":     [["-t", "vfat", "-o", "ro,noatime,codepage=437,iocharset=utf8"], ["-t", "vfat", "-o", "ro,noatime"]],
    "exfat":    [["-t", "exfat", "-o", "ro,noatime"]],
    "ext2":     [["-t", "ext2", "-o", "ro,noatime"], ["-t", "ext4", "-o", "ro,noatime"]],
    "ext3":     [["-t", "ext3", "-o", "ro,noatime,noload"], ["-t", "ext4", "-o", "ro,noatime,noload"]],
    "ext4":     [["-t", "ext4", "-o", "ro,noatime,noload"]],
    # norecovery: never replay the log; nouuid: cloned disks share XFS UUIDs
    "xfs":      [["-t", "xfs", "-o", "ro,noatime,norecovery,nouuid"]],
    "btrfs":    [["-t", "btrfs", "-o", "ro,noatime,rescue=nologreplay"], ["-t", "btrfs", "-o", "ro,noatime,nologreplay"]],
    "f2fs":     [["-t", "f2fs", "-o", "ro,noatime,norecovery"]],
    "hfsplus":  [["-t", "hfsplus", "-o", "ro,noatime"]],
    "hfs":      [["-t", "hfs", "-o", "ro,noatime"]],
    "udf":      [["-t", "udf", "-o", "ro,noatime"]],
    "iso9660":  [["-t", "iso9660", "-o", "ro"]],
    "squashfs": [["-t", "squashfs", "-o", "ro"]],
}
FS_TOKEN = {"crypto_luks": "luks", "lvm2_member": "lvm", "linux_raid_member": "raid",
            "vmfs_volume_member": "vmfs", "bitlocker": "bitlocker"}
ROLE_TOKEN = {"msr": "msr", "extended": "extended", "ldm": "ldm", "storage_spaces": "storagespaces",
              "bios_boot": "biosboot", "protective": "protective", "luks": "luks"}


# ── Logging ───────────────────────────────────────────────────────────────────
class ColouredFormatter(logging.Formatter):
    COLOURS = {logging.DEBUG: CYAN, logging.INFO: GREEN,
               logging.WARNING: YELLOW, logging.ERROR: RED}
    def format(self, record):
        c = self.COLOURS.get(record.levelno, RESET)
        return f"{c}[{record.levelname[:4]}]{RESET} {record.getMessage()}"

def setup_logging(log_file: str, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("mount_evidence")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(ColouredFormatter())
    logger.addHandler(ch)
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    except OSError:
        logger.warning(f"Cannot write log to {log_file}")
    return logger

log = logging.getLogger("mount_evidence")


# ── Errors and interruption ───────────────────────────────────────────────────
class StepError(Exception):
    """A failure with a category: missing_dependency, device_error, damaged, ..."""
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category

class Interrupted(Exception):
    pass

STOP = False

def _on_signal(signum, frame):
    global STOP
    if STOP:
        raise KeyboardInterrupt
    STOP = True
    log.warning("Interrupt: finishing the current step, then stopping. Everything attached so far "
                "is journaled - run --unmount to release it. Press Ctrl-C again to abort at once.")

def checkpoint():
    if STOP:
        raise Interrupted()


# ── Subprocess ────────────────────────────────────────────────────────────────
def run(cmd: list, timeout: int = 60, input: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run without a shell; never raises. rc 127 = not installed, 124 = timed out."""
    cmd = [str(c) for c in cmd]
    log.debug("CMD: " + " ".join(shlex.quote(c) for c in cmd))
    try:
        # own session: Ctrl-C reaches only this script, which finishes the step
        # and journals what the child created instead of half-killing it
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, input=input, start_new_session=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not installed")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]} timed out after {timeout}s")
    if r.returncode:
        log.debug(f"  rc={r.returncode} {r.stderr.strip()[:400]}")
    return r

def err_text(r: subprocess.CompletedProcess) -> str:
    lines = [l.strip() for l in (r.stderr or r.stdout or "").splitlines()
             if l.strip() and "dmesg(1) may have more information" not in l]
    return lines[-1] if lines else f"exit code {r.returncode}"


# ── Journal: every resource is recorded as soon as it exists ──────────────────
def atomic_write(path: Path, text: str):
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

class Journal:
    def __init__(self, path: Path, meta: dict):
        self.path = path
        self.data = {"version": 2, "tool": "mount_evidence", "tool_version": VERSION,
                     "created_utc": utc_now(), **meta, "resources": []}

    def add(self, kind: str, **kw) -> dict:
        rec = {"kind": kind, **kw}
        self.data["resources"].append(rec)
        self.save()
        return rec

    def drop(self, rec: dict):
        self.data["resources"].remove(rec)
        self.save()

    def save(self):
        # The image folder is the journal's home; until it exists there is
        # nothing else to record (the folders above it are recorded with it).
        if self.path.parent.is_dir():
            atomic_write(self.path, json.dumps(self.data, indent=2))

def load_state(path: Path) -> Optional[dict]:
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return d if d.get("version") == 2 else from_v1(d)

def from_v1(d: dict) -> dict:
    """State files of the previous script version, as v2 resources (creation order)."""
    image_dir = d.get("mount_base", "")
    res = [{"kind": "fuse", "path": p} for p in d.get("fuse_mounts", [])]
    for dev in d.get("loop_devices", []):
        res.append({"kind": "loop", "dev": dev, "backing": None})
    for dev in d.get("nbd_devices", []):
        res.append({"kind": "nbd", "dev": dev, "image": d.get("image_path")})
    for dev in d.get("loop_devices", []) + d.get("nbd_devices", []):
        res.append({"kind": "kpartx", "parent": dev, "maps": None})
    res += [{"kind": "dm", "name": Path(p).name} for p in d.get("lvm_volume_groups", [])]
    res += [{"kind": "mount", "path": p} for p in d.get("partitions", [])]
    return {"version": 1, "image_path": d.get("image_path", ""), "image_dir": image_dir, "resources": res}


# ── Small system helpers ──────────────────────────────────────────────────────
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _unoct(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)

def mountinfo() -> dict[str, dict]:
    """mount point -> {opts (per-mount), fstype, source, super}"""
    out: dict[str, dict] = {}
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        a, _, b = line.partition(" - ")
        f, g = a.split(), b.split()
        if len(f) >= 6 and len(g) >= 2:
            out[_unoct(f[4])] = {"opts": f[5], "fstype": g[0], "source": _unoct(g[1]),
                                 "super": g[2] if len(g) > 2 else ""}
    return out

def is_mounted(path) -> bool:
    return str(path) in mountinfo()

def getro(dev: str) -> bool:
    r = run(["blockdev", "--getro", dev], timeout=15)
    return r.returncode == 0 and r.stdout.strip() == "1"

def dev_size(dev: str) -> Optional[int]:
    r = run(["blockdev", "--getsize64", dev], timeout=15)
    return int(r.stdout) if r.returncode == 0 and r.stdout.strip().isdigit() else None

def wait_for(pred, timeout: float = 5.0, step: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(step)

def dm_node(name: str) -> str:
    """/dev/mapper/<name>, waiting for udev; without a running udev (containers,
    minimal systems) dmsetup creates the node itself."""
    path = f"/dev/mapper/{name}"
    r = run(["dmsetup", "info", "-c", "--noheadings", "-o", "major,minor", name], timeout=15)
    want = tuple(int(x) for x in r.stdout.strip().split(":")) if r.returncode == 0 else None
    def right():
        try:
            st = os.stat(path)
        except OSError:
            return False
        return want is None or (os.major(st.st_rdev), os.minor(st.st_rdev)) == want
    if Path("/run/udev/control").exists() and shutil.which("udevadm"):
        run(["udevadm", "settle", "-t", "10"], timeout=15)
    if not wait_for(right, 2):                 # missing, or a stale node from an earlier device
        run(["dmsetup", "mknodes", name], timeout=15)
    return path

def loop_backing(dev: str) -> Optional[str]:
    try:
        return Path(f"/sys/block/{Path(dev).name}/loop/backing_file").read_text().strip()
    except OSError:
        return None

def nbd_live(dev: str, image: Optional[str]) -> bool:
    try:
        pid = Path(f"/sys/block/{Path(dev).name}/pid").read_text().strip()
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return False
    return "qemu-nbd" in cmdline and (not image or image in cmdline)

def dm_exists(name: str) -> bool:
    return run(["dmsetup", "info", name], timeout=15).returncode == 0

def dm_blkdev(name: str) -> Optional[str]:
    r = run(["dmsetup", "info", "-c", "--noheadings", "-o", "blkdevname", name], timeout=15)
    return (r.stdout.strip() or None) if r.returncode == 0 else None

def dm_deps(name: str) -> list[str]:
    r = run(["dmsetup", "deps", "-o", "devname", name], timeout=15)
    return re.findall(r"\(([^)]+)\)", r.stdout) if r.returncode == 0 else []

def dm_names() -> list[str]:
    r = run(["dmsetup", "ls"], timeout=15)
    if r.returncode or "No devices found" in r.stdout:
        return []
    return [l.split()[0] for l in r.stdout.splitlines() if l.split()]


# ── Dependency check ──────────────────────────────────────────────────────────
def check_deps() -> bool:
    ok = True
    for t in ["losetup", "sfdisk", "blkid", "blockdev", "mount", "umount", "kpartx", "dmsetup"]:
        if not shutil.which(t):
            log.error(f"Required tool missing: {t}")
            ok = False
    for t, what in [("ewfmount", "E01 images (ewf-tools)"), ("qemu-nbd", "VMDK/QCOW2/VHDX (qemu-utils)"),
                    ("affuse", "AFF images (afflib-tools)"), ("ntfs-3g", "NTFS (ntfs-3g)"),
                    ("lvs", "LVM volumes (lvm2)"), ("vshadowinfo", "VSS detection (libvshadow-utils)"),
                    ("fuser", "naming processes that hold a busy mount (psmisc)")]:
        if not shutil.which(t):
            log.debug(f"Optional tool '{t}' not found - needed for {what}")
    return ok


# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class Volume:
    id: str                                  # p03, p08.evvg-root, p03.vss01, disk
    source: str                              # partition | whole_disk | lvm | vss | kpartx_only
    number: Optional[int] = None             # partition number in the table
    dev: str = ""                            # read-only block device
    start_sector: Optional[int] = None
    sectors: Optional[int] = None
    size_bytes: Optional[int] = None
    part_type: str = ""                      # GPT type GUID or MBR type id, as in the table
    part_type_name: str = ""
    part_name: str = ""                      # GPT partition name (not the filesystem label)
    part_uuid: str = ""
    part_attrs: str = ""
    role: str = ""                           # efi, msr, basic, recovery, swap, lvm, ...
    fs_type: str = ""                        # blkid signature
    fs_usage: str = ""
    fs_version: str = ""
    fs_label: str = ""                       # filesystem / volume label (not the GPT name)
    fs_uuid: str = ""
    lvm: dict = field(default_factory=dict)
    vss: dict = field(default_factory=dict)
    action: str = ""                         # mount | vmfs | lvm | skip
    status: str = ""                         # mounted | block_device | skipped | failed | planned
    category: str = ""
    reason: str = ""
    name: str = ""
    mount_point: str = ""
    mount_fstype: str = ""
    mount_options: str = ""
    read_only_verified: Optional[bool] = None
    device_read_only: Optional[bool] = None
    dev_link: str = ""
    discrepancies: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    sources: dict = field(default_factory=dict)

@dataclass
class ImageReport:
    path: str
    host: str
    label: str
    format: str = ""
    access: str = ""
    image_dir: str = ""
    dev_dir: str = ""
    disk_dev: str = ""
    size_bytes: Optional[int] = None
    sector_size: Optional[int] = None
    segments: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    table: dict = field(default_factory=dict)
    volumes: list = field(default_factory=list)
    unallocated: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    status: str = ""

@dataclass
class Ctx:
    mount_base: Path
    dev_base: Path
    block_only: bool = False
    vss: bool = False
    dry_run: bool = False
    ntfs_driver: str = "ntfs-3g"


# ── Parsing (pure, unit-tested) ───────────────────────────────────────────────
def parse_udev(text: str) -> dict[str, str]:
    """blkid -o udev output; *_ENC values are \\xHH-escaped bytes (keeps spaces and UTF-8 exact)."""
    d: dict[str, str] = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            d[k.strip()] = v.strip()
    for k in list(d):
        if k.endswith("_ENC"):
            raw = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), d[k].encode())
            d[k[:-4]] = raw.decode("utf-8", errors="replace")
    return d

KPARTX_RE = re.compile(r"^add map (\S+) \((\d+:\d+)\): 0 (\d+) \S+ (\S+) (\d+)")

def parse_kpartx(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = KPARTX_RE.match(line.strip())
        if m:
            num = re.search(r"p(\d+)$", m.group(1))
            out.append({"name": m.group(1), "number": int(num.group(1)) if num else None,
                        "sectors": int(m.group(3))})
    return out

def part_role(table: str, ptype: str) -> tuple[str, str]:
    if table == "gpt":
        return GPT_TYPES.get(ptype.lower(), ("unknown", f"GPT type {ptype}"))
    if table == "dos":
        return MBR_TYPES.get(ptype.lower().lstrip("0") or "0", ("unknown", f"MBR type 0x{ptype}"))
    return ("", "")

def classify(v: Volume):
    """Decide what to do with a volume from its partition type and signature."""
    fs, role = v.fs_type, v.role
    def skip(category, reason):
        v.action, v.category, v.reason = "skip", category, reason
    if role == "extended":
        skip("container", "MBR extended partition: it only holds the logical partitions listed separately")
    elif role == "protective":
        skip("container", "GPT protective MBR entry")
    elif fs == "swap":
        skip("swap", "Linux swap: never activated or mounted; read the block device with forensic tools")
    elif fs == "bitlocker":
        skip("encrypted", "BitLocker encrypted volume: needs the recovery key (dislocker -r or bdemount), not automated")
    elif fs == "crypto_luks" or (role == "luks" and not fs):
        skip("encrypted", "LUKS encrypted volume: needs the key (cryptsetup open --readonly), not automated")
    elif fs == "lvm2_member":
        v.action, v.category, v.reason = "lvm", "container", "LVM physical volume: its logical volumes are listed separately"
    elif fs.endswith("raid_member"):
        skip("needs_tooling", "software RAID member: assemble with mdadm --assemble --readonly (not automated)")
    elif role == "ldm":
        skip("needs_tooling", "Windows dynamic disk (LDM): volumes can be mapped with ldmtool (not automated)")
    elif role == "storage_spaces":
        skip("needs_tooling", "Windows Storage Spaces member: no Linux reader is automated")
    elif fs == "vmfs_volume_member":
        v.action = "vmfs"
    elif fs and (fs in FS_OPTS_RO or fs == "ntfs" or v.fs_usage == "filesystem"):
        v.action = "mount"
    elif role == "msr":
        skip("special_partition", "Microsoft Reserved partition: no filesystem by design")
    elif role == "bios_boot":
        skip("special_partition", "BIOS boot partition: boot-loader code, no filesystem")
    elif fs:
        skip("unsupported", f"signature '{fs}' ({v.fs_usage or 'unknown usage'}) is not a mountable filesystem")
    else:
        skip("no_filesystem", "no recognized filesystem signature (unformatted, wiped, encrypted or unknown)")

def discrepancies(v: Volume, blk: dict[str, str]) -> list[str]:
    out = []
    exp = EXPECTED_FS.get(v.role)
    if exp is not None and v.fs_type and v.fs_type not in exp:
        out.append(f"partition type '{v.part_type_name}' normally holds "
                   f"{'/'.join(sorted(exp)) or 'no filesystem'}, but blkid found '{v.fs_type}'")
    if exp and not v.fs_type and v.role in ("swap", "efi"):
        out.append(f"partition type '{v.part_type_name}' but no {'/'.join(sorted(exp))} signature")
    for key, mine in (("ID_PART_ENTRY_OFFSET", v.start_sector), ("ID_PART_ENTRY_SIZE", v.sectors)):
        if key in blk and mine is not None and blk[key].isdigit() and int(blk[key]) != mine:
            out.append(f"blkid {key}={blk[key]} but sfdisk says {mine}")
    if blk.get("_AMBIVALENT"):
        out.append("blkid found more than one signature (ambivalent); nothing was chosen")
    return out

def safe_token(s: str, maxlen: int = 32) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    s = re.sub(r"[^A-Za-z0-9.-]+", "_", s).strip("._-")
    return s[:maxlen].rstrip("._-")

def volume_name(v: Volume) -> str:
    parts = [f"p{v.number:02d}" if v.number is not None else "disk"]
    if v.source == "lvm":
        parts.append(safe_token(f"{v.lvm.get('vg', '')}-{v.lvm.get('lv', '')}", 48))
    tok = FS_TOKEN.get(v.fs_type, safe_token(v.fs_type)) or ROLE_TOKEN.get(v.role, "nofs")
    parts.append(tok)
    if v.role in ("efi", "recovery") and tok != v.role and v.source == "partition":
        parts.append(v.role)
    label = safe_token(v.fs_label)
    if label and label.lower() not in (p.lower() for p in parts[1:]):
        parts.append(label)
    if v.source == "vss":
        parts.append(f"vss{v.vss.get('store', 0):02d}")
    return "_".join(parts)

def classify_mount_error(text: str) -> tuple[str, str]:
    t = text.lower()
    if "hibernat" in t:
        return "hibernated", "Windows is hibernated (hiberfil.sys in use)"
    if "unclean" in t or "fast restart" in t or "dirty" in t:
        return "dirty", "volume was not shut down cleanly (dirty / Fast Startup)"
    if "unknown filesystem type" in t or "no such device" in t or "not installed" in t:
        return "missing_dependency", "no driver for this filesystem on this system"
    if "duplicate" in t or "already mounted" in t:
        return "collision", "a filesystem with the same identity is already mounted (cloned disk?)"
    if "input/output error" in t or "i/o error" in t or "corrupt" in t or "bad superblock" in t \
            or "can't read superblock" in t or "failed to read" in t:
        return "damaged", "filesystem structures could not be read (damaged, truncated or not what the signature says)"
    if "bitlocker" in t:
        return "encrypted", "BitLocker encrypted"
    return "mount_failed", "mount failed"

def unallocated(parts: list[Volume], first: int, last: int) -> list[dict]:
    """Gaps between first and last usable sector not covered by any primary/GPT partition."""
    spans = sorted((p.start_sector, p.start_sector + p.sectors - 1) for p in parts
                   if p.start_sector is not None and p.sectors and p.role != "extended")
    gaps, pos = [], first
    for s, e in spans:
        if s > pos:
            gaps.append({"start_sector": pos, "sectors": s - pos})
        pos = max(pos, e + 1)
    if last >= pos:
        gaps.append({"start_sector": pos, "sectors": last - pos + 1})
    return gaps

def lvm_tables(lvs: list[dict], pvs: list[dict], ours: set[str]) -> list[dict]:
    """
    Device-mapper tables for each LV, built from LVM's own metadata. Creating
    the mappings ourselves (instead of vgchange -ay) never touches the
    workstation's LVM state, never collides with a host VG of the same name,
    and works for cloned images whose VGs share names and UUIDs.
    """
    pe_start = {p["pv_name"]: int(p["pe_start"]) for p in pvs}
    out: dict[tuple, dict] = {}
    for s in lvs:
        if s["lv_name"].startswith("["):          # hidden component of another LV
            continue
        key = (s["vg_name"], s["lv_name"])
        lv = out.setdefault(key, {"vg": s["vg_name"], "lv": s["lv_name"], "lv_uuid": s.get("lv_uuid", ""),
                                  "vg_uuid": s.get("vg_uuid", ""), "size_sectors": int(s["lv_size"]),
                                  "table": [], "problem": ""})
        extent = int(s["vg_extent_size"])
        ranges = s["seg_pe_ranges"].split()
        devs = [r.rsplit(":", 1) for r in ranges]
        if s["segtype"] not in ("linear", "striped"):
            lv["problem"] = f"segment type '{s['segtype']}' is not mapped (only linear and striped)"
        elif not ranges or any(d not in ours or d not in pe_start for d, _ in devs):
            lv["problem"] = "part of this LV is on a physical volume that is not in this image"
        else:
            targets = [f"{d} {pe_start[d] + int(r.split('-')[0]) * extent}" for d, r in devs]
            start, size = int(s["seg_start"]), int(s["seg_size"])
            if s["segtype"] == "linear":
                lv["table"].append(f"{start} {size} linear {targets[0]}")
            else:
                lv["table"].append(f"{start} {size} striped {s['stripes']} {s['stripe_size']} " + " ".join(targets))
    return list(out.values())


# ── NBD ───────────────────────────────────────────────────────────────────────
def nbd_get_max() -> int:
    try:
        return int(Path("/sys/module/nbd/parameters/nbds_max").read_text().strip())
    except (OSError, ValueError):
        return 16

def nbd_is_free(index: int) -> bool:
    name = f"nbd{index}"
    if Path(f"/sys/block/{name}/pid").exists():
        return False
    try:
        return int(Path(f"/sys/block/{name}/size").read_text().strip()) == 0
    except (OSError, ValueError):
        return True

def nbd_find_free() -> Optional[str]:
    for i in range(nbd_get_max()):
        if Path(f"/dev/nbd{i}").exists() and nbd_is_free(i):
            return f"/dev/nbd{i}"
    return None


# ── Opening images as a read-only disk device ─────────────────────────────────
def make_dirs(path: Path, journal: Journal, stop: Path):
    """Create path and any missing parents below stop, journaling each one."""
    missing = []
    p = path
    while p != stop and not p.exists():
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        journal.add("dir", path=str(d))            # recorded first: a kill -9 can't orphan it
        d.mkdir()
        journal.save()                             # the image folder is the journal's own home

def loop_attach(path: Path, journal: Journal) -> str:
    r = run(["losetup", "--find", "--show", "--read-only", path])
    dev = r.stdout.strip()
    if r.returncode or not dev:
        raise StepError("device_error", f"losetup failed for {path}: {err_text(r)}")
    journal.add("loop", dev=dev, backing=str(path))
    return dev

def fuse_helper(tool: str, args: list, img: Path, fdir: Path, journal: Journal, stop: Path, pkg: str):
    if not shutil.which(tool):
        raise StepError("missing_dependency", f"{tool} not found (apt install {pkg})")
    make_dirs(fdir, journal, stop)
    rec = journal.add("fuse", path=str(fdir))
    r = run([tool, *args, img, fdir], timeout=180)
    if not is_mounted(fdir):
        journal.drop(rec)
        raise StepError("device_error", f"{tool} failed: {err_text(r)}")

def open_image(img: Path, rep: ImageReport, ctx: Ctx, journal: Journal, dev_dir: Path) -> tuple[str, bool]:
    """Returns (read-only disk device, is_nbd)."""
    ext = img.suffix.lower()
    stop = DRY_ROOT / "dev" if ctx.dry_run else ctx.dev_base
    if ext in EWF_FIRST_EXTS:
        rep.format, rep.access = "ewf", "ewfmount (FUSE) -> read-only loop -> kpartx -r"
        if shutil.which("ewfinfo"):
            r = run(["ewfinfo", img], timeout=120)
            rep.meta["ewfinfo"] = {k.strip(): v.strip() for k, _, v in
                                   (l.partition(":") for l in r.stdout.splitlines() if ":" in l) if v.strip()}
        rep.segments = sorted(str(p) for p in img.parent.iterdir()
                              if p.stem == img.stem and EWF_SEG_PAT.match(p.suffix))
        fdir = dev_dir / ".ewf"
        fuse_helper("ewfmount", [], img, fdir, journal, stop, "ewf-tools")
        raw = fdir / "ewf1"
        if not raw.exists():
            files = sorted(fdir.iterdir())
            if not files:
                raise StepError("damaged", f"ewfmount exposed nothing in {fdir}")
            raw = files[0]
        return loop_attach(raw, journal), False
    if ext in AFF_EXTS:
        rep.format, rep.access = "aff", "affuse (FUSE) -> read-only loop -> kpartx -r"
        fdir = dev_dir / ".aff"
        fuse_helper("affuse", [], img, fdir, journal, stop, "afflib-tools")
        raws = sorted(p for p in fdir.iterdir() if p.suffix == ".raw")
        if not raws:
            raise StepError("damaged", f"affuse exposed no .raw file in {fdir}")
        return loop_attach(raws[0], journal), False
    if ext in VMDK_EXTS | QCOW_EXTS | VHD_EXTS:
        rep.format = ext.lstrip(".")
        rep.access = "qemu-nbd --read-only"
        if not shutil.which("qemu-nbd"):
            raise StepError("missing_dependency", "qemu-nbd not found (apt install qemu-utils)")
        r = run(["qemu-img", "info", "--output=json", "-U", img], timeout=60)
        if r.returncode == 0:
            try:
                rep.meta["qemu_img_info"] = json.loads(r.stdout)
            except ValueError:
                pass
        if not Path("/dev/nbd0").exists():
            raise StepError("missing_dependency", "NBD devices missing: modprobe nbd nbds_max=16 max_part=0")
        dev = nbd_find_free()
        if not dev:
            raise StepError("device_error", "all NBD slots in use (--unmount, or --nbd-max N)")
        r = run(["qemu-nbd", "--read-only", "--connect", dev, img], timeout=60)
        if r.returncode:
            raise StepError("device_error", f"qemu-nbd failed: {err_text(r)}")
        journal.add("nbd", dev=dev, image=str(img))
        if not wait_for(lambda: (dev_size(dev) or 0) > 0, 10):
            raise StepError("damaged", f"qemu-nbd connected {dev} but it has size 0 (corrupt image?)")
        return dev, True
    rep.format, rep.access = "raw", "read-only loop -> kpartx -r"
    return loop_attach(img, journal), False


# ── Partition and filesystem discovery ────────────────────────────────────────
def blkid_probe(dev: str) -> dict[str, str]:
    """Low-level probe (-p): reads the device itself, never the blkid cache."""
    r = run(["blkid", "-p", "-o", "udev", dev], timeout=60)
    d = parse_udev(r.stdout)
    if r.returncode == 8:
        d["_AMBIVALENT"] = "1"
    return d

def map_partitions(disk: str, is_nbd: bool, journal: Journal, rep: ImageReport) -> dict[int, str]:
    """partition number -> read-only device. kpartx -r for loops (and NBD without kernel partitions)."""
    if is_nbd:
        kernel = {int(m.group(1)): p for p in glob.glob(f"{disk}p*") if (m := re.search(r"p(\d+)$", p))}
        if kernel:
            return kernel
    parent = {"parent_backing": loop_backing(disk)} if not is_nbd else {"parent_image": rep.path}
    r = run(["kpartx", "-a", "-r", "-s", "-v", disk], timeout=60)
    maps = parse_kpartx(r.stdout)
    if maps:
        journal.add("kpartx", parent=disk, maps=[m["name"] for m in maps], **parent)
    elif r.returncode:
        rep.warnings.append(f"kpartx: {err_text(r)}")
    return {m["number"]: dm_node(m["name"]) for m in maps if m["number"] is not None}

def discover_volumes(disk: str, is_nbd: bool, rep: ImageReport, journal: Journal) -> list[Volume]:
    rep.size_bytes = dev_size(disk)
    r = run(["sfdisk", "--json", disk], timeout=60)
    for line in r.stderr.splitlines():
        if line.strip():
            rep.warnings.append(f"sfdisk: {line.strip()}")
    pt = None
    if r.returncode == 0:
        try:
            pt = json.loads(r.stdout)["partitiontable"]
        except (ValueError, KeyError):
            pt = None
    vols: list[Volume] = []
    if pt is None:
        whole = blkid_probe(disk)
        if whole.get("ID_PART_TABLE_TYPE"):
            rep.errors.append({"category": "damaged", "message":
                               f"blkid sees a {whole['ID_PART_TABLE_TYPE']} partition table but sfdisk cannot read it"})
        rep.table = {"type": "none", "source": "sfdisk --json (no partition table)"}
        rep.sector_size = int(run(["blockdev", "--getss", disk], timeout=15).stdout.strip() or 512)
        v = Volume(id="disk", source="whole_disk", dev=disk, start_sector=0,
                   size_bytes=rep.size_bytes, sources={"filesystem": "blkid -p"})
        apply_blkid(v, whole)
        return [v]

    ss = int(pt.get("sectorsize", 512))
    rep.sector_size = ss
    label = pt.get("label", "")
    rep.table = {"type": label, "id": pt.get("id", ""), "first_lba": pt.get("firstlba"),
                 "last_lba": pt.get("lastlba"), "source": "sfdisk --json"}
    devs = map_partitions(disk, is_nbd, journal, rep)
    for p in pt.get("partitions", []):
        num = int(re.search(r"(\d+)$", p["node"]).group(1))
        role, tname = part_role(label, p.get("type", ""))
        v = Volume(id=f"p{num:02d}", source="partition", number=num, dev=devs.pop(num, ""),
                   start_sector=p["start"], sectors=p["size"], size_bytes=p["size"] * ss,
                   part_type=p.get("type", ""), part_type_name=tname, part_name=p.get("name", ""),
                   part_uuid=p.get("uuid", ""), part_attrs=p.get("attrs", ""), role=role,
                   sources={"partition": "sfdisk --json", "filesystem": "blkid -p"})
        vols.append(v)
    for num, dev in sorted(devs.items()):          # kpartx saw a partition sfdisk did not
        vols.append(Volume(id=f"p{num:02d}", source="kpartx_only", number=num, dev=dev,
                           discrepancies=["kpartx mapped this partition but sfdisk does not list it"]))
    if label == "dos":
        first, last = 1, (rep.size_bytes or 0) // ss - 1
    else:
        first, last = pt.get("firstlba", 0), pt.get("lastlba", 0)
    rep.unallocated = [dict(g, bytes=g["sectors"] * ss) for g in unallocated(vols, first, last)]

    for v in vols:
        checkpoint()
        if not v.dev:
            v.action, v.status, v.category = "skip", "failed", "device_error"
            v.reason = "no device was mapped for this partition (kpartx)"
            continue
        apply_blkid(v, blkid_probe(v.dev))
    return vols

def apply_blkid(v: Volume, blk: dict[str, str]):
    v.fs_type = "" if blk.get("_AMBIVALENT") else blk.get("ID_FS_TYPE", "").lower()
    v.fs_usage = blk.get("ID_FS_USAGE", "")
    v.fs_version = blk.get("ID_FS_VERSION", "")
    v.fs_label = blk.get("ID_FS_LABEL", "")
    v.fs_uuid = blk.get("ID_FS_UUID", "")
    if v.sectors is None and v.dev:
        v.size_bytes = dev_size(v.dev)
    v.discrepancies += discrepancies(v, blk)
    if v.action:                                   # already decided (no device)
        return
    classify(v)
    if blk.get("_AMBIVALENT") and v.action == "skip":
        v.category, v.reason = "ambivalent", "more than one filesystem signature; not mounted to avoid guessing"
    elif v.category == "no_filesystem":
        oem = boot_oem(v.dev)
        if oem:
            v.category = "damaged"
            v.reason = (f"boot sector says {oem} but blkid could not validate the filesystem "
                        "(damaged or partly overwritten); try a forensic parser on the block device")
            v.discrepancies.append(f"boot sector OEM id '{oem}' vs blkid: no filesystem")

BOOT_OEM = {b"NTFS    ": "NTFS", b"EXFAT   ": "exFAT", b"-FVE-FS-": "BitLocker"}

def boot_oem(dev: str) -> str:
    """8-byte OEM id at offset 3 of the boot sector; blkid rejects NTFS whose MFT is unreadable."""
    try:
        with open(dev, "rb") as f:
            f.seek(3)
            return BOOT_OEM.get(f.read(8), "")
    except OSError:
        return ""


# ── LVM (metadata read-only, mappings created by us) ──────────────────────────
def lvm_volumes(pvs: list[Volume], img: str, journal: Journal, rep: ImageReport) -> list[Volume]:
    if not shutil.which("lvs"):
        for v in pvs:
            v.reason += " - lvm2 not installed, logical volumes not read"
        return []
    devs = [v.dev for v in pvs]
    accept = ",".join(f'"a|^{re.escape(d)}$|"' for d in devs) + ',"r|.*|"'
    # Only this image's PVs are visible, metadata can never be written, and the
    # workstation's devices file / filters are bypassed for this command only.
    cfg = (f"devices {{ use_devicesfile=0 filter=[{accept}] global_filter=[{accept}] }} "
           f"global {{ metadata_read_only=1 }}")
    common = ["--readonly", "--config", cfg, "--reportformat", "json", "--units", "s", "--nosuffix"]
    rp = run(["pvs", *common, "-o", "pv_name,pv_uuid,pe_start,vg_name"], timeout=60)
    rl = run(["lvs", *common, "-a", "-o", "vg_name,vg_uuid,vg_extent_size,lv_name,lv_uuid,lv_size,"
              "segtype,seg_start,seg_size,stripes,stripe_size,seg_pe_ranges"], timeout=60)
    try:
        pv_rows = json.loads(rp.stdout)["report"][0].get("pv", [])
        lv_rows = json.loads(rl.stdout)["report"][0].get("lv", [])
    except (ValueError, KeyError, IndexError):
        rep.errors.append({"category": "damaged", "message": f"could not read LVM metadata: {err_text(rl)}"})
        return []
    by_dev = {v.dev: v for v in pvs}
    for p in pv_rows:
        if p["pv_name"] in by_dev:
            by_dev[p["pv_name"]].lvm = {"vg": p.get("vg_name", ""), "pv_uuid": p.get("pv_uuid", "")}
    tag = hashlib.sha1(img.encode()).hexdigest()[:8]
    out = []
    for lv in lvm_tables(lv_rows, pv_rows, set(devs)):
        checkpoint()
        first_pv = next((by_dev[d] for d in by_dev if any(d + " " in t for t in lv["table"])), pvs[0])
        v = Volume(id=f"{first_pv.id}.{lv['vg']}-{lv['lv']}", source="lvm", number=first_pv.number,
                   size_bytes=lv["size_sectors"] * 512,
                   lvm={k: lv[k] for k in ("vg", "lv", "vg_uuid", "lv_uuid")},
                   sources={"lvm": "lvs/pvs --readonly (metadata_read_only)", "filesystem": "blkid -p"})
        out.append(v)
        if lv["problem"]:
            v.action, v.status, v.category, v.reason = "skip", "skipped", "unsupported", lv["problem"]
            continue
        name = DM_PREFIX + safe_token(f"{tag}-{lv['vg']}-{lv['lv']}", 100)
        rec = journal.add("dm", name=name)
        r = run(["dmsetup", "create", name, "--readonly"], input="\n".join(lv["table"]) + "\n", timeout=30)
        if r.returncode:
            journal.drop(rec)
            v.action, v.status, v.category = "skip", "failed", "device_error"
            v.reason = f"dmsetup create failed: {err_text(r)}"
            continue
        v.dev = dm_node(name)
        v.lvm["dm_table"] = lv["table"]
        apply_blkid(v, blkid_probe(v.dev))
    return out


# ── Volume Shadow Copies (experimental: --vss) ────────────────────────────────
def vss_detect(v: Volume):
    """Shadow copies live inside the NTFS volume; vshadowinfo reads only the catalog."""
    if not shutil.which("vshadowinfo"):
        v.vss = {"checked": False, "note": "libvshadow-utils not installed"}
        return
    r = run(["vshadowinfo", v.dev], timeout=300)
    m = re.search(r"Number of stores\s*:\s*(\d+)", r.stdout)
    stores = int(m.group(1)) if m else 0
    times = re.findall(r"Creation time\s*:\s*(.+)", r.stdout)
    v.vss = {"checked": True, "stores": stores, "creation_times": [t.strip() for t in times],
             "source": "vshadowinfo"}
    if not m and r.returncode and "No Volume Shadow" not in r.stdout + r.stderr:
        v.vss["note"] = err_text(r)

def vss_volumes(v: Volume, dev_dir: Path, ctx: Ctx, journal: Journal) -> list[Volume]:
    fdir = dev_dir / ".vss" / v.id
    stop = DRY_ROOT / "dev" if ctx.dry_run else ctx.dev_base
    fuse_helper("vshadowmount", [], Path(v.dev), fdir, journal, stop, "libvshadow-utils")
    out = []
    for i in range(1, v.vss.get("stores", 0) + 1):
        f = fdir / f"vss{i}"
        sv = Volume(id=f"{v.id}.vss{i:02d}", source="vss", number=v.number, role=v.role,
                    vss={"store": i, "of_volume": v.id, "experimental": True},
                    sources={"vss": "vshadowmount (read-only FUSE)", "filesystem": "blkid -p"})
        out.append(sv)
        if not f.exists():
            sv.action, sv.status, sv.category, sv.reason = "skip", "failed", "device_error", f"{f} missing"
            continue
        sv.dev = loop_attach(f, journal)
        apply_blkid(sv, blkid_probe(sv.dev))
    return out


# ── Mounting ──────────────────────────────────────────────────────────────────
def mount_volume(v: Volume, mp: Path, ctx: Ctx, journal: Journal, stop: Path):
    # Defence in depth: the device itself must refuse writes before any mount.
    v.device_read_only = getro(v.dev)
    if not v.device_read_only:
        v.status, v.category, v.reason = "failed", "safety", f"{v.dev} is writable; refusing to mount"
        return
    if is_mounted(mp):
        v.status, v.category, v.reason = "failed", "collision", f"{mp} is already a mount point"
        return
    if v.action == "vmfs":
        if not shutil.which("vmfs6-fuse"):
            v.status, v.category, v.reason = "failed", "missing_dependency", "vmfs6-fuse not installed"
            return
        attempts = [["vmfs6-fuse", v.dev, mp, "-o", "ro,allow_other"], ["vmfs6-fuse", v.dev, mp, "-o", "ro"]]
    else:
        fs = v.fs_type
        chain = (NTFS3 if ctx.ntfs_driver == "ntfs3" else NTFS_3G) if fs == "ntfs" else \
            FS_OPTS_RO.get(fs, [["-t", fs, "-o", "ro"]])
        attempts = [["mount", *o, v.dev, mp] for o in chain]
    n0 = len(journal.data["resources"])
    make_dirs(mp, journal, stop)
    made = journal.data["resources"][n0:]
    rec = journal.add("mount", path=str(mp))
    errors = []
    for cmd in attempts:
        r = run(cmd, timeout=300)
        info = mountinfo().get(str(mp))
        if r.returncode == 0 and not info:
            run(["umount", mp], timeout=120)
            v.status, v.category, v.reason = "failed", "safety", "mount succeeded but is not visible in mountinfo"
            return
        if r.returncode == 0:
            v.mount_point, v.mount_fstype = str(mp), info["fstype"]
            v.mount_options = f"{info['opts']} ({info['super']})" if info["super"] else info["opts"]
            v.read_only_verified = "ro" in info["opts"].split(",")
            if not v.read_only_verified:
                run(["umount", mp], timeout=120)
                v.status, v.category, v.reason = "failed", "safety", "mount came up read-write; unmounted"
                return
            v.status, v.reason = "mounted", ""
            v.sources["mount_options"] = "/proc/self/mountinfo"
            if r.stderr.strip():
                v.notes.append(f"mount: {err_text(r)}")
            if v.fs_type == "ntfs":
                hib = hibernation(mp)
                if hib:
                    v.notes.append(hib)
            return
        errors.append((r.stderr or r.stdout or "").strip())
    journal.drop(rec)
    for d in reversed(made):                           # no empty folders for failed mounts
        try:
            Path(d["path"]).rmdir()
            journal.drop(d)
        except OSError:
            break
    v.category, why = classify_mount_error("\n".join(errors))
    first = next((l.strip() for e in errors for l in e.splitlines()
                  if l.strip() and "dmesg(1)" not in l), "")
    v.status, v.reason = "failed", f"{why}: {first}"
    if v.category == "hibernated" or v.category == "dirty":
        v.reason += " - no repair or journal replay was attempted; use a forensic parser (e.g. Sleuth Kit) on the block device"


def hibernation(mp: Path) -> str:
    """ntfs-3g mounts a hibernated volume read-only without saying so."""
    try:
        with open(mp / "hiberfil.sys", "rb") as f:
            magic = f.read(4)
    except OSError:
        return ""
    if magic.upper() in (b"HIBR", b"RSTR", b"WAKE"):
        return (f"hiberfil.sys header '{magic.decode(errors='replace')}': Windows was hibernated or "
                "Fast Startup was on - this view may miss changes still in memory; hiberfil.sys holds that memory")
    return ""


# ── One image ─────────────────────────────────────────────────────────────────
def state_live(state: dict) -> bool:
    mounts = mountinfo()
    for r in state.get("resources", []):
        k = r["kind"]
        if k in ("mount", "fuse") and r["path"] in mounts:
            return True
        if k == "loop" and loop_backing(r["dev"]) and (r.get("backing") is None or loop_backing(r["dev"]) == r["backing"]):
            return True
        if k == "nbd" and nbd_live(r["dev"], r.get("image")):
            return True
        if k == "dm" and dm_exists(r["name"]):
            return True
    return False

def process_image(img: Path, host: str, label: str, ctx: Ctx) -> ImageReport:
    rep = ImageReport(path=str(img), host=host, label=label,
                      image_dir=str(ctx.mount_base / host / label), dev_dir=str(ctx.dev_base / host / label))
    root = DRY_ROOT / "mnt" if ctx.dry_run else ctx.mount_base
    droot = DRY_ROOT / "dev" if ctx.dry_run else ctx.dev_base
    work, dev_dir = root / host / label, droot / host / label
    jpath = work / STATE_FILE
    if jpath.exists():
        st = load_state(jpath)
        if st and state_live(st):
            rep.status = "already_mounted"
            rep.warnings.append("already mounted by an earlier run - run --unmount first to remount")
            return rep
        log.info("  Earlier state found but nothing is still attached - clearing it")
        teardown_state(jpath, lazy=False)
    if is_mounted(work):
        rep.status = "failed"
        rep.errors.append({"category": "collision", "message": f"{work} is itself a mount point"})
        return rep

    journal = Journal(jpath, {"image_path": str(img), "host": host, "label": label,
                              "image_dir": str(work), "dev_dir": str(dev_dir), "dry_run": ctx.dry_run})
    try:
        make_dirs(work, journal, root)
        disk, is_nbd = open_image(img, rep, ctx, journal, dev_dir)
        rep.disk_dev = disk
        if not getro(disk):
            raise StepError("safety", f"{disk} is writable; stopping before anything is mounted")
        vols = discover_volumes(disk, is_nbd, rep, journal)

        pvs = [v for v in vols if v.action == "lvm" and v.dev]
        if pvs:
            vols += lvm_volumes(pvs, str(img), journal, rep)
        for v in list(vols):
            if v.fs_type == "ntfs" and v.dev and v.source != "vss":
                vss_detect(v)
                if ctx.vss and v.vss.get("stores"):
                    try:
                        vols += vss_volumes(v, dev_dir, ctx, journal)
                    except StepError as e:
                        v.vss["error"] = str(e)
        for v in vols:
            v.name = volume_name(v)

        for v in vols:
            checkpoint()
            if v.status:                                   # decided during discovery
                continue
            if v.action in ("mount", "vmfs"):
                if ctx.dry_run:
                    v.status, v.reason = "planned", f"would mount at {Path(rep.image_dir) / v.name}"
                elif ctx.block_only:
                    v.status, v.reason = "block_device", "--block-only: not mounted"
                else:
                    mount_volume(v, work / v.name, ctx, journal, root)
            elif v.action == "lvm":
                v.status = "skipped"
            else:
                v.status = "skipped"
        rep.volumes = vols

        if not ctx.dry_run:
            make_dirs(dev_dir, journal, droot)
            link(dev_dir / "disk", disk, journal)
            for v in vols:
                if v.dev:
                    v.dev_link = link(dev_dir / v.name, v.dev, journal)
        failed = [v for v in vols if v.status == "failed"]
        rep.status = "failed" if rep.errors or (failed and len(failed) == len(vols)) else \
            "partial" if failed else "ok"
    except StepError as e:
        rep.status = "failed"
        rep.errors.append({"category": e.category, "message": str(e)})
        teardown_state(jpath, lazy=False, quiet=True)  # nothing useful is left attached
    except Interrupted:
        rep.status = "interrupted"
    finally:
        if not ctx.dry_run and jpath.exists():
            write_manifest(rep, work)
        if ctx.dry_run:
            teardown_state(jpath, lazy=False, quiet=True)
    return rep

def link(path: Path, target: str, journal: Journal) -> str:
    if path.is_symlink():
        path.unlink()
    journal.add("symlink", path=str(path))
    path.symlink_to(target)
    return str(path)


# ── Manifest and human summary ────────────────────────────────────────────────
def human(n: Optional[int]) -> str:
    if n is None:
        return "?"
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024

def volume_rows(rep: ImageReport) -> list[list[str]]:
    rows = []
    for v in rep.volumes:
        where = v.mount_point or v.reason
        if v.status == "mounted":
            where = f"{v.name}/  ({v.mount_fstype}, ro verified)"
        elif v.status == "block_device":
            where = f"block device {v.dev}"
        rows.append([v.id, v.part_type_name or v.source, v.fs_type or "-", v.fs_label or "-",
                     human(v.size_bytes), v.status + (f": {v.category}" if v.status != "mounted" and v.category else ""),
                     where])
    return rows

def table(rows: list[list[str]], head: list[str]) -> str:
    w = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head) - 1)]
    fmt = lambda r: "  ".join(str(c).ljust(w[i]) if i < len(w) else str(c) for i, c in enumerate(r))
    return "\n".join([fmt(head)] + [fmt(r) for r in rows])

def write_manifest(rep: ImageReport, work: Path):
    doc = {"tool": "mount_evidence", "tool_version": VERSION, "generated_utc": utc_now(),
           "read_only_note": "Read-only mounts prevent writes through this tool; they do not prove the "
                             "image was unaltered before acquisition. Verify acquisition hashes separately.",
           **asdict(rep)}
    atomic_write(work / MANIFEST_FILE, json.dumps(doc, indent=2))
    lines = [f"Image:            {rep.path}",
             f"Format:           {rep.format}  ({rep.access})",
             f"Size:             {human(rep.size_bytes)} ({rep.size_bytes} bytes), sector size {rep.sector_size}",
             f"Partition table:  {rep.table.get('type', '?')}  id={rep.table.get('id', '')}",
             f"Host / image dir: {rep.host} / {rep.label}",
             f"Disk device (ro): {rep.disk_dev}   -> {Path(rep.dev_dir) / 'disk'}",
             f"Block devices:    {rep.dev_dir}",
             f"Status:           {rep.status}",
             f"Generated:        {utc_now()} by mount_evidence {VERSION}", ""]
    if rep.volumes:
        lines.append(table(volume_rows(rep), ["ID", "Type", "FS", "Label", "Size", "Status", "Location / reason"]))
    for v in rep.volumes:
        if v.part_name and v.part_name != v.fs_label:
            lines.append(f"  {v.id}: GPT partition name '{v.part_name}'")
        if v.vss.get("stores"):
            lines.append(f"  {v.id}: {v.vss['stores']} volume shadow copies"
                         + ("" if any(x.source == "vss" for x in rep.volumes) else " (mount them with --vss)"))
        for d in v.discrepancies:
            lines.append(f"  {v.id}: DISCREPANCY {d}")
        for n in v.notes:
            lines.append(f"  {v.id}: NOTE {n}")
    if rep.unallocated:
        lines.append("\nUnallocated regions (read from the disk device): " + ", ".join(
            f"sectors {g['start_sector']}-{g['start_sector'] + g['sectors'] - 1} ({human(g['bytes'])})"
            for g in rep.unallocated))
    for w in rep.warnings:
        lines.append(f"WARNING: {w}")
    for e in rep.errors:
        lines.append(f"ERROR [{e['category']}]: {e['message']}")
    lines.append("\nRead-only mounts prevent writes through this tool; they do not prove the image was "
                 "unaltered before acquisition (check ewfverify / acquisition hashes).")
    atomic_write(work / INFO_FILE, "\n".join(lines) + "\n")


# ── Discovery of images ───────────────────────────────────────────────────────
def sanitise(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name.replace(" ", "_"))

def is_ewf_segment(ext: str) -> bool:
    return EWF_SEG_PAT.match(ext.lower()) is not None and ext.lower() not in EWF_FIRST_EXTS

def is_vmdk_flat_data_file(f: Path) -> bool:
    """Skip a flat VMDK data file when a sibling descriptor/sparse VMDK covers it."""
    if f.suffix.lower() != ".vmdk":
        return False
    def header(p: Path) -> bytes:
        try:
            with p.open("rb") as fh:
                return fh.read(4)
        except OSError:
            return b""
    def sparse_or_descriptor(p: Path) -> bool:
        h = header(p)
        return h == b"KDMV" or h[:1] in (b"#", b"v", b"e", b"d")
    if sparse_or_descriptor(f):
        return False
    return any(s != f and sparse_or_descriptor(s) for s in f.parent.glob("*.vmdk"))

def discover(evidence: Path, skip: list[Path]) -> list[tuple[Path, str, str]]:
    if evidence.is_file():
        files, root = [evidence], evidence.parent
    else:
        files, root = [], evidence
        for dirpath, dirnames, filenames in os.walk(evidence):
            dirnames[:] = sorted(d for d in dirnames if not any(
                Path(dirpath, d) == s or s in Path(dirpath, d).parents for s in skip))
            files += [Path(dirpath, f) for f in sorted(filenames)]
    results, seen = [], {}
    for f in sorted(files):
        ext = f.suffix.lower()
        if ext not in ALL_EXTS or is_ewf_segment(ext) or is_vmdk_flat_data_file(f):
            continue
        parts = f.relative_to(root).parts
        hostname = sanitise(root.name if len(parts) == 1 else parts[0])
        base = sanitise(f.stem)
        label, n = f"{base}{f.suffix}", 1
        used = seen.setdefault(hostname, set())
        while label in used:
            label, n = f"{base}_{n}{f.suffix}", n + 1
        used.add(label)
        results.append((f, hostname, label))
    return results


# ── Teardown ──────────────────────────────────────────────────────────────────
def remove_holders(sysname: str) -> tuple[bool, str]:
    """Device-mapper devices stacked on one of ours (e.g. LVs a host udev rule
    auto-activated on evidence) are released first. Never forced."""
    try:
        holders = os.listdir(f"/sys/block/{sysname}/holders")
    except OSError:
        return True, ""
    for h in holders:
        ok, msg = remove_holders(h)
        if not ok:
            return ok, msg
        try:
            name = Path(f"/sys/block/{h}/dm/name").read_text().strip()
        except OSError:
            return False, f"{sysname} is held by {h}"
        r = run(["dmsetup", "remove", name], timeout=30)
        if r.returncode:
            return False, f"{name} (stacked on {sysname}) is in use: {err_text(r)}"
        log.info(f"    removed {name} (stacked on our device)")
    return True, ""

def release(r: dict, lazy: bool, image_dir: str, image_path: str) -> tuple[bool, str]:
    k = r["kind"]
    if k in ("mount", "fuse"):
        mp = r["path"]
        if mp not in mountinfo():
            return True, ""
        res = run(["umount", *(["-l"] if lazy else []), mp], timeout=120)
        if res.returncode == 0:
            return True, f"unmounted {mp}" + (" (lazy)" if lazy else "")
        who = run(["fuser", "-vm", mp], timeout=30)
        held = (who.stderr + who.stdout).strip() if who.returncode != 127 else ""
        return False, f"cannot unmount {mp}: {err_text(res)}" + \
            (f"\n      held by:\n        " + held.replace("\n", "\n        ") if held else "")
    if k == "dm":
        name = r["name"]
        if not dm_exists(name):
            return True, ""
        sysname = dm_blkdev(name)
        if sysname:
            ok, msg = remove_holders(sysname)
            if not ok:
                return False, msg
        for _ in range(3):
            res = run(["dmsetup", "remove", name], timeout=30)
            if res.returncode == 0:
                return True, f"removed {name}"
            time.sleep(0.5)
        return False, f"cannot remove {name}: {err_text(res)}"
    if k == "kpartx":
        parent = r["parent"]
        if r.get("parent_backing") and loop_backing(parent) != r["parent_backing"]:
            return True, ""                            # loop already gone (or reused by someone else)
        if r.get("parent_image") and not nbd_live(parent, r["parent_image"]):
            return True, ""
        maps = r.get("maps")
        if maps is None:                               # v1 state: maps named <parent>p<N> on that parent
            pname = Path(parent).name
            maps = [n for n in dm_names() if re.fullmatch(rf"{re.escape(pname)}p\d+", n)
                    and pname in dm_deps(n)]
        for n in maps:
            sysname = dm_blkdev(n) if dm_exists(n) else None
            if sysname:
                ok, msg = remove_holders(sysname)
                if not ok:
                    return False, msg
        run(["kpartx", "-d", "-v", parent], timeout=60)
        left = [n for n in maps if dm_exists(n)]
        for n in left:
            run(["dmsetup", "remove", n], timeout=30)
        left = [n for n in left if dm_exists(n)]
        if left:
            return False, f"partition mappings still in use: {', '.join(left)}"
        return True, f"removed partition mappings of {parent}" if maps else ""
    if k == "loop":
        dev, backing = r["dev"], r.get("backing")
        cur = loop_backing(dev)
        if not cur or (backing and cur != backing) or \
                (backing is None and cur != image_path and not cur.startswith(image_dir)):
            return True, ""
        ok, msg = remove_holders(Path(dev).name)       # partition maps a kill -9 kept out of the journal
        if not ok:
            return False, msg
        run(["losetup", "-d", dev], timeout=30)
        if wait_for(lambda: loop_backing(dev) != cur, 3):
            return True, f"detached {dev}"
        try:
            holders = os.listdir(f"/sys/block/{Path(dev).name}/holders")
        except OSError:
            holders = []
        return False, f"{dev} is still open{(' by ' + ', '.join(holders)) if holders else ''}; " \
                      f"it is set to detach itself when released"
    if k == "nbd":
        dev = r["dev"]
        if not nbd_live(dev, r.get("image")):
            return True, ""
        run(["qemu-nbd", "--disconnect", dev], timeout=30)
        if wait_for(lambda: not nbd_live(dev, r.get("image")), 5):
            return True, f"disconnected {dev}"
        return False, f"{dev} did not disconnect"
    if k == "dir":
        p = Path(r["path"])
        if p.is_dir() and not is_mounted(p):
            try:
                p.rmdir()
            except OSError:
                log.debug(f"    kept {p} (not empty)")   # e.g. a host folder another image still uses
        return True, ""
    if k == "symlink":
        p = Path(r["path"])
        if p.is_symlink():
            p.unlink()
        return True, ""
    return True, f"unknown resource kind {k} ignored"

def teardown_state(jpath: Path, lazy: bool, quiet: bool = False) -> bool:
    if not jpath.exists():
        return True
    state = load_state(jpath)
    if state is None:
        log.warning(f"  unreadable state file {jpath} - left in place")
        return False
    res = state["resources"]
    say = log.debug if quiet else log.info
    own_files = [jpath.parent / MANIFEST_FILE, jpath.parent / INFO_FILE, jpath]
    while res:
        r = res[-1]
        if r["kind"] == "dir" and Path(r["path"]) == jpath.parent:
            for f in own_files:                        # our files go just before our folder
                try:
                    f.unlink()
                except OSError:
                    pass
        ok, msg = release(r, lazy, state.get("image_dir", ""), state.get("image_path", ""))
        if msg:
            (say if ok else log.error)(f"    {msg}")
        if not ok:
            if state.get("version") == 2:
                atomic_write(jpath, json.dumps(state, indent=2))
            return False
        res.pop()
        if state.get("version") == 2 and jpath.parent.is_dir():
            atomic_write(jpath, json.dumps(state, indent=2))
    for f in own_files:
        try:
            f.unlink()
        except OSError:
            pass
    if state.get("version") == 1:                      # v1 did not record its folders
        for dirpath, _, _ in os.walk(jpath.parent, topdown=False):
            try:
                if not is_mounted(dirpath):
                    os.rmdir(dirpath)
            except OSError:
                pass
    # Host folders are shared by a host's images; the last one out removes it.
    for d in {jpath.parent.parent, Path(state.get("dev_dir") or jpath.parent).parent}:
        try:
            if d.is_dir() and not is_mounted(d):
                d.rmdir()
        except OSError:
            pass
    return True

def state_files(ctx: Ctx) -> list[Path]:
    # Fixed depth: never walk into mounted evidence.
    return sorted(set(ctx.mount_base.glob(f"*/*/{STATE_FILE}")) | set((DRY_ROOT / "mnt").glob(f"*/*/{STATE_FILE}")),
                  reverse=True)

def leftovers(ctx: Ctx, images: set[str]) -> list[str]:
    """Anything that still looks like ours after teardown but is in no journal
    (busy images keep theirs and are reported separately)."""
    known: set[str] = set()
    for sf in state_files(ctx):
        for r in (load_state(sf) or {}).get("resources", []):
            known.update(str(r.get(k)) for k in ("path", "dev", "name") if r.get(k))
            known.update(r.get("maps") or [])
    out = []
    for mp, info in mountinfo().items():
        if mp not in known and any(mp == str(b) or mp.startswith(str(b) + "/")
                                   for b in (ctx.mount_base, ctx.dev_base, DRY_ROOT)):
            out.append(f"mount {mp} ({info['source']}):  umount {shlex.quote(mp)}")
    for bf in glob.glob("/sys/block/loop*/loop/backing_file"):
        dev = "/dev/" + Path(bf).parts[3]
        try:
            back = Path(bf).read_text().strip()
        except OSError:
            continue
        if dev not in known and (back in images or back.startswith(str(ctx.dev_base) + "/")
                                 or back.startswith(str(DRY_ROOT))):
            out.append(f"loop {dev} -> {back}:  losetup -d {dev}")
    for n in dm_names():
        if n.startswith(DM_PREFIX) and n not in known:
            out.append(f"device-mapper {n}:  dmsetup remove {n}")
    return out

def unmount_all(ctx: Ctx, lazy: bool) -> int:
    banner("Unmounting evidence", str(ctx.mount_base))
    files = state_files(ctx)
    images, released, busy = set(), 0, []
    for sf in files:
        st = load_state(sf) or {}
        images.add(st.get("image_path", ""))
        log.info(f"── {st.get('image_path', sf.parent)}")
        if teardown_state(sf, lazy):
            released += 1
        else:
            busy.append(st.get("image_path", str(sf)))
    if not files:
        log.info("No state files found - nothing recorded as mounted by this tool")
    # Empty host/image folders with no journal (a kill -9 between mkdir and the
    # journal's first save). rmdir only ever removes an empty folder.
    for base in (ctx.mount_base, ctx.dev_base, DRY_ROOT / "mnt", DRY_ROOT / "dev"):
        for d in sorted(base.glob("*/*"), reverse=True) + sorted(base.glob("*")):
            try:
                if d.is_dir() and not d.is_symlink() and not is_mounted(d):
                    d.rmdir()
            except OSError:
                pass
    left = leftovers(ctx, images)
    print()
    log.info(f"Released {released} of {len(files)} image(s)")
    for b in busy:
        log.error(f"Still attached (busy): {b} - close the programs listed above, then run --unmount again")
    if left:
        log.warning("Still present and not released (check before removing):")
        for l in left:
            log.warning(f"  {l}")
    if not busy and not left:
        log.info("Nothing left: no mounts, loop devices or mappings from this tool remain")
    return 1 if busy or left else 0


# ── Status ────────────────────────────────────────────────────────────────────
def show_status(ctx: Ctx) -> int:
    files = state_files(ctx)
    if not files:
        print("Nothing is mounted by this tool.")
        return 0
    mounts = mountinfo()
    for sf in sorted(files):
        st = load_state(sf) or {}
        res = st.get("resources", [])
        live_m = [r["path"] for r in res if r["kind"] == "mount" and r["path"] in mounts]
        devs = [r["dev"] for r in res if r["kind"] in ("loop", "nbd") and
                (loop_backing(r["dev"]) or nbd_live(r["dev"], r.get("image")))]
        print(f"{BOLD}{st.get('image_path', '?')}{RESET}")
        print(f"  folder:  {sf.parent}")
        print(f"  devices: {', '.join(devs) or 'none'}   dm: {', '.join(n for r in res if r['kind'] == 'kpartx' for n in (r.get('maps') or [])) or '-'}")
        for m in live_m:
            print(f"  mounted: {m}  [{mounts[m]['fstype']} {mounts[m]['opts'].split(',')[0]}]")
    return 0


# ── UI ────────────────────────────────────────────────────────────────────────
def banner(title: str, detail: str = ""):
    line = "═" * 60
    print(f"\n{BOLD}{CYAN}{line}{RESET}\n{BOLD}{CYAN}  {title}{RESET}")
    if detail:
        print(f"{CYAN}  {detail}{RESET}")
    print(f"{BOLD}{CYAN}{line}{RESET}")

COLOUR_BY_STATUS = {"mounted": GREEN, "planned": CYAN, "block_device": CYAN, "skipped": "", "failed": RED}

def print_image(rep: ImageReport):
    head = f"{rep.format or '?'}, {human(rep.size_bytes)}, {rep.table.get('type', '?')}"
    print(f"  {head}   disk {rep.disk_dev or '-'}")
    if rep.volumes:
        rows = volume_rows(rep)
        text = table(rows, ["ID", "Type", "FS", "Label", "Size", "Status", "Location / reason"]).splitlines()
        print("  " + text[0])
        for v, line in zip(rep.volumes, text[1:]):
            c = COLOUR_BY_STATUS.get(v.status, "")
            print(f"  {c}{line}{RESET if c else ''}")
    for v in rep.volumes:
        for d in v.discrepancies:
            log.warning(f"  {v.id}: {d}")
        for n in v.notes:
            log.warning(f"  {v.id}: {n}")
    for w in rep.warnings:
        log.warning(f"  {w}")
    for e in rep.errors:
        log.error(f"  [{e['category']}] {e['message']}")

def print_summary(reports: list[ImageReport], ctx: Ctx, log_file: str):
    vols = [v for r in reports for v in r.volumes]
    count = lambda s: sum(1 for v in vols if v.status == s)
    failed = [(r, v) for r in reports for v in r.volumes
              if v.status == "failed" or v.category in ("damaged", "ambivalent")]
    print(f"\n{BOLD}{'═' * 60}{RESET}\n{BOLD}  Summary{RESET}\n{'─' * 60}")
    print(f"  Images:   {len(reports)}  (ok {sum(r.status == 'ok' for r in reports)}, "
          f"partial {sum(r.status == 'partial' for r in reports)}, failed {sum(r.status == 'failed' for r in reports)}, "
          f"already mounted {sum(r.status == 'already_mounted' for r in reports)})")
    print(f"  Volumes:  {len(vols)}  (mounted {count('mounted')}, planned {count('planned')}, "
          f"block-only {count('block_device')}, skipped {count('skipped')}, failed {count('failed')})")
    cats: dict[str, int] = {}
    for v in vols:
        if v.status == "skipped" and v.category not in ("damaged", "ambivalent"):
            cats[v.category] = cats.get(v.category, 0) + 1
    if cats:
        print("  Skipped by design: " + ", ".join(f"{k} {n}" for k, n in sorted(cats.items())))
    if failed or any(r.errors for r in reports):
        print(f"  {RED}Needs attention:{RESET}")
        for r, v in failed:
            print(f"    {r.host}/{r.label} {v.id}: [{v.category}] {v.reason}")
        for r in reports:
            for e in r.errors:
                print(f"    {r.host}/{r.label}: [{e['category']}] {e['message']}")
    special = [(r, v) for r in reports for v in r.volumes if v.category in ("encrypted", "needs_tooling")
               or v.vss.get("stores")]
    if special:
        print("  Needs other tooling:")
        for r, v in special:
            what = f"{v.vss['stores']} shadow copies (--vss)" if v.vss.get("stores") else v.reason
            print(f"    {r.host}/{r.label} {v.id}: {what}")
    print(f"{'─' * 60}\n  Mounts:        {ctx.mount_base}\n  Block devices: {ctx.dev_base}\n  Log:           {log_file}")
    print(f"{BOLD}{'═' * 60}{RESET}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(prog="mount_evidence.py", description="Forensic Evidence Mass Mounter (read-only)",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("evidence_root", nargs="?", metavar="EVIDENCE_ROOT|IMAGE")
    p.add_argument("-o", "--mount-base", default="/mnt/IOC_SCAN")
    p.add_argument("--dev-base", help="block-device symlinks and helper mounts (default: <mount-base>_dev)")
    p.add_argument("-l", "--log", default="/var/log/mount_evidence.log")
    p.add_argument("-d", "--dry-run", action="store_true",
                   help="identify partitions read-only, print the plan, leave nothing attached")
    p.add_argument("--block-only", action="store_true",
                   help="attach read-only block devices and write the manifest, but mount nothing")
    p.add_argument("--vss", action="store_true",
                   help="EXPERIMENTAL: also mount NTFS volume shadow copies (vshadowmount)")
    p.add_argument("--ntfs-driver", choices=["ntfs-3g", "ntfs3"], default="ntfs-3g")
    p.add_argument("-u", "--unmount", action="store_true", help="release everything this tool attached")
    p.add_argument("--lazy", action="store_true", help="with --unmount: lazy-unmount busy mounts (umount -l)")
    p.add_argument("--status", action="store_true", help="list what this tool currently has attached")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--nbd-max", type=int, default=0, metavar="N",
                   help="reload nbd with N slots first (rmmod nbd && modprobe nbd nbds_max=N max_part=0)")
    p.add_argument("-r", "--readonly", action="store_true", help=argparse.SUPPRESS)   # always on; kept for old scripts
    p.add_argument("-w", "--readwrite", action="store_true", help=argparse.SUPPRESS)
    return p

def acquire_lock():
    Path(LOCK_FILE).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        other = os.pread(fd, 32, 0).decode(errors="replace").strip()
        log.error(f"Another mount_evidence is running (pid {other or '?'}); wait for it to finish")
        sys.exit(1)
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd

def main() -> int:
    args = build_parser().parse_args()
    setup_logging(args.log, args.verbose)
    if args.readwrite:
        log.error("Read-write mounting was removed: evidence is always mounted read-only. Work on a copy instead.")
        return 2
    if os.geteuid() != 0:
        log.error("Must run as root")
        return 1
    mount_base = Path(args.mount_base).resolve()
    ctx = Ctx(mount_base=mount_base, dev_base=Path(args.dev_base).resolve() if args.dev_base
              else mount_base.with_name(mount_base.name + "_dev"),
              block_only=args.block_only, vss=args.vss, dry_run=args.dry_run, ntfs_driver=args.ntfs_driver)
    if args.status:
        return show_status(ctx)
    lock = acquire_lock()
    if args.unmount:
        return unmount_all(ctx, args.lazy)
    if not args.evidence_root:
        build_parser().print_help()
        return 2
    evidence = Path(args.evidence_root).resolve()
    if not evidence.exists():
        log.error(f"Not found: {evidence}")
        return 2
    if not check_deps():
        return 1
    if args.nbd_max > 0 and args.nbd_max != nbd_get_max():
        log.info(f"Reloading nbd module: nbds_max={args.nbd_max} max_part=0")
        for cmd in (["rmmod", "nbd"], ["modprobe", "nbd", f"nbds_max={args.nbd_max}", "max_part=0"]):
            r = run(cmd)
            if r.returncode:
                log.warning(f"Could not reload nbd: {err_text(r)}")
                break

    images = discover(evidence, [ctx.mount_base, ctx.dev_base])
    if not images:
        log.error(f"No forensic images found under {evidence} (supported: {', '.join(sorted(ALL_EXTS))})")
        return 1
    for d in (ctx.mount_base, ctx.dev_base) if not ctx.dry_run else (DRY_ROOT / "mnt", DRY_ROOT / "dev"):
        d.mkdir(parents=True, exist_ok=True)
    mode = "DRY RUN (identify only)" if ctx.dry_run else "BLOCK DEVICES ONLY" if ctx.block_only else "READ-ONLY"
    banner("Forensic Evidence Mass Mounter " + VERSION,
           f"Root: {evidence} | Base: {ctx.mount_base} | Mode: {mode} | Images: {len(images)}")

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    reports = []
    for img, host, label in images:
        if STOP:
            break
        print(f"\n{BOLD}── {host} / {label}{RESET}   ({img})")
        rep = process_image(img, host, label, ctx)
        print_image(rep)
        reports.append(rep)
    print_summary(reports, ctx, args.log)
    if STOP:
        log.warning("Stopped early by interrupt. Run --unmount to release what was attached.")
        return 130
    bad = any(r.status in ("failed", "partial") for r in reports)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
