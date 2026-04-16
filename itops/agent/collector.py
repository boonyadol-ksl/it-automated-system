from __future__ import annotations

import platform
import socket
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from .policies import SoftwarePolicy

_DISK_PATH = "C:\\" if platform.system() == "Windows" else "/"
_IS_WINDOWS = platform.system() == "Windows"


@dataclass(frozen=True)
class AssetInfo:
    hostname: str
    ip: str
    network_segment: str
    role: str
    os: str
    cpu: str
    ram_gb: float
    disk_total_gb: float
    disk_free_gb: float
    bios_date: str
    last_seen: str


@dataclass(frozen=True)
class Checklist:
    antivirus: str          # installed / not_installed / outdated
    admin_rights: bool
    internet_access: bool
    wmi_service: str        # running / stopped
    vnc_status: str         # running / stopped / not_installed
    disk_cleanup: bool      # True = disk free > 10%


@dataclass(frozen=True)
class Metrics:
    cpu_usage: float
    ram_usage: float
    disk_usage_percent: float


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "0.0.0.0"


def _bytes_to_gb(value: float) -> float:
    return round(value / (1024**3), 2)


def _run_ps(cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, timeout=timeout
        )
        return r.stdout.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _get_bios_date() -> str:
    if not _IS_WINDOWS:
        return "unknown"
    out = _run_ps("(Get-WmiObject Win32_BIOS).ReleaseDate")
    # Format: 20230101000000.000000+000 → 2023-01-01
    if out and len(out) >= 8 and out[:8].isdigit():
        d = out[:8]
        return f"{d[:4]}-{d[4:6]}-{d[6:8]}"
    return "unknown"


def _get_cpu_name() -> str:
    if _IS_WINDOWS:
        out = _run_ps("(Get-WmiObject Win32_Processor).Name")
        if out:
            return out.strip()
    return platform.processor() or "unknown"


def _get_installed_software() -> List[str]:
    if not _IS_WINDOWS:
        return []
    software: List[str] = []
    try:
        import winreg
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        seen: set[str] = set()
        for hive, path in keys:
            try:
                with winreg.OpenKey(hive, path) as key:
                    count = winreg.QueryInfoKey(key)[0]
                    for i in range(count):
                        try:
                            sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                            name, _ = winreg.QueryValueEx(sub, "DisplayName")
                            if name and name not in seen:
                                seen.add(name)
                                software.append(name)
                        except Exception:
                            pass
            except Exception:
                pass
    except ImportError:
        pass
    return sorted(software)


def _get_antivirus_status() -> str:
    if not _IS_WINDOWS:
        return "unknown"
    # Known EDR/AV process names (Cortex XDR, Defender, etc.)
    _AV_PROCESSES = {
        "cortex": "Cortex XDR",
        "cytool": "Cortex XDR",
        "traps": "Cortex XDR",
        "msmpeng": "Windows Defender",
        "msseces": "Microsoft Security Essentials",
        "avgnt": "Avast/AVG",
        "avguard": "Avast/AVG",
        "ekrn": "ESET",
        "bdagent": "Bitdefender",
        "mcshield": "McAfee",
        "savservice": "Sophos",
        "csc": "CrowdStrike",
        "csfalconservice": "CrowdStrike",
    }
    try:
        running = {p.name().lower() for p in psutil.process_iter(["name"])}
        for proc_key, av_name in _AV_PROCESSES.items():
            if any(proc_key in p for p in running):
                return f"installed ({av_name})"
    except Exception:
        pass
    # Fallback: SecurityCenter2 via wmic
    try:
        result = subprocess.run(
            ["wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct",
             "get", "displayName,productState", "/value"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        if "displayName=" in output.lower():
            for line in output.splitlines():
                if "productState=" in line:
                    try:
                        state = int(line.split("=", 1)[1].strip())
                        mid = format(state, "06x")[2:4]
                        return "installed" if mid == "10" else "outdated"
                    except Exception:
                        pass
            return "installed"
    except Exception:
        pass
    return "not_installed"


def _is_admin() -> bool:
    if not _IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _check_internet() -> bool:
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except Exception:
        return False


def _get_service_status(service_name: str) -> str:
    try:
        for svc in psutil.win_service_iter():
            if svc.name().lower() == service_name.lower():
                return "running" if svc.status() == "running" else "stopped"
    except Exception:
        pass
    return "not_installed"


def _get_vnc_status() -> str:
    vnc_services = ["vncserver", "tvnserver", "winvnc4", "uvnc_service"]
    for name in vnc_services:
        status = _get_service_status(name)
        if status != "not_installed":
            return status
    return "not_installed"


class SystemCollector:
    def __init__(self, network_segment: str, role: str, policy: SoftwarePolicy):
        self.network_segment = network_segment
        self.role = role
        self.policy = policy

    def collect_asset_info(self) -> AssetInfo:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(_DISK_PATH)
        return AssetInfo(
            hostname=platform.node() or socket.gethostname(),
            ip=_get_ip(),
            network_segment=self.network_segment,
            role=self.role,
            os=f"{platform.system()} {platform.release()}",
            cpu=_get_cpu_name(),
            ram_gb=_bytes_to_gb(float(vm.total)),
            disk_total_gb=_bytes_to_gb(float(disk.total)),
            disk_free_gb=_bytes_to_gb(float(disk.free)),
            bios_date=_get_bios_date(),
            last_seen=_utc_now_iso(),
        )

    def collect_checklist(self) -> Checklist:
        disk = psutil.disk_usage(_DISK_PATH)
        return Checklist(
            antivirus=_get_antivirus_status(),
            admin_rights=_is_admin(),
            internet_access=_check_internet(),
            wmi_service=_get_service_status("winmgmt"),
            vnc_status=_get_vnc_status(),
            disk_cleanup=disk.percent < 90.0,
        )

    def collect_installed_software(self) -> List[str]:
        return _get_installed_software()

    def collect_metrics(self) -> Metrics:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(_DISK_PATH)
        return Metrics(
            cpu_usage=float(psutil.cpu_percent(interval=0.5)),
            ram_usage=float(vm.percent),
            disk_usage_percent=float(disk.percent),
        )

    def compile_payload(self) -> Dict[str, Any]:
        asset = self.collect_asset_info()
        checklist = self.collect_checklist()
        metrics = self.collect_metrics()
        installed_software = self.collect_installed_software()

        return {
            "asset": asdict(asset),
            "checklist": asdict(checklist),
            "metrics": asdict(metrics),
            "installed_software": installed_software,
            "software_policy": asdict(self.policy),
            "agent_version": "0.2.0",
            "collection_timestamp": _utc_now_iso(),
        }
