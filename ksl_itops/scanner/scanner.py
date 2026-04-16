from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_IS_WINDOWS = platform.system() == "Windows"
COMMON_PORTS = {
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
}


@dataclass
class ScanResult:
    ip: str
    hostname: str
    status: str          # online / offline / no_hostname
    open_ports: List[int]
    services: Dict[int, str]
    scanned_at: str


def _ping(ip: str, timeout: int = 1) -> bool:
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return r.returncode == 0
    except Exception:
        return False


def _get_netbios_name(ip: str) -> str:
    """Query NetBIOS name via nbtstat — Windows computer name only."""
    if not _IS_WINDOWS:
        return ""
    try:
        r = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True, text=True, timeout=5, encoding="utf-8", errors="ignore"
        )
        for line in r.stdout.splitlines():
            # Look for <00> UNIQUE entry = computer name
            if "<00>" in line and "UNIQUE" in line:
                name = line.strip().split()[0].strip().rstrip("\x00").strip()
                # Remove <XX> suffix if present
                if "<" in name:
                    name = name[:name.index("<")].strip()
                if name:
                    return name.upper()
    except Exception:
        pass
    return ""


def _check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _scan_host(ip: str) -> ScanResult:
    now = datetime.now(timezone.utc).isoformat()
    alive = _ping(ip)
    if not alive:
        return ScanResult(ip=ip, hostname="", status="offline", open_ports=[], services={}, scanned_at=now)

    open_ports = [p for p in COMMON_PORTS if _check_port(ip, p)]
    services = {p: COMMON_PORTS[p] for p in open_ports}

    # Must have SMB (445) to be considered a Windows computer
    if 445 not in open_ports:
        return ScanResult(ip=ip, hostname="", status="no_hostname", open_ports=open_ports, services=services, scanned_at=now)

    # Only get NetBIOS name (Windows computer name)
    # Skip devices without NetBIOS (routers, printers, cameras, etc.)
    hostname = _get_netbios_name(ip)
    status = "online" if hostname else "no_hostname"

    return ScanResult(
        ip=ip,
        hostname=hostname,
        status=status,
        open_ports=open_ports,
        services=services,
        scanned_at=now,
    )


def scan_cidr(cidr: str, max_workers: int = 50) -> List[ScanResult]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    results: List[ScanResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    results.sort(key=lambda r: ipaddress.ip_address(r.ip))
    return results


def scan_segments(segments: List[Dict[str, Any]], max_workers: int = 50) -> List[ScanResult]:
    all_results: List[ScanResult] = []
    for seg in segments:
        cidr = seg.get("cidr") or ""
        if not cidr:
            continue
        results = scan_cidr(cidr, max_workers=max_workers)
        # tag segment name
        for r in results:
            r.__dict__["network_segment"] = seg.get("name") or cidr
        all_results.extend(results)
    return all_results
