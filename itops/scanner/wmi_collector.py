from __future__ import annotations

import subprocess
from typing import Any, Dict, List


def _ps_remote(ip: str, user: str, password: str, script: str) -> str:
    """Run PowerShell script on remote machine via Invoke-Command."""
    full_script = f"""
$pass = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{user}', $pass)
Invoke-Command -ComputerName {ip} -Credential $cred -ScriptBlock {{ {script} }} -ErrorAction Stop
"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", full_script],
            capture_output=True, timeout=60
        )
        return r.stdout.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        return f"__ERROR__:{e}"


def _ps_local_wmi(ip: str, user: str, password: str, wmi_class: str, props: List[str]) -> List[Dict[str, str]]:
    """Query WMI on remote machine via PowerShell Get-WmiObject."""
    prop_str = ", ".join(props)
    script = f"Get-WmiObject -Class {wmi_class} -ComputerName {ip} -Credential (New-Object PSCredential('{user}',(ConvertTo-SecureString '{password}' -AsPlainText -Force))) | Select-Object {prop_str} | ConvertTo-Json -Compress"
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=60
        )
        out = r.stdout.decode("utf-8", errors="ignore").strip()
        if not out or "__ERROR__" in out:
            return []
        import json
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{k: str(v) if v is not None else "" for k, v in item.items() if k in props} for item in data]
    except Exception:
        return []


def collect_remote(ip: str, hostname: str, user: str, password: str) -> Dict[str, Any]:
    """Collect machine info via PowerShell/WMI without agent."""
    try:
        return _collect_remote_inner(ip, hostname, user, password)
    except Exception as e:
        return {"source": "wmi_remote", "asset": {}, "installed_software": [], "services_running": [], "error": str(e)}


def _collect_remote_inner(ip: str, hostname: str, user: str, password: str) -> Dict[str, Any]:

    def _query(wmi_class: str, props: List[str]) -> Dict[str, str]:
        rows = _ps_local_wmi(ip, user, password, wmi_class, props)
        return rows[0] if rows else {}

    # Test connection first
    test = _ps_remote(ip, user, password, "$env:COMPUTERNAME")
    if "__ERROR__" in test:
        return {"source": "wmi_remote", "asset": {}, "installed_software": [], "services_running": [], "error": test.replace("__ERROR__:", "")}

    # OS
    os_info = _query("Win32_OperatingSystem", ["Caption", "Version", "LastBootUpTime"])

    # CPU
    cpu_info = _query("Win32_Processor", ["Name", "NumberOfCores", "MaxClockSpeed"])

    # RAM
    mem_info = _query("Win32_ComputerSystem", ["TotalPhysicalMemory", "UserName"])
    try:
        ram_gb = round(int(mem_info.get("TotalPhysicalMemory", 0)) / 1024**3, 2)
    except Exception:
        ram_gb = 0

    # Disk C:
    disk_script = f"Get-WmiObject -Class Win32_LogicalDisk -ComputerName {ip} -Credential (New-Object PSCredential('{user}',(ConvertTo-SecureString '{password}' -AsPlainText -Force))) -Filter \"DeviceID='C:'\" | Select-Object Size,FreeSpace | ConvertTo-Json -Compress"
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", disk_script], capture_output=True, timeout=30)
        import json
        disk_raw = json.loads(r.stdout.decode("utf-8", errors="ignore").strip() or "{}")
        disk_total = round(int(disk_raw.get("Size", 0)) / 1024**3, 2)
        disk_free = round(int(disk_raw.get("FreeSpace", 0)) / 1024**3, 2)
    except Exception:
        disk_total = disk_free = 0

    # BIOS
    bios_info = _query("Win32_BIOS", ["ReleaseDate", "SMBIOSBIOSVersion"])
    bios_date = bios_info.get("ReleaseDate", "")[:8]
    if len(bios_date) == 8 and bios_date.isdigit():
        bios_date = f"{bios_date[:4]}-{bios_date[4:6]}-{bios_date[6:8]}"

    # Installed software via registry (faster than Win32_Product)
    sw_script = f"""
$cred = New-Object PSCredential('{user}',(ConvertTo-SecureString '{password}' -AsPlainText -Force))
Invoke-Command -ComputerName {ip} -Credential $cred -ScriptBlock {{
    $paths = @(
        'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
        'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object {{ $_.DisplayName }} |
        Select-Object -ExpandProperty DisplayName |
        Sort-Object -Unique
}} | ConvertTo-Json -Compress"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", sw_script], capture_output=True, timeout=60)
        import json
        sw_raw = r.stdout.decode("utf-8", errors="ignore").strip()
        installed_software = sorted(json.loads(sw_raw)) if sw_raw and sw_raw.startswith("[") else []
    except Exception:
        installed_software = []

    # Running services
    svc_script = f"""
$cred = New-Object PSCredential('{user}',(ConvertTo-SecureString '{password}' -AsPlainText -Force))
Invoke-Command -ComputerName {ip} -Credential $cred -ScriptBlock {{
    Get-Service | Where-Object {{$_.Status -eq 'Running'}} | Select-Object -ExpandProperty DisplayName | Sort-Object
}} | ConvertTo-Json -Compress"""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", svc_script], capture_output=True, timeout=30)
        import json
        svc_raw = r.stdout.decode("utf-8", errors="ignore").strip()
        services = json.loads(svc_raw) if svc_raw and svc_raw.startswith("[") else []
    except Exception:
        services = []

    return {
        "source": "wmi_remote",
        "asset": {
            "hostname": hostname,
            "ip": ip,
            "os": os_info.get("Caption", "-"),
            "os_version": os_info.get("Version", "-"),
            "cpu": cpu_info.get("Name", "-"),
            "cpu_cores": cpu_info.get("NumberOfCores", "-"),
            "ram_gb": ram_gb,
            "disk_total_gb": disk_total,
            "disk_free_gb": disk_free,
            "bios_date": bios_date or "-",
            "last_user": mem_info.get("UserName", "-"),
            "last_boot": os_info.get("LastBootUpTime", "-")[:12],
        },
        "installed_software": installed_software,
        "services_running": services,
        "error": None,
    }
