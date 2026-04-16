from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from typing import Any, Dict

_IS_WINDOWS = platform.system() == "Windows"


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


def action_clear_temp(params: Dict[str, Any]) -> Dict[str, Any]:
    removed = 0
    errors = []
    dirs = []

    if _IS_WINDOWS:
        dirs = [
            tempfile.gettempdir(),
            os.path.expandvars(r"%WINDIR%\Temp"),
            os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
        ]
    else:
        dirs = ["/tmp"]

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            path = os.path.join(d, name)
            try:
                if os.path.isfile(path) or os.path.islink(path):
                    os.remove(path)
                    removed += 1
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                    removed += 1
            except Exception as e:
                errors.append(str(e))

    return {"removed_items": removed, "errors": errors[:10], "dirs_cleaned": dirs}


def action_check_software(params: Dict[str, Any]) -> Dict[str, Any]:
    if not _IS_WINDOWS:
        return {"error": "Windows only"}
    try:
        import winreg
        software = []
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        seen: set[str] = set()
        for hive, path in keys:
            try:
                with winreg.OpenKey(hive, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
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
        return {"installed_software": sorted(software), "count": len(software)}
    except Exception as e:
        return {"error": str(e)}


def action_check_disk(params: Dict[str, Any]) -> Dict[str, Any]:
    import psutil
    path = params.get("path", "C:\\" if _IS_WINDOWS else "/")
    try:
        usage = psutil.disk_usage(path)
        return {
            "path": path,
            "total_gb": round(usage.total / 1024**3, 2),
            "used_gb": round(usage.used / 1024**3, 2),
            "free_gb": round(usage.free / 1024**3, 2),
            "percent": usage.percent,
        }
    except Exception as e:
        return {"error": str(e)}


def action_check_antivirus(params: Dict[str, Any]) -> Dict[str, Any]:
    if not _IS_WINDOWS:
        return {"error": "Windows only"}
    code, out = _run([
        "wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct",
        "get", "displayName,productState", "/value"
    ])
    products = []
    current: Dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            current[k.strip()] = v.strip()
        elif not line.strip() and current:
            if current.get("displayName"):
                products.append(current)
            current = {}
    if current.get("displayName"):
        products.append(current)
    return {"products": products, "count": len(products)}


def action_kill_process(params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name") or ""
    pid = params.get("pid")
    if not name and not pid:
        return {"error": "Provide 'name' or 'pid'"}
    import psutil
    killed = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if (pid and proc.pid == int(pid)) or (name and name.lower() in proc.name().lower()):
                proc.kill()
                killed.append({"pid": proc.pid, "name": proc.name()})
        except Exception:
            pass
    return {"killed": killed, "count": len(killed)}


def action_restart_service(params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name") or ""
    if not name:
        return {"error": "Provide 'name'"}
    if _IS_WINDOWS:
        code, out = _run(["sc", "stop", name])
        _run(["sc", "start", name])
        code2, out2 = _run(["sc", "query", name])
        return {"service": name, "stop_output": out, "query_output": out2}
    else:
        code, out = _run(["systemctl", "restart", name])
        return {"service": name, "returncode": code, "output": out}


_ACTION_MAP = {
    "clear_temp": action_clear_temp,
    "check_software": action_check_software,
    "check_disk": action_check_disk,
    "check_antivirus": action_check_antivirus,
    "kill_process": action_kill_process,
    "restart_service": action_restart_service,
}


def execute_action(action: str, params: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
    fn = _ACTION_MAP.get(action)
    if not fn:
        return False, {"error": f"Unknown action: {action}"}
    try:
        result = fn(params)
        return True, result
    except Exception as e:
        return False, {"error": str(e)}
