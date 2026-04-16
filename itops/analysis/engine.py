from __future__ import annotations

from typing import Any, Dict, List, Optional


def _score_deduction(severity: str) -> int:
    return {"low": 5, "medium": 15, "high": 25, "critical": 40}.get(severity, 0)


def _check_software(installed: List[str], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = []
    installed_lower = {s.lower() for s in installed}

    for req in policy.get("required") or []:
        if not any(req.lower() in s for s in installed_lower):
            issues.append({
                "type": "software",
                "scope": "device_issue",
                "severity": "high",
                "description": f"Required software not installed: {req}",
                "root_cause": "Software missing from installed list",
                "recommendation": f"Install {req} immediately via software deployment tool",
            })

    for forbidden in policy.get("forbidden") or []:
        if any(forbidden.lower() in s for s in installed_lower):
            issues.append({
                "type": "software",
                "scope": "device_issue",
                "severity": "critical",
                "description": f"Forbidden software detected: {forbidden}",
                "root_cause": "Unauthorized software installed on machine",
                "recommendation": f"Uninstall {forbidden} immediately and audit user activity",
            })

    return issues


def _check_checklist(checklist: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = []

    av = checklist.get("antivirus")
    if av == "not_installed":
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "critical",
            "description": "Antivirus not installed",
            "root_cause": "No endpoint protection present",
            "recommendation": "Deploy antivirus agent immediately via GPO",
        })
    elif av == "outdated":
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "high",
            "description": "Antivirus definitions are outdated",
            "root_cause": "Antivirus not updated",
            "recommendation": "Force antivirus definition update via management console",
        })

    if checklist.get("admin_rights"):
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "high",
            "description": "User is running with administrator rights",
            "root_cause": "Standard user account has elevated privileges",
            "recommendation": "Revoke admin rights and enforce least-privilege policy via GPO",
        })

    if not checklist.get("internet_access"):
        issues.append({
            "type": "config",
            "scope": "device_issue",
            "severity": "medium",
            "description": "No internet connectivity detected",
            "root_cause": "Network misconfiguration or firewall block",
            "recommendation": "Check network gateway and DNS settings",
        })

    if checklist.get("wmi_service") == "stopped":
        issues.append({
            "type": "config",
            "scope": "device_issue",
            "severity": "medium",
            "description": "WMI service is stopped",
            "root_cause": "Windows Management Instrumentation service not running",
            "recommendation": "Start WMI service: sc start winmgmt",
        })

    vnc = checklist.get("vnc_status")
    if vnc == "running":
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "high",
            "description": "VNC service is running",
            "root_cause": "Remote access tool active without authorization",
            "recommendation": "Stop and disable VNC service unless explicitly authorized",
        })

    if not checklist.get("disk_cleanup"):
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "medium",
            "description": "Disk usage above 90% — cleanup required",
            "root_cause": "Insufficient free disk space",
            "recommendation": "Run disk cleanup, remove temp files, archive old data",
        })

    return issues


def _check_metrics(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = []

    cpu = metrics.get("cpu_usage") or 0
    ram = metrics.get("ram_usage") or 0
    disk = metrics.get("disk_usage_percent") or 0

    if cpu >= 90:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "high",
            "description": f"CPU usage critical: {cpu}%",
            "root_cause": "Process consuming excessive CPU resources",
            "recommendation": "Identify and terminate runaway process via Task Manager or taskkill",
        })
    elif cpu >= 75:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "medium",
            "description": f"CPU usage elevated: {cpu}%",
            "root_cause": "High CPU load",
            "recommendation": "Monitor CPU usage and identify top processes",
        })

    if ram >= 90:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "high",
            "description": f"RAM usage critical: {ram}%",
            "root_cause": "Insufficient memory for current workload",
            "recommendation": "Close unnecessary applications or consider RAM upgrade",
        })
    elif ram >= 80:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "medium",
            "description": f"RAM usage elevated: {ram}%",
            "root_cause": "High memory consumption",
            "recommendation": "Monitor memory usage and identify top consumers",
        })

    if disk >= 95:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "critical",
            "description": f"Disk almost full: {disk}%",
            "root_cause": "Disk space critically low",
            "recommendation": "Immediately free disk space — delete temp files, move data to network storage",
        })
    elif disk >= 85:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "medium",
            "description": f"Disk usage high: {disk}%",
            "root_cause": "Low available disk space",
            "recommendation": "Run disk cleanup and review large files",
        })

    return issues


def _check_asset(asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = []

    ram_gb = asset.get("ram_gb") or 0
    if ram_gb < 4:
        issues.append({
            "type": "config",
            "scope": "device_issue",
            "severity": "medium",
            "description": f"Low RAM: {ram_gb} GB",
            "root_cause": "Hardware below minimum recommended specification",
            "recommendation": "Schedule RAM upgrade to minimum 8 GB",
        })

    bios_date = str(asset.get("bios_date") or "")
    if len(bios_date) >= 4:
        try:
            bios_year = int(bios_date[:4])
            if bios_year < 2015:
                issues.append({
                    "type": "config",
                    "scope": "device_issue",
                    "severity": "low",
                    "description": f"Outdated BIOS: {bios_date}",
                    "root_cause": "BIOS has not been updated in many years",
                    "recommendation": "Check vendor site for BIOS update",
                })
        except ValueError:
            pass

    return issues


def analyze_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    asset = payload.get("asset") or {}
    checklist = payload.get("checklist") or {}
    metrics = payload.get("metrics") or {}
    installed_software = payload.get("installed_software") or []
    software_policy = payload.get("software_policy") or {}

    issues: List[Dict[str, Any]] = []
    issues += _check_checklist(checklist)
    issues += _check_metrics(metrics)
    issues += _check_software(installed_software, software_policy)
    issues += _check_asset(asset)

    # Sort: critical > high > medium > low
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    issues.sort(key=lambda x: _order.get(x.get("severity", "low"), 3))

    score = max(0, 100 - sum(_score_deduction(i["severity"]) for i in issues))

    if score >= 80:
        status = "healthy"
    elif score >= 50:
        status = "warning"
    else:
        status = "critical"

    return {
        "status": status,
        "scope": "device",
        "network_segment": asset.get("network_segment") or "unknown",
        "compliance_score": score,
        "issues": issues,
        "insight": "",
        "summary": (
            f"Found {len(issues)} issue(s). Compliance score: {score}/100."
            if issues else "No issues detected. Machine is healthy."
        ),
    }


def analyze_segment(payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Cross-machine analysis for a network segment."""
    if not payloads:
        return {"status": "unknown", "machines": 0, "issues": [], "insight": "No data"}

    results = [analyze_payload(p) for p in payloads]
    segment = (payloads[0].get("asset") or {}).get("network_segment") or "unknown"

    # Detect network-wide patterns
    network_issues: List[Dict[str, Any]] = []
    total = len(results)

    # Count issue types across machines
    issue_counter: Dict[str, int] = {}
    for r in results:
        seen_in_machine: set[str] = set()
        for issue in r.get("issues") or []:
            key = issue.get("description") or ""
            if key not in seen_in_machine:
                issue_counter[key] = issue_counter.get(key, 0) + 1
                seen_in_machine.add(key)

    for desc, count in issue_counter.items():
        if count >= max(2, total // 2):  # affects >= 50% or at least 2 machines
            network_issues.append({
                "type": "config",
                "scope": "network_issue",
                "severity": "high",
                "description": f"[{count}/{total} machines] {desc}",
                "root_cause": "Systemic issue affecting multiple machines in segment",
                "recommendation": "Apply fix via GPO or automated deployment across segment",
            })

    avg_score = int(sum(r["compliance_score"] for r in results) / total)
    critical_count = sum(1 for r in results if r["status"] == "critical")
    warning_count = sum(1 for r in results if r["status"] == "warning")

    if critical_count > 0:
        seg_status = "critical"
    elif warning_count > total // 2:
        seg_status = "warning"
    else:
        seg_status = "healthy"

    insight = ""
    if network_issues:
        insight = f"{len(network_issues)} systemic issue(s) detected across {total} machines in segment {segment}"

    return {
        "status": seg_status,
        "scope": "network",
        "network_segment": segment,
        "machines": total,
        "avg_compliance_score": avg_score,
        "critical_machines": critical_count,
        "warning_machines": warning_count,
        "network_issues": network_issues,
        "insight": insight,
        "summary": f"Segment {segment}: {total} machines, avg score {avg_score}/100, {critical_count} critical",
    }
