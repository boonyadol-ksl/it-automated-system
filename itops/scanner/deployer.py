from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class DeployResult:
    ip: str
    hostname: str
    success: bool
    message: str


# Task Scheduler XML template
_TASK_XML = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT4H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>{python_exe}</Command>
      <Arguments>-m itops.agent.run --config "{config_path}" --policies "{policies_path}"</Arguments>
      <WorkingDirectory>{work_dir}</WorkingDirectory>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
  </Settings>
</Task>
"""


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return -1, str(e)


def deploy_via_psexec(
    ip: str,
    hostname: str,
    agent_source_dir: str,
    agent_dest_dir: str,
    python_exe: str,
    config_path: str,
    policies_path: str,
    domain_user: str,
    domain_password: str,
) -> DeployResult:
    """
    Deploy agent to remote machine using PsExec + file copy via UNC path.
    Requirements: PsExec in PATH, SMB port 445 open, admin share accessible.
    """
    dest_unc = agent_dest_dir.replace(':', '$').replace('\\', '\\\\', 1)
    unc_dest = f"\\\\{ip}\\{dest_unc}"

    # 1. Copy agent files via SMB
    code, out = _run(["robocopy", agent_source_dir, unc_dest, "/E", "/NFL", "/NDL", "/NJH"])
    if code >= 8:
        return DeployResult(ip=ip, hostname=hostname, success=False, message=f"robocopy failed: {out}")

    # 2. Register Task Scheduler via PsExec
    task_xml = _TASK_XML.format(
        python_exe=python_exe,
        config_path=config_path,
        policies_path=policies_path,
        work_dir=os.path.dirname(agent_dest_dir),
    )
    xml_unc = f"{unc_dest}\\ksl_agent_task.xml"
    try:
        with open(xml_unc, "w", encoding="utf-16") as f:
            f.write(task_xml)
    except Exception as e:
        return DeployResult(ip=ip, hostname=hostname, success=False, message=f"write task xml failed: {e}")

    remote_xml = os.path.join(agent_dest_dir, "ksl_agent_task.xml")
    code, out = _run([
        "psexec", f"\\\\{ip}", "-u", domain_user, "-p", domain_password,
        "-s", "-d", "schtasks",
        "/Create", "/TN", "KSL_IT_Agent", "/XML", remote_xml, "/F"
    ], timeout=60)

    if code != 0:
        return DeployResult(ip=ip, hostname=hostname, success=False, message=f"schtasks failed: {out}")

    # 3. Run agent once immediately
    _run([
        "psexec", f"\\\\{ip}", "-u", domain_user, "-p", domain_password,
        "-s", "-d", python_exe, "-m", "itops.agent.run",
        "--config", config_path, "--policies", policies_path, "--no-jitter"
    ], timeout=120)

    return DeployResult(ip=ip, hostname=hostname, success=True, message="Agent deployed and scheduled")


def deploy_via_wmi(
    ip: str,
    hostname: str,
    python_exe: str,
    agent_dir: str,
    config_path: str,
    policies_path: str,
    domain_user: str,
    domain_password: str,
) -> DeployResult:
    """
    Trigger agent run on remote machine via WMIC (no file copy, agent already present).
    """
    cmd_line = f'"{python_exe}" -m itops.agent.run --config "{config_path}" --policies "{policies_path}" --no-jitter'
    code, out = _run([
        "wmic", f"/node:{ip}", f"/user:{domain_user}", f"/password:{domain_password}",
        "process", "call", "create", cmd_line
    ], timeout=60)

    success = code == 0 and "ReturnValue = 0" in out
    return DeployResult(
        ip=ip,
        hostname=hostname,
        success=success,
        message=out[:300] if not success else "Agent triggered via WMI",
    )
