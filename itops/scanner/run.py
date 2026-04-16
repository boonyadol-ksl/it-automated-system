from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from typing import Any, Dict, List

import requests
import yaml


def _load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _report_to_server(base_url: str, api_key: str, results: list) -> None:
    try:
        requests.post(
            f"{base_url}/api/v1/scan/report",
            json={"results": results},
            headers={"X-API-Key": api_key},
            timeout=30,
        )
    except Exception as e:
        print(f"[scanner] report to server failed: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="KSL Network Scanner")
    parser.add_argument("--config", required=True, help="Path to scanner.yml")
    parser.add_argument("--deploy", action="store_true", help="Auto-deploy agent to discovered machines")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cfg = _load_config(args.config)
    segments = cfg.get("segments") or []
    server = cfg.get("server") or {}
    deploy_cfg = cfg.get("deploy") or {}

    from .scanner import scan_segments

    print(f"[scanner] scanning {len(segments)} segment(s)...")
    results = scan_segments(segments, max_workers=cfg.get("max_workers") or 50)

    online = [r for r in results if r.status == "online"]
    offline = [r for r in results if r.status == "offline"]

    print(f"[scanner] found {len(online)} online / {len(offline)} offline")

    if args.verbose:
        for r in online:
            seg = getattr(r, "network_segment", "")
            ports = ", ".join(f"{p}({r.services[p]})" for p in r.open_ports)
            print(f"  [{seg}] {r.ip:16s}  {r.hostname or '(no rdns)':30s}  ports: {ports or 'none'}")

    # Report to server
    if server.get("base_url"):
        payload = [
            {**asdict(r), "network_segment": getattr(r, "network_segment", "")}
            for r in results
        ]
        _report_to_server(server["base_url"], server.get("api_key") or "", payload)
        print(f"[scanner] reported {len(payload)} results to server")

    # Auto-deploy agent
    if args.deploy and deploy_cfg.get("enabled"):
        from .deployer import deploy_via_wmi, deploy_via_psexec

        method = deploy_cfg.get("method") or "wmi"
        python_exe = deploy_cfg.get("python_exe") or "python"
        agent_dir = deploy_cfg.get("agent_dir") or r"C:\ksl_agent"
        config_path = deploy_cfg.get("config_path") or r"C:\ksl_agent\config\agent.yml"
        policies_path = deploy_cfg.get("policies_path") or r"C:\ksl_agent\config\policies.yml"
        domain_user = deploy_cfg.get("domain_user") or ""
        domain_password = deploy_cfg.get("domain_password") or ""

        for r in online:
            if 445 not in r.open_ports and 135 not in r.open_ports:
                if args.verbose:
                    print(f"  [deploy] skip {r.ip} — SMB/RPC not open")
                continue

            if method == "psexec":
                result = deploy_via_psexec(
                    ip=r.ip, hostname=r.hostname,
                    agent_source_dir=deploy_cfg.get("agent_source_dir") or ".",
                    agent_dest_dir=agent_dir,
                    python_exe=python_exe,
                    config_path=config_path,
                    policies_path=policies_path,
                    domain_user=domain_user,
                    domain_password=domain_password,
                )
            else:
                result = deploy_via_wmi(
                    ip=r.ip, hostname=r.hostname,
                    python_exe=python_exe,
                    agent_dir=agent_dir,
                    config_path=config_path,
                    policies_path=policies_path,
                    domain_user=domain_user,
                    domain_password=domain_password,
                )

            status = "ok" if result.success else "fail"
            print(f"  [deploy] {r.ip} ({r.hostname}) -> {status}: {result.message}")


if __name__ == "__main__":
    main()
