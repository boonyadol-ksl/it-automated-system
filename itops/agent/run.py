from __future__ import annotations

import argparse
import random
import time

import requests

from .actions import execute_action
from .client import submit_payload
from .collector import SystemCollector
from .config import load_agent_config
from .network import load_segment_map, resolve_network_segment
from .policies import load_policy_map


def _poll_and_run(cfg, hostname: str, verbose: bool) -> None:
    url = f"{cfg.api.base_url}/api/v1/machine/{hostname}/commands/pending"
    try:
        r = requests.get(url, headers={"X-API-Key": cfg.api.api_key}, timeout=cfg.api.timeout_seconds)
        r.raise_for_status()
        commands = r.json()
    except Exception as e:
        if verbose:
            print(f"[agent] poll commands failed: {e}")
        return

    for cmd in commands:
        cmd_id = cmd["id"]
        action = cmd["action"]
        params = cmd.get("params") or {}
        if verbose:
            print(f"[agent] executing command #{cmd_id}: {action} params={params}")

        success, result = execute_action(action, params)

        if verbose:
            print(f"[agent] command #{cmd_id} {'ok' if success else 'failed'}: {result}")

        try:
            requests.post(
                f"{cfg.api.base_url}/api/v1/command/{cmd_id}/result",
                json={"success": success, "result": result},
                headers={"X-API-Key": cfg.api.api_key},
                timeout=cfg.api.timeout_seconds,
            )
        except Exception as e:
            if verbose:
                print(f"[agent] report result failed: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run KSL agent once (MVP)")
    parser.add_argument("--config", required=True)
    parser.add_argument("--policies", required=True)
    parser.add_argument("--no-jitter", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cfg = load_agent_config(args.config)
    policies = load_policy_map(args.policies)
    policy = policies.get(cfg.asset.role)
    if not policy:
        raise SystemExit(f"Role '{cfg.asset.role}' not found in {args.policies}")

    jitter = 0 if args.no_jitter else random.randint(0, max(cfg.schedule.jitter_seconds, 0))
    if args.verbose:
        print(f"[agent] base_url={cfg.api.base_url}")
        print(f"[agent] role={cfg.asset.role}")
        print(f"[agent] network_segment={cfg.asset.network_segment}")
        print(f"[agent] jitter_seconds={jitter}")
    if jitter > 0:
        time.sleep(jitter)

    network_segment = cfg.asset.network_segment
    collector = SystemCollector(network_segment=network_segment, role=cfg.asset.role, policy=policy)

    if network_segment.strip().lower() == "auto":
        if not cfg.asset.network_segments_file:
            raise SystemExit("asset.network_segments_file is required when network_segment=auto")
        segment_map = load_segment_map(cfg.asset.network_segments_file)
        asset_info = collector.collect_asset_info()
        resolved = resolve_network_segment(asset_info.ip, segment_map)
        network_segment = resolved or "unknown"
        if args.verbose:
            print(f"[agent] detected ip={asset_info.ip} -> segment={network_segment}")
        collector = SystemCollector(network_segment=network_segment, role=cfg.asset.role, policy=policy)

    payload = collector.compile_payload()
    hostname = (payload.get("asset") or {}).get("hostname", "unknown")

    if args.verbose:
        print(f"[agent] submitting hostname={hostname} segment={network_segment}")
    submit_payload(cfg.api, payload)
    if args.verbose:
        print("[agent] submit ok")

    # Poll and execute pending commands
    _poll_and_run(cfg, hostname, args.verbose)


if __name__ == "__main__":
    main()
