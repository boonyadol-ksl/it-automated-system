from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import yaml


@dataclass(frozen=True)
class ApiConfig:
    base_url: str
    api_key: str
    timeout_seconds: int = 30


@dataclass(frozen=True)
class ScheduleConfig:
    interval_seconds: int = 14400
    jitter_seconds: int = 300


@dataclass(frozen=True)
class AssetConfig:
    role: str
    network_segment: str
    network_segments_file: str | None = None


@dataclass(frozen=True)
class AgentConfig:
    api: ApiConfig
    schedule: ScheduleConfig
    asset: AssetConfig


def load_agent_config(path: str) -> AgentConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    api = raw.get("api") or {}
    schedule = raw.get("schedule") or {}
    asset = raw.get("asset") or {}

    return AgentConfig(
        api=ApiConfig(
            base_url=str(api.get("base_url") or "http://127.0.0.1:8000").rstrip("/"),
            api_key=str(api.get("api_key") or ""),
            timeout_seconds=int(api.get("timeout_seconds") or 30),
        ),
        schedule=ScheduleConfig(
            interval_seconds=int(schedule.get("interval_seconds") or 14400),
            jitter_seconds=int(schedule.get("jitter_seconds") or 300),
        ),
        asset=AssetConfig(
            role=str(asset.get("role") or "office_user"),
            network_segment=str(asset.get("network_segment") or "unknown"),
            network_segments_file=(
                str(asset.get("network_segments_file"))
                if asset.get("network_segments_file") is not None
                else None
            ),
        ),
    )
