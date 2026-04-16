from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

import yaml


def load_segment_map(path: str) -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    with open(path, "r", encoding="utf-8") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    segments = raw.get("segments") or []
    result: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for item in segments:
        name = str(item.get("name") or "").strip()
        cidr = str(item.get("cidr") or "").strip()
        if not name or not cidr:
            continue
        result.append((name, ipaddress.ip_network(cidr, strict=False)))
    return result


def resolve_network_segment(ip: str, segment_map: list[tuple[str, ipaddress._BaseNetwork]]) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for name, network in segment_map:
        if addr in network:
            return name
    return None

