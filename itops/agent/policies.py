from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import yaml


@dataclass(frozen=True)
class SoftwarePolicy:
    required: List[str]
    optional: List[str]
    forbidden: List[str]


def load_policy_map(path: str) -> Dict[str, SoftwarePolicy]:
    with open(path, "r", encoding="utf-8") as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    roles = raw.get("roles") or {}
    policy_map: Dict[str, SoftwarePolicy] = {}
    for role, policy in roles.items():
        policy_map[str(role)] = SoftwarePolicy(
            required=list(policy.get("required") or []),
            optional=list(policy.get("optional") or []),
            forbidden=list(policy.get("forbidden") or []),
        )
    return policy_map

