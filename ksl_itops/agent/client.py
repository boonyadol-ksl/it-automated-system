from __future__ import annotations

from typing import Any, Dict

import requests

from .config import ApiConfig


def submit_payload(api: ApiConfig, payload: Dict[str, Any]) -> None:
    url = f"{api.base_url}/api/v1/ingest"
    try:
        r = requests.post(
            url,
            json={"payload": payload},
            headers={"X-API-Key": api.api_key},
            timeout=api.timeout_seconds,
        )
        r.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Failed to submit payload to {url}: {e}") from e
