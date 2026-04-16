from __future__ import annotations

from fastapi import Header, HTTPException


def require_api_key(expected_api_key: str, x_api_key: str | None = Header(default=None)) -> None:
    if not expected_api_key or expected_api_key == "change-me":
        raise HTTPException(status_code=500, detail="Server api_key not configured")
    if not x_api_key or x_api_key != expected_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

