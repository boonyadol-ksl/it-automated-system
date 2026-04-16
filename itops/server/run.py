from __future__ import annotations

import argparse

import uvicorn

from .app import create_app
from .config import ServerSettings


def _load_settings(env_file: str | None) -> ServerSettings:
    if env_file:
        class _Env(ServerSettings):
            model_config = ServerSettings.model_config | {"env_file": env_file}

        return _Env()
    return ServerSettings()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run KSL IT Ops API server")
    parser.add_argument("--env-file", default=None, help="Path to env file (e.g. config/server.env)")
    args = parser.parse_args()

    settings = _load_settings(args.env_file)
    app = create_app(settings)

    print(f"[server] listening on http://{settings.host}:{settings.port}")
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()
