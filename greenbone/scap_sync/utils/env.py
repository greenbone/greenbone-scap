# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
from typing import Dict, TypedDict


class ScapEnv(TypedDict):
    NVD_API_KEY: str | None
    DATABASE_HOST: str
    DATABASE_PORT: int
    DATABASE_NAME: str
    DATABASE_USER: str
    DATABASE_PASSWORD: str
    LOG_LEVEL: str


def read_envs() -> ScapEnv:
    env: Dict[str, str | int] = {
        "LOG_LEVEL": "info",
        "DATABASE_PORT": "5432",
    }
    missing: list[str] = []
    for key in ScapEnv.__annotations__:
        value = os.getenv(key)

        if value is None:
            value = env.get(key)

        if key == "NVD_API_KEY" and not value:
            continue

        if key == "DATABASE_PORT" and value:
            value = int(value)

        if value is None:
            missing.append(key)
            continue

        else:
            env[key] = value

    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}"
        )

    # The runtime ``env`` dict has exactly the keys of ScapEnv, so it is safe to cast.
    return env  # type: ignore[return-value]


__all__ = ["read_envs", "ScapEnv"]
