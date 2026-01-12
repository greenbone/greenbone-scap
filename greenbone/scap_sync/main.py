from __future__ import annotations

import asyncio

from pontos.nvd.cpe import CPEApi
from pontos.nvd.cve import CVEApi

from .cpe import sync_cpes
from .cve import sync_cves
from .utils.db import create_async_db_from_env
from .utils.env import ScapEnv, read_envs


async def main_async() -> None:
    env: ScapEnv = read_envs()
    db = create_async_db_from_env(env)

    api_key = env.get("NVD_API_KEY")
    cve_api = CVEApi(token=api_key, request_attempts=10)
    cpe_api = CPEApi(token=api_key, request_attempts=10)

    try:
        await asyncio.gather(
            sync_cpes(db, cpe_api),
            sync_cves(db, cve_api),
        )

    except Exception as e:
        print(f"Error syncing scap data: {e}")
        raise e

    finally:
        await db.dispose()


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
