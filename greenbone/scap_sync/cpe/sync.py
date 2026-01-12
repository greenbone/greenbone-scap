from pontos.nvd.cpe import CPEApi
from sqlalchemy.ext.asyncio import AsyncEngine

from greenbone.scap.cpe.models import CPEModel

from ..utils.db import get_latest_last_modified
from .upsert import upsert_cpes


async def sync_cpes(db: AsyncEngine, api: CPEApi) -> None:
    print("Starting CPE sync...")
    last_modified = await get_latest_last_modified(db, CPEModel)

    print(f"Downloading CPEs modified since {last_modified}...")
    results = await api.cpes(last_modified_start_date=last_modified)

    async for cpes in results.chunks():
        await upsert_cpes(db, cpes)
        print(f"Upserted {len(cpes)} CPEs")
