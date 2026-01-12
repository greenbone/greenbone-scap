from pontos.nvd.cve import CVEApi
from sqlalchemy.ext.asyncio import AsyncEngine

from greenbone.scap.cve.models import CVEModel

from ..utils.db import get_latest_last_modified
from .upsert import upsert_cves


async def sync_cves(db: AsyncEngine, api: CVEApi) -> None:
    print("Starting CVE sync...")
    last_modified = await get_latest_last_modified(db, CVEModel)

    print(f"Downloading CVEs modified since {last_modified}...")
    results = await api.cves(last_modified_start_date=last_modified)

    async for cves in results.chunks():
        await upsert_cves(db, cves)
        print(f"Upserted {len(cves)} CVEs")
