from typing import Sequence

from pontos.cpe import CPE as CPEParser
from pontos.nvd.models.cpe import CPE
from sqlalchemy.dialects.postgresql import Insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from greenbone.scap.cpe.models import (
    CPEModel,
    CPENamesModel,
    DeprecatedByModel,
    ReferenceModel,
    TitleModel,
)
from greenbone.scap.version import canonical_version


async def upsert_cpes(db: AsyncEngine, cpes: Sequence[CPE]) -> None:
    if not cpes:
        return

    async with db.begin() as tx:
        await _upsert_cpes(tx, cpes)

        await _upsert_cpe_names(tx, cpes)
        await _upsert_titles(tx, cpes)
        await _upsert_references(tx, cpes)
        await _upsert_deprecated_by(tx, cpes)


async def _upsert_cpes(conn: AsyncConnection, cpes: Sequence[CPE]) -> None:
    db_cpes = [
        dict(
            cpe_name=cpe.cpe_name,
            cpe_name_id=cpe.cpe_name_id,
            deprecated=cpe.deprecated,
            last_modified=cpe.last_modified,
            created=cpe.created,
        )
        for cpe in cpes
    ]

    statement = Insert(CPEModel)
    statement = statement.on_conflict_do_update(
        index_elements=[CPEModel.cpe_name],
        set_=dict(
            cpe_name_id=statement.excluded.cpe_name_id,
            deprecated=statement.excluded.deprecated,
            last_modified=statement.excluded.last_modified,
            created=statement.excluded.created,
        ),
    )

    await conn.execute(statement, db_cpes)


async def _upsert_cpe_names(conn: AsyncConnection, cpes: Sequence[CPE]) -> None:
    if not cpes:
        return

    cpe_names_data = []
    for cpe in cpes:
        parsed_cpe = CPEParser.from_string(cpe.cpe_name)
        cpe_names_data.append(
            dict(
                cpe_name=cpe.cpe_name,
                part=parsed_cpe.part.value,
                vendor=parsed_cpe.vendor,
                product=parsed_cpe.product,
                version=parsed_cpe.version,
                version_canonical=canonical_version(parsed_cpe.version),
                update=parsed_cpe.update,
                edition=parsed_cpe.edition,
                language=parsed_cpe.language,
                sw_edition=parsed_cpe.sw_edition,
                target_sw=parsed_cpe.target_sw,
                target_hw=parsed_cpe.target_hw,
                other=parsed_cpe.other,
            )
        )

    statement = Insert(CPENamesModel)
    statement = statement.on_conflict_do_update(
        index_elements=[CPENamesModel.cpe_name],
        set_=dict(
            part=statement.excluded.part,
            vendor=statement.excluded.vendor,
            product=statement.excluded.product,
            version=statement.excluded.version,
            version_canonical=statement.excluded.version_canonical,
            update=statement.excluded["update"],
            edition=statement.excluded.edition,
            language=statement.excluded.language,
            sw_edition=statement.excluded.sw_edition,
            target_sw=statement.excluded.target_sw,
            target_hw=statement.excluded.target_hw,
            other=statement.excluded.other,
        ),
    )

    await conn.execute(statement, cpe_names_data)


async def _upsert_titles(conn: AsyncConnection, cpes: Sequence[CPE]) -> None:
    titles_data = [
        dict(
            cpe=cpe.cpe_name,
            title=title.title,
            lang=title.lang,
        )
        for cpe in cpes
        for title in cpe.titles
    ]

    if not titles_data:
        return

    statement = Insert(TitleModel)
    statement = statement.on_conflict_do_update(
        index_elements=[TitleModel.cpe, TitleModel.title, TitleModel.lang],
        set_=dict(
            title=statement.excluded.title,
            lang=statement.excluded.lang,
        ),
    )
    await conn.execute(statement, titles_data)


async def _upsert_references(
    conn: AsyncConnection, cpes: Sequence[CPE]
) -> None:
    references_data = [
        dict(
            cpe=cpe.cpe_name,
            ref=ref.ref,
            type=str(ref.type) if ref.type else None,
        )
        for cpe in cpes
        for ref in cpe.refs
    ]

    if not references_data:
        return

    statement = Insert(ReferenceModel)
    statement = statement.on_conflict_do_update(
        index_elements=[ReferenceModel.cpe, ReferenceModel.ref],
        set_=dict(
            ref=statement.excluded.ref,
            type=statement.excluded.type,
        ),
    )

    await conn.execute(statement, references_data)


async def _upsert_deprecated_by(
    conn: AsyncConnection, cpes: Sequence[CPE]
) -> None:
    deprecated_by_data = [
        dict(
            cpe=cpe.cpe_name,
            cpe_name=deprecated.cpe_name,
            cpe_name_id=deprecated.cpe_name_id,
        )
        for cpe in cpes
        for deprecated in cpe.deprecated_by
    ]

    if not deprecated_by_data:
        return

    statement = Insert(DeprecatedByModel)
    statement = statement.on_conflict_do_update(
        index_elements=[DeprecatedByModel.cpe, DeprecatedByModel.cpe_name],
        set_=dict(
            cpe_name=statement.excluded.cpe_name,
            cpe_name_id=statement.excluded.cpe_name_id,
        ),
    )

    await conn.execute(statement, deprecated_by_data)


__all__ = ["upsert_cpes"]
