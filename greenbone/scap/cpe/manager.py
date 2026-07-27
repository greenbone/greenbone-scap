# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Self

from pontos.cpe import ANY, NA
from pontos.cpe import CPE as CPEParser
from pontos.nvd.models.cpe import CPE
from sqlalchemy import (
    ColumnElement,
    Integer,
    func,
    or_,
    select,
    true,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import contains_eager, selectinload
from sqlalchemy.sql.expression import FunctionElement

from greenbone.scap.db import Database
from greenbone.scap.errors import ScapError
from greenbone.scap.version import canonical_version

from .models import (
    Base,
    CPEModel,
    CPENamesModel,
    DeprecatedByModel,
    ReferenceModel,
    TitleModel,
)

DEFAULT_THRESHOLD = 100
DEFAULT_YIELD_PER = 100


class VersionRangeError(ScapError):
    """An invalid range was supplied"""


class VersionFunc(FunctionElement):
    inherit_cache = True
    type = ARRAY(Integer)


@compiles(VersionFunc)
def compile(element, compiler, **kw):
    if len(element.clauses) != 1:
        raise TypeError("VersionFunc requires exactly one argument")
    return f"regexp_split_to_array({compiler.process(element.clauses, **kw)}, '\\.')::bigint[]"


def cpe_condition(cpe: CPEParser, exact: bool = False) -> ColumnElement[bool]:
    clause = CPENamesModel.part == cpe.part.value
    if exact or cpe.vendor != ANY:
        clause = clause & (CPENamesModel.vendor == cpe.vendor)
    if exact or cpe.product != ANY:
        clause = clause & (CPENamesModel.product == cpe.product)
    if exact or cpe.version != ANY:
        clause = clause & (CPENamesModel.version == cpe.version)
    if exact or cpe.update != ANY:
        clause = clause & (CPENamesModel.update == cpe.update)
    if exact or cpe.edition != ANY:
        clause = clause & (CPENamesModel.edition == cpe.edition)
    if exact or cpe.language != ANY:
        clause = clause & (CPENamesModel.language == cpe.language)
    if exact or cpe.sw_edition != ANY:
        clause = clause & (CPENamesModel.sw_edition == cpe.sw_edition)
    if exact or cpe.target_sw != ANY:
        clause = clause & (CPENamesModel.target_sw == cpe.target_sw)
    if exact or cpe.target_hw != ANY:
        clause = clause & (CPENamesModel.target_hw == cpe.target_hw)
    if exact or cpe.other != ANY:
        clause = clause & (CPENamesModel.other == cpe.other)
    return clause


@dataclass(frozen=True, kw_only=True)
class VersionRange:
    cpe: CPEParser | None
    version_start_excluding: str | None
    version_start_including: str | None
    version_end_excluding: str | None
    version_end_including: str | None

    def __post_init__(self):
        if self.version_start_excluding and self.version_start_including:
            raise VersionRangeError(
                "Both version_start_excluding and version_start_including "
                "are provided"
            )
        if self.version_end_excluding and self.version_end_including:
            raise VersionRangeError(
                "Both version_end_excluding and version_end_including "
                "are provided"
            )

    def __bool__(self) -> bool:
        return bool(
            self.cpe
            or self.version_end_excluding
            or self.version_end_including
            or self.version_start_excluding
            or self.version_start_including
        )

    def as_condition(self) -> ColumnElement[bool]:
        if self.cpe:
            clause = cpe_condition(self.cpe)
        else:
            clause = true()

        if self.version_start_excluding:
            clause = clause & (
                VersionFunc(CPENamesModel.version_canonical)
                > VersionFunc(canonical_version(self.version_start_excluding))
            )
        elif self.version_start_including:
            clause = clause & (
                VersionFunc(CPENamesModel.version_canonical)
                >= VersionFunc(canonical_version(self.version_start_including))
            )

        if self.version_end_excluding:
            clause = clause & (
                VersionFunc(CPENamesModel.version_canonical)
                < VersionFunc(canonical_version(self.version_end_excluding))
            )
        elif self.version_end_including:
            clause = clause & (
                VersionFunc(CPENamesModel.version_canonical)
                <= VersionFunc(canonical_version(self.version_end_including))
            )

        return clause


class CPEManager(AbstractAsyncContextManager):
    def __init__(
        self,
        db: Database,
        *,
        insert_threshold: int = DEFAULT_THRESHOLD,
        yield_per: int = DEFAULT_YIELD_PER,
        update: bool = True,
    ) -> None:
        self._db = db
        self._cpes: list[CPE] = []
        self._insert_threshold = insert_threshold
        self._update = update
        self._yield_per = yield_per

    async def __aenter__(self) -> Self:
        await self._db.init(Base.metadata.create_all)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if not exc_type:
            # not an error
            await self.add_cpes(self._cpes)

    async def add(self, cpe: CPE) -> None:
        self._cpes.append(cpe)

        if len(self._cpes) > self._insert_threshold:
            await self.add_cpes(self._cpes)

    async def add_cpes(self, cpes: Sequence[CPE]) -> None:
        if not cpes:
            return

        statement = self._db.insert(CPEModel)
        if self._update:
            statement = statement.on_conflict_do_update(
                index_elements=[CPEModel.cpe_name],
                set_={
                    "cpe_name": statement.excluded.cpe_name,
                    "cpe_name_id": statement.excluded.cpe_name_id,
                    "deprecated": statement.excluded.deprecated,
                    "last_modified": statement.excluded.last_modified,
                    "created": statement.excluded.created,
                },
            )
        else:
            statement = statement.on_conflict_do_nothing()

        async with self._db.transaction() as transaction:
            await transaction.execute(
                statement,
                [
                    {
                        "cpe_name": cpe.cpe_name,
                        "cpe_name_id": cpe.cpe_name_id,
                        "deprecated": cpe.deprecated,
                        "last_modified": cpe.last_modified,
                        "created": cpe.created,
                    }
                    for cpe in cpes
                ],
            )
            await self._insert_foreign_data(transaction, cpes)

        self._cpes = []

    async def _insert_foreign_data(
        self, connection: AsyncConnection, cpes: Sequence[CPE]
    ) -> None:
        cpe_names_data = []
        for cpe in cpes:
            parsed_cpe = CPEParser.from_string(cpe.cpe_name)
            cpe_names_data.append(
                {
                    "cpe_name": cpe.cpe_name,
                    "part": parsed_cpe.part.value,
                    "vendor": parsed_cpe.vendor,
                    "product": parsed_cpe.product,
                    "version": parsed_cpe.version,
                    "version_canonical": canonical_version(parsed_cpe.version),
                    "update": parsed_cpe.update,
                    "edition": parsed_cpe.edition,
                    "language": parsed_cpe.language,
                    "sw_edition": parsed_cpe.sw_edition,
                    "target_sw": parsed_cpe.target_sw,
                    "target_hw": parsed_cpe.target_hw,
                    "other": parsed_cpe.other,
                }
            )
        if cpe_names_data:
            statement = self._db.insert(CPENamesModel)
            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[CPENamesModel.cpe_name],
                    set_={
                        "cpe_name": statement.excluded.cpe_name,
                        "part": statement.excluded.part,
                        "vendor": statement.excluded.vendor,
                        "product": statement.excluded.product,
                        "version": statement.excluded.version,
                        "version_canonical": statement.excluded.version_canonical,
                        "update": statement.excluded["update"],
                        "edition": statement.excluded.edition,
                        "language": statement.excluded.language,
                        "sw_edition": statement.excluded.sw_edition,
                        "target_sw": statement.excluded.target_sw,
                        "target_hw": statement.excluded.target_hw,
                        "other": statement.excluded.other,
                    },
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, cpe_names_data)

        titles_data = [
            {
                "cpe": cpe.cpe_name,
                "title": title.title,
                "lang": title.lang,
            }
            for cpe in cpes
            for title in cpe.titles
        ]
        if titles_data:
            statement = self._db.insert(TitleModel)
            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        TitleModel.cpe,
                        TitleModel.title,
                        TitleModel.lang,
                    ],
                    set_={
                        "title": statement.excluded.title,
                        "lang": statement.excluded.lang,
                    },
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, titles_data)

        references_data = [
            {
                "cpe": cpe.cpe_name,
                "ref": ref.ref,
                "type": str(ref.type) if ref.type else None,
            }
            for cpe in cpes
            for ref in cpe.refs
        ]
        if references_data:
            statement = self._db.insert(ReferenceModel)
            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        ReferenceModel.cpe,
                        ReferenceModel.ref,
                    ],
                    set_={
                        "ref": statement.excluded.ref,
                        "type": statement.excluded.type,
                    },
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, references_data)

        deprecated_by_data = [
            {
                "cpe": cpe.cpe_name,
                "cpe_name": deprecated.cpe_name,
                "cpe_name_id": deprecated.cpe_name_id,
            }
            for cpe in cpes
            for deprecated in cpe.deprecated_by
        ]
        if deprecated_by_data:
            statement = self._db.insert(DeprecatedByModel)
            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        DeprecatedByModel.cpe,
                        DeprecatedByModel.cpe_name,
                    ],
                    set_={
                        "cpe_name": statement.excluded.cpe_name,
                        "cpe_name_id": statement.excluded.cpe_name_id,
                    },
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, deprecated_by_data)

    async def find(
        self,
        *,
        cpe: CPE | CPEParser | str | None = None,
        exact: bool = False,
        deprecated: bool | None = None,
        has_version: bool | None = None,
        limit: int | None = None,
        order_by_cpe_name: bool = False,
        version_ranges: Iterable[VersionRange] | None = None,
    ) -> AsyncIterator[CPEModel]:
        if cpe is None:
            clauses = []
        else:
            if isinstance(cpe, str):
                cpe = CPEParser.from_string(cpe)
            elif hasattr(cpe, "cpe_name"):
                cpe = CPEParser.from_string(cpe.cpe_name)  # type: ignore
            elif not isinstance(cpe, CPEParser):
                raise TypeError("Invalid type for cpe argument")

            clauses = [cpe_condition(cpe, exact)]

        if deprecated is not None:
            clauses.append(CPEModel.deprecated != (not deprecated))

        if has_version or version_ranges:
            clauses.append(CPENamesModel.version.is_not(None))
            clauses.append(CPENamesModel.version != NA)

        if version_ranges is not None:
            version_clauses = [
                version_range.as_condition()
                for version_range in version_ranges
                if version_range
            ]

            clauses.append(or_(*version_clauses))

        statement = (
            select(CPEModel)
            .join(CPEModel.cpe_names_model)
            .where(*clauses)
            .execution_options(yield_per=self._yield_per)
            .limit(limit)
        )

        if order_by_cpe_name:
            statement = statement.order_by(CPEModel.cpe_name)

        async with self._db.session() as session, session.begin():
            result = await session.stream_scalars(statement)
            async for cpe_model in result:
                yield cpe_model

    async def all(self, *, limit: int | None = None) -> AsyncIterator[CPEModel]:
        statement = (
            select(CPEModel)
            .outerjoin(CPEModel.cpe_names_model)
            .options(
                contains_eager(CPEModel.cpe_names_model),
                selectinload(CPEModel.deprecated_by),
                selectinload(CPEModel.refs),
                selectinload(CPEModel.titles),
            )
            .order_by(CPEModel.cpe_name)
            .limit(limit)
            .execution_options(yield_per=self._yield_per)
        )

        async with self._db.session() as session, session.begin():
            result = await session.stream_scalars(statement)
            async for cpe_model in result:
                yield cpe_model

    async def count(self) -> int:
        statement = select(func.count(CPEModel.cpe_name))
        async with self._db.transaction() as transaction:
            result = await transaction.execute(statement)
            return result.scalar()  # type: ignore[return-value]
