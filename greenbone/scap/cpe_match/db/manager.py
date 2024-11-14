# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from types import TracebackType
from typing import AsyncContextManager, AsyncIterator, Self, Sequence

from pontos.nvd.models.cpe_match_string import CPEMatchString
from sqlalchemy import (
    func,
    select,
)
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.orm import selectinload

from greenbone.scap.db import Database

from greenbone.scap.cpe_match.db.models import (
    BaseDatabaseModel,
    CPEMatchStringDatabaseModel,
    CPEMatchDatabaseModel,
)


DEFAULT_THRESHOLD = 100
DEFAULT_YIELD_PER = 100


class CPEMatchStringDatabaseManager(AsyncContextManager):
    def __init__(
        self,
        db: Database,
        *,
        insert_threshold: int = DEFAULT_THRESHOLD,
        yield_per: int = DEFAULT_YIELD_PER,
        update: bool = True,
    ) -> None:
        self._db = db
        self._cpe_match_strings: list[CPEMatchString] = []
        self._insert_threshold = insert_threshold
        self._update = update
        self._yield_per = yield_per

    async def __aenter__(self) -> Self:
        await self._db.init(BaseDatabaseModel.metadata.create_all)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if not exc_type:
            # not an error
            await self.add_cpe_match_strings(self._cpe_match_strings)
        return

    async def add(self, match_string: CPEMatchString) -> None:
        self._cpe_match_strings.append(match_string)

        if len(self._cpe_match_strings) > self._insert_threshold:
            await self.add_cpe_match_strings(self._cpe_match_strings)

    async def add_cpe_match_strings(
        self, match_strings: Sequence[CPEMatchString]
    ) -> None:
        if not match_strings:
            return

        statement = self._db.insert(CPEMatchStringDatabaseModel)
        if self._update:
            statement = statement.on_conflict_do_update(
                index_elements=[CPEMatchStringDatabaseModel.match_criteria_id],
                set_=dict(
                    criteria=statement.excluded.criteria,
                    status=statement.excluded.status,
                    cpe_last_modified=statement.excluded.cpe_last_modified,
                    created=statement.excluded.created,
                    last_modified=statement.excluded.last_modified,
                    version_start_including=statement.excluded.version_start_including,
                    version_start_excluding=statement.excluded.version_start_excluding,
                    version_end_including=statement.excluded.version_end_including,
                    version_end_excluding=statement.excluded.version_end_excluding,
                ),
            )
        else:
            statement = statement.on_conflict_do_nothing()

        async with self._db.transaction() as transaction:
            await transaction.execute(
                statement,
                [
                    dict(
                        match_criteria_id=match_string.match_criteria_id,
                        criteria=match_string.criteria,
                        status=match_string.status,
                        cpe_last_modified=match_string.cpe_last_modified,
                        created=match_string.created,
                        last_modified=match_string.last_modified,
                        version_start_including=match_string.version_start_including,
                        version_start_excluding=match_string.version_start_excluding,
                        version_end_including=match_string.version_end_including,
                        version_end_excluding=match_string.version_end_excluding,
                    )
                    for match_string in match_strings
                ],
            )
            await self._insert_foreign_data(transaction, match_strings)

        self._cpes = []

    async def _insert_foreign_data(
        self,
        connection: AsyncConnection,
        match_strings: Sequence[CPEMatchString],
    ) -> None:
        matches_data = [
            dict(
                match_criteria_id=match_string.match_criteria_id,
                cpe_name=match.cpe_name,
                cpe_name_id=match.cpe_name_id,
            )
            for match_string in match_strings
            for match in match_string.matches
        ]
        if matches_data:
            statement = self._db.insert(CPEMatchDatabaseModel)
            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        CPEMatchDatabaseModel.match_criteria_id,
                        CPEMatchDatabaseModel.cpe_name_id,
                    ],
                    set_=dict(
                        match_criteria_id=statement.excluded.match_criteria_id,
                        cpe_name=statement.excluded.cpe_name,
                        cpe_name_id=statement.excluded.cpe_name_id,
                    ),
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, matches_data)

    async def find(
        self,
        *,
        match_criteria_id: str | None = None,
        limit: int | None = None,
        index: int | None = None,
        last_modification_start_date: datetime | None = None,
        last_modification_end_date: datetime | None = None,
        published_start_date: datetime | None = None,
        published_end_date: datetime | None = None,
    ) -> AsyncIterator[CPEMatchStringDatabaseModel]:
        clauses = []

        if match_criteria_id is not None:
            clauses.append(
                CPEMatchStringDatabaseModel.match_criteria_id
                == match_criteria_id
            )

        if last_modification_start_date:
            clauses.append(
                CPEMatchStringDatabaseModel.last_modified
                >= last_modification_start_date
            )
        if last_modification_end_date:
            clauses.append(
                CPEMatchStringDatabaseModel.last_modified
                <= last_modification_end_date
            )
        if published_start_date:
            clauses.append(
                CPEMatchStringDatabaseModel.published >= published_start_date
            )
        if published_end_date:
            clauses.append(
                CPEMatchStringDatabaseModel.published <= published_end_date
            )

        statement = (
            select(CPEMatchStringDatabaseModel)
            .options(
                selectinload(CPEMatchStringDatabaseModel.matches),
            )
            .where(*clauses)
            .execution_options(yield_per=self._yield_per)
            .limit(limit)
        )

        if index is not None:
            statement = statement.offset(index)

        async with self._db.session() as session, session.begin():
            result = await session.stream_scalars(statement)
            async for cpe_model in result:
                yield cpe_model

    async def all(
        self, *, limit: int | None = None
    ) -> AsyncIterator[CPEMatchStringDatabaseModel]:
        statement = (
            select(CPEMatchStringDatabaseModel)
            .options(
                selectinload(CPEMatchStringDatabaseModel.matches),
            )
            .limit(limit)
            .execution_options(yield_per=self._yield_per)
        )

        async with self._db.session() as session, session.begin():
            result = await session.stream_scalars(statement)
            async for cpe_model in result:
                yield cpe_model

    async def count(
        self,
        *,
        match_criteria_id: str | None,
        last_modification_start_date: datetime | None = None,
        last_modification_end_date: datetime | None = None,
        published_start_date: datetime | None = None,
        published_end_date: datetime | None = None,
    ) -> int:
        clauses = []

        if match_criteria_id is not None:
            clauses.append(
                CPEMatchStringDatabaseModel.match_criteria_id
                == match_criteria_id
            )

        if last_modification_start_date:
            clauses.append(
                CPEMatchStringDatabaseModel.last_modified
                >= last_modification_start_date
            )
        if last_modification_end_date:
            clauses.append(
                CPEMatchStringDatabaseModel.last_modified
                <= last_modification_end_date
            )
        if published_start_date:
            clauses.append(
                CPEMatchStringDatabaseModel.published >= published_start_date
            )
        if published_end_date:
            clauses.append(
                CPEMatchStringDatabaseModel.published <= published_end_date
            )

        statement = select(
            func.count(CPEMatchStringDatabaseModel.match_criteria_id)
        ).where(*clauses)
        async with self._db.transaction() as transaction:
            result = await transaction.execute(statement)
            return result.scalar()  # type: ignore[return-value]
