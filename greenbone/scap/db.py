# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from types import TracebackType
from typing import Any, AsyncContextManager, Callable, Literal, Self
from urllib.parse import quote_plus

from sqlalchemy.dialects.postgresql import Insert as PostgresInsert
from sqlalchemy.dialects.sqlite import Insert as SqliteInsert
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DEFAULT_CONNECTIONS = 20
MAX_CONNECTIONS = 50
DEFAULT_CONNECTION_TIMEOUT = 300.0  # 5 min


class Database(AsyncContextManager):
    def __init__(
        self,
        engine: AsyncEngine,
    ) -> None:
        self.engine = engine
        self._session_maker = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
        )

    def session(self) -> AsyncSession:
        return self._session_maker()

    def transaction(self) -> AsyncContextManager[AsyncConnection]:
        return self.engine.begin()

    def delete(self) -> None:
        pass

    def insert(self, table) -> SqliteInsert | PostgresInsert:
        raise NotImplementedError()

    async def init(self, func: Callable[..., Any]) -> None:
        async with self.transaction() as connection:
            await connection.run_sync(func)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        await self.engine.dispose()
        return


class PostgresDatabase(Database):
    def __init__(
        self,
        *,
        password: str,
        user: str,
        host: str,
        port: str | int = 5432,
        dbname: str,
        echo: bool | Literal["debug"] = False,
        schema: str | None = None,
    ) -> None:
        engine = create_async_engine(
            "postgresql+psycopg_async://"
            f"{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{dbname}",
            echo=echo,
            pool_size=DEFAULT_CONNECTIONS,
            max_overflow=MAX_CONNECTIONS - DEFAULT_CONNECTIONS,
            pool_timeout=DEFAULT_CONNECTION_TIMEOUT,
        )
        if schema:
            engine = engine.execution_options(
                schema_translate_map={None: schema}
            )
        super().__init__(engine)

    def insert(self, table) -> PostgresInsert:
        return PostgresInsert(table)
