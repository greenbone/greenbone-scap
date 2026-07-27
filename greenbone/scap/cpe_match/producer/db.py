# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace
from collections.abc import AsyncIterator
from uuid import UUID

from pontos.nvd.models.cpe_match_string import CPEMatch, CPEMatchString
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import DEFAULT_VERBOSITY
from greenbone.scap.cpe_match.cli.processor import CPE_MATCH_TYPE_PLURAL
from greenbone.scap.cpe_match.db.manager import CPEMatchStringDatabaseManager
from greenbone.scap.cpe_match.db.models import (
    BaseDatabaseModel,
    CPEMatchStringDatabaseModel,
)
from greenbone.scap.errors import ScapError
from greenbone.scap.generic_cli.producer.db import DatabaseProducer


class CpeMatchDatabaseProducer(DatabaseProducer[CPEMatchString]):
    """
    Async context manager class for a producer querying
    CPE match strings from a database.
    """

    _item_type_plural = CPE_MATCH_TYPE_PLURAL
    "Plural form of the type of items to use in log messages"

    _arg_defaults = DatabaseProducer._arg_defaults
    "Default values for optional arguments."

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchDatabaseProducer":
        """
        Create a new `CPEMatchDatabaseProducer` with parameters from
         the given command line args gathered by an `ArgumentParser`.

        Args:
            args: Command line arguments to use
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.

        Returns:
            The new `CpeMatchDatabaseProducer`.
        """
        return CpeMatchDatabaseProducer(
            console,
            error_console,
            progress,
            database_name=args.database_name,
            database_schema=args.database_schema,
            database_host=args.database_host,
            database_port=args.database_port,
            database_user=args.database_user,
            database_password=args.database_password,
            echo_sql=args.echo_sql,
            verbose=args.verbose or 0,
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        database_name: str | None,
        database_schema: str | None,
        database_host: str | None,
        database_port: int | None,
        database_user: str | None,
        database_password: str | None,
        echo_sql: bool = False,
        verbose: int = DEFAULT_VERBOSITY,
    ):
        """
        Constructor for a CPE match string database producer.

        If the `database_...` arguments are None or not given, corresponding
        environment variables will be tried next before finally using the
        defaults as a fallback.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.
            database_name: Name of the database to use.
            database_schema: Optional database schema to use.
            database_host: IP address or hostname of the database server to use.
            database_port: Port of the database server to use.
            database_user: Name of the database user to use.
            database_password: Password of the database user to use.
            echo_sql: Whether to print SQL statements.
            verbose: Verbosity level of log messages.
        """
        self._manager: CPEMatchStringDatabaseManager

        super().__init__(
            console,
            error_console,
            progress,
            database_name=database_name,
            database_schema=database_schema,
            database_host=database_host,
            database_port=database_port,
            database_user=database_user,
            database_password=database_password,
            echo_sql=echo_sql,
            verbose=verbose,
        )

    def _create_manager(self) -> CPEMatchStringDatabaseManager:
        """
        Callback creating a new database manager for handling CPE match strings.

        Returns: The new database manager.
        """
        return CPEMatchStringDatabaseManager(self._database)

    def _convert_db_model(self, db_model: BaseDatabaseModel) -> CPEMatchString:
        """
        Callback converting a CPE match string database model to a Pontos model.

        Args:
            db_model: The database model convert

        Returns:
            The converted model object.
        """
        if not isinstance(db_model, CPEMatchStringDatabaseModel):
            raise ScapError(
                f"DB model is not a CPEMatchDatabaseModel: {db_model}"
            )
        match_string_db_model: CPEMatchStringDatabaseModel = db_model

        if not match_string_db_model.match_criteria_id:
            raise ScapError(f"Missing match_criteria_id in {db_model}")
        if match_string_db_model.matches is None:
            raise ScapError(f"Missing matches in {db_model}")

        matches = []
        for db_match in match_string_db_model.matches:
            if not db_match.cpe_name_id:
                raise ScapError(f"Missing cpe_name_id in {db_match}")

            matches.append(
                CPEMatch(
                    cpe_name_id=UUID(str(db_match.cpe_name_id)),
                    cpe_name=db_match.cpe_name,
                )
            )

        return CPEMatchString(
            match_criteria_id=UUID(
                str(match_string_db_model.match_criteria_id)
            ),
            criteria=match_string_db_model.criteria,
            status=match_string_db_model.status,
            cpe_last_modified=match_string_db_model.cpe_last_modified,
            created=match_string_db_model.created,
            last_modified=match_string_db_model.last_modified,
            matches=matches,
            version_start_including=match_string_db_model.version_start_including,
            version_start_excluding=match_string_db_model.version_start_excluding,
            version_end_including=match_string_db_model.version_end_including,
            version_end_excluding=match_string_db_model.version_end_excluding,
        )

    async def _db_item_count(self) -> int:
        """
        Callback getting the total number of CPE match strings in the database.

        Returns:
            The total number of CPE match strings
        """
        return await self._manager.count()

    def _db_item_iter(self) -> AsyncIterator[BaseDatabaseModel]:
        """
        Callback getting an async iterator of database items to process.

        Returns:
            An async iterator over database items.
        """
        return self._manager.all()
