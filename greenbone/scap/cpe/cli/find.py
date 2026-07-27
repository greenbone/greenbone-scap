# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import os
import sys
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from collections.abc import Sequence

import shtab
from pontos.cpe import CPE
from rich.console import Console

from greenbone.scap.cli import (
    DEFAULT_POSTGRES_DATABASE_NAME,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_POSTGRES_USER,
)
from greenbone.scap.cpe.manager import CPEManager, VersionRange
from greenbone.scap.db import PostgresDatabase
from greenbone.scap.errors import ScapError


def parse_args(args: Sequence[str] | None = None) -> Namespace:
    parser = ArgumentParser(description="Search for CPEs in the database")
    shtab.add_argument_to(parser)

    parser.add_argument("cpe", help="CPE match to search for")
    parser.add_argument(
        "--echo-sql",
        action="store_true",
        help="Print out all SQL queries.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Enable verbose output.",
    )
    parser.add_argument(
        "--exact",
        action="store_true",
        help="Find only CPE information that match exactly the provided CPE "
        "name",
    )
    db_group = parser.add_argument_group()
    db_group.add_argument(
        "--database-name",
        help="Name of the CPE database.",
    )
    db_group.add_argument(
        "--database-host",
        help="Name of the CPE database host.",
    )
    db_group.add_argument(
        "--database-port",
        help="Name of the CPE database port.",
        type=int,
    )
    db_group.add_argument(
        "--database-user",
        help="Name of the CPE database user.",
    )
    db_group.add_argument(
        "--database-password",
        help="Name of the CPE database password.",
    )
    db_group.add_argument(
        "--database-schema",
        help="Name of the CPE database schema.",
    )

    filter_group = parser.add_argument_group("Filter")
    filter_group.add_argument(
        "--version-start-including",
        metavar="VERSION",
        help="Find CPEs with version greater or equal then VERSION",
    )
    filter_group.add_argument(
        "--version-start-excluding",
        metavar="VERSION",
        help="Find CPEs with version greater then VERSION",
    )
    filter_group.add_argument(
        "--version-end-including",
        metavar="VERSION",
        help="Find CPEs with version less or equal then VERSION",
    )
    filter_group.add_argument(
        "--version-end-excluding",
        metavar="VERSION",
        help="Find CPEs with version less then VERSION",
    )
    filter_group.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Limit to N number of CPEs",
    )
    filter_group.add_argument(
        "--include-deprecated",
        action=BooleanOptionalAction,
        default=False,
        help="Consider deprecated CPEs",
    )
    return parser.parse_args(args)


async def find_cpes(console: Console) -> None:
    args = parse_args()

    echo_sql: bool = args.echo_sql
    verbose: int = args.verbose
    version_start_including: str | None = args.version_start_including
    version_start_excluding: str | None = args.version_start_excluding
    version_end_including: str | None = args.version_end_including
    version_end_excluding: str | None = args.version_end_excluding
    limit: int | None = args.limit
    include_deprecated: bool = args.include_deprecated

    cpe_database_name: str = (
        args.database_name
        or os.environ.get("CPE_DATABASE_NAME")
        or os.environ.get("DATABASE_NAME")
        or DEFAULT_POSTGRES_DATABASE_NAME
    )
    cpe_database_user: str = (
        args.database_user
        or os.environ.get("CPE_DATABASE_USER")
        or os.environ.get("DATABASE_USER")
        or DEFAULT_POSTGRES_USER
    )
    cpe_database_host: str = (
        args.database_host
        or os.environ.get("CPE_DATABASE_HOST")
        or os.environ.get("DATABASE_HOST")
        or DEFAULT_POSTGRES_HOST
    )
    cpe_database_port: int = int(
        args.database_port
        or os.environ.get("CPE_DATABASE_PORT")
        or os.environ.get("DATABASE_PORT")
        or DEFAULT_POSTGRES_PORT
    )
    cpe_database_schema: str | None = (
        args.database_schema
        or os.environ.get("CPE_DATABASE_SCHEMA")
        or os.environ.get("DATABASE_SCHEMA")
    )
    cpe_database_password: str | None = (
        args.database_password
        or os.environ.get("CPE_DATABASE_PASSWORD")
        or os.environ.get("DATABASE_PASSWORD")
    )
    if not cpe_database_password:
        raise ScapError("Missing password for CPE database")

    cpe_database = PostgresDatabase(
        user=cpe_database_user,
        password=cpe_database_password,
        host=cpe_database_host,
        port=cpe_database_port,
        dbname=cpe_database_name,  # type: ignore
        schema=cpe_database_schema,
        echo=echo_sql,
    )
    if verbose:
        console.log(f"Using PostgreSQL database {cpe_database_name}")

    async with cpe_database as db, CPEManager(db) as manager:
        count = 0
        console.log(f"Searching for CPEs matching '{args.cpe}'")

        async for cpe in manager.find(
            exact=args.exact,
            version_ranges=[
                VersionRange(
                    cpe=CPE.from_string(args.cpe),
                    version_start_excluding=version_start_excluding,
                    version_start_including=version_start_including,
                    version_end_excluding=version_end_excluding,
                    version_end_including=version_end_including,
                )
            ],
            limit=limit,
            deprecated=include_deprecated,
        ):
            count += 1
            console.print(cpe, end="\n\n")

        console.log(f"Found {count} matching CPEs")


def main() -> None:
    console = Console(log_path=False)
    error_console = Console(file=sys.stderr, log_path=False)
    try:
        asyncio.run(find_cpes(console))
    except KeyboardInterrupt:
        pass
    except ScapError as e:
        error_console.print(f"Error: {e}")


if __name__ == "__main__":
    main()
