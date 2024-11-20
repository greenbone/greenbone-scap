# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import gzip
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console

from greenbone.scap.data_utils.json import (
    JsonEncoder,
    JsonManager,
)


@dataclass
class MatchStringItem:
    """
    Data class to represent a CPE match string item.

    Attributes:
        match_string: The match string instance associated with this item.
    """

    match_string: CPEMatchString


@dataclass
class MatchStringResponse:
    """
    Data class to represent a response containing CPE match string data.

    Attributes:
        results_per_page: Number of results per page.
        start_index: The starting index of the results.
        total_results: Total number of results.
        timestamp: Timestamp of the response creation.
        products: List of products.
        format: Format of the response, default is "NVD_CPE".
        version: Version of the response format, default is "2.0".
    """

    results_per_page: int
    start_index: int
    total_results: int
    timestamp: datetime
    match_strings: list[MatchStringItem]

    format: str = "NVD_CPEMatchString"
    version: str = "2.0"


class MatchStringJsonManager(JsonManager):
    """
    Manages the storage and organization of CPE match data.
    """

    def __init__(
        self,
        error_console: Console,
        storage_path: Path,
        *,
        compress: bool = False,
        schema_path: Path | None = None,
        raise_error_on_validation=False,
    ):
        super().__init__(
            error_console=error_console,
            schema_path=schema_path,
            raise_error_on_validation=raise_error_on_validation,
        )
        self._match_string_response = MatchStringResponse(
            results_per_page=1,
            start_index=0,
            total_results=1,
            timestamp=datetime.now(),
            match_strings=[],
        )
        self._compress: bool = compress
        self._storage_path: Path = storage_path

    def add_match_string(self, match_string: CPEMatchString) -> None:
        self._match_string_response.match_strings.append(
            MatchStringItem(match_string=match_string)
        )

    def add_match_strings(
        self, match_strings: Sequence[CPEMatchString]
    ) -> None:
        for match_string in match_strings:
            self.add_match_string(match_string)

    def write(self) -> None:
        """
        Write the CPE data to JSON files with optional compression in the specified folder.
        """

        self._match_string_response.results_per_page = len(
            self._match_string_response.match_strings
        )
        self._match_string_response.total_results = len(
            self._match_string_response.match_strings
        )

        json_data = json.dumps(
            asdict(self._match_string_response), cls=JsonEncoder, indent=1
        )
        self._validate_json("nvd-cpe-matches", json_data)

        if self._compress:
            path = self._storage_path / "nvd-cpe-matches.json.gz"
            path.write_bytes(gzip.compress(json_data.encode("utf-8")))
        else:
            path = self._storage_path / "nvd-cpe-matches.json"
            path.write_bytes(json_data.encode("utf-8"))
