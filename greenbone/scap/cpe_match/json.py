# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import gzip
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Sequence, TextIO

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console

from greenbone.scap.data_utils.json import (
    JsonEncoder,
    JsonManager,
    convert_keys_to_camel,
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

    def _encode_json(
        self,
        data: dict[str, Any],
        out_file: TextIO,
        validation_buffer: Optional[bytearray] = None,
        *,
        indent: int = 1,
    ):
        encoder = JsonEncoder(indent=indent)

        for chunk in encoder.iterencode(data):
            out_file.write(chunk)
            if validation_buffer is not None:
                validation_buffer.extend(chunk.encode("utf-8"))

    def write(self, file_name: str = "nvd_cpe_matches") -> None:
        """
        Write the CPE data to JSON files with optional compression in the specified folder.
        """

        self._match_string_response.results_per_page = len(
            self._match_string_response.match_strings
        )
        self._match_string_response.total_results = len(
            self._match_string_response.match_strings
        )

        validation_buffer: Optional[bytearray] = None
        if self.validate:
            validation_buffer = bytearray()

        response_dict = asdict(self._match_string_response)
        convert_keys_to_camel(response_dict)

        if self._compress:
            path = self._storage_path / f"{file_name}.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as out_file:
                self._encode_json(response_dict, out_file, validation_buffer)
        else:
            path = self._storage_path / f"{file_name}.json"
            with open(path, "wt", encoding="utf-8") as out_file:
                self._encode_json(response_dict, out_file, validation_buffer)

        if validation_buffer:
            self._validate_json(file_name, validation_buffer.decode("utf-8"))
