# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import fastjsonschema
from rich.console import Console

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _snake_to_camel(snake_str: str) -> str:
    """
    Convert a snake_case string to camelCase.

    Args:
        snake_str: The snake_case string to convert.

    Returns:
        The camelCase version of the input string.
    """
    components = snake_str.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def convert_keys_to_camel(obj: Any) -> Any:
    """
    Recursively converts all dictionary keys of an object from snake_case to camelCase
    and excludes all None/null values, modifying the object in place.

    Args:
        obj: The object to convert, which can be a dictionary, list, or other type.
    """

    if isinstance(obj, dict):
        old_keys = set(obj.keys())
        for old_key in old_keys:
            v = obj[old_key]
            convert_keys_to_camel(v)
            # Exclude None values
            if v is not None:
                new_key = _snake_to_camel(old_key)
                obj[new_key] = v
            del obj[old_key]
    elif isinstance(obj, list):
        for item in obj:
            convert_keys_to_camel(item)


def _custom_uuid_validate(value):
    """
    Validate whether the given value matches a UUID pattern.

    Parameters:
        value: The value to be validated as a UUID.

    Returns:
        True if the value matches the UUID pattern, False otherwise.
    """

    if UUID_PATTERN.match(value):
        return True


class JsonEncoder(json.JSONEncoder):
    """
    A custom JSON encoder that serializes datetime and date objects to ISO format.
    """

    def default(self, obj: Any) -> Any:
        """
        Handle custom serialization for datetime and date objects.

        Args:
            obj: The object to serialize.

        Returns:
            The serialized form of the datetime or date object, or the default JSON encoding.
        """

        if isinstance(obj, datetime):
            return (
                obj.astimezone(timezone.utc)
                .replace(tzinfo=None)
                .isoformat(timespec="milliseconds")
                + "Z"
                if obj.tzinfo
                else obj.isoformat(timespec="milliseconds") + "Z"
            )
        elif isinstance(obj, date):
            return obj.isoformat()
        elif isinstance(obj, uuid.UUID):
            return str(obj).upper()

        return super().default(obj)

    def iterencode(self, obj: Any, _one_shot: bool = False) -> Any:
        """
        Encode an object to JSON format, converting keys to camelCase.

        Args:
            obj: The object to encode.

        Returns:
            The JSON-encoded string with converted date and datetime objects.
        """

        return super().iterencode(obj, _one_shot)


class JsonManager:
    def __init__(
        self,
        error_console: Console,
        schema_path: Path | None = None,
        raise_error_on_validation=False,
    ):
        """
        Initializes the JsonManager

        Parameters:
            error_console:
                An instance of the Console class used for logging errors and
                validation messages.
            schema_path:
                A Path object pointing to the JSON schema file used for validating
                CPE data. If provided, the schema is loaded during initialization.
            raise_error_on_validation:
                If True, raises an exception on json validation errors.
                If False, log validation warnings.
        Attributes:
            _error_console:
                The Console instance for error and validation message output.
            validate:
                A compiled validation function for the schema, or None if no schema
                is provided.
            _raise_error_on_validation:
                Raises an exception on json validation errors.
        """

        self._error_console = error_console
        self.validate = (
            fastjsonschema.compile(
                json.loads(schema_path.read_text()),
                formats={"uuid": _custom_uuid_validate},
            )
            if schema_path
            else None
        )
        self._raise_error_on_validation = raise_error_on_validation

    def _validate_json(self, name: str, data: str | bytes) -> None:
        """
        Validates JSON data against a predefined schema.

        Parameters:
            name: A name identifier for the JSON data being validated. Used in error messages.
            data: The JSON data in string format to be validated.

        Raises:
            JsonSchemaException: If the JSON data does not conform to the schema.

        Notes:
            - If `self.validate` is None or empty, the method returns without performing validation.
        """

        if not self.validate:
            return

        try:
            if isinstance(data, bytes):
                self.validate(json.loads(data).decode("utf-8"))
            else:
                self.validate(json.loads(data))
        except fastjsonschema.JsonSchemaException as e:
            msg = (
                f"JSON file {name} is invalid."
                f" Name: {e.name} Value: {e.value}"
                f" Definition: {e.definition}"
                f" Rule: {e.rule}"
            )
            # Work around progress bar issue with console_error
            print(msg)
            self._error_console.print(msg)
            if self._raise_error_on_validation:
                raise e
