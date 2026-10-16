"""Canonical JSON serialization for typed protocol objects."""

from __future__ import annotations

import base64
import json
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ppml_healthcare.errors import SchemaValidationError


def _normalize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _normalize(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise SchemaValidationError("canonical datetime values must be timezone-aware UTC")
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise SchemaValidationError("canonical JSON object keys must be strings")
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise SchemaValidationError("canonical JSON does not permit non-finite numbers")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise SchemaValidationError(f"unsupported canonical value type: {type(value).__name__}")


def canonical_object(value: Any) -> dict[str, Any]:
    """Return normalized object fields. Top-level values must be mappings/dataclasses."""
    normalized = _normalize(value)
    if not isinstance(normalized, dict):
        raise SchemaValidationError("canonical object must be a dataclass or mapping")
    return normalized


def canonical_bytes(value: Any) -> bytes:
    """Serialize with sorted keys, compact separators, UTF-8, and no NaN/Infinity."""
    try:
        encoded = json.dumps(
            _normalize(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError("value cannot be canonically serialized") from exc
    return encoded.encode("utf-8")
