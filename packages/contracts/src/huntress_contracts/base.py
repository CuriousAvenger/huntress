"""Contract base model, identifiers, canonical JSON, and hashing helpers."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

CONTRACT_VERSION = "1.0"

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}_[a-zA-Z0-9][a-zA-Z0-9_-]{5,80}$")


class Contract(BaseModel):
    """Base for every public contract.

    - ``extra="forbid"`` blocks model-invented fields (including scope or budget
      mutations smuggled into an action proposal).
    - ``frozen=True`` makes a constructed contract an immutable record. Use
      ``model_copy(update=...)`` to derive a new state.
    - ``validate_assignment`` is unnecessary on a frozen model.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
        use_enum_values=False,
    )


def utc_now() -> datetime:
    """Timezone-aware UTC timestamp. All persisted times are UTC."""

    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Create a prefixed, URL-safe identifier.

    UUID4 is intentional: IDs are opaque, never sequence numbers, so they do
    not leak volume or ordering across tenants.
    """

    if not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", prefix):
        raise ValueError(f"invalid id prefix: {prefix!r}")
    return f"{prefix}_{uuid.uuid4().hex}"


def validate_id(value: str, prefix: str) -> str:
    """Validate an identifier shape without accepting arbitrary strings."""

    if not value.startswith(f"{prefix}_") or not _ID_RE.fullmatch(value):
        raise ValueError(f"expected {prefix}_* identifier, got {value!r}")
    return value


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for hashes and signatures.

    Pydantic models are serialized in JSON mode, datetimes to RFC 3339, and
    keys sorted. Floats are only allowed when finite.
    """

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def content_hash(value: BaseModel | dict[str, Any]) -> str:
    return sha256_hex(canonical_json(value))


def ensure_utc(value: datetime) -> datetime:
    """Reject naive datetimes; normalize aware datetimes to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware (UTC)")
    return value.astimezone(UTC)


def ensure_between(value: int | float, minimum: int | float, maximum: int | float, name: str) -> None:
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}, got {value}")


class ContractRef(Contract):
    """A typed reference to another contract record."""

    kind: str
    id: str
    version: str = CONTRACT_VERSION

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.kind}:{self.id}"


def model_self_hash(model: BaseModel, *, exclude: frozenset[str] = frozenset()) -> str:
    """Hash a model excluding its own hash/signature fields."""

    data = model.model_dump(mode="json")
    for field in exclude:
        data.pop(field, None)
    return content_hash(data)


def with_hash[ModelT: BaseModel](
    model: ModelT,
    *,
    field: str = "content_hash",
    exclude: frozenset[str] = frozenset(),
) -> ModelT:
    """Return a copy with a computed content hash."""

    digest = model_self_hash(model, exclude=exclude | {field})
    return model.model_copy(update={field: digest})
