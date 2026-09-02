from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .envelope import ObjectEnvelope
from .relationships import Relationship


def canonical_json(value: Any) -> str:
    """Canonical UTF-8-compatible JSON representation used by protocol hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def envelope_to_json(envelope: ObjectEnvelope) -> str:
    return canonical_json(envelope.to_dict())


def envelope_from_json(value: str) -> ObjectEnvelope:
    decoded = _decode_object(value)
    return ObjectEnvelope.from_dict(decoded)


def relationship_to_json(relationship: Relationship) -> str:
    return canonical_json(relationship.to_dict())


def relationship_from_json(value: str) -> Relationship:
    decoded = _decode_object(value)
    return Relationship.from_dict(decoded)


def _decode_object(value: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("canonical protocol object must decode to a JSON object")
    return decoded
