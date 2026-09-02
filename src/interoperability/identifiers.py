from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError

from .records import _require_text, coerce_enum

# Identifier kinds named by the frozen interoperability contract: resolution may
# use IBAN, account numbers, aliases, phone numbers, merchant IDs, QR data,
# wallet addresses or other jurisdictional identifiers. The vocabulary below is
# closed over the explicitly named schemes; unknown schemes fail closed and a
# vocabulary extension is a governed schema change in this domain.
class IdentifierScheme(StrEnum):
    IBAN = "IBAN"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    ALIAS = "ALIAS"
    PHONE_NUMBER = "PHONE_NUMBER"
    MERCHANT_ID = "MERCHANT_ID"
    QR_DATA = "QR_DATA"
    WALLET_ADDRESS = "WALLET_ADDRESS"


_IDENTIFIER_KEYS = frozenset({"scheme", "value", "jurisdiction"})

_ALNUM_ACCOUNT = re.compile(r"[A-Za-z0-9.\-]{1,64}")
_ALNUM_MERCHANT = re.compile(r"[A-Za-z0-9._\-]{1,64}")
_ALNUM_WALLET = re.compile(r"[A-Za-z0-9]{1,128}")
_E164_PHONE = re.compile(r"\+[1-9][0-9]{6,14}")
_IBAN_ELECTRONIC = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
_JURISDICTION = re.compile(r"[A-Z]{2}")

_MAX_ALIAS_LENGTH = 256
_MAX_QR_LENGTH = 512


def _validate_iban(value: str) -> str:
    """Validate an IBAN and return its canonical electronic form.

    Structural rules follow ISO 13616 (15-34 alphanumeric characters after
    normalization) and the check digits are verified with the ISO 7064
    mod-97 scheme. Written forms with interstitial spaces are normalized.
    """
    electronic = value.replace(" ", "").upper()
    if not _IBAN_ELECTRONIC.fullmatch(electronic):
        raise CoreValidationError(
            f"identifier.value is not a structurally valid IBAN: {value!r}"
        )
    rearranged = electronic[4:] + electronic[:4]
    numeric = "".join(str(int(character, 36)) for character in rearranged)
    if int(numeric) % 97 != 1:
        raise CoreValidationError(
            f"identifier.value fails the IBAN mod-97 check digit test: {value!r}"
        )
    return electronic


def _validate_value(scheme: IdentifierScheme, value: str) -> str:
    _require_text("identifier.value", value)
    if scheme is IdentifierScheme.IBAN:
        return _validate_iban(value)
    if scheme is IdentifierScheme.PHONE_NUMBER:
        if not _E164_PHONE.fullmatch(value):
            raise CoreValidationError(
                f"identifier.value must be an E.164 phone number (+, 7-15 digits, "
                f"no leading zero), got {value!r}"
            )
        return value
    if scheme is IdentifierScheme.ACCOUNT_NUMBER:
        if not _ALNUM_ACCOUNT.fullmatch(value):
            raise CoreValidationError(
                f"identifier.value must be 1-64 alphanumeric account characters, got {value!r}"
            )
        return value
    if scheme is IdentifierScheme.MERCHANT_ID:
        if not _ALNUM_MERCHANT.fullmatch(value):
            raise CoreValidationError(
                f"identifier.value must be 1-64 alphanumeric merchant characters, got {value!r}"
            )
        return value
    if scheme is IdentifierScheme.WALLET_ADDRESS:
        if not _ALNUM_WALLET.fullmatch(value):
            raise CoreValidationError(
                f"identifier.value must be 1-128 alphanumeric wallet characters, got {value!r}"
            )
        return value
    if scheme is IdentifierScheme.ALIAS:
        if value != value.strip() or len(value) > _MAX_ALIAS_LENGTH:
            raise CoreValidationError(
                f"identifier.value must be a trimmed alias of at most "
                f"{_MAX_ALIAS_LENGTH} characters, got {value!r}"
            )
        return value
    if scheme is IdentifierScheme.QR_DATA:
        if len(value) > _MAX_QR_LENGTH:
            raise CoreValidationError(
                f"identifier.value must be QR data of at most {_MAX_QR_LENGTH} characters"
            )
        return value
    raise CoreValidationError(f"unknown identifier scheme: {scheme!r}")


def _validate_jurisdiction(scheme: IdentifierScheme, value: str,
                           jurisdiction: str | None) -> str | None:
    if jurisdiction is None:
        return None
    _require_text("identifier.jurisdiction", jurisdiction)
    if not _JURISDICTION.fullmatch(jurisdiction):
        raise CoreValidationError(
            f"identifier.jurisdiction must be an ISO 3166-1 alpha-2 code, got {jurisdiction!r}"
        )
    if scheme is IdentifierScheme.IBAN and value[:2] != jurisdiction:
        raise CoreValidationError(
            f"identifier.jurisdiction {jurisdiction!r} does not match the IBAN country code "
            f"{value[:2]!r}"
        )
    return jurisdiction


@dataclass(frozen=True, slots=True)
class EndpointIdentifier:
    """A jurisdictional identifier by which an endpoint can be addressed."""

    scheme: IdentifierScheme
    value: str
    jurisdiction: str | None = None

    def __post_init__(self) -> None:
        scheme = coerce_enum("identifier.scheme", IdentifierScheme, self.scheme)
        value = _validate_value(scheme, self.value)
        jurisdiction = _validate_jurisdiction(scheme, value, self.jurisdiction)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "jurisdiction", jurisdiction)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme.value,
            "value": self.value,
            "jurisdiction": self.jurisdiction,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EndpointIdentifier":
        if not isinstance(value, Mapping):
            raise CoreValidationError("identifier must be an object")
        if set(value) != _IDENTIFIER_KEYS:
            missing = sorted(_IDENTIFIER_KEYS - set(value))
            extra = sorted(set(value) - _IDENTIFIER_KEYS)
            raise CoreValidationError(
                f"non-canonical identifier fields; missing={missing}, extra={extra}"
            )
        return cls(
            scheme=value["scheme"],
            value=value["value"],
            jurisdiction=value["jurisdiction"],
        )

    def identity_key(self) -> tuple[str, str]:
        """Canonical matching key used by endpoint resolution."""
        return (self.scheme.value, self.value)


__all__ = ["EndpointIdentifier", "IdentifierScheme"]
