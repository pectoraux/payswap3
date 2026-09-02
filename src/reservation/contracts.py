"""Frozen public-boundary contracts for the reservation domain (WORK-012).

The reservation domain owns the protocol-level ``Reservation`` lifecycle of
the frozen v0.1 command family
``Create/Hold/Commit/Amend/Release/Expire/Default/Consume``. No reservation
object type is listed in the frozen protocol registry (the registry lists
protocol-visible ``payswap/...`` object types and the ``reservation`` event
namespace only), so — following the sibling convention of ``src/intent``,
``src/capability`` and ``src/market`` — the reservation object type below
uses an internal non-registry ``reservation/...`` format. No new
protocol-visible name is invented here.
"""

from __future__ import annotations

from enum import StrEnum

# -- typed, versioned public boundary --------------------------------------

#: Version of this domain's public API surface (bumped only through a new
#: immutable contract version, never in place).
RESERVATION_API_VERSION = 1

#: Governing frozen architecture version.
RESERVATION_PROTOCOL_VERSION = "v0.1"

#: Schema version of the reservation payload and envelope contracts.
RESERVATION_SCHEMA_VERSION = 1

# Internal (non-registry) object type of the reservation domain.
RESERVATION_OBJECT_TYPE = "reservation/resource-reservation/v1"

# -- the frozen command family ---------------------------------------------

#: The frozen v0.1 ``Reservation`` command family, in the exact order the
#: architecture lock spells it out: the protocol-level vocabulary this
#: domain implements. The market-local ``Reservation`` of WORK-010 is a
#: bounded mechanism artifact covering only the
#: ``Create/Commit/Release/Expire`` subset; this family is its protocol-level
#: superset with encumbrance holding, amendment, default handling and
#: consumption.
RESERVATION_COMMANDS = (
    "Create",
    "Hold",
    "Commit",
    "Amend",
    "Release",
    "Expire",
    "Default",
    "Consume",
)


class ReservationCommand(StrEnum):
    """Closed command vocabulary of the protocol reservation lifecycle."""

    CREATE = "Create"
    HOLD = "Hold"
    COMMIT = "Commit"
    AMEND = "Amend"
    RELEASE = "Release"
    EXPIRE = "Expire"
    DEFAULT = "Default"
    CONSUME = "Consume"
