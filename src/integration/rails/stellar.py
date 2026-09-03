"""The Stellar testnet rail — IG-005's second REAL external rail adapter.

``StellarTestnetRail`` implements the merged execution domain's typed
ports (:class:`src.execution.adapters.EffectSubmissionPort` /
:class:`src.execution.adapters.EffectReconciliationPort`) over the
PUBLIC Stellar testnet: an open, credential-free sandbox network
accessed through the public Horizon API. No credential exists or is
required (the work order forbids production credentials; the testnet
is not production). The rail's test accounts are deterministic Ed25519
keypairs derived from PUBLIC constants — documented as NON-SECRET by
construction (anyone can derive them; they hold testnet XLM only and
are never used against any production network).

The envelope encoding is the current testnet TransactionV0 shape
(muxed-account source, trailing ext), pinned byte-for-byte by the
suite's golden test and verified against the live network before
pinning. The signature payload is
``sha256(network_id || ENVELOPE_TYPE_TX_V0 tag || tx bytes)`` with the
frozen testnet passphrase ``"Test SDF Network ; September 2015"``.

SECURITY (non-negotiable, mirroring the merged WORK-027 rail):

* errors are sanitized to ``{http_status, result_codes}`` /
  ``{transport error_class}`` envelopes — no headers, no raw provider
  bodies, no secrets (there are none to leak: the rail is
  credential-free);
* only safe normalized references (the transaction hash) are kept and
  reported;
* an unreachable or failing sandbox means OFFLINE MODE: the effect is
  NOT ATTEMPTED when the world cannot even be prepared (account
  lookup/funding fails), the submission returns an explicit UNKNOWN
  with a sanitized reason, and reconciliation reports NOT_FOUND for
  never-attempted effects (the honest retry-safe truth).

Rail-side idempotency is DURABLE: the idempotency key is carried as
the transaction MEMO, and every submission first looks the memo up in
the source account's recent transactions — a key that was already
paid returns the SAME native reference (the on-chain transaction
hash) without a new network submission, exactly like the merged Stripe
rail's ``Idempotency-Key`` behavior.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.interoperability import (
    AdapterStatusMap,
    CanonicalPaymentStatus,
    EffectInterface,
    IdentifierScheme,
    ObservationInterface,
    StatusMapEntry,
    WorldAdapter,
)
from src.execution.adapters import (
    AdapterBinding,
    AdapterQueryResult,
    AdapterSubmission,
    EffectReconciliationPort,
    EffectSubmissionPort,
)
from src.execution.contracts import QueryOutcome, SubmissionStatus

from .ed25519 import ed25519_public_key, ed25519_sign

#: The public Stellar testnet network passphrase (frozen network data).
STELLAR_TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"

#: The network id: sha256 of the passphrase (the signature salt).
STELLAR_NETWORK_ID = hashlib.sha256(
    STELLAR_TESTNET_PASSPHRASE.encode("utf-8")
).digest()

#: The public Horizon testnet REST endpoint.
STELLAR_HORIZON_BASE = "https://horizon-testnet.stellar.org"

#: The public friendbot funding endpoint of the testnet.
STELLAR_FRIENDBOT_BASE = "https://friendbot.stellar.org"

#: One XLM is 10^7 stroops (the native asset's fixed scale).
STELLAR_STROOPS_PER_XLM = 10_000_000

#: The native asset's decimal scale.
STELLAR_NATIVE_SCALE = 7

#: The deterministic per-operation fee the rail declares (stroops;
#: the network base fee is 100 — the declared constant leaves a
#: congestion margin while staying dust).
STELLAR_FEE_STROOPS = 1000

#: The canonical transaction memo length bound (XDR string).
_STELLAR_MEMO_MAX = 28

#: How many of the source account's most recent transactions the
#: memo-based reconciliation covers (one call, deterministic bound —
#: the rail's scenario keys are recent and unique; older keys
#: reconcile NOT_FOUND, the honest retry-safe truth for the lookup's
#: reach).
_STELLAR_MEMO_LOOKUP_LIMIT = 200

#: Declared test accounts: deterministic Ed25519 keypairs derived from
#: PUBLIC constants. NON-SECRET by construction (testnet-only, derived
#: from public repo constants, hold testnet XLM only).
_SOURCE_SEED = hashlib.sha256(
    b"payswap-ig005-stellar-testnet-source-account"
).digest()[:32]
_DESTINATION_SEED = hashlib.sha256(
    b"payswap-ig005-stellar-testnet-destination-account"
).digest()[:32]
_UNFUNDED_SEED = hashlib.sha256(
    b"payswap-ig005-stellar-testnet-unfunded-destination"
).digest()[:32]

_STROOPS_PATTERN = re.compile(r"^[0-9a-f]{64}$")

#: The rail's declared native status vocabulary (the closed map into
#: the merged canonical payment status vocabulary; an undeclared
#: native word fails closed through the map itself).
STELLAR_STATUS_MAP = (
    StatusMapEntry("completed", CanonicalPaymentStatus.SETTLED),
    StatusMapEntry("pending", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("failed", CanonicalPaymentStatus.FAILED),
)

#: The declared adapter identity of the Stellar testnet rail.
RAILS_STELLAR_ADAPTER_ID = "interoperability/adapter/stellar-testnet"

#: The definitive on-chain business-rejection operation codes (the
#: payment did not and will not happen; a retry of the same envelope
#: can never succeed).
_DEFINITIVE_REJECTION_CODES = frozenset(
    {
        "op_no_destination",
        "op_no_trustline",
        "op_underfunded",
        "op_not_authorized",
        "op_line_full",
        "op_amount_too_large",
    }
)

_TIMEOUT_SECONDS = 20

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _base32_encode(data: bytes) -> str:
    bits = 0
    value = 0
    output: list[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            output.append(_BASE32_ALPHABET[(value >> (bits - 5)) & 31])
            bits -= 5
    if bits:
        output.append(_BASE32_ALPHABET[(value << (5 - bits)) & 31])
    return "".join(output)


def strkey_encode_account(public_key: bytes) -> str:
    """Encode a raw Ed25519 public key as a Stellar account strkey."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise CoreValidationError("account strkeys encode 32-byte keys")
    payload = bytes([6 << 3]) + bytes(public_key)
    checksum = _crc16_xmodem(payload).to_bytes(2, "little")
    return _base32_encode(payload + checksum)


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _require_seed_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise CoreValidationError(f"{name} must be exactly 32 bytes")


def build_payment_transaction_bytes(
    *,
    source_public_key: bytes,
    destination_public_key: bytes,
    sequence: int,
    amount_stroops: int,
    memo: str,
    fee_stroops: int = STELLAR_FEE_STROOPS,
) -> bytes:
    """The TransactionV0 bytes (muxed source … trailing ext inclusive).

    The exact shape the current public testnet accepts — verified
    byte-for-byte against the live network and pinned by the suite's
    golden test:

    ``[tag 2][source muxed tag 0 + key 32][fee u32][seq i64]
    [timeBounds* null][MEMO_TEXT + padded][ops 1]
    [op source* null][PAYMENT][dest muxed tag 0 + key 32]
    [ASSET_TYPE_NATIVE][amount i64][ext 0]``
    """
    _require_seed_bytes(source_public_key, "source_public_key")
    _require_seed_bytes(destination_public_key, "destination_public_key")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise CoreValidationError("the sequence must be a non-negative integer")
    if (
        not isinstance(amount_stroops, int)
        or isinstance(amount_stroops, bool)
        or amount_stroops < 1
    ):
        raise CoreValidationError("the amount must be a positive integer of stroops")
    if (
        not isinstance(fee_stroops, int)
        or isinstance(fee_stroops, bool)
        or fee_stroops < 100
    ):
        raise CoreValidationError("the fee must be at least the network base fee")
    if not isinstance(memo, str) or not memo.strip():
        raise CoreValidationError("the transaction memo must be a non-empty string")
    if len(memo.encode("utf-8")) > _STELLAR_MEMO_MAX:
        raise CoreValidationError(
            f"the memo must be at most {_STELLAR_MEMO_MAX} bytes"
        )
    memo_bytes = memo.encode("utf-8")
    parts = [
        _u32(0),  # source MuxedAccount tag: KEY_TYPE_ED25519
        bytes(source_public_key),
        _u32(fee_stroops),
        _u64(sequence),
        _u32(0),  # TimeBounds* null
        _u32(1),  # Memo: MEMO_TEXT
        _u32(len(memo_bytes)),
        _pad4(memo_bytes),
        _u32(1),  # operations count
        _u32(0),  # Operation.sourceAccount* null
        _u32(1),  # OperationType: PAYMENT
        _u32(0),  # destination MuxedAccount tag: KEY_TYPE_ED25519
        bytes(destination_public_key),
        _u32(0),  # Asset: ASSET_TYPE_NATIVE
        _u64(amount_stroops),
        _u32(0),  # TransactionV0 trailing ext: void
    ]
    return b"".join(parts)


def build_payment_envelope(
    *,
    source_seed: bytes,
    destination_public_key: bytes,
    sequence: int,
    amount_stroops: int,
    memo: str,
    fee_stroops: int = STELLAR_FEE_STROOPS,
) -> str:
    """Build and sign one payment envelope; return it base64-encoded."""
    transaction = build_payment_transaction_bytes(
        source_public_key=ed25519_public_key(source_seed),
        destination_public_key=destination_public_key,
        sequence=sequence,
        amount_stroops=amount_stroops,
        memo=memo,
        fee_stroops=fee_stroops,
    )
    return _sign_transaction(source_seed, transaction)


def _sign_transaction(source_seed: bytes, transaction: bytes) -> str:
    """Sign the transaction bytes and wrap them in the V0 envelope."""
    payload = hashlib.sha256(STELLAR_NETWORK_ID + _u32(2) + transaction).digest()
    signature = ed25519_sign(source_seed, payload)
    public_key = ed25519_public_key(source_seed)
    envelope = (
        _u32(2)
        + transaction
        + _u32(1)  # ENVELOPE_TYPE_TX_V0
        + public_key[-4:]  # one DecoratedSignature
        + _u32(len(signature))
        + signature
    )
    return base64.b64encode(envelope).decode("ascii")


def _transaction_boundary(envelope: bytes) -> int:
    """Walk one V0 envelope to the offset of the signatures count."""
    offset = 4  # envelope tag
    offset += 4 + 32  # source muxed tag + key
    offset += 4  # fee
    offset += 8  # seq
    time_bounds = int.from_bytes(envelope[offset : offset + 4], "big")
    offset += 4
    if time_bounds:
        offset += 16
    memo_type = int.from_bytes(envelope[offset : offset + 4], "big")
    offset += 4
    if memo_type == 1:
        length = int.from_bytes(envelope[offset : offset + 4], "big")
        offset += 4 + len(_pad4(b"\x00" * length))
    elif memo_type != 0:
        raise CoreValidationError("unsupported memo type in the envelope")
    operations = int.from_bytes(envelope[offset : offset + 4], "big")
    offset += 4
    for _ in range(operations):
        source_pointer = int.from_bytes(envelope[offset : offset + 4], "big")
        offset += 4
        if source_pointer:
            offset += 4 + 32
        operation_type = int.from_bytes(envelope[offset : offset + 4], "big")
        offset += 4
        if operation_type == 1:  # PAYMENT
            offset += 4 + 32 + 4 + 8  # dest muxed + asset native + amount
        elif operation_type == 0:  # CREATE_ACCOUNT
            offset += 4 + 32 + 8
        else:
            raise CoreValidationError(
                "unsupported operation type in the envelope"
            )
    offset += 4  # trailing ext
    return offset


def stellar_transaction_hash(envelope_base64: str) -> str:
    """The transaction hash of one signed envelope (hex)."""
    envelope = base64.b64decode(envelope_base64.encode("ascii"))
    boundary = _transaction_boundary(envelope)
    digest = hashlib.sha256(STELLAR_NETWORK_ID + envelope[:boundary]).digest()
    return digest.hex()


def _http(
    method: str,
    url: str,
    *,
    params: Mapping[str, Any] | None = None,
    timeout: int = _TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """One HTTP call returning a sanitized outcome envelope.

    Raises nothing on provider errors — the envelope carries
    ``{"transport": ...}`` or ``{"provider_error": {...}}`` so the
    ports can translate explicitly. No header or secret material is
    ever included (the rail holds no credentials at all).
    """
    data = None
    if params is not None:
        data = urllib.parse.urlencode(params).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"User-Agent": "payswap-ig005-rail/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"ok": json.loads(response.read().decode("utf-8"))}
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read().decode("utf-8"))
        except Exception:  # sanitized: never leak raw bodies
            payload = {}
        extras = payload.get("extras", {})
        result_codes = extras.get("result_codes")
        return {
            "provider_error": {
                "http_status": error.code,
                "result_codes": (
                    {
                        "transaction": result_codes.get("transaction"),
                        "operations": result_codes.get("operations"),
                    }
                    if isinstance(result_codes, Mapping)
                    else None
                ),
            }
        }
    except Exception as error:  # transport failure, sanitized
        return {"transport": {"error_class": type(error).__name__}}


class StellarTestnetRail(EffectSubmissionPort, EffectReconciliationPort):
    """The REAL_PROVIDER_SANDBOX Stellar testnet rail.

    Submissions build, sign and POST one native XLM payment whose MEMO
    is the request's idempotency key (durable rail-side idempotency:
    the memo lookup returns the SAME on-chain transaction hash for an
    already-paid key, never a second payment). Rejections are
    deterministic: a declared rejection key pays the deterministic
    UNFUNDED destination, which the network definitively rejects
    (``op_no_destination`` — the payment never happened and a retry of
    the same envelope can never succeed). Queries reconcile through
    the rail's own recorded hash or the memo lookup.
    """

    def __init__(
        self,
        *,
        api_base: str = STELLAR_HORIZON_BASE,
        friendbot_base: str = STELLAR_FRIENDBOT_BASE,
        reject_keys: Iterable[str] = (),
        timeout_seconds: int = _TIMEOUT_SECONDS,
        memo_lookup_limit: int = _STELLAR_MEMO_LOOKUP_LIMIT,
    ) -> None:
        self._api_base = api_base.rstrip("/")
        self._friendbot_base = friendbot_base.rstrip("/")
        self._reject_keys = frozenset(reject_keys)
        self._timeout_seconds = timeout_seconds
        self._memo_lookup_limit = memo_lookup_limit
        self._source_seed = _SOURCE_SEED
        self._destination_public = ed25519_public_key(_DESTINATION_SEED)
        self._unfunded_public = ed25519_public_key(_UNFUNDED_SEED)
        self._native: dict[str, dict[str, Any]] = {}
        self._rejected: dict[str, str] = {}
        self._native_status: dict[str, str] = {}
        self._world_ready = False
        self.submit_call_count = 0
        self.query_call_count = 0
        self.network_submit_count = 0
        self.offline_reason: str | None = None

    # -- public rail facts (sanitized, safe references only) -------------

    @property
    def credential_env_var(self) -> None:
        """The Stellar testnet is credential-free (public sandbox)."""
        return None

    @property
    def source_account_strkey(self) -> str:
        return strkey_encode_account(ed25519_public_key(self._source_seed))

    @property
    def destination_account_strkey(self) -> str:
        return strkey_encode_account(self._destination_public)

    @property
    def unfunded_destination_strkey(self) -> str:
        return strkey_encode_account(self._unfunded_public)

    @property
    def processed_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._native))

    @property
    def rejected_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._rejected))

    def native_status_for(self, key: str) -> str | None:
        return self._native_status.get(key)

    def native_payment(self, key: str) -> dict[str, Any] | None:
        native = self._native.get(key)
        return None if native is None else dict(native)

    # -- world preparation --------------------------------------------------

    def _get_json(self, path: str) -> dict[str, Any]:
        return _http(
            "GET", f"{self._api_base}{path}", timeout=self._timeout_seconds
        )

    def _account_sequence(self, strkey: str) -> int | None:
        result = self._get_json(f"/accounts/{strkey}")
        if "ok" in result:
            return int(result["ok"]["sequence"])
        return None

    def _ensure_funded(self, strkey: str) -> bool:
        """Ensure one deterministic test account exists (idempotent)."""
        result = self._get_json(f"/accounts/{strkey}")
        if "ok" in result:
            return True
        if "transport" in result:
            self.offline_reason = (
                f"rail unreachable ({result['transport']['error_class']})"
            )
            return False
        funding = _http(
            "GET",
            f"{self._friendbot_base}"
            f"?addr={urllib.parse.quote(strkey)}",
            timeout=self._timeout_seconds,
        )
        if "ok" in funding and funding["ok"].get("successful") is True:
            return True
        self.offline_reason = "testnet account funding unavailable"
        return False

    def _prepare_world(self) -> bool:
        """Prepare the deterministic source/destination accounts once."""
        if self._world_ready:
            return True
        if not self._ensure_funded(self.source_account_strkey):
            return False
        if not self._ensure_funded(self.destination_account_strkey):
            return False
        self._world_ready = True
        return True

    def _memo_lookup(self, key: str) -> tuple[bool, str | None, bool]:
        """Look the idempotency key up in the source account's memos.

        Returns ``(found, transaction_hash, successful)``. Covers the
        account's most recent ``memo_lookup_limit`` transactions (the
        deterministic bound documented on the constant).
        """
        result = self._get_json(
            "/accounts/"
            f"{self.source_account_strkey}"
            f"/transactions?limit={self._memo_lookup_limit}&order=desc"
        )
        if "ok" not in result:
            if "transport" in result:
                raise _TransportFailure(
                    result["transport"]["error_class"]
                )
            raise _ProviderQueryFailure(
                result["provider_error"]["http_status"]
            )
        for record in result["ok"].get("_embedded", {}).get("records", []):
            if record.get("memo") == key:
                return True, record.get("hash"), bool(record.get("successful"))
        return False, None, False

    # -- the typed ports -----------------------------------------------------

    def submit_effect(self, request: Any) -> AdapterSubmission:
        from src.transition.payload import payload_to_json_value

        self.submit_call_count += 1
        spec = request.spec
        key = spec.idempotency_key
        recorded = self._native.get(key)
        if recorded is not None:
            # Rail-side idempotency: the same key never causes a
            # second rail-side effect (constitution invariant 9).
            return AdapterSubmission(
                status=SubmissionStatus.ACCEPTED,
                native_reference=recorded["id"],
                reason=None,
            )
        rejected = self._rejected.get(key)
        if rejected is not None:
            return AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason=rejected,
            )
        payload = payload_to_json_value(spec.payload)
        if not isinstance(payload, Mapping):
            raise CoreValidationError(
                "the Stellar rail requires a payment payload object"
            )
        amount_stroops = self._stroops_of(payload)

        if not self._prepare_world():
            # The world could not even be prepared: the effect was NOT
            # ATTEMPTED (offline mode — the honest offline contract).
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    f"rail world unavailable: effect NOT ATTEMPTED "
                    f"(offline mode; {self.offline_reason})"
                ),
            )

        # Durable cross-process idempotency: an already-paid key (same
        # memo) returns the SAME on-chain transaction hash.
        try:
            found, found_hash, found_successful = self._memo_lookup(key)
        except _TransportFailure as failure:
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "transport failure during idempotency lookup: no "
                    f"definitive submission response ({failure})"
                ),
            )
        except _ProviderQueryFailure as failure:
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "provider error during idempotency lookup (http "
                    f"{failure})"
                ),
            )
        if found and found_hash:
            self._record_native(key, found_hash, found_successful)
            if found_successful:
                return AdapterSubmission(
                    status=SubmissionStatus.ACCEPTED,
                    native_reference=found_hash,
                    reason=None,
                )
            reason = "stellar:memo_transaction_failed"
            self._rejected[key] = reason
            return AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason=reason,
            )

        sequence = self._account_sequence(self.source_account_strkey)
        if sequence is None:
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "transport failure: no definitive submission response "
                    "(account sequence unavailable)"
                ),
            )
        destination = (
            self._unfunded_public
            if key in self._reject_keys
            else self._destination_public
        )
        envelope = build_payment_envelope(
            source_seed=self._source_seed,
            destination_public_key=destination,
            sequence=sequence + 1,
            amount_stroops=amount_stroops,
            memo=key,
        )
        self.network_submit_count += 1
        result = _http(
            "POST",
            f"{self._api_base}/transactions",
            params={"tx": envelope},
            timeout=self._timeout_seconds,
        )
        if "ok" in result:
            transaction = result["ok"]
            transaction_hash = transaction["hash"]
            successful = bool(transaction.get("successful"))
            self._record_native(key, transaction_hash, successful)
            if successful:
                return AdapterSubmission(
                    status=SubmissionStatus.ACCEPTED,
                    native_reference=transaction_hash,
                    reason=None,
                )
            reason = "stellar:transaction_failed"
            self._rejected[key] = reason
            return AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason=reason,
            )
        if "transport" in result:
            # The submission response was lost: the effect MIGHT have
            # landed — UNKNOWN, reconciled before any retry.
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "transport failure: no definitive submission response "
                    f"({result['transport']['error_class']})"
                ),
            )
        error = result["provider_error"]
        codes = error.get("result_codes") or {}
        operations = codes.get("operations") or []
        definitive = any(
            code in _DEFINITIVE_REJECTION_CODES for code in operations
        )
        if definitive:
            # The network definitively processed and rejected the
            # payment: it did not and will not happen.
            code = next(
                code for code in operations if code in _DEFINITIVE_REJECTION_CODES
            )
            reason = f"stellar:{code}"
            self._rejected[key] = reason
            return AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason=reason,
            )
        return AdapterSubmission(
            status=SubmissionStatus.UNKNOWN,
            native_reference=None,
            reason=(
                "provider rejected the envelope without a definitive "
                f"business outcome (http {error['http_status']}); "
                "reconciliation required"
            ),
        )

    def query_effect(self, request: Any) -> AdapterQueryResult:
        self.query_call_count += 1
        key = request.spec.idempotency_key
        native = self._native.get(key)
        if native is not None:
            result = self._get_json(f"/transactions/{native['id']}")
            if "ok" in result:
                transaction = result["ok"]
                successful = bool(transaction.get("successful"))
                self._native[key]["status"] = (
                    "completed" if successful else "failed"
                )
                if successful:
                    return AdapterQueryResult(
                        outcome=QueryOutcome.SUCCEEDED,
                        native_reference=native["id"],
                        detail=None,
                    )
                return AdapterQueryResult(
                    outcome=QueryOutcome.FAILED,
                    native_reference=native["id"],
                    detail=None,
                )
            if "transport" in result:
                return AdapterQueryResult(
                    outcome=QueryOutcome.UNKNOWN,
                    native_reference=None,
                    detail="transport failure during reconciliation",
                )
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail=(
                    "provider error during reconciliation (http "
                    f"{result['provider_error']['http_status']})"
                ),
            )
        if key in self._rejected:
            return AdapterQueryResult(
                outcome=QueryOutcome.NOT_FOUND,
                native_reference=None,
                detail="the rail definitively rejected this effect",
            )
        if not self._world_ready:
            # The effect was never attempted (the world was never even
            # prepared): never fabricated as success.
            return AdapterQueryResult(
                outcome=QueryOutcome.NOT_FOUND,
                native_reference=None,
                detail="the rail never received or processed this effect",
            )
        # A key this process never recorded: reconcile through the
        # durable memo (cross-process idempotency / lost responses).
        try:
            found, found_hash, found_successful = self._memo_lookup(key)
        except _TransportFailure:
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail="transport failure during reconciliation",
            )
        except _ProviderQueryFailure as failure:
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail=(
                    "provider error during reconciliation (http "
                    f"{failure})"
                ),
            )
        if found and found_hash:
            self._record_native(key, found_hash, found_successful)
            if found_successful:
                return AdapterQueryResult(
                    outcome=QueryOutcome.SUCCEEDED,
                    native_reference=found_hash,
                    detail=None,
                )
            return AdapterQueryResult(
                outcome=QueryOutcome.FAILED,
                native_reference=found_hash,
                detail=None,
            )
        return AdapterQueryResult(
            outcome=QueryOutcome.NOT_FOUND,
            native_reference=None,
            detail=(
                "the rail never received or processed this effect "
                "(no transaction carries the idempotency-key memo)"
            ),
        )

    # -- internals -----------------------------------------------------------

    def _record_native(self, key: str, transaction_hash: str, successful: bool) -> None:
        self._native[key] = {
            "id": transaction_hash,
            "status": "completed" if successful else "failed",
        }
        self._native_status[key] = "completed" if successful else "failed"

    def _stroops_of(self, payload: Mapping[str, Any]) -> int:
        """The declared canonical amount translated to native stroops.

        The declared canonical asset (a canonical fiat code — the merged
        money authority's closed vocabulary) is recorded by the canonical
        chain; the testnet rail settles the declared AMOUNT (value and
        scale) natively as the documented sandbox-conformance
        translation (an exact power-of-ten integer conversion, never a
        float and never a value claim about the declared asset).
        """
        currency = payload.get("currency")
        if currency != "USD":
            raise CoreValidationError(
                "the rail settles the scenario's declared canonical asset "
                "word; a payload currency "
                f"{currency!r} fails closed (asset substitution is never "
                "normalized)"
            )
        amount_value = payload.get("amount_value")
        amount_scale = payload.get("amount_scale")
        if not isinstance(amount_value, int) or isinstance(amount_value, bool):
            raise CoreValidationError("the amount value must be an integer")
        if not isinstance(amount_scale, int) or isinstance(amount_scale, bool):
            raise CoreValidationError("the amount scale must be an integer")
        if not 0 <= amount_scale <= STELLAR_NATIVE_SCALE:
            raise CoreValidationError(
                "the amount scale must fit the native asset's scale"
            )
        stroops = amount_value * (
            10 ** (STELLAR_NATIVE_SCALE - amount_scale)
        )
        if stroops < 1:
            raise CoreValidationError(
                "the amount must convert to at least one stroop"
            )
        return stroops


class _TransportFailure(Exception):
    """Internal sanitized transport-failure marker (never escapes)."""


class _ProviderQueryFailure(Exception):
    """Internal sanitized provider-error marker (never escapes)."""


def make_stellar_world_adapter() -> WorldAdapter:
    """The Stellar testnet rail's declared world-adapter contract.

    ``SIMULATION`` fidelity declares the world-coupling truthfully: the
    adapter is coupled to the PUBLIC Stellar TESTNET — a real external
    sandbox world with no production funds (REAL_PROVIDER_SANDBOX in
    the IG-005 rail-classification vocabulary), addressed through the
    same semantic interface a production rail declares.
    """
    return WorldAdapter(
        adapter_id=RAILS_STELLAR_ADAPTER_ID,
        capability_id="capability/stellar-testnet",
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )


def make_stellar_status_map() -> AdapterStatusMap:
    return AdapterStatusMap(
        adapter_id=RAILS_STELLAR_ADAPTER_ID, entries=STELLAR_STATUS_MAP
    )


def make_stellar_binding(rail: StellarTestnetRail) -> AdapterBinding:
    """Bind the Stellar testnet rail through the PUBLIC adapter path."""
    return AdapterBinding(
        adapter_id=RAILS_STELLAR_ADAPTER_ID,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=make_stellar_world_adapter(),
        status_map=make_stellar_status_map(),
    )


__all__ = [
    "STELLAR_FEE_STROOPS",
    "STELLAR_HORIZON_BASE",
    "STELLAR_NETWORK_ID",
    "STELLAR_STATUS_MAP",
    "STELLAR_STROOPS_PER_XLM",
    "STELLAR_TESTNET_PASSPHRASE",
    "StellarTestnetRail",
    "build_payment_envelope",
    "build_payment_transaction_bytes",
    "make_stellar_binding",
    "make_stellar_status_map",
    "make_stellar_world_adapter",
    "stellar_transaction_hash",
    "strkey_encode_account",
]
