"""Selective disclosure: commitment-based proofs over isolated datasets.

The commitment scheme (typed, deterministic, on the single canonical
hash authority ``src.core.serialization.canonical_sha256``):

```text
field_commitment  = SHA-256(canon({"field": name, "value": value}))
record_commitment = SHA-256(canon({"record_id": id, "fields": {field: commitment}}))
root              = SHA-256(canon({"dataset_id": id, "records": {record_id: commitment}}))
```

A :class:`SelectiveDisclosureProof` for a requested subset discloses,
per record, the VALUES of policy-permitted fields while carrying only
the COMMITMENTS of withheld fields, plus every per-field commitment,
every record commitment and the dataset root. Verification proves that
the disclosed subset satisfies the declared policy and matches the
underlying committed data WITHOUT revealing any withheld value:

* the leakage gate fails closed if any disclosed field is not
  policy-permitted for the stated purpose;
* every disclosed value must re-hash to its stated commitment (a
  tampered dataset or proof value fails closed);
* every record commitment must cover exactly the full field commitment
  map (no splicing, no dropped fields);
* the recomputed root must match the proof's (and the trusted expected
  root's, when supplied) — dropped or extra records fail closed.

Determinism: commitments are unsalted digests of canonical values —
no entropy sources exist anywhere in the domain (the sibling
no-wall-clock/no-entropy scan applies). The hiding property therefore
relies on pre-image resistance of the digest over the canonical value
domain; salted/blinded commitments would require entropy and are
recorded as a known limitation, not silently weakened.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256, validate_canonical_value

from .contracts import (
    SELECTIVE_PROOF_OBJECT_TYPE,
    DisclosurePurpose,
    ProofState,
)
from .disclosure import DisclosureRequest
from .policy import DataPolicy, require_active_policy
from ._validation import (
    parse_enum,
    require_identifier,
    require_pair_items,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)


def _field_commitment(field_name: str, value: Any) -> str:
    return canonical_sha256({"field": field_name, "value": value})


def _record_commitment(record_id: str, field_commitments: Mapping[str, str]) -> str:
    return canonical_sha256(
        {"record_id": record_id, "fields": dict(field_commitments)}
    )


def _root_commitment(dataset_id: str, record_commitments: Mapping[str, str]) -> str:
    return canonical_sha256(
        {"dataset_id": dataset_id, "records": dict(record_commitments)}
    )


def dataset_record(record_id: str, fields: Mapping[str, Any]) -> "DatasetRecord":
    """Build one typed dataset record from a field mapping (sorted pairs)."""
    if not isinstance(fields, Mapping):
        raise CoreValidationError("dataset fields must be a mapping")
    keys = list(fields)
    if not keys:
        raise CoreValidationError("dataset record must declare at least one field")
    if len(set(keys)) != len(keys):
        raise CoreValidationError("dataset record contains duplicate fields")
    for key in keys:
        require_text("dataset field name", key)
        validate_canonical_value(f"dataset field {key!r}", fields[key])
    return DatasetRecord(
        record_id=record_id,
        fields=tuple((key, fields[key]) for key in sorted(keys)),
    )


@dataclass(frozen=True, slots=True)
class DatasetRecord:
    """One typed record of an isolated dataset: sorted unique field pairs."""

    record_id: str
    fields: tuple[tuple[str, Any], ...]

    def __post_init__(self) -> None:
        require_identifier("dataset record_id", self.record_id)
        if not isinstance(self.fields, tuple) or not self.fields:
            raise CoreValidationError("dataset record fields must be a non-empty tuple")
        keys = [key for key, _ in self.fields]
        for key in keys:
            require_text("dataset field name", key)
        if len(set(keys)) != len(keys):
            raise CoreValidationError("dataset record contains duplicate fields")
        if keys != sorted(keys):
            raise CoreValidationError("dataset record fields must be sorted")
        for key, value in self.fields:
            validate_canonical_value(f"dataset field {key!r}", value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "fields": [[key, value] for key, value in self.fields],
        }

    @classmethod
    def from_dict(cls, value: object) -> "DatasetRecord":
        if not isinstance(value, Mapping) or set(value) != {"record_id", "fields"}:
            raise CoreValidationError(
                "dataset record fields are not canonical; expected {record_id, fields}"
            )
        return cls(
            record_id=value["record_id"],
            fields=tuple(
                (pair[0], pair[1])
                for pair in require_pair_items("dataset record fields", value["fields"])
            ),
        )


@dataclass(frozen=True, slots=True)
class IsolatedDataset:
    """An isolated, typed dataset: sorted records over declared fields."""

    dataset_id: str
    records: tuple[DatasetRecord, ...]

    def __post_init__(self) -> None:
        require_identifier("dataset.dataset_id", self.dataset_id)
        if not isinstance(self.records, tuple) or not self.records:
            raise CoreValidationError("dataset.records must be a non-empty tuple")
        ids = [record.record_id for record in self.records]
        if len(set(ids)) != len(ids):
            raise CoreValidationError("dataset record ids must be unique")
        if ids != sorted(ids):
            raise CoreValidationError("dataset records must be sorted by record id")
        for record in self.records:
            if not isinstance(record, DatasetRecord):
                raise CoreValidationError("dataset.records entries must be DatasetRecord")

    def field_names(self) -> tuple[str, ...]:
        names: list[str] = []
        for record in self.records:
            for key, _ in record.fields:
                if key not in names:
                    names.append(key)
        return tuple(sorted(names))

    def record_ids(self) -> tuple[str, ...]:
        return tuple(record.record_id for record in self.records)

    def record_by_id(self, record_id: str) -> DatasetRecord:
        for record in self.records:
            if record.record_id == record_id:
                return record
        raise CoreValidationError(f"unknown dataset record: {record_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "records": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, value: object) -> "IsolatedDataset":
        strict_fields("dataset", value, {"dataset_id", "records"})
        return cls(
            dataset_id=value["dataset_id"],
            records=tuple(DatasetRecord.from_dict(item) for item in value["records"]),
        )


@dataclass(frozen=True, slots=True)
class RecordCommitment:
    """Per-record commitment: every field digest plus the record digest."""

    record_id: str
    field_commitments: tuple[tuple[str, str], ...]
    record_commitment: str

    def __post_init__(self) -> None:
        require_identifier("commitment record_id", self.record_id)
        if not isinstance(self.field_commitments, tuple) or not self.field_commitments:
            raise CoreValidationError("commitment.field_commitments must be a non-empty tuple")
        keys = [key for key, _ in self.field_commitments]
        for key in keys:
            require_text("commitment field name", key)
        if len(set(keys)) != len(keys):
            raise CoreValidationError("commitment field commitments must be unique")
        if keys != sorted(keys):
            raise CoreValidationError("commitment field commitments must be sorted")
        require_text("commitment.record_commitment", self.record_commitment)

    def commitment_map(self) -> dict[str, str]:
        return {key: value for key, value in self.field_commitments}

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "field_commitments": [[key, value] for key, value in self.field_commitments],
            "record_commitment": self.record_commitment,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RecordCommitment":
        if not isinstance(value, Mapping) or set(value) != {
            "record_id",
            "field_commitments",
            "record_commitment",
        }:
            raise CoreValidationError(
                "record commitment fields are not canonical; expected "
                "{record_id, field_commitments, record_commitment}"
            )
        return cls(
            record_id=value["record_id"],
            field_commitments=tuple(
                (pair[0], pair[1])
                for pair in require_pair_items(
                    "record commitment field_commitments", value["field_commitments"]
                )
            ),
            record_commitment=value["record_commitment"],
        )


@dataclass(frozen=True, slots=True)
class DatasetCommitment:
    """The commitment of an entire dataset: per-record commitments + root."""

    dataset_id: str
    records: tuple[RecordCommitment, ...]
    root: str

    def __post_init__(self) -> None:
        require_identifier("commitment.dataset_id", self.dataset_id)
        if not isinstance(self.records, tuple) or not self.records:
            raise CoreValidationError("commitment.records must be a non-empty tuple")
        ids = [record.record_id for record in self.records]
        if len(set(ids)) != len(ids):
            raise CoreValidationError("commitment record ids must be unique")
        if ids != sorted(ids):
            raise CoreValidationError("commitment records must be sorted by record id")
        require_text("commitment.root", self.root)
        # the recorded root must recompute exactly from the record commitments
        expected = _root_commitment(
            self.dataset_id, {record.record_id: record.record_commitment for record in self.records}
        )
        if self.root != expected:
            raise CoreValidationError("commitment root does not match its record commitments")

    def record_ids(self) -> tuple[str, ...]:
        return tuple(record.record_id for record in self.records)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "records": [record.to_dict() for record in self.records],
            "root": self.root,
        }

    @classmethod
    def from_dict(cls, value: object) -> "DatasetCommitment":
        strict_fields("dataset commitment", value, {"dataset_id", "records", "root"})
        return cls(
            dataset_id=value["dataset_id"],
            records=tuple(RecordCommitment.from_dict(item) for item in value["records"]),
            root=value["root"],
        )


def commit_dataset(dataset: IsolatedDataset) -> DatasetCommitment:
    """Commit an isolated dataset deterministically (field/record/root digests)."""
    if not isinstance(dataset, IsolatedDataset):
        raise CoreValidationError("commit_dataset requires an IsolatedDataset")
    commitments: list[RecordCommitment] = []
    for record in dataset.records:
        field_commitments = {
            key: _field_commitment(key, value) for key, value in record.fields
        }
        commitments.append(
            RecordCommitment(
                record_id=record.record_id,
                field_commitments=tuple(sorted(field_commitments.items())),
                record_commitment=_record_commitment(record.record_id, field_commitments),
            )
        )
    root = _root_commitment(
        dataset.dataset_id, {item.record_id: item.record_commitment for item in commitments}
    )
    return DatasetCommitment(
        dataset_id=dataset.dataset_id, records=tuple(commitments), root=root
    )


@dataclass(frozen=True, slots=True)
class ProofRecord:
    """One record's slice of a selective-disclosure proof."""

    record_id: str
    disclosed_fields: tuple[tuple[str, Any], ...]
    withheld_fields: tuple[str, ...]
    field_commitments: tuple[tuple[str, str], ...]
    record_commitment: str

    def __post_init__(self) -> None:
        require_identifier("proof record_id", self.record_id)
        if not isinstance(self.disclosed_fields, tuple):
            raise CoreValidationError("proof.disclosed_fields must be a tuple")
        disclosed_keys = [key for key, _ in self.disclosed_fields]
        for key in disclosed_keys:
            require_text("proof disclosed field", key)
        if len(set(disclosed_keys)) != len(disclosed_keys):
            raise CoreValidationError("proof disclosed fields must be unique")
        if not isinstance(self.withheld_fields, tuple):
            raise CoreValidationError("proof.withheld_fields must be a tuple")
        for key in self.withheld_fields:
            require_text("proof withheld field", key)
        if len(set(self.withheld_fields)) != len(self.withheld_fields):
            raise CoreValidationError("proof withheld fields must be unique")
        overlap = set(disclosed_keys) & set(self.withheld_fields)
        if overlap:
            raise CoreValidationError(
                f"proof record {self.record_id} both discloses and withholds {sorted(overlap)}"
            )
        if not isinstance(self.field_commitments, tuple) or not self.field_commitments:
            raise CoreValidationError("proof.field_commitments must be a non-empty tuple")
        commitment_keys = [key for key, _ in self.field_commitments]
        if sorted(set(commitment_keys)) != commitment_keys or len(set(commitment_keys)) != len(
            commitment_keys
        ):
            raise CoreValidationError("proof field commitments must be sorted and unique")
        covered = set(commitment_keys)
        if covered != set(disclosed_keys) | set(self.withheld_fields):
            raise CoreValidationError(
                "proof field commitments must cover exactly the disclosed and withheld fields"
            )
        require_text("proof.record_commitment", self.record_commitment)
        for key, value in self.disclosed_fields:
            validate_canonical_value(f"proof disclosed value {key!r}", value)
        for key, digest in self.field_commitments:
            require_text("proof field commitment digest", digest)

    def commitment_map(self) -> dict[str, str]:
        return {key: value for key, value in self.field_commitments}

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "disclosed_fields": [[key, value] for key, value in self.disclosed_fields],
            "withheld_fields": list(self.withheld_fields),
            "field_commitments": [[key, value] for key, value in self.field_commitments],
            "record_commitment": self.record_commitment,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ProofRecord":
        if not isinstance(value, Mapping) or set(value) != {
            "record_id",
            "disclosed_fields",
            "withheld_fields",
            "field_commitments",
            "record_commitment",
        }:
            raise CoreValidationError(
                "proof record fields are not canonical; expected {record_id, "
                "disclosed_fields, withheld_fields, field_commitments, record_commitment}"
            )
        return cls(
            record_id=value["record_id"],
            disclosed_fields=tuple(
                (pair[0], pair[1])
                for pair in require_pair_items(
                    "proof record disclosed_fields", value["disclosed_fields"]
                )
            ),
            withheld_fields=tuple(value["withheld_fields"]),
            field_commitments=tuple(
                (pair[0], pair[1])
                for pair in require_pair_items(
                    "proof record field_commitments", value["field_commitments"]
                )
            ),
            record_commitment=value["record_commitment"],
        )


_PROOF_PAYLOAD_FIELDS = frozenset(
    {
        "proof_id",
        "dataset_id",
        "policy_id",
        "policy_version",
        "purpose",
        "as_of",
        "subject_ref",
        "requested_fields",
        "disclosed_records",
        "root",
        "produced_by",
        "produced_at",
    }
)


@dataclass(frozen=True, slots=True)
class SelectiveDisclosureProof:
    """Immutable durable selective-disclosure proof (envelope + payload + seal).

    The payload carries, for every record of the committed dataset, the
    policy-permitted disclosed values, the names of withheld fields, the
    per-field commitments of ALL fields, the record commitment and the
    dataset root. No withheld value is ever present.
    """

    envelope: ObjectEnvelope
    payload: Any
    integrity_hash: str

    def __post_init__(self) -> None:
        decode_composite(
            composite_to_dict(self.envelope, self.payload, self.integrity_hash),
            expected_object_type=SELECTIVE_PROOF_OBJECT_TYPE,
            state_type=ProofState,
        )
        if self.envelope.object_id != self.payload.proof_id:
            raise CoreValidationError("proof object id must equal the proof identifier")
        verify_composite(
            self.envelope, self.payload, self.integrity_hash, self.envelope.object_id
        )

    @property
    def proof_id(self) -> str:
        return self.payload.proof_id

    @property
    def dataset_id(self) -> str:
        return self.payload.dataset_id

    @property
    def state(self) -> ProofState:
        return ProofState(self.envelope.state)

    @property
    def disclosed_records(self) -> tuple[ProofRecord, ...]:
        return self.payload.disclosed_records

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.payload, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.payload, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: object) -> "SelectiveDisclosureProof":
        envelope, payload = decode_composite(
            value, expected_object_type=SELECTIVE_PROOF_OBJECT_TYPE, state_type=ProofState
        )
        return cls(
            envelope=envelope,
            payload=ProofPayload.from_dict(payload),
            integrity_hash=value["integrity_hash"],
        )

    @classmethod
    def from_json(cls, value: str) -> "SelectiveDisclosureProof":
        decoded = decode_composite_json(
            value, expected_object_type=SELECTIVE_PROOF_OBJECT_TYPE, state_type=ProofState
        )
        return cls.from_dict(
            {"envelope": decoded[0].to_dict(), "payload": decoded[1], "integrity_hash": decoded[2]}
        )


@dataclass(frozen=True, slots=True)
class ProofPayload:
    """Immutable proof payload: the disclosure slice plus its commitments."""

    proof_id: str
    dataset_id: str
    policy_id: str
    policy_version: int
    purpose: Any
    as_of: str
    subject_ref: str
    requested_fields: tuple[str, ...]
    disclosed_records: tuple[ProofRecord, ...]
    root: str
    produced_by: str
    produced_at: str

    def __post_init__(self) -> None:
        require_identifier("proof.proof_id", self.proof_id)
        require_identifier("proof.dataset_id", self.dataset_id)
        require_identifier("proof.policy_id", self.policy_id)
        if not isinstance(self.policy_version, int) or isinstance(self.policy_version, bool):
            raise CoreValidationError("proof.policy_version must be an integer")
        object.__setattr__(
            self, "purpose", parse_enum("proof.purpose", DisclosurePurpose, self.purpose)
        )
        require_utc_timestamp("proof.as_of", self.as_of)
        require_identifier("proof.subject_ref", self.subject_ref)
        if not isinstance(self.requested_fields, tuple) or not self.requested_fields:
            raise CoreValidationError("proof.requested_fields must be a non-empty tuple")
        if len(set(self.requested_fields)) != len(self.requested_fields):
            raise CoreValidationError("proof.requested_fields must be unique")
        if not isinstance(self.disclosed_records, tuple) or not self.disclosed_records:
            raise CoreValidationError("proof.disclosed_records must be a non-empty tuple")
        ids = [record.record_id for record in self.disclosed_records]
        if len(set(ids)) != len(ids) or ids != sorted(ids):
            raise CoreValidationError("proof records must be sorted and unique")
        for record in self.disclosed_records:
            if not isinstance(record, ProofRecord):
                raise CoreValidationError("proof.disclosed_records entries must be ProofRecord")
        require_text("proof.root", self.root)
        require_identifier("proof.produced_by", self.produced_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "dataset_id": self.dataset_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "purpose": self.purpose.value,
            "as_of": self.as_of,
            "subject_ref": self.subject_ref,
            "requested_fields": list(self.requested_fields),
            "disclosed_records": [record.to_dict() for record in self.disclosed_records],
            "root": self.root,
            "produced_by": self.produced_by,
            "produced_at": self.produced_at,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ProofPayload":
        strict_fields("proof", value, _PROOF_PAYLOAD_FIELDS)
        return cls(
            proof_id=value["proof_id"],
            dataset_id=value["dataset_id"],
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            purpose=value["purpose"],
            as_of=value["as_of"],
            subject_ref=value["subject_ref"],
            requested_fields=tuple(value["requested_fields"]),
            disclosed_records=tuple(
                ProofRecord.from_dict(item) for item in value["disclosed_records"]
            ),
            root=value["root"],
            produced_by=value["produced_by"],
            produced_at=value["produced_at"],
        )


def produce_disclosure_proof(
    *,
    proof_id: str,
    dataset: IsolatedDataset,
    commitment: DatasetCommitment,
    request: DisclosureRequest,
    policy: DataPolicy,
    as_of: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> SelectiveDisclosureProof:
    """Produce a proof that discloses only the policy-permitted subset.

    Fail-closed paths: the policy must be ACTIVE at ``as_of``; every
    requested field must be classified; the commitment must be exactly
    the dataset's commitment (tampered or spliced datasets fail closed);
    the dataset and commitment must agree on dataset id and record set.
    """
    if not isinstance(request, DisclosureRequest):
        raise CoreValidationError("produce_disclosure_proof requires a DisclosureRequest")
    require_active_policy(policy, as_of)
    if not isinstance(dataset, IsolatedDataset) or not isinstance(
        commitment, DatasetCommitment
    ):
        raise CoreValidationError(
            "produce_disclosure_proof requires an IsolatedDataset and DatasetCommitment"
        )
    if dataset.dataset_id != commitment.dataset_id:
        raise CoreValidationError("dataset and commitment identifiers disagree")
    if dataset.record_ids() != commitment.record_ids():
        raise CoreValidationError("dataset and commitment record sets disagree")
    # recompute the full commitment from the dataset: any value change,
    # dropped or extra record fails closed here.
    recomputed = commit_dataset(dataset)
    if recomputed.root != commitment.root:
        raise CoreValidationError(
            "the dataset does not match its commitment (tampered or spliced data)"
        )
    allowed = policy.spec.classes_for(request.purpose)
    permitted: list[str] = []
    for field_name in request.requested_fields:
        data_class = policy.spec.data_class_for(field_name)  # fail closed on unknown field
        if data_class in allowed:
            permitted.append(field_name)
    if not permitted:
        raise CoreValidationError(
            "the declared policy permits none of the requested fields; a proof that "
            "discloses nothing cannot be produced"
        )
    commitment_by_record = {
        record.record_id: record for record in commitment.records
    }
    proof_records: list[ProofRecord] = []
    for record in dataset.records:
        fields = {key: value for key, value in record.fields}
        disclosed = tuple(
            (key, fields[key]) for key in sorted(fields) if key in set(permitted)
        )
        withheld = tuple(key for key in sorted(fields) if key not in set(permitted))
        source = commitment_by_record[record.record_id]
        proof_records.append(
            ProofRecord(
                record_id=record.record_id,
                disclosed_fields=disclosed,
                withheld_fields=withheld,
                field_commitments=source.field_commitments,
                record_commitment=source.record_commitment,
            )
        )
    payload = ProofPayload(
        proof_id=proof_id,
        dataset_id=dataset.dataset_id,
        policy_id=policy.policy_id,
        policy_version=policy.envelope.object_version,
        purpose=request.purpose,
        as_of=as_of,
        subject_ref=request.subject_ref,
        requested_fields=request.requested_fields,
        disclosed_records=tuple(proof_records),
        root=commitment.root,
        produced_by=provenance.issuer,
        produced_at=as_of,
    )
    envelope = build_domain_envelope(
        object_id=proof_id,
        object_type=SELECTIVE_PROOF_OBJECT_TYPE,
        state=ProofState.ISSUED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return SelectiveDisclosureProof(
        envelope=envelope, payload=payload, integrity_hash=seal_composite(envelope, payload)
    )


def verify_disclosure_proof(
    proof: SelectiveDisclosureProof,
    *,
    policy: DataPolicy,
    as_of: str,
    expected_root: str | None = None,
) -> None:
    """Verify a selective-disclosure proof; raise on any failure path.

    Checks (all fail closed with ``CoreValidationError``):

    1. the proof is ISSUED (revoked proofs are not relied upon);
    2. the policy is ACTIVE at ``as_of`` and is the proof's policy;
    3. the leakage gate: every disclosed field must be policy-permitted
       for the proof's purpose;
    4. every disclosed value re-hashes to its stated commitment;
    5. every record commitment covers exactly the full field commitment
       map and recomputes exactly;
    6. the recomputed root matches the proof's root, and the trusted
       expected root when supplied (splicing gate).
    """
    if not isinstance(proof, SelectiveDisclosureProof):
        raise CoreValidationError("verify_disclosure_proof requires a SelectiveDisclosureProof")
    if proof.state is not ProofState.ISSUED:
        raise CoreValidationError(
            f"proof {proof.proof_id} is {proof.state.value} and cannot be relied upon"
        )
    if not isinstance(policy, DataPolicy):
        raise CoreValidationError("verification requires a DataPolicy")
    require_active_policy(policy, as_of)
    if policy.policy_id != proof.payload.policy_id:
        raise CoreValidationError(
            f"verification policy {policy.policy_id} is not the proof's policy "
            f"{proof.payload.policy_id}"
        )
    if policy.envelope.object_version != proof.payload.policy_version:
        raise CoreValidationError(
            "verification policy version does not match the proof's pinned policy version"
        )
    allowed = policy.spec.classes_for(proof.payload.purpose)
    record_commitments: dict[str, str] = {}
    for record in proof.payload.disclosed_records:
        commitment_map = record.commitment_map()
        # leakage gate + disclosed-value commitment check
        for key, value in record.disclosed_fields:
            data_class = policy.spec.data_class_for(key)
            if data_class not in allowed:
                raise CoreValidationError(
                    f"proof record {record.record_id} discloses field {key!r} which the "
                    "declared policy does not permit for this purpose"
                )
            expected = _field_commitment(key, value)
            if commitment_map.get(key) != expected:
                raise CoreValidationError(
                    f"proof record {record.record_id}: commitment mismatch on disclosed "
                    f"field {key!r} (tampered value)"
                )
        # record commitment covers exactly the full field map
        expected_record = _record_commitment(record.record_id, commitment_map)
        if record.record_commitment != expected_record:
            raise CoreValidationError(
                f"proof record {record.record_id} commitment does not cover its fields"
            )
        record_commitments[record.record_id] = record.record_commitment
    expected_root = expected_root if expected_root is not None else proof.payload.root
    recomputed_root = _root_commitment(proof.payload.dataset_id, record_commitments)
    if recomputed_root != expected_root:
        raise CoreValidationError(
            "the proof root does not match the expected dataset commitment"
        )
    if proof.payload.root != recomputed_root:
        raise CoreValidationError(
            "the proof root does not match its own record commitments"
        )


def revoke_disclosure_proof(
    proof: SelectiveDisclosureProof, *, provenance: Provenance
) -> SelectiveDisclosureProof:
    """Revoke an ISSUED proof (ISSUED -> REVOKED, terminal)."""
    if proof.state is not ProofState.ISSUED:
        raise CoreValidationError(
            f"proof {proof.proof_id} cannot be revoked from state {proof.state.value}"
        )
    envelope = advance_envelope(
        proof.envelope, state=ProofState.REVOKED.value, provenance=provenance
    )
    return SelectiveDisclosureProof(
        envelope=envelope, payload=proof.payload, integrity_hash=seal_composite(envelope, proof.payload)
    )
