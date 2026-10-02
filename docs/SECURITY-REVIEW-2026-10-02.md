# Focused source and adversarial-input review

Scope: registry validation/snapshot, normalization, replay identity, XML/JSON export parsing, evidence persistence and offline delivery payloads. This is an implementation review with synthetic regression tests, not an independent certification or production assessment.

## Issues corrected

| Issue | Correction and evidence |
|---|---|
| Caller could mutate exception data after registry fingerprinting | Deep-copy registry input; regression proves the compiled registry remains unchanged |
| Windows host delimiters could create ambiguous composite replay identities | Require bounded ASCII computer names without delimiters; existing ordinary host identities remain stable |
| Falsey malformed `errorCode` could be interpreted as successful S3 access | Require a nonempty bounded string whenever the field is present |
| Duplicate/misleading XML fields or ambiguous audit outcome | Exact namespace and singleton fields; reject duplicate EventData and failure/success ambiguity |
| XML entity expansion or export amplification | Reject DTD/entities and non-UTF-8 input; input, tree, field and record-count bounds |
| Deep JSON or overflowing number could reach later serializers | Enforce depth/node bounds and finite floats, including exponent overflow, at the common JSON parser |
| Native optional fields can legitimately be multiline/empty | Bound them without treating unused fields as required normalized values; consumed fields remain strict |
| Transport error/redirect could be mistaken for acceptance | Local mock requires HTTP 200 and unambiguous integer HEC code zero; rejects redirect, error, duplicate code and oversized response |
| Packet rendering could imply real SIEM receipt | No production sender command, explicit mock receipt result, separate indexing and analyst acknowledgment flags |

Earlier input-boundary checks also cover extreme date conversion, non-string registry regions, unsupported operations, raw identifier collisions and corrupt-database handle cleanup.

## Residual boundaries

Source authenticity still depends on trusted collectors and protected original exports. SHA-256 comparisons do not prevent privileged evidence rewriting. Local acknowledgment is not authenticated. SQLite has no production retention/quota/HA. Single-writer operation remains required. Real TLS/auth/expiry/rate/outbox controls are specified for the future production sender and are not implemented by the loopback mock. Full SIEM and deployment acceptance remains open.

Windows UTF-8 XML conversion and CloudTrail envelope handling are verified with synthetic exports. Real source exports must be inspected for supported fields, aliases, event outcomes, key representation and collector log-generation behavior before claiming coverage.
