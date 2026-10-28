"""CloudTrail log inbox processing. Reads operator-managed local files only.

Fetching trail logs from S3 stays a deployment concern (for example a
credential-scoped sync job). This module validates and processes files that
already landed in a watched inbox directory. Decompression is bounded against
gzip bombs; malformed files fail visibly and stay unmarked for retry.
"""

import gzip
import io
import json

from .collection import MAX_EVENT_BYTES
from .core import ContractError, normalize, parse_json

MAX_INBOX_BYTES = 16 * 1024 * 1024
MAX_INBOX_RECORDS = 10000
MAX_INBOX_NODES = 1000000
GZIP_MAGIC = b"\x1f\x8b"


def cloudtrail_records_file(payload: bytes) -> list[dict]:
    """Validate one bounded CloudTrail log file and return its records."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_INBOX_BYTES:
        raise ContractError("CloudTrail log file must be bytes of at most 16 MiB")
    if payload[:2] == GZIP_MAGIC:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as handle:
            data = handle.read(MAX_INBOX_BYTES + 1)
        if len(data) > MAX_INBOX_BYTES:
            raise ContractError("decompressed CloudTrail log exceeds 16 MiB")
    else:
        data = payload
    try:
        document = parse_json(data, max_nodes=MAX_INBOX_NODES)
    except UnicodeError as exc:
        raise ContractError("CloudTrail log must be UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {"Records"}:
        raise ContractError("CloudTrail log requires an exact Records envelope")
    records = document["Records"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_INBOX_RECORDS:
        raise ContractError("CloudTrail log requires 1 to 10000 records")
    for record in records:
        if not isinstance(record, dict):
            raise ContractError("CloudTrail record must be an object")
        if len(json.dumps(record, ensure_ascii=True).encode()) > MAX_EVENT_BYTES:
            raise ContractError("CloudTrail record exceeds 64 KiB")
        if normalize(record)["source"] != "aws.cloudtrail.s3":
            raise ContractError("CloudTrail batch contains a different source")
    return records
