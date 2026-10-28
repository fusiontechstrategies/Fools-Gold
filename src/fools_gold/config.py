"""Validated operator configuration profiles.

Profiles carry non-secret defaults only. Secrets (HEC tokens, evidence keys'
contents) stay in protected files or the environment. CLI arguments always win
over profile values. Relative paths resolve against the profile directory.
"""

from pathlib import Path

from .core import ContractError, parse_json, text

MAX_PROFILE_BYTES = 64 * 1024
PATH_KEYS = (
    "registry",
    "database",
    "evidence_key_file",
    "wazuh_output",
    "state_file",
    "inbox",
)
STRING_KEYS = PATH_KEYS + ("splunk_host", "route")
PROFILE_KEYS = set(STRING_KEYS) | {"splunk_port"}


def load_profile(path) -> dict:
    profile_path = Path(path)
    if profile_path.is_symlink() or not profile_path.is_file():
        raise ContractError("profile must be a regular file")
    with profile_path.open("rb") as handle:
        payload = handle.read(MAX_PROFILE_BYTES + 1)
    if len(payload) > MAX_PROFILE_BYTES:
        raise ContractError("profile exceeds 64 KiB")
    document = parse_json(payload)
    if not isinstance(document, dict):
        raise ContractError("profile must be a JSON object")
    unknown = set(document) - PROFILE_KEYS
    if unknown:
        raise ContractError(
            "profile contains unsupported keys: " + ", ".join(sorted(unknown))
        )
    resolved = {}
    for key, value in document.items():
        if key in STRING_KEYS:
            text(value, f"profile {key}", 2048)
            if key in PATH_KEYS and not Path(value).is_absolute():
                value = str(profile_path.parent / value)
            resolved[key] = value
        elif key == "splunk_port":
            if type(value) is not int or not 1 <= value <= 65535:
                raise ContractError("profile splunk_port must be 1 to 65535")
            resolved[key] = value
    return resolved
