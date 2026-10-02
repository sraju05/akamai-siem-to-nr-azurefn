"""
Payload filtering for Akamai SIEM events.

Supports dot-notation paths for nested fields, e.g. "httpMessage.requestHeaders".

Drop:     remove a field entirely
Truncate: cap a string field at N characters (appends "…" marker)
"""

import copy
import json
import os


def load_filter_config() -> tuple[list[str], dict[str, int]]:
    """Parse FILTER_DROP_FIELDS and FILTER_TRUNCATE_FIELDS from environment."""
    raw_drop = os.environ.get("FILTER_DROP_FIELDS", "")
    drop_fields = [f.strip() for f in raw_drop.split(",") if f.strip()]

    raw_trunc = os.environ.get("FILTER_TRUNCATE_FIELDS", "").strip()
    if not raw_trunc or raw_trunc == "{}":
        truncate_fields: dict[str, int] = {}
    elif raw_trunc.startswith("{"):
        # JSON format: '{"httpMessage.requestHeaders": 512, "httpMessage.responseHeaders": 512}'
        truncate_fields = json.loads(raw_trunc)
    else:
        # Simple format: "httpMessage.requestHeaders:512,httpMessage.responseHeaders:256"
        truncate_fields = {}
        for part in raw_trunc.split(","):
            part = part.strip()
            if ":" in part:
                field, _, length = part.rpartition(":")
                truncate_fields[field.strip()] = int(length.strip())

    return drop_fields, truncate_fields


def apply_filters(
    event: dict,
    drop_fields: list[str],
    truncate_fields: dict[str, int],
) -> dict:
    """Return a filtered deep copy of event. Unrecognised paths are silently ignored."""
    if not drop_fields and not truncate_fields:
        return event  # fast path — no copy needed

    result = copy.deepcopy(event)

    for path in drop_fields:
        _delete_path(result, path.split("."))

    for path, max_len in truncate_fields.items():
        _truncate_path(result, path.split("."), int(max_len))

    return result


# ── internal helpers ───────────────────────────────────────────────────────────

def _delete_path(obj: dict, parts: list[str]) -> None:
    if not isinstance(obj, dict):
        return
    if len(parts) == 1:
        obj.pop(parts[0], None)
        return
    child = obj.get(parts[0])
    if isinstance(child, dict):
        _delete_path(child, parts[1:])


def _truncate_path(obj: dict, parts: list[str], max_len: int) -> None:
    if not isinstance(obj, dict):
        return
    if len(parts) == 1:
        val = obj.get(parts[0])
        if isinstance(val, str) and len(val) > max_len:
            obj[parts[0]] = val[:max_len] + "…[truncated]"
        return
    child = obj.get(parts[0])
    if isinstance(child, dict):
        _truncate_path(child, parts[1:], max_len)
