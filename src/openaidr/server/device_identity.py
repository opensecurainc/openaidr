"""Hardware and OS installation identifiers reported by sensors.

A sensor may report a ``device`` object on enrollment and heartbeat:
``serial_number`` and ``hardware_uuid`` come from firmware, ``machine_id``
identifies the OS installation, and ``source`` names the collection method.
Every field is optional. The values help recognize the same device across
reinstalls and renames; they are reported, unverified, and never used for
authentication.
"""

from .httpx import require

FIELDS = ("serial_number", "hardware_uuid", "machine_id", "source")
COLUMNS = ("serial_number", "hardware_uuid", "machine_id", "device_id_source")
MAX_LENGTH = 128


def validate(data):
    """Return the reported identity, or None when the request has no ``device``.

    Unknown fields are ignored. Missing or null fields are empty strings, and
    values are trimmed. Invalid shapes are rejected with HTTP 400 before any
    write occurs.
    """
    device = data.get("device")
    if device is None:
        return None
    require(isinstance(device, dict), "device must be an object")
    result = {}
    for field in FIELDS:
        value = device.get(field)
        if value is None:
            value = ""
        require(
            isinstance(value, str) and len(value) <= MAX_LENGTH and value.isprintable(),
            f"device.{field} must be a printable string of at most {MAX_LENGTH} characters",
        )
        result[field] = value.strip()
    return result


def values(device):
    """Column values for an insert, in COLUMNS order."""
    return tuple((device or {}).get(field, "") for field in FIELDS)


def presentation(row):
    """Move the stored columns into a ``device`` object on an API record."""
    row["device"] = {
        field: row.pop(column, "") for field, column in zip(FIELDS, COLUMNS)
    }
    return row
