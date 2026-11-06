"""Shared HTTP validation and response helpers."""

from openaidr_api_client.contracts.errors import (
    APIError as APIError,
    require as require,
)

import json
import uuid
from datetime import datetime

from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse
from .model import public, public_record


def uuid_param(value, name="id"):
    try:
        uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise APIError(400, "invalid " + name) from None
    return value


def parse_time(value):
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def page(query):
    try:
        limit = int(query.get("limit") or 0)
        require(limit >= 0, "invalid limit")
    except ValueError:
        raise APIError(400, "invalid limit") from None
    cursor = query.get("cursor", "")
    if cursor:
        from .store import decode_cursor

        try:
            decoded = decode_cursor(cursor)
            require(decoded is not None, "invalid cursor")
        except (ValueError, TypeError):
            raise APIError(400, "invalid cursor") from None
    return {"limit": limit, "cursor": cursor}


def body(request, limit=1 << 20):
    raw = request.state.body
    require(len(raw) <= limit, "request body too large", 413)
    require(raw, "empty body")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise APIError(400, "invalid json") from None
    require(isinstance(data, dict), "body must be a JSON object")
    string_fields = (
        "email",
        "password",
        "name",
        "slug",
        "owner_email",
        "owner_name",
        "token",
        "role",
        "status",
        "label",
        "host_kind",
        "enrollment_token",
        "hostname",
        "os",
        "arch",
        "user",
        "sensor_id",
        "finding_id",
        "type",
        "body",
        "resolution",
        "assignee_id",
        "plan",
    )
    for key in string_fields:
        if key in data:
            if data[key] is None and key not in (
                "status",
                "resolution",
                "assignee_id",
                "host_kind",
                "label",
            ):
                data[key] = ""
            if data[key] is not None:
                require(isinstance(data[key], str), key + " must be a string")
    for key in ("disabled", "enabled", "hook_installed"):
        if key in data and data[key] is not None:
            require(isinstance(data[key], bool), key + " must be a boolean")
    for key in (
        "policy_version",
        "queue_depth",
        "uptime_s",
        "expires_in_hours",
        "max_uses",
    ):
        if key in data and data[key] is not None:
            require(type(data[key]) is int, key + " must be an integer")
    return data


def response(value=None, status=200):
    return JSONResponse(jsonable_encoder(public(value), sqlalchemy_safe=False), status_code=status)


def listing(result, kind=None):
    items, cursor = result
    if kind:
        items = [public_record(item, kind) for item in items or []]
    return {"items": items or [], "next_cursor": cursor or ""}
