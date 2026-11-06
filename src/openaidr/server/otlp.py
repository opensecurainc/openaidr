"""OTLP-compatible failure responses."""

from starlette.responses import Response
from openaidr.core.telemetry import error_bytes


def error_response(status, message, content_type):
    code = {
        400: 3,
        401: 16,
        403: 7,
        404: 5,
        409: 6,
        413: 8,
        415: 3,
        429: 8,
        503: 14,
    }.get(status, 13)
    media_type = (
        "application/x-protobuf"
        if content_type.split(";", 1)[0].strip().lower() == "application/x-protobuf"
        else "application/json"
    )
    headers = {"Retry-After": "5"} if status in (429, 503) else {}
    return Response(
        error_bytes(code, message, media_type),
        status_code=status,
        media_type=media_type,
        headers=headers,
    )
