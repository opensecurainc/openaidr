"""Expose only an authenticated sensor's shared organization credit totals."""

import asyncio

import httpx
from openaidr_api_client.client import Unavailable
from openaidr_api_client.contracts.errors import APIError

from openaidr.core.desktop_credits import read
from .free_tier import matches_installation
from .model_keys import selected_connection


def overview(st, cfg, sensor):
    try:
        connection = selected_connection(cfg, st)
        if connection is None or connection.tenant_id != sensor['tenant_id']:
            raise ValueError('Credit connection is unavailable')
        return asyncio.run(read(connection, 'free' if matches_installation(cfg) else 'paid'))
    except (Unavailable, httpx.HTTPError, TimeoutError, OSError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError, RecursionError):
        raise APIError(503, 'Credit usage is unavailable. Try again shortly.') from None
