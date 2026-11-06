"""Read confirmed monthly customer credits without returning credentials or private costs."""

import asyncio

import httpx
from openaidr.core.desktop_credits import fetch, project

from .config import Config, configuration_lock
from .free_enrollment import prepare


def read(config, *, transport=None):
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if not config.enrolled() or config.get('connection_mode') != 'free':
            raise ValueError('Monthly free usage requires a free-plan connection.')
        connection = prepare(config).connection
        try:
            raw = asyncio.run(fetch(connection, transport))
            if not isinstance(raw, dict) or raw.get('tenant_id') != connection.tenant_id or raw.get('plan') != 'free':
                raise ValueError('Free usage belongs to another installation')
            usage = project(raw.get('usage'))
            if usage is None:
                raise ValueError('Monthly credit usage is unknown')
            return dict(sensor_id=config['sensor_id'], server_url=config['server_url'].rstrip('/'),
                        usage=usage, configured=usage['status'] != 'disabled')
        except (httpx.HTTPError, TimeoutError, ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            raise ValueError('Free plan usage is unavailable. Try again shortly.') from None
