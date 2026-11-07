"""Read only the connected personal account or organization's credit summary."""

import asyncio

import httpx
from openaidr_api_client.client import Unavailable

from openaidr.core import desktop_credits
from .config import Config, configuration_lock
from .runtime import Client, NOT_ENROLLED
from .usage import identity as enrollment_identity


def read(config, *, transport=None):
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if not config.enrolled() or config.get('disabled') or config.get('desktop_removal'):
            raise ValueError(NOT_ENROLLED)
        identity = dict(sensor_id=config['sensor_id'], server_url=config['server_url'].rstrip('/'),
                        scope=enrollment_identity(config))
        try:
            mode = config.get('connection_mode', 'organization')
            if mode in ('free', 'api_key'):
                if mode == 'free':
                    from .free_enrollment import prepare
                    connection = prepare(config).connection
                else:
                    from .api_key import connection as api_connection
                    connection = api_connection(config)
                if transport is None:
                    from . import network_proxy

                    transport = network_proxy.async_transport(config, connection.origin, connection.verify())
                plan = 'free' if mode == 'free' else 'account' if config.get('google_account') else 'paid'
                result = asyncio.run(desktop_credits.read(connection, plan, transport=transport))
            else:
                client = Client.from_config(config)
                try:
                    result = client.post('credits/summary', {}, timeout=15)
                finally:
                    client.close()
                result = desktop_credits.project_summary(result)
            return {**identity, **result}
        except (Unavailable, httpx.HTTPError, TimeoutError, OSError, ValueError, TypeError, KeyError,
                AttributeError, OverflowError, RecursionError):
            raise ValueError('Credit usage is unavailable. Try refreshing shortly.') from None
