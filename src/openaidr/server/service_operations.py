"""Dormant customer operations; never select or change a running caller's SDK."""

import logging
from uuid import UUID, uuid4

from openaidr_api_client.client import Connection, Unavailable
from openaidr_api_client.contracts.credits import BillingReceipt, SERVICES

from . import service_billing

log = logging.getLogger(__name__)


def contracts():
    # Current callers still use the original SDK. Resolve the receiving contract
    # before transport creation so accidental activation cannot send a request.
    try:
        from openaidr_api_client import service_models
    except ImportError:
        raise Unavailable("Customer service SDK is unavailable") from None
    return service_models


class ServiceOperation:
    def __init__(self, store, tenant, service, connection, *, request_id=None):
        if not isinstance(connection, Connection) or connection.tenant_id != str(tenant):
            raise ValueError("Service operation tenant mismatch")
        if service not in SERVICES:
            raise ValueError("Unknown customer service")
        ident = request_id if request_id is not None else str(uuid4())
        if not isinstance(ident, str) or str(UUID(ident)) != ident:
            raise ValueError("Invalid service request identity")
        self.store, self.tenant, self.service = store, str(tenant), service
        self.connection, self.id, self.receipt = connection, ident, None
        # The same captured selection binds dispatch, accounting and any cache.
        self.cache_identity = connection.fingerprint()

    def capture(self, value):
        receipt = BillingReceipt.model_validate(value).model_dump()
        if receipt["request_id"] != self.id or receipt["service"] != self.service:
            raise ValueError("Service receipt identity mismatch")
        self.receipt = receipt

    def finish(self):
        # API accounting is authoritative. No response never means a zero charge.
        if self.store is None or self.receipt is None:
            return
        try:
            service_billing.record(self.store, self.tenant, self.connection, self.receipt,
                                   request_id=self.id, service=self.service)
        except Exception:
            log.warning("Service credit receipt recording unavailable")
