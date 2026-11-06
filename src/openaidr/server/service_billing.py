"""Validated customer receipt mirrors; the Intelligence API owns the ledger."""

from contextlib import nullcontext

from openaidr_api_client.client import Connection
from openaidr_api_client.contracts.credits import BillingReceipt, amount, microcredits


PROGRESS = {
    "disabled": {"disabled"},
    "reserved": {"reserved", "pending", "settled", "released"},
    "pending": {"pending", "settled", "released"},
    "settled": {"settled"},
    "released": {"released"},
}


def view(row):
    return {
        "request_id": row["request_id"], "service": row["service"], "state": row["state"],
        "credits_reserved": amount(row["reserved_microcredits"]) if row["reserved_microcredits"] is not None else None,
        "credits_charged": amount(row["charged_microcredits"]) if row["charged_microcredits"] is not None else None,
        "rate_version": row["rate_version"],
    }


def record(st, tenant, connection, value, *, request_id, service, conn=None, max_credits=None):
    if not isinstance(connection, Connection) or connection.tenant_id != tenant:
        raise ValueError("Service receipt tenant mismatch")
    receipt = BillingReceipt.model_validate(value).model_dump()
    if receipt["request_id"] != request_id or receipt["service"] != service:
        raise ValueError("Service receipt identity mismatch")
    reserved = microcredits(receipt["credits_reserved"]) if receipt["credits_reserved"] is not None else None
    charged = microcredits(receipt["credits_charged"]) if receipt["credits_charged"] is not None else None
    if max_credits is not None and (reserved is None or reserved > microcredits(max_credits)):
        raise ValueError("Service receipt exceeds admission")
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        st.execute("""INSERT INTO service_credit_receipts
            (tenant_id,request_id,origin,api_tenant_id,service,state,reserved_microcredits,charged_microcredits,rate_version)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING""",
            tenant, request_id, connection.origin, connection.tenant_id, service, receipt["state"], reserved,
            charged, receipt["rate_version"], conn=conn)
        old = st.one("SELECT * FROM service_credit_receipts WHERE tenant_id=$1 AND request_id=$2 FOR UPDATE",
                     tenant, request_id, conn=conn)
        if (old["origin"] != connection.origin or old["api_tenant_id"] != connection.tenant_id
                or old["service"] != service or old["reserved_microcredits"] != reserved
                or old["rate_version"] != receipt["rate_version"]
                or receipt["state"] not in PROGRESS[old["state"]]
                or old["charged_microcredits"] is not None and old["charged_microcredits"] != charged):
            raise ValueError("Service receipt changed immutable accounting")
        # Repeated terminal reads must not restart rolling charge windows.
        st.execute("""UPDATE service_credit_receipts SET state=$3,charged_microcredits=$4,updated_at=clock_timestamp()
            WHERE tenant_id=$1 AND request_id=$2
              AND (state IS DISTINCT FROM $3 OR charged_microcredits IS DISTINCT FROM $4)""",
            tenant, request_id, receipt["state"], charged, conn=conn)
    return receipt
