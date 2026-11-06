"""Typed device requests, separate from all native provider traffic."""

import asyncio
import ssl
from urllib.parse import urlsplit
import uuid

import httpx

class BackendError(Exception):
    def __init__(self, code, status=None):
        self.code, self.status = code, status
        super().__init__(code)


class BackendUnavailable(BackendError):
    pass


class BackendDenied(BackendError):
    pass


class BackendRejected(BackendError):
    pass


def enrollment(config):
    url = urlsplit(config["server_url"])
    # The sensor validates the URL when it prepares the client options.
    return {
        "server_url": config["server_url"].rstrip("/"),
        "tenant_id": str(uuid.UUID(config["tenant_id"])) if config.get("tenant_id") else None,
        "sensor_id": str(uuid.UUID(config["sensor_id"])),
        "origin": (
            url.scheme.lower(),
            url.hostname.lower(),
            url.port or (443 if url.scheme == "https" else 80),
        ),
    }


def _uuid(value):
    return str(uuid.UUID(value))


def _certificate_error(error):
    # HTTPX and HTTP Core preserve the underlying TLS exception as a cause.
    # Do not turn an explicit certificate rejection into outage permission.
    for _ in range(8):
        if isinstance(error, ssl.SSLCertVerificationError):
            return True
        if isinstance(error, ssl.SSLError) and any(
            code in (getattr(error, "reason", "") or "")
            for code in ("CERTIFICATE", "UNKNOWN_CA", "ACCESS_DENIED")
        ):
            return True
        error = error.__cause__
        if error is None:
            break
    return False


class Backend:
    def __init__(self, config, *, client_options, transport=None, concurrency=4, local_only=False):
        if type(concurrency) is not int or not 1 <= concurrency <= 16:
            raise ValueError("invalid managed request concurrency")
        options = dict(client_options)
        self.identity = enrollment(config)
        self.local_only = local_only
        self.limit = asyncio.Semaphore(concurrency)
        self.http = None if local_only else httpx.AsyncClient(
            base_url=self.identity["server_url"] + "/ingest/v1/",
            headers={
                "Accept": "application/json",
                "User-Agent": "openaidr/managed",
                **options.pop("headers"),
            },
            timeout=30,
            follow_redirects=False,
            transport=transport,
            **options,
        )

    async def aclose(self):
        if self.http is not None:
            await self.http.aclose()

    async def _post(self, path, payload):
        if self.local_only:
            raise BackendUnavailable("unverified_history")
        if self.identity["tenant_id"] is None and path != "managed-bootstrap":
            raise BackendRejected("bootstrap_required")
        status = None
        try:
            async with self.limit:
                async with self.http.stream("POST", path, json=payload) as response:
                    status = response.status_code
                    if status in (401, 403):
                        raise BackendDenied("backend_denied", status)
                    if status == 429 or status >= 500:
                        raise BackendUnavailable("backend_unavailable", status)
                    await response.aread()
        except httpx.TransportError as exc:
            if status in (401, 403) or _certificate_error(exc):
                raise BackendDenied("backend_denied", status) from None
            if (
                status is not None
                and status not in (200, 201, 202, 429)
                and status < 500
            ):
                raise BackendRejected("backend_rejected", status) from None
            raise BackendUnavailable("backend_unavailable") from None
        try:
            data = response.json()
        except (ValueError, UnicodeError, RecursionError):
            raise BackendRejected(
                "invalid_backend_response", response.status_code
            ) from None
        if not isinstance(data, dict):
            raise BackendRejected("invalid_backend_response", response.status_code)
        if response.status_code not in (200, 201, 202):
            known = {
                "policy_changed",
                "context_changed",
                "context_protocol_required",
                "policy_floor_changed",
                "payload_changed",
                "action_rejected",
                "action_blocked",
                "approval_pending",
                "approval_expired",
                "approval_revoked",
                "approvals_disabled",
                "record_unavailable",
                "epoch_changed",
                "stale_close",
                "action_already_consumed",
            }
            code = (
                data.get("error", {}).get("code")
                if isinstance(data.get("error"), dict)
                else None
            )
            raise BackendRejected(
                code if code in known else "backend_rejected", response.status_code
            )
        return data

    async def bootstrap(self):
        value = await self._post("managed-bootstrap", {})
        try:
            tenant_id = str(uuid.UUID(value["tenant_id"]))
            sensor_id = str(uuid.UUID(value["sensor_id"]))
            if (
                type(value.get("version")) is not int or value["version"] != 1
                or sensor_id != self.identity["sensor_id"]
                or self.identity["tenant_id"] not in (None, tenant_id)
                or not isinstance(value.get("capture"), dict)
                or not isinstance(value.get("policy"), dict)
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, AttributeError):
            raise BackendRejected("invalid_backend_binding") from None
        # Only bootstrap may fill an unknown enrollment identity, before a
        # registered journal is created. Local-only backends never reach here.
        self.identity["tenant_id"] = tenant_id
        return value

    async def reserve(self, product, epoch_id):
        return await self._post(
            "session-registrations",
            {
                "product": product,
                "assessment_mode": "inline",
                "delivery_protocol": 1,
                "delivery_epoch": _uuid(epoch_id),
            },
        )

    async def bind(self, registration_id, session_id):
        return await self._post(
            f"session-registrations/{_uuid(registration_id)}/bind",
            {"external_id": session_id},
        )

    async def status(self, registration_id, *, include_policy=False):
        return await self._post(
            f"session-registrations/{_uuid(registration_id)}/status",
            {"include_policy": True} if include_policy else {},
        )

    async def check(self, payload):
        return await self._post("guardrail-checks", payload)

    async def approval_status(self, approval_id):
        return await self._post(f"approvals/{_uuid(approval_id)}/status", {})

    async def consume(self, check_id, request_id, commitment):
        return await self._post(
            f"guardrail-checks/{_uuid(check_id)}/consume",
            {
                "request_id": _uuid(request_id),
                "action_commitment": commitment,
            },
        )

    async def outcome(self, release_id, outcome, *, exit_code=None, evidence_ids=()):
        return await self._post(
            f"guardrail-releases/{_uuid(release_id)}/outcome",
            {
                "outcome": outcome,
                "exit_code": exit_code,
                "evidence_ids": list(evidence_ids),
            },
        )

    async def events(self, events):
        result = await self._post(
            "events", {"sensor_id": self.identity["sensor_id"], "events": events}
        )
        if result.get("rejected"):
            raise BackendRejected("evidence_rejected", 400)
        return result

    async def delivery(self, registration_id, epoch_id, records):
        return await self._post(
            f"session-registrations/{_uuid(registration_id)}/delivery",
            {
                "epoch_id": _uuid(epoch_id),
                "records": records,
            },
        )

    async def close_session(self, registration_id, payload):
        return await self._post(
            f"session-registrations/{_uuid(registration_id)}/close", payload
        )

    async def delivery_status(self, registration_id):
        return await self._post(
            f"session-registrations/{_uuid(registration_id)}/delivery-status", {}
        )
