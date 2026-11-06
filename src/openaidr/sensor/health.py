"""Small diagnostic snapshots for fleet health, without exception text."""

import time
from datetime import datetime, timezone


class HealthReporter:
    def __init__(self):
        self.clock = time.monotonic
        self.pending = {}

    def stalled(self, name, depth, progress):
        stamp = self.clock()
        previous, since = self.pending.get(name, (None, None))
        if not depth:
            since = None
        elif since is None or progress != previous:
            since = stamp
        self.pending[name] = (progress, since)
        return int(max(0, stamp - since)) if since is not None else 0

    def report(self, *, activity, depth, dropped, telemetry, collectors, disabled):
        forwarded = telemetry.get("last_forwarded_at")
        enabled = telemetry.get("enabled", False)
        return dict(
            version=1,
            activity=dict(
                upload_failed=bool(activity["last_error"]),
                stalled_for_s=self.stalled("activity", 0 if disabled else depth, activity["last_ship_at"]),
                last_success_at=activity["last_ship_at"],
                dropped=dropped,
            ),
            telemetry=dict(
                enabled=enabled,
                listening=bool(telemetry.get("listening")),
                upload_failed=bool(telemetry.get("last_error")),
                stalled_for_s=self.stalled("telemetry", telemetry.get("queue_depth", 0) if enabled and not disabled else 0, forwarded),
                last_success_at=datetime.fromtimestamp(forwarded, timezone.utc).isoformat() if forwarded is not None else None,
            ),
            collectors_failed=sum(bool(item.get("error")) for item in collectors),
        )
