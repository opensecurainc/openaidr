"""Explicit tenant retention with bounded partition removal and disk feedback."""

from datetime import timedelta
import time

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from . import host_metrics
from .httpx import require
from .store import new_id, now

MODES = ('7', '30', '90', 'automatic', 'unlimited')
MESSAGES = {
    'unconfigured': 'No retention policy has been saved. Telemetry is retained.',
    'retained': 'Telemetry has no age limit. Automatic disk cleanup is not enabled.',
    'waiting': 'Waiting for the next retention check.',
    'healthy': 'Disk usage is below the cleanup threshold.',
    'waiting_sample': 'Waiting for a new disk measurement after cleanup.',
    'disk_unavailable': 'Automatic cleanup is paused until fresh database disk measurements are available.',
    'no_progress': 'Cleanup did not reduce disk usage. Inspect storage, then save the policy to resume.',
    'disk_changed': 'Disk capacity changed during cleanup. Verify storage, then save the policy to resume.',
    'processing': 'Older telemetry is still needed by unfinished processing.',
    'no_eligible_data': 'No eligible completed days are available for cleanup.',
    'deleted': 'An expired telemetry day was removed.',
    'busy': 'Cleanup is waiting for database activity to finish.',
}
PUBLIC = 'mode,cleanup_threshold_percent,version,updated_at,status,checked_at,last_deleted_day,last_cleanup_at'


def get_settings(st, tenant_id, cfg, conn=None):
    rows = st.many(f'SELECT {PUBLIC} FROM tenant_telemetry_retention WHERE tenant_id=$1', tenant_id, conn=conn)
    result = rows[0] if rows else dict(mode=None, cleanup_threshold_percent=None,
                                     version=0, updated_at=None, status='unconfigured',
                                     checked_at=None, last_deleted_day=None, last_cleanup_at=None)
    return {**result, 'message': MESSAGES[result['status']],
            'automatic_available': bool(_disk(st, tenant_id, cfg, conn))}


def save_settings(st, tenant_id, payload, actor, cfg):
    require(set(payload) in ({'mode', 'version'}, {'mode', 'version', 'cleanup_threshold_percent'}),
            'mode and version are required; cleanup_threshold_percent is optional')
    require(payload['mode'] in MODES, 'invalid telemetry retention mode')
    require(type(payload['version']) is int and payload['version'] >= 0, 'invalid version')
    threshold = payload.get('cleanup_threshold_percent', 80 if payload['mode'] == 'automatic' else None)
    require(threshold is None or (type(threshold) is int and threshold in (70, 80, 90)),
            'cleanup threshold must be 70, 80, 90, or null')
    require(payload['mode'] != 'automatic' or threshold == 80, 'legacy Automatic uses an 80% threshold')
    with st.transaction() as conn:
        st.execute('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
                   'telemetry-retention:' + tenant_id, conn=conn)
        previous = get_settings(st, tenant_id, cfg, conn)
        require(previous['version'] == payload['version'], 'retention settings changed', 409)
        require(threshold is None or previous['automatic_available'],
                'Automatic requires fresh measurements of a verified dedicated database disk', 409)
        keep_feedback = (previous['cleanup_threshold_percent'] is not None and threshold is not None
                         and previous['status'] not in ('no_progress', 'disk_changed'))
        st.execute('''INSERT INTO tenant_telemetry_retention(tenant_id,mode,cleanup_threshold_percent) VALUES($1,$2,$3)
            ON CONFLICT(tenant_id) DO UPDATE SET mode=EXCLUDED.mode,
                cleanup_threshold_percent=EXCLUDED.cleanup_threshold_percent,
                version=tenant_telemetry_retention.version+1,updated_at=clock_timestamp(),
                pressure_active=COALESCE(tenant_telemetry_retention.cleanup_threshold_percent=EXCLUDED.cleanup_threshold_percent,false)
                    AND tenant_telemetry_retention.pressure_active,
                status='waiting',sample_at=CASE WHEN $4 THEN tenant_telemetry_retention.sample_at END,
                sample_used_bytes=CASE WHEN $4 THEN tenant_telemetry_retention.sample_used_bytes END,
                sample_total_bytes=CASE WHEN $4 THEN tenant_telemetry_retention.sample_total_bytes END,
                scan_after_day=NULL''', tenant_id, payload['mode'], threshold, keep_feedback, conn=conn)
        st.execute('''INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
            target_type,target_id,details) VALUES($1,$2,$3,$4,$5,'telemetry.retention.configure','telemetry',$2,$6)''',
            new_id(), tenant_id, actor.get('type', 'user'), actor.get('id', ''), actor.get('name', ''),
            Jsonb({'before': previous['mode'], 'mode': payload['mode'],
                   'before_cleanup_threshold_percent': previous['cleanup_threshold_percent'],
                   'cleanup_threshold_percent': threshold, 'version': previous['version'] + 1}), conn=conn)
        return get_settings(st, tenant_id, cfg, conn)


def _disk(st, tenant_id, cfg, conn=None):
    # This opt-in path is the operator's assertion that the collector observes
    # the dedicated PostgreSQL data filesystem, including any tablespaces.
    if not cfg.telemetry_retention_disk_path or cfg.tenant_id != tenant_id:
        return None
    if not st.scalar('SELECT count(*)=1 AND bool_and(id=$1) FROM tenants', tenant_id, conn=conn):
        return None
    metrics = host_metrics.read_metrics(cfg.host_metrics_path, '1h')
    if (metrics['status'] != 'ok' or metrics['disk_path'] != cfg.telemetry_retention_disk_path
            or not metrics['samples']):
        return None
    sample = metrics['samples'][-1]
    if 'disk_used_bytes' not in sample or sample['time'] != metrics['last_sample_at']:
        return None
    return dict(at=host_metrics.timestamp(sample['time']), used=sample['disk_used_bytes'],
                total=sample['disk_total_bytes'])


class _Budget:
    def __init__(self, conn):
        self.conn, self.deadline = conn, time.monotonic() + 5

    def execute(self, query, params=None):
        remaining = int((self.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise TimeoutError('retention budget exhausted')
        self.conn.execute(f'SET LOCAL statement_timeout={min(2000, remaining)}; SET LOCAL lock_timeout=100')
        return self.conn.execute(query, params)


def _status(st, tenant, status, conn):
    st.execute('''UPDATE tenant_telemetry_retention SET status=CASE
        WHEN status IN ('no_progress','disk_changed') AND $2='busy' THEN status ELSE $2 END,
        checked_at=clock_timestamp() WHERE tenant_id=$1''',
               tenant, status, conn=conn)


def _retire_keys(st, tenant, conn):
    removed = 0
    for table in ('event_keys', 'telemetry_export_keys'):
        removed += st.execute(f'''DELETE FROM {table} WHERE id IN (
            SELECT k.id FROM {table} k JOIN telemetry_partition_days d USING(tenant_id,storage_day)
            WHERE k.tenant_id=$1 AND d.retired_at IS NOT NULL LIMIT 100)''', tenant, conn=conn)
    # Keep tombstones while identities remain, so a restart resumes cleanup.
    removed += st.execute('''DELETE FROM telemetry_partition_days d WHERE tenant_id=$1 AND retired_at IS NOT NULL
        AND NOT EXISTS(SELECT 1 FROM event_keys k WHERE k.tenant_id=d.tenant_id AND k.storage_day=d.storage_day)
        AND NOT EXISTS(SELECT 1 FROM telemetry_export_keys k WHERE k.tenant_id=d.tenant_id AND k.storage_day=d.storage_day)''',
        tenant, conn=conn)
    return removed


def cleanup_keys(st, cfg):
    """Drain metadata continuously in small transactions after committed drops."""
    with st.transaction() as raw:
        conn = _Budget(raw)
        rows = st.many('''SELECT tenant_id FROM telemetry_partition_days WHERE retired_at IS NOT NULL
            AND ($1::uuid IS NULL OR tenant_id=$1) ORDER BY retired_at LIMIT 1''', cfg.tenant_id or None, conn=conn)
        if not rows:
            return False
        tenant = rows[0]['tenant_id']
        if not st.scalar('SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))',
                         'telemetry-retention:' + tenant, conn=conn):
            return False
        return bool(_retire_keys(st, tenant, conn))


def _drop(st, tenant, day, conn):
    # Lock session identities first. Late observations, receipts, binding, and
    # finalization must serialize with the final safety check and removal.
    st.scalar('''SELECT count(*) FROM (SELECT s.id FROM agent_sessions s WHERE s.tenant_id=$1
        AND EXISTS(SELECT 1 FROM events e WHERE e.tenant_id=$1 AND e.storage_day=$2 AND e.session_id=s.id)
        FOR UPDATE OF s NOWAIT) locked''', tenant, day, conn=conn)
    st.scalar('''SELECT count(*) FROM (SELECT r.id FROM session_registrations r WHERE r.tenant_id=$1
        AND EXISTS(SELECT 1 FROM agent_sessions s JOIN events e ON e.session_id=s.id AND e.tenant_id=s.tenant_id
            WHERE s.registration_id=r.id AND e.tenant_id=$1 AND e.storage_day=$2)
        FOR UPDATE OF r NOWAIT) locked''', tenant, day, conn=conn)
    names = [root + '_' + tenant.replace('-', '') + '_' + day.strftime('%Y%m%d')
             for root in ('events', 'telemetry_exports')]
    for name in names:
        conn.execute(sql.SQL('LOCK TABLE {} IN ACCESS EXCLUSIVE MODE NOWAIT').format(sql.Identifier(name)))
    pending = st.scalar('''SELECT
        EXISTS(SELECT 1 FROM telemetry_exports WHERE tenant_id=$1 AND storage_day=$2
            AND (resource_summary IS NULL OR (signal='logs' AND (translated_at IS NULL OR costs_processed_at IS NULL))
                OR (signal='metrics' AND service_names @> ARRAY['cursor']::text[]
                    AND received_at>=now()-interval '30 days' AND costs_processed_at IS NULL)))
        OR EXISTS(SELECT 1 FROM events e LEFT JOIN detect_cursors c ON c.tenant_id=e.tenant_id
            WHERE e.tenant_id=$1 AND e.storage_day=$2 AND
            (c.tenant_id IS NULL OR (e.received_at,e.id)>(c.last_received_at,c.last_event_id)
             OR e.risk->>'status'='pending'
             OR (e.received_at>=clock_timestamp()-interval '24 hours' AND
                 (e.risk IS NULL OR e.risk->>'status'='error'))))
        OR EXISTS(SELECT 1 FROM events e JOIN agent_sessions s ON s.id=e.session_id
            JOIN session_registrations r ON r.id=s.registration_id
            LEFT JOIN session_finalizations f ON f.registration_id=r.id
            LEFT JOIN tenant_session_detection_settings settings ON settings.tenant_id=r.tenant_id
            WHERE e.tenant_id=$1 AND e.storage_day=$2 AND r.assessment_mode='inline'
            AND (f.snapshot_id IS NULL OR f.lifecycle NOT IN ('closed','incomplete') OR f.failure_code<>''
                OR f.next_evaluation_at IS NOT NULL OR COALESCE(f.settings_version,0)<>COALESCE(settings.version,0)
                OR EXISTS(SELECT 1 FROM session_input_dirty WHERE registration_id=r.id)
                OR NOT EXISTS(SELECT 1 FROM session_snapshots WHERE id=f.snapshot_id)))
        OR EXISTS(SELECT 1 FROM events waiting WHERE waiting.tenant_id=$1
            AND (waiting.risk->>'status'='pending' OR (waiting.received_at>=clock_timestamp()-interval '24 hours'
                AND (waiting.risk IS NULL OR waiting.risk->>'status'='error')))
            AND EXISTS(SELECT 1 FROM events old WHERE old.tenant_id=$1 AND old.storage_day=$2
                AND old.session_id=waiting.session_id))''', tenant, day, conn=conn)
    if pending:
        return False
    for name in names:
        conn.execute(sql.SQL('DROP TABLE {}').format(sql.Identifier(name)))
    st.execute('UPDATE telemetry_partition_days SET retired_at=clock_timestamp() WHERE tenant_id=$1 AND storage_day=$2',
               tenant, day, conn=conn)
    st.execute('''UPDATE tenant_telemetry_retention SET last_deleted_day=$2,last_cleanup_at=clock_timestamp()
        WHERE tenant_id=$1''', tenant, day, conn=conn)
    st.execute('''INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
        VALUES($1,$2,'system','','Retention worker','telemetry.retention.delete','telemetry',$2,$3)''',
        new_id(), tenant, Jsonb({'storage_day': day.isoformat()}), conn=conn)
    return True


def _pressure(st, tenant, row, cfg, conn):
    threshold = row['cleanup_threshold_percent']
    if threshold is None:
        return False, None, None
    if row['status'] in ('no_progress', 'disk_changed'):
        return False, None, row['status']
    sample = _disk(st, tenant, cfg, conn)
    if sample is None:
        return False, None, 'disk_unavailable'
    if row['last_cleanup_at'] and sample['at'] <= row['last_cleanup_at'] + timedelta(seconds=5):
        return False, None, 'waiting_sample'
    if row['sample_at'] is not None:
        if sample['at'] <= row['sample_at']:
            return False, None, 'waiting_sample'
        if sample['total'] != row['sample_total_bytes']:
            return False, None, 'disk_changed'
        if sample['used'] >= row['sample_used_bytes']:
            return False, None, 'no_progress'
    used = sample['used'] * 100
    start = sample['total'] * threshold
    # Existing Automatic policies keep their strict boundary until edited.
    below_start = used <= start if row['mode'] == 'automatic' else used < start
    if used < sample['total'] * (threshold - 5) or (not row['pressure_active'] and below_start):
        st.execute('''UPDATE tenant_telemetry_retention SET pressure_active=false,sample_at=NULL,
            sample_used_bytes=NULL,sample_total_bytes=NULL WHERE tenant_id=$1''', tenant, conn=conn)
        return False, sample, 'healthy'
    st.execute('UPDATE tenant_telemetry_retention SET pressure_active=true WHERE tenant_id=$1', tenant, conn=conn)
    return True, sample, None


def _cleanup_evidence(st, tenant):
    from .ingest_evidence import cleanup

    try:
        with st.transaction() as conn:
            st.execute("SET LOCAL statement_timeout='500ms'; SET LOCAL lock_timeout='50ms'", conn=conn)
            if st.scalar('SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))',
                         'telemetry-retention:' + tenant, conn=conn):
                cleanup(st, tenant, conn)
    except (psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled, psycopg.errors.DeadlockDetected):
        # Evidence cleanup has its own transaction and budget. Retry it next
        # tick without holding back eligible telemetry partition retirement.
        pass


def tick(st, cfg):
    # One day per tenant per pass bounds both deletion and DDL pressure.
    tenants = st.many('''SELECT tenant_id FROM tenant_telemetry_retention
        WHERE ($1::uuid IS NULL OR tenant_id=$1) ORDER BY checked_at NULLS FIRST,tenant_id LIMIT 10''', cfg.tenant_id or None)
    for item in tenants:
        tenant = item['tenant_id']
        _cleanup_evidence(st, tenant)
        try:
            with st.transaction() as raw:
                conn = _Budget(raw)
                if not st.scalar('SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))',
                                 'telemetry-retention:' + tenant, conn=conn):
                    continue
                row = st.one('SELECT * FROM tenant_telemetry_retention WHERE tenant_id=$1 FOR UPDATE', tenant, conn=conn)
                automatic, sample, pressure_status = _pressure(st, tenant, row, cfg, conn)
                if not automatic and row['mode'] in ('automatic', 'unlimited'):
                    _status(st, tenant, pressure_status or 'retained', conn)
                    continue
                cutoff = now().date() if automatic else (now() - timedelta(days=int(row['mode']))).date()
                query = '''SELECT storage_day FROM telemetry_partition_days d
                    WHERE tenant_id=$1 AND storage_day<$2 AND retired_at IS NULL
                    AND (NOT $3 OR EXISTS(SELECT 1 FROM events e WHERE e.tenant_id=$1 AND e.storage_day=d.storage_day)
                        OR EXISTS(SELECT 1 FROM telemetry_exports e WHERE e.tenant_id=$1 AND e.storage_day=d.storage_day))
                    AND ($4::date IS NULL OR storage_day>$4) ORDER BY storage_day LIMIT 16'''
                days = st.many(query, tenant, cutoff, automatic, row['scan_after_day'], conn=conn)
                if not days and row['scan_after_day'] is not None:
                    days = st.many(query, tenant, cutoff, automatic, None, conn=conn)
                status = 'no_eligible_data'
                for candidate in days:
                    day = candidate['storage_day']
                    if _drop(st, tenant, day, conn):
                        status = 'waiting_sample' if automatic else 'deleted'
                        if automatic:
                            st.execute('''UPDATE tenant_telemetry_retention SET sample_at=$2,sample_used_bytes=$3,
                                sample_total_bytes=$4 WHERE tenant_id=$1''', tenant, sample['at'], sample['used'], sample['total'], conn=conn)
                        break
                    status = 'processing'
                st.execute('UPDATE tenant_telemetry_retention SET scan_after_day=$2 WHERE tenant_id=$1',
                           tenant, days[-1]['storage_day'] if days and status == 'processing' else None, conn=conn)
                # Age expiry must not clear a disk-safety latch or a pending sample.
                if pressure_status and pressure_status != 'healthy':
                    status = pressure_status
                _status(st, tenant, status, conn)
        except (psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled, psycopg.errors.DeadlockDetected, TimeoutError):
            # Roll back all DDL and bookkeeping together before recording delay.
            with st.transaction() as conn:
                st.execute("SET LOCAL statement_timeout='1s'; SET LOCAL lock_timeout='100ms'", conn=conn)
                _status(st, tenant, 'busy', conn)
