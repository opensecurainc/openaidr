"""Retention policy and storage boundaries against real PostgreSQL."""

from datetime import timedelta
from types import SimpleNamespace

from psycopg.types.json import Jsonb
import pytest

from openaidr.server import host_metrics, telemetry_retention as retention
from openaidr.server.store import now, new_id
from test_hook_policy import system as system, browser
from test_telemetry_partitions import database as database
from test_store import db as db
from test_inline_guardrail import system as inline_system


def config(st, tenant='', path=''):
    return SimpleNamespace(tenant_id=tenant, host_metrics_path=path, telemetry_retention_disk_path='/data' if path else '')


def policy(st, tenant, cfg, mode='7', **options):
    current = retention.get_settings(st, tenant, cfg)
    return retention.save_settings(st, tenant, {'mode': mode, 'version': current['version'], **options}, {}, cfg)


def seed(st, sensor, age, *, pending=False):
    day = now().date() - timedelta(days=age)
    st.execute('SELECT ensure_telemetry_partitions($1,$2)', sensor['tenant_id'], day)
    stamp = now() - timedelta(days=age)
    ident = new_id()
    st.execute('''INSERT INTO events(id,tenant_id,sensor_id,time,kind,product,body,storage_day,received_at,risk)
        VALUES($1,$2,$3,$4,'sensor','',$5,$6,$4,$7)''', ident, sensor['tenant_id'], sensor['id'], stamp,
        Jsonb({'id': ident, 'kind': 'sensor'}), day, Jsonb({'status': 'pending' if pending else 'scored'}))
    st.set_detect_cursor(sensor['tenant_id'], {'time': now(), 'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff'})
    return ident, day


def sample(path, used, *, age=0, total=1000, root_used=None):
    stamp = now() - timedelta(seconds=age)
    host_metrics.save_sample(path, 'database-host', {
        'time': stamp.isoformat(), 'cpu_percent': 1, 'memory_percent': 10, 'disk_percent': used * 100 / total,
        'disk_read_bytes_per_second': 0, 'disk_write_bytes_per_second': 0,
        'cpu_count': 2, 'memory_used_bytes': 10, 'memory_total_bytes': 100,
        'disk_used_bytes': used, 'disk_total_bytes': total,
        **({'disk_is_root': False, 'disk_available_bytes': total - used,
            'root_disk_percent': root_used / 10, 'root_disk_used_bytes': root_used,
            'root_disk_total_bytes': 1000, 'root_disk_available_bytes': 1000 - root_used}
           if root_used is not None else {}),
    }, '/data')


def advance_feedback(st, tenant):
    # Model a later worker process and a new collector sample without sleeping.
    st.execute("UPDATE tenant_telemetry_retention SET last_cleanup_at=clock_timestamp()-interval '61 seconds', sample_at=clock_timestamp()-interval '62 seconds' WHERE tenant_id=$1", tenant)


def test_retention_http_permissions_versions_and_explicit_opt_in(system):
    path = 'settings/telemetry-retention'
    current = browser(system, 'GET', path)
    assert current.status_code == 200 and current.headers['cache-control'] == 'no-store'
    assert current.json()['mode'] is None
    assert current.json()['cleanup_threshold_percent'] is None
    assert browser(system, 'PUT', path, {'mode': '7', 'version': 0}, user='viewer').status_code == 403
    assert system.client.put('/api/v1/' + path, json={'mode': '7', 'version': 0}, headers={'X-OpenAIDR-CSRF': '1'}).status_code == 401
    no_csrf = {k: v for k, v in system.headers['admin'].items() if k.lower() != 'x-openaidr-csrf'}
    assert system.client.put('/api/v1/' + path, json={'mode': '7', 'version': 0}, headers=no_csrf).status_code == 403
    for mode in ('forever', 7, None):
        assert browser(system, 'PUT', path, {'mode': mode, 'version': 0}).status_code == 400
    assert browser(system, 'PUT', path, {'mode': 'automatic', 'version': 0}).status_code == 409
    for threshold in (True, '80', 80.0, 0, 75, 100):
        assert browser(system, 'PUT', path, {
            'mode': 'unlimited', 'version': 0, 'cleanup_threshold_percent': threshold,
        }).status_code == 400
    assert browser(system, 'PUT', path, {
        'mode': '30', 'version': 0, 'cleanup_threshold_percent': 70,
    }).status_code == 409
    assert browser(system, 'PUT', path, {
        'mode': 'unlimited', 'version': 0, 'cleanup_threshold_percent': 90,
    }, user='viewer').status_code == 403
    for version, mode in enumerate(('7', '30', '90', 'unlimited')):
        saved = browser(system, 'PUT', path, {'mode': mode, 'version': version})
        assert saved.status_code == 200 and saved.json()['mode'] == mode
        assert saved.json()['cleanup_threshold_percent'] is None
    assert browser(system, 'PUT', path, {'mode': '7', 'version': 0}).status_code == 409
    assert browser(system, 'GET', path, user='foreign').json()['mode'] is None
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action='telemetry.retention.configure'") == 4


def test_retention_controls_migration_preserves_existing_policies(database):
    st, sensor = database
    tenant = sensor['tenant_id']
    st.execute('ALTER TABLE tenant_telemetry_retention DROP COLUMN cleanup_threshold_percent')
    st.execute('DELETE FROM schema_migrations WHERE version=57')
    for mode in ('7', '30', '90', 'automatic'):
        own = st.bootstrap_tenant('Existing ' + mode, 'existing-' + mode)['tenant']['id']
        st.execute('''INSERT INTO tenant_telemetry_retention(tenant_id,mode,version,pressure_active,status,
            sample_at,sample_used_bytes,sample_total_bytes) VALUES($1,$2,4,true,'waiting_sample',now(),850,1000)''', own, mode)
    before = st.many('SELECT * FROM tenant_telemetry_retention ORDER BY tenant_id')
    assert st.migrate() == ['0057_retention_controls.sql']
    assert st.migrate() == []
    after = st.many('SELECT * FROM tenant_telemetry_retention ORDER BY tenant_id')
    for row in after:
        assert row.pop('cleanup_threshold_percent') == (80 if row['mode'] == 'automatic' else None)
    assert before == after
    assert retention.get_settings(st, tenant, config(st))['mode'] is None


@pytest.mark.parametrize('threshold', [70, 80, 90])
@pytest.mark.parametrize('mode', ['30', 'unlimited'])
def test_independent_age_and_disk_limits_with_exact_thresholds(database, tmp_path, threshold, mode):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    old, _ = seed(st, sensor, 31)
    younger, _ = seed(st, sensor, 10)
    seed(st, sensor, 5)
    protected, _ = seed(st, sensor, 3, pending=True)
    today, _ = seed(st, sensor, 0)
    # Boot pressure must not delete telemetry while the data disk is below its limit.
    sample(path, threshold * 10 - 1, root_used=970)
    saved = policy(st, tenant, cfg, mode, cleanup_threshold_percent=threshold)
    assert saved['mode'] == mode and saved['cleanup_threshold_percent'] == threshold
    audit = st.one("SELECT details FROM audit_log WHERE action='telemetry.retention.configure'")['details']
    assert audit['cleanup_threshold_percent'] == threshold and audit['before_cleanup_threshold_percent'] is None
    retention.tick(st, cfg)
    assert st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', old) == (mode == 'unlimited')
    assert st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', younger)
    # Age expiry also needs a fresh post-deletion sample before pressure cleanup.
    st.execute("UPDATE tenant_telemetry_retention SET last_cleanup_at=clock_timestamp()-interval '61 seconds' WHERE tenant_id=$1", tenant)
    sample(path, threshold * 10)
    retention.tick(st, cfg)
    count = st.scalar('SELECT count(*) FROM events')
    assert count == (4 if mode == 'unlimited' else 3)
    policy(st, tenant, cfg, mode, cleanup_threshold_percent=threshold)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == count
    advance_feedback(st, tenant)
    sample(path, (threshold - 5) * 10)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == count - 1
    advance_feedback(st, tenant)
    sample(path, (threshold - 5) * 10 - 1)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == count - 1
    assert not st.scalar('SELECT pressure_active FROM tenant_telemetry_retention WHERE tenant_id=$1', tenant)
    assert st.scalar('SELECT count(*) FROM events WHERE id=ANY($1::uuid[])', [protected, today]) == 2


def test_unlimited_without_pressure_and_age_expiry_with_unavailable_disk(database, tmp_path):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    old, _ = seed(st, sensor, 100)
    young, _ = seed(st, sensor, 1)
    sample(path, 950)
    policy(st, tenant, cfg, 'unlimited', cleanup_threshold_percent=None)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 2
    assert retention.get_settings(st, tenant, cfg)['status'] == 'retained'
    sample(path, 850)
    policy(st, tenant, cfg, '7', cleanup_threshold_percent=80)
    path.unlink()
    retention.tick(st, cfg)
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', old)
    assert st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', young)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'disk_unavailable'
    expired, _ = seed(st, sensor, 110)
    sample(path, 950)
    policy(st, tenant, cfg, '7', cleanup_threshold_percent=None)
    retention.tick(st, cfg)
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', expired)
    assert st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', young)


def test_threshold_and_age_changes_preserve_feedback_and_latches(database, tmp_path):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    for age in (40, 10, 5):
        seed(st, sensor, age)
    sample(path, 900)
    policy(st, tenant, cfg, 'unlimited', cleanup_threshold_percent=90)
    retention.tick(st, cfg)
    policy(st, tenant, cfg, '30', cleanup_threshold_percent=70)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 2
    advance_feedback(st, tenant)
    sample(path, 900)
    retention.tick(st, cfg)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'no_progress'
    expired, _ = seed(st, sensor, 35)
    retention.tick(st, cfg)
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', expired)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'no_progress'
    sample(path, 800)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 2


@pytest.mark.parametrize('days', [7, 30, 90])
def test_fixed_age_keeps_younger_data_other_tenants_and_cleans_keys_after_restart(database, days):
    st, sensor = database
    tenant = sensor['tenant_id']
    cfg = config(st)
    expired, old_day = seed(st, sensor, days + 1)
    retained, _ = seed(st, sensor, days)
    other = st.bootstrap_tenant('Other', 'other')
    remote, _, _ = st.enroll_sensor({'enrollment_token': other['enrollment_token'], 'hostname': 'other'})
    foreign, _ = seed(st, remote, days + 2)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 3
    policy(st, tenant, cfg, str(days))
    retention.tick(st, cfg)
    assert st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', expired) is False
    assert st.scalar('SELECT count(*) FROM events WHERE id=ANY($1::uuid[])', [retained, foreign]) == 2
    assert st.scalar('SELECT retired_at IS NOT NULL FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day=$2', tenant, old_day)
    assert st.scalar('SELECT EXISTS(SELECT 1 FROM event_keys WHERE id=$1)', expired)
    retention.cleanup_keys(st, config(st))
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM event_keys WHERE id=$1)', expired)
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day=$2)', tenant, old_day)


def test_automatic_hysteresis_freshness_and_no_progress_latch(database, tmp_path):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    records = [seed(st, sensor, age)[0] for age in (50, 40, 30, 20)]
    sample(path, 800)
    policy(st, tenant, cfg, 'automatic')
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 4
    sample(path, 810)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 3
    # Saving again must not bypass feedback or reset the active 75% target.
    policy(st, tenant, cfg, 'automatic')
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 3
    advance_feedback(st, tenant)
    sample(path, 770)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 2
    advance_feedback(st, tenant)
    sample(path, 750)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1  # Stop is strictly below 75%.
    advance_feedback(st, tenant)
    sample(path, 749)
    retention.tick(st, cfg)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'healthy'
    sample(path, 810)
    retention.tick(st, cfg)
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=ANY($1::uuid[]))', records)
    seed(st, sensor, 10)
    advance_feedback(st, tenant)
    sample(path, 810)
    retention.tick(st, cfg)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'no_progress'
    sample(path, 809)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1
    policy(st, tenant, cfg, 'automatic')
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 0


def test_missing_stale_wrong_or_shared_disk_never_deletes(database, tmp_path):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    seed(st, sensor, 30)
    sample(path, 850)
    policy(st, tenant, cfg, 'automatic')
    # Remove fresh history before replacing with an older collector sample.
    path.unlink()
    sample(path, 850, age=240)
    retention.tick(st, cfg)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'disk_unavailable'
    sample(path, 850)
    cfg.telemetry_retention_disk_path = '/wrong'
    retention.tick(st, cfg)
    cfg.telemetry_retention_disk_path = '/data'
    st.bootstrap_tenant('Other', 'other')
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1


def test_pending_processing_and_busy_partition_are_preserved(database):
    st, sensor = database
    tenant, cfg = sensor['tenant_id'], config(st)
    ident, day = seed(st, sensor, 30, pending=True)
    policy(st, tenant, cfg)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1
    retention.tick(st, cfg)  # The first pass also retires an empty provisioning day.
    assert retention.get_settings(st, tenant, cfg)['status'] == 'processing'
    st.execute("UPDATE events SET risk='{}' WHERE id=$1", ident)
    st.execute('DELETE FROM detect_cursors WHERE tenant_id=$1', tenant)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1
    st.set_detect_cursor(tenant, {'time': now(), 'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff'})
    with st.transaction() as blocker:
        st.scalar('SELECT count(*) FROM events WHERE tenant_id=$1 AND storage_day=$2', tenant, day, conn=blocker)
        retention.tick(st, cfg)
        assert retention.get_settings(st, tenant, cfg)['status'] == 'busy'
    assert st.scalar('SELECT count(*) FROM events') == 1
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 0


def test_export_processing_and_surviving_references(database):
    from openaidr.server.agent_cost_usage import process_pending
    from test_telemetry_dashboard import cost_payload

    st, sensor = database
    tenant, cfg = sensor['tenant_id'], config(st)
    day = now().date() - timedelta(days=20)
    st.execute('SELECT ensure_telemetry_partitions($1,$2)', tenant, day)
    ident = new_id()
    st.execute('''INSERT INTO telemetry_exports(id,tenant_id,sensor_id,signal,batch_id,payload_sha256,
        record_count,payload,storage_day) VALUES($1,$2,$3,'logs',$4,'test',1,$5,$6)''',
        ident, tenant, sensor['id'], new_id(), Jsonb(cost_payload(
            'claude-code', now() - timedelta(days=20), [('claude_code.api_request', {'cost_usd': '0.5', 'effort': 'high'})])), day)
    policy(st, tenant, cfg)
    for field in ('translated_at', 'costs_processed_at'):
        retention.tick(st, cfg)
        assert st.scalar('SELECT count(*) FROM telemetry_exports') == 1
        if field == 'costs_processed_at':
            assert process_pending(st) == {'exports': 1, 'failed': 0}
        else:
            st.execute(f'UPDATE telemetry_exports SET {field}=clock_timestamp() WHERE id=$1', ident)
    costs = st.many('SELECT to_jsonb(r) AS row FROM agent_cost_records r')
    assert len(costs) == 1
    assert costs[0]['row']['reasoning_effort'] == 'high'
    # Replaying 0051 on retained accounting requeues exports for metadata.
    # Retention must wait for that work even though usage was already priced.
    st.execute('ALTER TABLE agent_cost_records DROP COLUMN sensor_id, DROP COLUMN reasoning_effort')
    st.execute('DELETE FROM schema_migrations WHERE version=51')
    assert st.migrate() == ['0051_desktop_usage_effort.sql']
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM telemetry_exports') == 1
    assert process_pending(st) == {'exports': 1, 'failed': 0}
    assert st.many('SELECT to_jsonb(r) AS row FROM agent_cost_records r') == costs
    retained, _ = seed(st, sensor, 1)
    st.execute('UPDATE events SET export_id=$2 WHERE id=$1', retained, ident)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM telemetry_exports') == 0
    assert st.scalar('SELECT export_id FROM events WHERE id=$1', retained) == ident
    assert retention.cleanup_keys(st, cfg)
    assert st.scalar('SELECT export_id FROM events WHERE id=$1', retained) is None
    costs[0]['row']['export_id'] = None
    assert st.many('SELECT to_jsonb(r) AS row FROM agent_cost_records r') == costs


def test_automatic_capacity_change_pauses_without_rearming(database, tmp_path):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    for age in (30, 20):
        seed(st, sensor, age)
    sample(path, 850)
    policy(st, tenant, cfg, 'automatic')
    retention.tick(st, cfg)
    advance_feedback(st, tenant)
    sample(path, 1800, total=2000)
    retention.tick(st, cfg)
    assert retention.get_settings(st, tenant, cfg)['status'] == 'disk_changed'
    assert st.scalar('SELECT count(*) FROM events') == 1


def test_session_finalization_dirty_inputs_and_saved_evidence(inline_system):
    from test_inline_guardrail import event
    from test_session_aggregation import registered, deliver, receipt, close_session, finalized, snapshot_page, detection_settings

    system = inline_system
    detection_settings(system, enabled=False)
    st, sensor = system.db, system.sensors['sensor'][0]
    tenant, cfg = sensor['tenant_id'], config(st)
    registration = registered(system)
    value = event(registration, 'response', text='Retained investigation evidence')
    st.ingest_batch(sensor, [value])
    original = st.one('SELECT id,agent_id,session_id,time,kind,product,body FROM events WHERE id=$1', value['id'])
    st.execute('DELETE FROM events WHERE id=$1', value['id'])
    day = now().date() - timedelta(days=30)
    st.execute('SELECT ensure_telemetry_partitions($1,$2)', tenant, day)
    st.execute('''INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body,received_at,storage_day)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)''', original['id'], tenant, sensor['id'],
        original['agent_id'], original['session_id'], original['time'], original['kind'], original['product'],
        Jsonb(original['body']), now() - timedelta(days=30), day)
    st.set_detect_cursor(tenant, {'time': now(), 'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff'})
    policy(st, tenant, cfg)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1
    deliver(system, registration, [receipt('observation', 1, event_id=value['id'])])
    close_session(system, registration, 1)
    state = finalized(system, registration)
    assert state['snapshot_id']
    before = snapshot_page(system, state['snapshot_id'])
    st.execute('INSERT INTO session_input_dirty(registration_id) VALUES($1)', registration['id'])
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 1
    finalized(system, registration)
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 0
    assert snapshot_page(system, state['snapshot_id']) == before


def test_automatic_scan_resumes_past_a_protected_backlog(database, tmp_path):
    st, sensor = database
    tenant, path = sensor['tenant_id'], tmp_path / 'metrics.json'
    cfg = config(st, tenant, str(path))
    for age in range(60, 43, -1):
        seed(st, sensor, age, pending=True)
    eligible, _ = seed(st, sensor, 43)
    sample(path, 850)
    policy(st, tenant, cfg, 'automatic')
    retention.tick(st, cfg)
    assert st.scalar('SELECT count(*) FROM events') == 18
    retention.tick(st, config(st, tenant, str(path)))
    assert st.scalar('SELECT count(*) FROM events') == 17
    assert not st.scalar('SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)', eligible)
