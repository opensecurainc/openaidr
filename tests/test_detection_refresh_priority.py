"""PostgreSQL queue ordering with the same one-item limit as the scheduler."""
from openaidr.server import ordinary_session_detection as ordinary
from openaidr.server.store import new_id
from test_store import db, tenant, sensor  # noqa: F401


def session(db, tenant_id, *, dirty=False, age=60, disabled=False):
    device, _, _ = sensor(db, tenant_id)
    agent, ident = new_id(), new_id()
    db.execute("INSERT INTO agents(id,tenant_id,sensor_id,product) VALUES($1,$2,$3,'codex-cli')",
               agent, tenant_id, device['id'])
    db.execute("""INSERT INTO agent_sessions(id,tenant_id,agent_id,sensor_id,external_id,product,started_at,last_event_at)
        VALUES($1,$2,$3,$4,$1::text,'codex-cli',now()-interval '1 hour',now()-interval '1 hour')""",
        ident, tenant_id, agent, device['id'])
    db.execute("""INSERT INTO ordinary_session_detection(session_id,tenant_id,input_version,settings_version,state,
        next_evaluation_at,updated_at) VALUES($1,$2,1,0,'{"evidence_summary":{"version":"1"}}',
        now()-interval '1 minute',now()-$3*interval '1 second')""", ident, tenant_id, age)
    if dirty:
        db.execute("INSERT INTO ordinary_session_input_dirty(tenant_id,session_id) VALUES($1,$2)", tenant_id, ident)
    if disabled:
        db.execute("UPDATE sensors SET disabled=true WHERE id=$1", device['id'])
    return ident


def test_changed_evidence_precedes_old_periodic_backlog(db, monkeypatch):
    owner = tenant(db)['id']
    older = [session(db, owner, age=3600 + i) for i in range(5)]
    changed = session(db, owner, dirty=True, age=10)
    selected = []
    monkeypatch.setattr(ordinary, 'finalize', lambda st, tenant_id, ident, **options: selected.append(ident))
    assert ordinary.finalize_pending(db, owner, limit=1, protocol_version=4) == 1
    assert selected == [changed]
    # Simulate the finalizer consuming the wakeup; routine work remains eligible.
    db.execute("DELETE FROM ordinary_session_input_dirty WHERE session_id=$1", changed)
    selected.clear()
    assert ordinary.finalize_pending(db, owner, limit=1, protocol_version=4) == 1
    assert selected == [older[-1]]


def test_priority_keeps_tenant_sensor_and_cooldown_filters(db, monkeypatch):
    owner, other = tenant(db)['id'], tenant(db)['id']
    routine = session(db, owner, age=100)
    session(db, other, dirty=True, age=200)
    session(db, owner, dirty=True, age=200, disabled=True)
    recent = session(db, owner, dirty=True, age=0)
    selected = []
    monkeypatch.setattr(ordinary, 'finalize', lambda st, tenant_id, ident, **options: selected.append(ident))
    assert ordinary.finalize_pending(db, owner, limit=1, protocol_version=4) == 1
    assert selected == [routine]
    assert db.scalar("SELECT EXISTS(SELECT 1 FROM ordinary_session_input_dirty WHERE session_id=$1)", recent)
