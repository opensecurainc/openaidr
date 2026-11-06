import pytest

from openaidr.server.database_maintenance import analyze_one
from test_store import db, tenant


@pytest.mark.parametrize('partitions', [False, True])
def test_statistics_refresh_is_bounded_and_skips_recent_analysis(db, partitions):
    if partitions:
        db.execute('SELECT ensure_telemetry_partitions($1)', tenant(db)['id'])
    for _ in range(4 if partitions else 2):
        assert analyze_one(db)
    rows = db.many("""SELECT name, greatest(last_analyze,last_autoanalyze) AS analyzed
        FROM unnest(ARRAY['events','telemetry_exports','ordinary_hook_checks','agent_cost_records']) name
        JOIN pg_stat_all_tables ON relid=to_regclass(name)""")
    assert not analyze_one(db), rows
    assert len(rows) == 4
    assert all(row['analyzed'] for row in rows
               if partitions or row['name'] not in ('events', 'telemetry_exports'))


def test_statistics_refresh_does_not_wait_for_another_worker(db):
    with db.transaction() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('dashboard-planner-statistics',0))")
        assert not analyze_one(db)
    assert analyze_one(db)


def test_locked_table_does_not_starve_other_statistics(db):
    with db.transaction() as conn:
        conn.execute('LOCK TABLE agent_cost_records IN ACCESS EXCLUSIVE MODE')
        assert analyze_one(db) == 'agent_cost_records'
        assert analyze_one(db, 'agent_cost_records') == 'ordinary_hook_checks'
