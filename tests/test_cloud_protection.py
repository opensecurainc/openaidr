"""Public cloud status rejects malformed or private service metadata."""

import json
import time

from openaidr.core.cloud_protection import FIELDS, project

def test_cloud_protection_projection_rejects_malformed_or_stale_availability():
    at = time.time()
    legacy = dict(state='active', checked_at=at, guardrail_available=True, guardrail_configured=True,
        allowance_nanos=2_000_000_000, spent_nanos=0, reserved_nanos=0, remaining_nanos=2_000_000_000,
        resets_at='2026-11-01T00:00:00+00:00')
    safe = project(legacy, at=at)
    assert set(safe) == FIELDS and safe['state'] == 'active'
    assert safe['credit_status'] is None and safe['credits_per_usd'] == '100'
    assert project(safe, at=at) == safe  # Backend, sensor, and bridge can each project it.
    assert project(None) is None
    for state in ('connecting', 'unavailable', 'exhausted'):
        initial = project(dict(state=state, checked_at=None), at=at)
        assert initial['state'] == state and initial['guardrail_available'] is False
        assert initial['credit_status'] is None
    for invalid in (
        False, [], {'state':'active', 'checked_at':at},
        {**legacy, 'remaining_nanos':True}, {**legacy, 'remaining_nanos':-1},
        {**legacy, 'spent_nanos':10**16}, {**legacy, 'resets_at':None},
        {**legacy, 'resets_at':'0001-01-01T00:00:00+14:00'},
        {**legacy, 'checked_at':10**400}, {**legacy, 'resets_at':'2026-11-01'}, {**legacy, 'guardrail_available':'true'},
        {**legacy, 'guardrail_configured':False}, {**legacy, 'guardrail_available':False},
        {**legacy, 'checked_at':None}, {**legacy, 'checked_at':at-181},
        {**legacy, 'checked_at':at+31}, {**legacy, 'checked_at':float('nan')},
        {**legacy, 'model':'private-model', 'provider':'private-provider', 'usage':{'tokens':123}},
        {**safe, 'credit_status':'unavailable'}, {**safe, 'credit_status':'unconfigured'},
        {**safe, 'credit_status':'exhausted'}, {**safe, 'schema_version':True},
        {**safe, 'credits_per_usd':'1'}, {**safe, 'model':'private-model'},
    ):
        result = project(invalid, at=at)
        assert set(result) == FIELDS
        assert result['state'] == 'unavailable' and result['guardrail_available'] is False
        assert not any(key in json.dumps(result) for key in ('_nanos', 'model', 'provider', 'tokens'))
    for credit in ('disabled', 'active', None):
        assert project({**safe, 'credit_status':credit}, at=at)['state'] == 'active'
