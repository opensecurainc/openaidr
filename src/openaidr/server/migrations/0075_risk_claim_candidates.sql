-- Keep completed assessments and hook-owned work out of background claim scans.
-- Kind and both time bounds remain index conditions in generic prepared plans.
CREATE INDEX events_risk_candidates_idx ON events (kind, received_at, risk_next_attempt_at)
    WHERE NOT risk_body_omitted AND risk_retry_attempts<3
      AND (risk IS NULL OR risk->>'status' IN ('pending','error'))
      AND body->'source'->>'hook_request_id' IS NULL
      AND NOT COALESCE(risk ? 'hook_check_id',false);
