"""PostgreSQL projection definitions shared by store queries."""

eventColumns = "id, tenant_id, sensor_id, agent_id, session_id, time, received_at, kind, product, command_text, file_path, network_host, tool_name, export_id, export_record, body, risk"
# Bound scoring input in PostgreSQL before JSON decoding in the API process.
riskEventColumns = """id, tenant_id, sensor_id, session_id, time, received_at, kind,
    agent_id, product,
    CASE WHEN NOT risk_body_omitted THEN body
         ELSE '{"truncated":true}'::jsonb END AS body,
    risk_body_omitted"""
agentColumns = "a.id, a.tenant_id, a.sensor_id, a.product, a.version, a.hostname, a.os, a.arch, a.username, a.models,\n\ta.first_seen, a.last_seen, a.sessions_total, a.events_total,\n\t(SELECT count(*) FROM findings f WHERE f.agent_id = a.id AND f.status IN ('open', 'triaged')) AS findings_open"
sessionColumns = "s.id, s.tenant_id, s.external_id, s.agent_id, s.sensor_id, s.product, s.cwd, s.git_branch, s.started_at, s.last_event_at, s.ended_at,\n\ts.events_total, s.tool_calls, s.commands,\n\t(SELECT count(*) FROM findings f WHERE f.session_id = s.id AND f.status IN ('open', 'triaged')) AS findings_open"
enrollmentColumns = (
    "id, tenant_id, label, created_at, expires_at, uses, max_uses, revoked_at"
)
sensorIdentityColumns = 'id,tenant_id,hostname,os,arch,username,username AS "user",host_kind,disabled'
# An older server can update the heartbeat without updating the capability.
# Only a report from that same heartbeat can describe the current installation.
sensorPolicyDelivery = """CASE WHEN {activity}.policy_delivery='backend'
    AND {activity}.policy_delivery_reported_at={activity}.last_heartbeat_at
    AND {activity}.last_heartbeat_at>=now()-interval '90 seconds'
    THEN 'backend' END AS policy_delivery"""
sensorColumns = "s.id, s.tenant_id, s.label, s.hostname, s.os, s.arch, s.username, s.host_kind, s.serial_number, s.hardware_uuid, s.machine_id, s.device_id_source, a.version, s.disabled, s.enrolled_at,\n\ta.last_heartbeat_at, a.collectors, a.hook_installed, a.queue_depth, a.policy_version, a.agents_total, a.events_total, a.telemetry_queue_depth, a.cpu_percent, a.memory_rss_bytes"
sensorColumns += ", " + sensorPolicyDelivery.format(activity="a")
sensorColumns += ", a.health_report, a.health_reported_at"
sensorColumns += ", a.latest_signed_in_user, a.latest_signed_in_at"
sensorFrom = "sensors s JOIN sensor_activity a ON a.sensor_id=s.id"
tenantColumns = "t.id, t.name, t.slug, t.status, t.plan, t.created_at,\n\tCOALESCE((SELECT u.email FROM tenant_users u WHERE u.tenant_id = t.id AND u.role IN ('owner','admin') ORDER BY u.created_at LIMIT 1),\n\t         (SELECT i.email FROM invites i WHERE i.tenant_id = t.id AND i.role IN ('owner','admin') ORDER BY i.created_at LIMIT 1), '') AS owner_email,\n\t(SELECT count(*) FROM tenant_users u WHERE u.tenant_id = t.id) AS users_total,\n\t(SELECT count(*) FROM sensors s WHERE s.tenant_id = t.id AND s.deleted_at IS NULL) AS sensors_total,\n\t(SELECT count(*) FROM sensors s JOIN sensor_activity sa ON sa.sensor_id=s.id WHERE s.tenant_id = t.id AND s.deleted_at IS NULL AND NOT s.disabled AND sa.last_heartbeat_at > now() - interval '90 seconds') AS sensors_online,\n\t(SELECT count(*) FROM events e WHERE e.tenant_id = t.id AND e.received_at > now() - interval '24 hours') AS events_24h,\n\t(SELECT count(*) FROM findings f WHERE f.tenant_id = t.id AND f.status IN ('open', 'triaged')) AS findings_open"
findingColumns = "f.id, f.tenant_id, f.rule_id, f.category, f.severity, f.status, f.title, f.summary, f.agent_id, f.session_id, f.sensor_id,\n\tf.hostname, f.os, f.arch, f.username, f.account, f.product, f.event_ids, f.primary_event_id, f.first_event_at, f.assignee_id, u.name AS assignee_name,\n\tf.resolution, f.created_at, f.updated_at, f.investigation_job_id, f.investigation_attempt_id, f.snapshot_id, f.finding_index, f.investigation_evidence"
findingFrom = " FROM findings f LEFT JOIN tenant_users u ON u.id = f.assignee_id "
noteColumns = "n.id, n.finding_id, n.author_id, COALESCE(u.name, '') AS author_name, n.body, n.created_at"
actionColumns = "a.id, a.tenant_id, a.finding_id, a.type, a.params, a.status, a.created_by, COALESCE(u.name, '') AS created_by_name, a.created_at, a.applied_at, a.message"
actionFrom = " FROM response_actions a LEFT JOIN tenant_users u ON u.id = a.created_by "
userColumns = (
    "id, tenant_id, email, name, role, roles, status, created_at, last_login_at, password_hash"
)
inviteColumns = "id, tenant_id, email, role, roles, expires_at, accepted_at, created_at"
