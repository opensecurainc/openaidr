CREATE INDEX audit_log_platform_idx ON audit_log (at DESC, id DESC)
    WHERE tenant_id IS NULL OR actor_type = 'admin';
