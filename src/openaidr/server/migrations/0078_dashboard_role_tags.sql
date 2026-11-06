ALTER TABLE tenant_users ADD COLUMN roles text[];
ALTER TABLE invites ADD COLUMN roles text[];

CREATE FUNCTION synchronize_tenant_roles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.roles IS NULL OR (TG_OP = 'UPDATE' AND NEW.roles IS NOT DISTINCT FROM OLD.roles AND NEW.role IS DISTINCT FROM OLD.role) THEN
        NEW.roles := CASE NEW.role
            WHEN 'owner' THEN ARRAY['it_admin','security_analyst','security_leadership']
            WHEN 'admin' THEN ARRAY['it_admin']
            WHEN 'analyst' THEN ARRAY['security_analyst']
            WHEN 'viewer' THEN ARRAY['security_leadership']
            ELSE ARRAY[]::text[] END;
    END IF;
    NEW.role := CASE
        WHEN NEW.roles @> ARRAY['it_admin','security_analyst','security_leadership'] THEN 'owner'
        WHEN 'it_admin' = ANY(NEW.roles) THEN 'admin'
        WHEN 'security_analyst' = ANY(NEW.roles) THEN 'analyst'
        ELSE 'viewer' END;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_user_roles BEFORE INSERT OR UPDATE OF role,roles ON tenant_users
FOR EACH ROW EXECUTE FUNCTION synchronize_tenant_roles();
CREATE TRIGGER invitation_roles BEFORE INSERT OR UPDATE OF role,roles ON invites
FOR EACH ROW EXECUTE FUNCTION synchronize_tenant_roles();

UPDATE tenant_users SET role=role;
UPDATE invites SET role=role;

ALTER TABLE tenant_users ALTER COLUMN roles SET NOT NULL, ALTER COLUMN role SET DEFAULT 'viewer';
ALTER TABLE invites ALTER COLUMN roles SET NOT NULL, ALTER COLUMN role SET DEFAULT 'viewer';

ALTER TABLE tenant_users ADD CONSTRAINT tenant_user_role_tags CHECK (
    cardinality(roles) BETWEEN 1 AND 3 AND roles = array_remove(ARRAY[
        CASE WHEN 'it_admin'=ANY(roles) THEN 'it_admin' END,
        CASE WHEN 'security_analyst'=ANY(roles) THEN 'security_analyst' END,
        CASE WHEN 'security_leadership'=ANY(roles) THEN 'security_leadership' END
    ],NULL)
);
ALTER TABLE invites ADD CONSTRAINT invitation_role_tags CHECK (
    cardinality(roles) BETWEEN 1 AND 3 AND roles = array_remove(ARRAY[
        CASE WHEN 'it_admin'=ANY(roles) THEN 'it_admin' END,
        CASE WHEN 'security_analyst'=ANY(roles) THEN 'security_analyst' END,
        CASE WHEN 'security_leadership'=ANY(roles) THEN 'security_leadership' END
    ],NULL)
);
