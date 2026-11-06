-- Run with application writers stopped and room for a second copy of these
-- tables and indexes. See docs/telemetry-retention.md for upgrade and rollback.
SET LOCAL lock_timeout = '2s';
LOCK TABLE telemetry_exports, events, agent_cost_records IN ACCESS EXCLUSIVE MODE;

-- Small identity tables enforce uniqueness across all tenants and days. A
-- composite foreign key binds each identity to exactly one physical partition.
CREATE TABLE telemetry_export_keys (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    storage_day date NOT NULL,
    sensor_id uuid NOT NULL REFERENCES sensors(id),
    signal text NOT NULL,
    batch_id uuid NOT NULL,
    payload_sha256 text NOT NULL,
    UNIQUE (tenant_id, storage_day, id),
    UNIQUE (tenant_id, sensor_id, signal, batch_id)
);
CREATE TABLE event_keys (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    storage_day date NOT NULL,
    UNIQUE (tenant_id, storage_day, id)
);
CREATE TABLE telemetry_partition_days (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    storage_day date NOT NULL,
    PRIMARY KEY (tenant_id, storage_day)
);

INSERT INTO telemetry_export_keys
SELECT id, tenant_id, (received_at AT TIME ZONE 'UTC')::date,
       sensor_id, signal, batch_id, payload_sha256 FROM telemetry_exports;
INSERT INTO event_keys
SELECT id, tenant_id, (received_at AT TIME ZONE 'UTC')::date FROM events;

-- Save definitions before renaming either table, including security and
-- evidence triggers. Recreate triggers only after copying historical rows.
CREATE TEMP TABLE telemetry_partition_migration ON COMMIT DROP AS
SELECT c.relname AS name,
       ARRAY(SELECT pg_get_indexdef(i.indexrelid) FROM pg_index i
             WHERE i.indrelid=c.oid AND NOT i.indisunique) AS indexes,
       ARRAY(SELECT format('ALTER TABLE %I ADD CONSTRAINT %I %s', c.relname,
                    conname, replace(pg_get_constraintdef(oid),
                    'REFERENCES telemetry_exports(id)', 'REFERENCES telemetry_export_keys(id)'))
             FROM pg_constraint WHERE conrelid=c.oid AND contype='f') AS foreign_keys,
       ARRAY(SELECT pg_get_triggerdef(oid) FROM pg_trigger
             WHERE tgrelid=c.oid AND NOT tgisinternal) AS triggers,
       (SELECT string_agg(quote_ident(attname), ',' ORDER BY attnum)
        FROM pg_attribute WHERE attrelid=c.oid AND attnum>0
          AND NOT attisdropped AND attgenerated='') AS columns
FROM pg_class c WHERE c.oid IN ('events'::regclass, 'telemetry_exports'::regclass);

DO $$
DECLARE
    source record;
    idx record;
    definition text;
BEGIN
    FOR source IN SELECT * FROM telemetry_partition_migration LOOP
        FOR idx IN SELECT i.indexrelid, c.relname FROM pg_index i
                   JOIN pg_class c ON c.oid=i.indexrelid
                   WHERE i.indrelid=source.name::regclass LOOP
            EXECUTE format('ALTER INDEX %I RENAME TO %I', idx.relname,
                           'partition_old_' || idx.indexrelid::text);
        END LOOP;
        EXECUTE format('ALTER TABLE %I RENAME TO %I', source.name, source.name || '_unpartitioned');
        EXECUTE format('CREATE TABLE %I (LIKE %I INCLUDING ALL EXCLUDING INDEXES,
            storage_day date NOT NULL DEFAULT ((clock_timestamp() AT TIME ZONE ''UTC'')::date))
            PARTITION BY LIST (tenant_id)', source.name, source.name || '_unpartitioned');
        EXECUTE format('ALTER TABLE %I ADD PRIMARY KEY (id, tenant_id, storage_day)', source.name);
        FOREACH definition IN ARRAY source.indexes LOOP EXECUTE definition; END LOOP;
        FOREACH definition IN ARRAY source.foreign_keys LOOP EXECUTE definition; END LOOP;
    END LOOP;
END;
$$;

ALTER TABLE telemetry_exports ADD FOREIGN KEY (tenant_id, storage_day, id)
    REFERENCES telemetry_export_keys(tenant_id, storage_day, id) ON DELETE CASCADE;
ALTER TABLE events ADD FOREIGN KEY (tenant_id, storage_day, id)
    REFERENCES event_keys(tenant_id, storage_day, id) ON DELETE CASCADE;
ALTER TABLE agent_cost_records DROP CONSTRAINT agent_cost_records_export_id_fkey;
ALTER TABLE agent_cost_records ADD CONSTRAINT agent_cost_records_export_id_fkey
    FOREIGN KEY (export_id) REFERENCES telemetry_export_keys(id) ON DELETE SET NULL;

-- Provision the requested UTC ingestion day and tomorrow before inserting.
-- Fast existing-day checks avoid DDL or a global lock on normal ingestion.
CREATE FUNCTION ensure_telemetry_partitions(tenant uuid, day date DEFAULT (clock_timestamp() AT TIME ZONE 'UTC')::date)
RETURNS void LANGUAGE plpgsql SET lock_timeout='1s' AS $$
DECLARE
    root text;
    tenant_table text;
    day_table text;
    bucket date;
BEGIN
    IF (SELECT count(*)=2 FROM telemetry_partition_days
        WHERE tenant_id=tenant AND storage_day IN (day, day+1)) THEN
        RETURN;
    END IF;
    IF NOT pg_try_advisory_xact_lock(684021562) THEN
        RAISE EXCEPTION 'telemetry partition provisioning busy' USING ERRCODE='55P03';
    END IF;
    FOREACH root IN ARRAY ARRAY['events', 'telemetry_exports'] LOOP
        tenant_table = root || '_' || replace(tenant::text, '-', '');
        IF to_regclass(tenant_table) IS NULL THEN
            EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES IN (%L)
                            PARTITION BY RANGE (storage_day)', tenant_table, root, tenant);
        END IF;
        FOREACH bucket IN ARRAY ARRAY[day, day+1] LOOP
            day_table = tenant_table || '_' || to_char(bucket, 'YYYYMMDD');
            IF to_regclass(day_table) IS NULL THEN
                EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                               day_table, tenant_table, bucket, bucket+1);
            END IF;
        END LOOP;
    END LOOP;
    INSERT INTO telemetry_partition_days VALUES (tenant, day), (tenant, day+1)
        ON CONFLICT DO NOTHING;
END;
$$;

DO $$
DECLARE
    bucket record;
    source record;
    definition text;
BEGIN
    FOR bucket IN SELECT tenant_id, storage_day FROM event_keys
                  UNION SELECT tenant_id, storage_day FROM telemetry_export_keys
                  UNION SELECT id, (clock_timestamp() AT TIME ZONE 'UTC')::date FROM tenants LOOP
        PERFORM ensure_telemetry_partitions(bucket.tenant_id, bucket.storage_day);
    END LOOP;
    FOR source IN SELECT * FROM telemetry_partition_migration LOOP
        EXECUTE format('INSERT INTO %I (%s, storage_day)
                        SELECT %s, (received_at AT TIME ZONE ''UTC'')::date FROM %I',
                       source.name, source.columns, source.columns, source.name || '_unpartitioned');
        FOREACH definition IN ARRAY source.triggers LOOP EXECUTE definition; END LOOP;
    END LOOP;
END;
$$;

DROP TABLE events_unpartitioned;
DROP TABLE telemetry_exports_unpartitioned;
ANALYZE events;
ANALYZE telemetry_exports;

CREATE FUNCTION register_telemetry_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_ARGV[0]='events' THEN
        INSERT INTO event_keys VALUES (NEW.id, NEW.tenant_id, NEW.storage_day)
            ON CONFLICT (id) DO NOTHING;
    ELSE
        INSERT INTO telemetry_export_keys
            VALUES (NEW.id, NEW.tenant_id, NEW.storage_day, NEW.sensor_id,
                    NEW.signal, NEW.batch_id, NEW.payload_sha256);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER events_register_identity BEFORE INSERT ON events
    FOR EACH ROW EXECUTE FUNCTION register_telemetry_identity('events');
CREATE TRIGGER telemetry_exports_register_identity BEFORE INSERT ON telemetry_exports
    FOR EACH ROW EXECUTE FUNCTION register_telemetry_identity('telemetry_exports');

CREATE FUNCTION protect_telemetry_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.tenant_id, NEW.storage_day) IS DISTINCT FROM (OLD.id, OLD.tenant_id, OLD.storage_day) THEN
        RAISE EXCEPTION 'telemetry storage identity is immutable' USING ERRCODE='23514';
    END IF;
    IF TG_ARGV[0]='telemetry_exports' THEN
        IF (NEW.sensor_id, NEW.signal, NEW.batch_id, NEW.payload_sha256)
            IS DISTINCT FROM (OLD.sensor_id, OLD.signal, OLD.batch_id, OLD.payload_sha256) THEN
            RAISE EXCEPTION 'telemetry export identity is immutable' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER events_protect_identity BEFORE UPDATE ON events
    FOR EACH ROW EXECUTE FUNCTION protect_telemetry_identity('events');
CREATE TRIGGER telemetry_exports_protect_identity BEFORE UPDATE ON telemetry_exports
    FOR EACH ROW EXECUTE FUNCTION protect_telemetry_identity('telemetry_exports');

-- Ordinary row deletion keeps the existing export-link SET NULL behavior.
-- Partition removal must retire identities explicitly; DROP does not run this.
CREATE FUNCTION remove_telemetry_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_ARGV[0]='events' THEN
        DELETE FROM event_keys WHERE id=OLD.id;
    ELSE
        DELETE FROM telemetry_export_keys WHERE id=OLD.id;
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER events_remove_identity AFTER DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION remove_telemetry_identity('events');
CREATE TRIGGER telemetry_exports_remove_identity AFTER DELETE ON telemetry_exports
    FOR EACH ROW EXECUTE FUNCTION remove_telemetry_identity('telemetry_exports');

CREATE FUNCTION provision_tenant_telemetry() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM ensure_telemetry_partitions(NEW.id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenants_provision_telemetry AFTER INSERT ON tenants
    FOR EACH ROW EXECUTE FUNCTION provision_tenant_telemetry();

-- Row triggers on a partition see the leaf's name, not the logical table.
CREATE OR REPLACE FUNCTION mark_session_input_dirty() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE registration uuid;
BEGIN
    IF TG_TABLE_NAME='session_delivery_receipts' THEN
        IF NEW.kind='close' AND EXISTS (
            SELECT 1 FROM session_delivery_receipts d WHERE d.registration_id=NEW.registration_id
              AND d.kind='close' AND d.id<>NEW.id AND d.payload-'record_id'=NEW.payload-'record_id'
        ) THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_TABLE_NAME='events' OR TG_ARGV[0]='events' THEN
        SELECT registration_id INTO registration FROM agent_sessions WHERE id=NEW.session_id;
    ELSE
        registration := NEW.registration_id;
    END IF;
    IF registration IS NOT NULL AND EXISTS (
        SELECT 1 FROM session_registrations r WHERE r.id=registration AND r.assessment_mode='inline'
    ) THEN
        INSERT INTO session_input_dirty(registration_id) VALUES(registration);
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER session_observation_dirty ON events;
CREATE TRIGGER session_observation_dirty AFTER INSERT ON events
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty('events');
