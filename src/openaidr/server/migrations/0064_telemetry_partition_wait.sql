-- Serialize provisioning with a bounded wait instead of rejecting contenders.
CREATE OR REPLACE FUNCTION ensure_telemetry_partitions(tenant uuid, day date DEFAULT (clock_timestamp() AT TIME ZONE 'UTC')::date)
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
    PERFORM pg_advisory_xact_lock(684021562);
    -- The previous provisioner may have committed while this transaction waited.
    IF (SELECT count(*)=2 FROM telemetry_partition_days
        WHERE tenant_id=tenant AND storage_day IN (day, day+1)) THEN
        RETURN;
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
