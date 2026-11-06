ALTER TABLE cloud_deployments
    ADD COLUMN machine_type text NOT NULL DEFAULT 'e2-medium'
        CHECK (machine_type IN ('e2-medium', 'e2-standard-2', 'e2-standard-4')),
    ADD COLUMN data_disk_size_gb integer NOT NULL DEFAULT 200
        CHECK (data_disk_size_gb BETWEEN 10 AND
            CASE WHEN machine_type = 'e2-medium' THEN 3052 ELSE 65536 END);
