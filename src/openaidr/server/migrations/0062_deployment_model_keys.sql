ALTER TABLE cloud_deployments
    ADD COLUMN model_keys_from_secret_manager boolean NOT NULL DEFAULT false;
