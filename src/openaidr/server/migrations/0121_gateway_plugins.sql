ALTER TABLE gateway_instances DROP CONSTRAINT gateway_instances_kind_check;
ALTER TABLE gateway_instances ADD CONSTRAINT gateway_instances_kind_check
    CHECK (kind ~ '^[a-z][a-z0-9_-]{0,31}$');

ALTER TABLE gateway_nodes ADD COLUMN gateway_version text NOT NULL DEFAULT '';
UPDATE gateway_nodes SET gateway_version=kong_version;
