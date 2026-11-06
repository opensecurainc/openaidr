-- Preserve old rows/job JSON and request hashes; new requests bind a destination.
ALTER TABLE cloud_deployments ADD COLUMN deployment_target jsonb;
ALTER TABLE cloud_deployments ALTER COLUMN project_id DROP NOT NULL;
ALTER TABLE cloud_deployments ALTER COLUMN zone DROP NOT NULL;
ALTER TABLE cloud_deployments ALTER COLUMN machine_type DROP NOT NULL;
ALTER TABLE cloud_deployments ADD CONSTRAINT deployment_destination_shape CHECK (
  (deployment_target IS NULL AND project_id IS NOT NULL AND zone IS NOT NULL AND machine_type IS NOT NULL)
  OR ((jsonb_typeof(deployment_target)='object' AND deployment_target->>'kind'='gcp'
       AND project_id IS NOT NULL AND zone IS NOT NULL AND machine_type IS NOT NULL) IS TRUE)
  OR ((jsonb_typeof(deployment_target)='object' AND deployment_target->>'kind'='onprem'
       AND project_id IS NULL AND zone IS NULL AND machine_type IS NULL) IS TRUE)
);
