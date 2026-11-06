CREATE SEQUENCE api_cost_revision;
CREATE TABLE api_cost_outbox (
    usage_id uuid PRIMARY KEY REFERENCES model_usage(id) ON DELETE CASCADE,
    revision bigint NOT NULL DEFAULT nextval('api_cost_revision')
);
CREATE INDEX api_cost_outbox_revision_idx ON api_cost_outbox(revision);

CREATE FUNCTION queue_api_cost() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO api_cost_outbox(usage_id) VALUES(NEW.id)
    ON CONFLICT(usage_id) DO UPDATE SET revision=nextval('api_cost_revision');
    RETURN NEW;
END;
$$;
CREATE TRIGGER model_usage_api_cost AFTER INSERT OR UPDATE ON model_usage
    FOR EACH ROW EXECUTE FUNCTION queue_api_cost();
INSERT INTO api_cost_outbox(usage_id) SELECT id FROM model_usage;

CREATE TABLE platform_api_costs (
    tenant_id uuid NOT NULL REFERENCES cloud_deployments(id),
    usage_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    provider text NOT NULL CHECK(provider IN ('openai','typesafe')),
    purpose text NOT NULL CHECK(purpose IN ('detection','guardrail','assistant','verification')),
    started_at timestamptz NOT NULL,
    status text NOT NULL CHECK(status IN ('pending','completed','error')),
    input_tokens bigint CHECK(input_tokens>=0),
    output_tokens bigint CHECK(output_tokens>=0),
    cost_usd numeric(24,12) CHECK(cost_usd>=0 AND cost_usd<'Infinity'::numeric),
    PRIMARY KEY(tenant_id,usage_id)
);
CREATE INDEX platform_api_costs_time_idx ON platform_api_costs(started_at,tenant_id);
CREATE TABLE platform_api_cost_reports (
    tenant_id uuid PRIMARY KEY REFERENCES cloud_deployments(id),
    generated_at timestamptz NOT NULL,
    has_more boolean NOT NULL
);
