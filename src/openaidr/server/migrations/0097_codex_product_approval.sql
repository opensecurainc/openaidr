ALTER TABLE ai_application_approvals
    ADD COLUMN approval_conflict boolean NOT NULL DEFAULT false,
    ADD COLUMN previous_decisions jsonb NOT NULL DEFAULT '[]'::jsonb;

-- Freeze previous decisions once. In particular, the old name fallback could
-- store a com.openai.codex installation under ChatGPT. Copy that decision when
-- installation evidence establishes the relationship, without linking future
-- ChatGPT decisions to Codex or removing the original approval history.
WITH installations AS (
    SELECT tenant_id,identifier,name,source FROM application_inventory
    UNION
    SELECT c.tenant_id,c.identifier,c.name,r.source
    FROM inventory_components c JOIN inventory_roots r
        ON r.id=c.root_id AND r.tenant_id=c.tenant_id AND r.sensor_id=c.sensor_id
    WHERE c.kind='application' AND r.source='osquery-apps'
), previous_products AS (
    SELECT tenant_id,product_id FROM ai_application_approvals
    WHERE product_id IN ('codex','codex-cli',
        'app-' || encode(sha256(convert_to('com.openai.codex','UTF8')),'hex'))
    UNION
    SELECT tenant_id,product_id FROM application_classifications c
    WHERE EXISTS (
        SELECT 1 FROM jsonb_array_elements(c.evidence) e
        WHERE COALESCE(e->>'ecosystem','')='' AND (lower(e->>'identifier')='com.openai.codex'
            OR (e->>'source'='windows-appx' AND lower(e->>'name')='openai.codex'
                AND split_part(lower(e->>'identifier'),'_',1)='openai.codex'))
    )
    UNION
    SELECT tenant_id,CASE
        WHEN lower(identifier)='com.openai.codex' AND lower(name) IN ('chatgpt','codex') THEN lower(name)
        WHEN lower(identifier)='com.openai.codex' THEN
            'app-' || encode(sha256(convert_to(lower(identifier),'UTF8')),'hex')
        ELSE 'app-' || encode(sha256(convert_to(source || ':' || lower(identifier),'UTF8')),'hex')
    END
    FROM installations
    WHERE lower(identifier)='com.openai.codex'
        OR (source='windows-appx' AND lower(name)='openai.codex'
            AND split_part(lower(identifier),'_',1)='openai.codex')
), decisions AS (
    SELECT a.tenant_id,bool_and(a.approved) AS approved,max(a.updated_at) AS updated_at,
        bool_and(a.approved)<>bool_or(a.approved) AS conflict,
        jsonb_agg(jsonb_build_object('product_id',a.product_id,'name',a.name,
            'approved',a.approved,'updated_at',a.updated_at) ORDER BY a.product_id) AS previous
    FROM ai_application_approvals a JOIN previous_products p
        ON p.tenant_id=a.tenant_id AND p.product_id=a.product_id
    GROUP BY a.tenant_id
)
INSERT INTO ai_application_approvals
    (tenant_id,product_id,name,approved,updated_at,approval_conflict,previous_decisions)
SELECT tenant_id,'codex','Codex',approved,updated_at,conflict,previous FROM decisions
ON CONFLICT(tenant_id,product_id) DO UPDATE SET
    name=EXCLUDED.name,approved=EXCLUDED.approved,updated_at=EXCLUDED.updated_at,
    approval_conflict=EXCLUDED.approval_conflict,previous_decisions=EXCLUDED.previous_decisions;
