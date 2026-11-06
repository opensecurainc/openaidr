-- The built-in "Warn on credential file reads" rule used the glob
-- **/.{aws,ssh,kube}/*, but policy globs have no brace groups, so it never
-- matched. Each stored copy of the built-in rule (source "builtin" with that
-- exact glob) becomes one rule per directory (**/.aws/** and so on, nested
-- files included) with the same action, reason, kinds, source, and enabled
-- state, and the id "<original id>-<directory>", as Store.save_policy
-- produces. An id another rule already has, or one without an original id,
-- gets a random UUID instead, so every id still names one rule. Custom rules
-- are left alone.
--
-- Policies use the first matching rule, and the old rule never matched, so
-- copies set to warn or allow go last: they must not come before a rule that
-- did, such as a tenant's own deny or ask for the same files. Copies set to
-- deny or ask keep the original's place.
--
-- A copy the tenant changed to ask is stored as deny with its id in
-- ask_rule_ids, and the new rules take its place there. If that id is shared
-- by another rule the copy was served as a deny (ambiguous ids fail closed),
-- and the new rules stay denies.
--
-- Target rows are locked first and updated only at the version they were
-- read, so a concurrent save is never overwritten. The policy version is
-- bumped so sensors fetch the update. The server runs this again at every
-- start and whenever it reads a policy that holds a legacy rule; it changes
-- nothing when no legacy rule is stored.
WITH targets AS MATERIALIZED (
    SELECT tenant_id, version, rules, ask_rule_ids
    FROM policies
    WHERE rules @> '[{"source": "builtin", "match": {"path_glob": "**/.{aws,ssh,kube}/*"}}]'
    FOR UPDATE
), id_counts AS MATERIALIZED (
    SELECT t.tenant_id, r.rule->>'id' AS id, count(*) AS n
    FROM targets t
    CROSS JOIN LATERAL jsonb_array_elements(t.rules) AS r(rule)
    GROUP BY 1, 2
), expanded AS MATERIALIZED (
    SELECT t.tenant_id, t.version, e.rule, e.ord, d.dir, d.n,
           CASE WHEN d.dir IS NULL THEN e.rule->>'id'
                ELSE (e.rule->>'id') || '-' || d.dir END AS new_id,
           d.dir IS NOT NULL
               AND (e.rule->>'id') = ANY(t.ask_rule_ids)
               AND c.n = 1 AS was_ask,
           d.dir IS NOT NULL
               AND coalesce(e.rule->>'action', '') NOT IN ('deny', 'ask') AS fallback
    FROM targets t
    CROSS JOIN LATERAL jsonb_array_elements(t.rules) WITH ORDINALITY AS e(rule, ord)
    LEFT JOIN id_counts c ON c.tenant_id = t.tenant_id AND c.id = e.rule->>'id'
    CROSS JOIN LATERAL unnest(
        CASE WHEN e.rule->>'source' = 'builtin'
              AND e.rule->'match'->>'path_glob' = '**/.{aws,ssh,kube}/*'
             THEN ARRAY['aws', 'ssh', 'kube'] ELSE ARRAY[NULL] END
    ) WITH ORDINALITY AS d(dir, n)
), taken AS MATERIALIZED (
    SELECT tenant_id, new_id, count(*) AS n
    FROM expanded
    GROUP BY 1, 2
), named AS MATERIALIZED (
    SELECT e.*,
           CASE WHEN e.dir IS NOT NULL AND (e.new_id IS NULL OR k.n > 1)
                THEN gen_random_uuid()::text ELSE e.new_id END AS final_id
    FROM expanded e
    LEFT JOIN taken k ON k.tenant_id = e.tenant_id AND k.new_id = e.new_id
), split AS (
    SELECT tenant_id, version,
           jsonb_agg(
               CASE WHEN dir IS NULL THEN rule
                    ELSE jsonb_set(
                        jsonb_set(
                            jsonb_set(rule, '{id}', to_jsonb(final_id)),
                            '{match,path_glob}', to_jsonb('**/.' || dir || '/**')),
                        '{name}', to_jsonb(coalesce(rule->>'name', '') || ' (.' || dir || ')'))
               END
               ORDER BY fallback, ord, n
           ) AS rules,
           coalesce(array_agg(rule->>'id') FILTER (WHERE dir IS NOT NULL AND rule->>'id' IS NOT NULL), '{}') AS old_ids,
           coalesce(array_agg(final_id) FILTER (WHERE was_ask), '{}') AS new_asks
    FROM named
    GROUP BY tenant_id, version
)
UPDATE policies p
SET rules = split.rules,
    ask_rule_ids = ARRAY(
        SELECT id FROM unnest(p.ask_rule_ids) AS id WHERE id <> ALL(split.old_ids)
    ) || split.new_asks,
    version = p.version + 1,
    updated_at = now()
FROM split
WHERE p.tenant_id = split.tenant_id AND p.version = split.version;
