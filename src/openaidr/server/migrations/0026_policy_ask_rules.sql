-- Ask rules are stored in rules as deny, so a server rolled back to a version
-- without ask serves a deny that older sensors enforce. This column, not a
-- rule field, records which stored denies are ask rules: rows written before
-- it may carry arbitrary rule fields, and none of them can turn a deny into an
-- ask.
ALTER TABLE policies ADD COLUMN ask_rule_ids text[] NOT NULL DEFAULT '{}';
