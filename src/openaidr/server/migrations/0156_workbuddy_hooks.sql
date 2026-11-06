ALTER TABLE ordinary_hook_checks DROP CONSTRAINT ordinary_hook_checks_product_check;
ALTER TABLE ordinary_hook_checks ADD CONSTRAINT ordinary_hook_checks_product_check
    CHECK (product IN ('codex-cli', 'claude-code', 'github-copilot', 'cursor', 'antigravity', 'opencode', 'hermes-agent', 'cowork', 'claude-ai', 'unknown', 'workbuddy'));
