"""Published Markdown must not link to documents this repository does not ship."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\]\(([^)\s#]+\.md)(?:#[^)]*)?\)")


def published_markdown():
    yield ROOT / "README.md"
    yield ROOT / "CONTRIBUTING.md"
    for folder in ("docs", "apps/desktop", "apps/dashboard", "packages"):
        for path in (ROOT / folder).rglob("*.md"):
            if "node_modules" not in path.parts:
                yield path


def test_relative_markdown_links_resolve_to_published_files():
    missing = []
    for path in published_markdown():
        for match in LINK.finditer(path.read_text(encoding="utf-8")):
            target = match.group(1)
            if "://" in target:
                continue
            if not (path.parent / target).resolve().exists():
                missing.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not missing, "unpublished link targets:\n" + "\n".join(sorted(missing))
