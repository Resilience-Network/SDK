"""Check Markdown local file links and the documented protocol source pin.

External links and Markdown fragment anchors are not validated by this checker.
It provides repository scaffold validation, not protocol or semantic verification.
"""

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", "node_modules", "dist", "coverage", "test-results", "playwright-report"}
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
errors = []
checked = 0
for page in sorted(ROOT.rglob("*.md")):
    if any(part in IGNORED for part in page.relative_to(ROOT).parts):
        continue
    content = re.sub(r"```.*?```", "", page.read_text(), flags=re.S)
    for match in LINK.finditer(content):
        target = match.group(1).strip().split(" ", 1)[0].strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        resolved = (page.parent / unquote(parsed.path)).resolve()
        if not resolved.is_relative_to(ROOT) or not resolved.exists():
            errors.append(f"{page.relative_to(ROOT)}: invalid local target {target}")
        checked += 1

pin = json.loads((ROOT / "protocol-source.json").read_text())
revision = pin["revision"]
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    errors.append("protocol-source.json: expected immutable 40-character revision")
if not re.fullmatch(r"[0-9a-f]{64}", pin.get("vectorSha256", "")):
    errors.append("protocol-source.json: expected SHA-256 provenance for the source vector")
if revision not in (ROOT / "docs/reference/protocol-sources.md").read_text():
    errors.append("protocol source documentation does not contain the recorded revision")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Documentation OK: {checked} local file links and protocol source pin.")
