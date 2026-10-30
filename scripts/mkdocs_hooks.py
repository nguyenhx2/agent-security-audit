"""MkDocs hook (mkdocs.yml `hooks:`): a relative link that leaves docs/ (../security-audit/SKILL.md,
../CONTRIBUTING.md) works on GitHub but not on the Pages site, so it is rewritten to the file's
GitHub URL at build time. The Markdown in the repository stays unchanged."""
from __future__ import annotations

import posixpath
import re

BLOB = "https://github.com/nguyenhx2/agent-security-audit/blob/main/"
LINK = re.compile(r"(\]\()([^)\s#]+)(#[^)\s]*)?(\))")


def on_page_markdown(markdown, page, config, files):  # noqa: ARG001 - MkDocs hook signature
    here = posixpath.dirname("docs/" + page.file.src_uri)

    def fix(m):
        url = m.group(2)
        if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I):
            return m.group(0)
        full = posixpath.normpath(posixpath.join(here, url))
        if full.startswith("docs/") or full.startswith(".."):
            return m.group(0)
        return f"{m.group(1)}{BLOB}{full}{m.group(3) or ''}{m.group(4)}"

    return LINK.sub(fix, markdown)
