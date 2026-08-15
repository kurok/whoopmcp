"""Guards for CONTRIBUTING."""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src" / "whoopmcp"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"

#: The only modules CONTRIBUTING.md's map permits to import ``mcp``. A
#: literal here, not derived from the doc's own prose: this set is what the
#: doc's claim is checked *against*, so deriving it from the doc itself
#: would make a broken claim untestable by construction.
MCP_SURFACE_MODULES = frozenset({"server.py", "webhooks.py", "mcpauth.py"})


def _map_entries() -> list[str]:
    """Every module name (``foo."""
    text = CONTRIBUTING.read_text()
    block = re.search(r"## Where things go\n\n```\n(.*?)\n```", text, re.DOTALL)
    assert block is not None, "couldn't find the 'Where things go' fenced block in CONTRIBUTING.md"
    return re.findall(r"^(\S+\.py)[ \t]", block.group(1), re.MULTILINE)


def _imports_mcp(path: Path) -> bool:
    """Whether ``path``'s own source contains ``import mcp`` or
    ``from mcp[...] import ...``, anywhere in the module -- AST-based, so a
    comment or a string literal mentioning "mcp" can't produce a false
    positive, and a transitive import through some other module can't
    produce a false negative the way checking ``sys.modules`` would.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name == "mcp" or alias.name.startswith("mcp.") for alias in node.names
        ):
            return True
        if (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and (node.module == "mcp" or node.module.startswith("mcp."))
        ):
            return True
    return False


def test_module_map_matches_src_whoopmcp() -> None:
    """CONTRIBUTING."""
    mapped = set(_map_entries())
    actual = {path.name for path in SRC_DIR.glob("*.py")}

    unmapped = sorted(actual - mapped)
    assert not unmapped, f"missing from CONTRIBUTING.md's 'Where things go' map: {unmapped}"

    stale = sorted(mapped - actual)
    assert not stale, f"CONTRIBUTING.md's map names files that no longer exist: {stale}"


def test_no_module_outside_mcp_surface_imports_mcp() -> None:
    """Only server."""
    violations = [
        path.name
        for path in sorted(SRC_DIR.glob("*.py"))
        if path.name not in MCP_SURFACE_MODULES and _imports_mcp(path)
    ]
    assert not violations, (
        f"import mcp but are not in the declared surface {sorted(MCP_SURFACE_MODULES)}: "
        f"{violations}"
    )
