"""Guards for CONTRIBUTING.md's "Where things go" map (issue #71).

The map is the placement contract: which module a change belongs in, and
which files may talk to the ``mcp`` SDK at all. It has gone stale silently
twice already -- 4 of the package's modules missing when #71 was filed, 9 of
18 by the time it was fixed -- because nothing enforced it against the real
package. These two tests are that enforcement, not just a correction:

- ``test_module_map_matches_src_whoopmcp``: every ``src/whoopmcp/*.py`` has a
  map entry, and every entry names a file that actually exists.
- ``test_no_module_outside_mcp_surface_imports_mcp``: the map's one
  structural rule -- only ``server.py``, ``webhooks.py``, and ``mcpauth.py``
  import ``mcp`` -- holds against every module's real AST.

Both parse source text directly (``Path.read_text`` + ``ast.parse``), never
``sys.modules`` or a module's ``__dict__``. That is the mechanism
``test_mcpauth.py``'s own ``test_mcpauth_does_not_import_auth`` uses, and
#71 explicitly warns it against: inspecting an already-imported module's
namespace can pick up a transitive import from an unrelated code path, not
just that module's own ``import`` statements.
"""

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
    """Every module name (``foo.py``) listed in the "Where things go" block.

    Parses the fenced block right after the "## Where things go" heading. A
    line counts as an entry only if it starts at column 0 with a
    ``name.py`` token; a wrapped continuation line (e.g. ``mcpauth.py``'s
    second line) is indented and so is skipped.
    """
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
    """CONTRIBUTING.md's map and ``src/whoopmcp/*.py`` name exactly the same files.

    This is the completeness half of #71: at the time this test was
    written the map named 8 files against 18 real ones. Checked in both
    directions, so a future rename shows up either way -- as a real file
    with no entry, or as an entry naming a file that no longer exists.
    """
    mapped = set(_map_entries())
    actual = {path.name for path in SRC_DIR.glob("*.py")}

    unmapped = sorted(actual - mapped)
    assert not unmapped, f"missing from CONTRIBUTING.md's 'Where things go' map: {unmapped}"

    stale = sorted(mapped - actual)
    assert not stale, f"CONTRIBUTING.md's map names files that no longer exist: {stale}"


def test_no_module_outside_mcp_surface_imports_mcp() -> None:
    """Only server.py, webhooks.py, and mcpauth.py import ``mcp``.

    #71's other half: CONTRIBUTING.md used to claim server.py was "the
    only" file that imports ``mcp``, which AST across all 18 modules
    disproves -- webhooks.py and mcpauth.py both do too. This enforces the
    corrected, three-file rule directly against source, so a future module
    reaching for ``mcp`` fails CI instead of quietly widening the surface
    the doc describes.
    """
    violations = [
        path.name
        for path in sorted(SRC_DIR.glob("*.py"))
        if path.name not in MCP_SURFACE_MODULES and _imports_mcp(path)
    ]
    assert not violations, (
        f"import mcp but are not in the declared surface {sorted(MCP_SURFACE_MODULES)}: "
        f"{violations}"
    )
