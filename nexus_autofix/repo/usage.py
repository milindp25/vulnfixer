"""Evidence about where a dependency is used, for components IQ cannot fix.

When IQ offers no version that clears a violation, upgrading is not an option and the
remaining ones are: bump whichever parent pulls it in, replace it, or drop it. Choosing
between those needs to know whether the thing is actually used, and this gathers what can
be known cheaply.

**This is evidence, not a verdict, and nothing here removes anything.** Every technique
below has false negatives that are dangerous in the same direction: a dependency loaded by
name at runtime, named in a config file this does not parse, or reached only on a path the
tests never take, all look unused and are not. Absence of evidence is reported as exactly
that, never as "safe to remove". The decision belongs to somebody who knows the service.

That asymmetry is also why this stays advisory. Everything else the tool changes is
directed by IQ — the target version is IQ's answer, not the agent's — and verified by a
real build. There is no equivalent authority for "this dependency is unnecessary", and a
passing test suite is not one: it proves the paths the tests take still work, which is a
much weaker claim than the change being safe.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

#: Where a dependency is declared per ecosystem. Searched to distinguish "the manifest
#: asks for this" from "something else drags it in", which decides whether removing it is
#: even a thing this repository can do.
MANIFEST_FILES: dict[str, tuple[str, ...]] = {
    "npm": ("package.json",),
    "yarn": ("package.json",),
    "pnpm": ("package.json",),
    "gradle": ("build.gradle", "build.gradle.kts", "settings.gradle", "gradle/libs.versions.toml"),
    "maven": ("pom.xml",),
}

#: Files that reference a dependency without importing it — a plugin named in a lint
#: config, a loader named in a bundler config. Missing these is the likeliest way to
#: conclude "unused" about something load-bearing.
CONFIG_GLOBS: tuple[str, ...] = (
    "*.json", "*.yml", "*.yaml", "*.toml", "*.xml", "*.config.js", "*.config.ts",
    ".*rc", ".*rc.js", ".*rc.json", "Dockerfile", "*.gradle", "*.gradle.kts",
)

_SKIP_DIRS = {
    ".git", "node_modules", "build", "target", "dist", "out", ".gradle", ".idea",
    "__pycache__", ".venv", "coverage",
}

_SOURCE_SUFFIXES = {
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "gradle": (".java", ".kt", ".kts", ".groovy", ".scala"),
}
_SOURCE_SUFFIXES["yarn"] = _SOURCE_SUFFIXES["npm"]
_SOURCE_SUFFIXES["pnpm"] = _SOURCE_SUFFIXES["npm"]
_SOURCE_SUFFIXES["maven"] = _SOURCE_SUFFIXES["gradle"]


@dataclass(frozen=True)
class Reference:
    path: str
    line_number: int
    line: str


@dataclass(frozen=True)
class UsageEvidence:
    component: str
    ecosystem: str
    declared_in_manifest: list[Reference] = field(default_factory=list)
    referenced_in_source: list[Reference] = field(default_factory=list)
    referenced_in_config: list[Reference] = field(default_factory=list)
    files_searched: int = 0

    @property
    def any_reference(self) -> bool:
        return bool(
            self.declared_in_manifest or self.referenced_in_source or self.referenced_in_config
        )

    @property
    def summary(self) -> str:
        """Deliberately phrased as what was found, never as a recommendation."""
        if self.declared_in_manifest and (self.referenced_in_source or self.referenced_in_config):
            return "declared in the manifest and referenced in the repository"
        if self.declared_in_manifest:
            return (
                "declared in the manifest, but no reference found in source or config. "
                "That is a hint and nothing more — it may be loaded by name at runtime, or "
                "named in a file this does not parse."
            )
        if self.any_reference:
            return (
                "referenced in the repository but NOT declared in the manifest — it is "
                "pulled in by something else, so it cannot be removed here directly"
            )
        return (
            "no reference found anywhere in the repository. This does NOT establish that "
            "it is unused: a transitive dependency is used by its parent, not by this code."
        )


def _search_terms(component: str, ecosystem: str) -> list[re.Pattern]:
    """Patterns that would match a real use of this component.

    Matching the bare name alone is far too loose — "core" or "common" appears in every
    file — so the name is anchored to the syntax that actually references a dependency.
    """
    name = component.strip()
    if not name:
        return []
    quoted = re.escape(name)
    patterns = [
        # In a manifest or config: a quoted key or value.
        rf'["\']{quoted}["\']',
    ]
    if ecosystem in ("npm", "yarn", "pnpm"):
        patterns += [
            rf'(?:require|import)\s*\(\s*["\']{quoted}(?:/[^"\']*)?["\']',
            rf'from\s+["\']{quoted}(?:/[^"\']*)?["\']',
        ]
    else:
        # Maven/Gradle: the artifactId as a package segment in an import, and the
        # group:artifact coordinate in a build file.
        artifact = name.split(":")[-1]
        patterns += [
            rf'^\s*import\s+[\w.]*{re.escape(artifact.replace("-", "."))}[\w.*]*',
            rf'{quoted}',
        ]
    return [re.compile(p, re.MULTILINE) for p in patterns]


def _scan_file(path: Path, patterns: list[re.Pattern], root: Path) -> list[Reference]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in patterns):
            hits.append(Reference(
                path=str(path.relative_to(root)), line_number=number, line=line.strip()[:200]
            ))
    return hits


def find_usage(component: str, checkout: Path, ecosystem: str) -> UsageEvidence:
    """Search a checkout for references to `component`."""
    patterns = _search_terms(component, ecosystem)
    if not patterns:
        return UsageEvidence(component=component, ecosystem=ecosystem)

    manifest_names = set(MANIFEST_FILES.get(ecosystem, ()))
    source_suffixes = set(_SOURCE_SUFFIXES.get(ecosystem, ()))
    declared: list[Reference] = []
    in_source: list[Reference] = []
    in_config: list[Reference] = []
    searched = 0

    for path in checkout.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(checkout).parts[:-1]):
            continue
        relative = str(path.relative_to(checkout)).replace("\\", "/")
        is_manifest = path.name in manifest_names or relative in manifest_names
        is_source = path.suffix in source_suffixes
        is_config = any(path.match(glob) for glob in CONFIG_GLOBS)
        if not (is_manifest or is_source or is_config):
            continue
        searched += 1
        hits = _scan_file(path, patterns, checkout)
        if not hits:
            continue
        if is_manifest:
            declared.extend(hits)
        elif is_source:
            in_source.extend(hits)
        else:
            in_config.extend(hits)

    log.info(
        "usage of %s: %d manifest, %d source, %d config reference(s) across %d file(s)",
        component, len(declared), len(in_source), len(in_config), searched,
    )
    return UsageEvidence(
        component=component, ecosystem=ecosystem, declared_in_manifest=declared,
        referenced_in_source=in_source, referenced_in_config=in_config, files_searched=searched,
    )
