from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", "build", "target", "dist", ".git"}


@dataclass(frozen=True)
class DetectedEcosystem:
    ecosystem: str
    manifest: Path


class RepoHygieneError(ValueError):
    """Raised when detection finds an ambiguous or conflicting repo state that must be escalated."""


def _walk(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        yield path


def detect_js_manager(root: Path) -> DetectedEcosystem | None:
    found: dict[str, Path] = {}
    for path in _walk(root):
        if path.name == "package-lock.json":
            found["npm"] = path
        elif path.name == "pnpm-lock.yaml":
            found["pnpm"] = path
        elif path.name == "yarn.lock":
            if (path.parent / ".yarnrc.yml").exists():
                found["yarn-berry"] = path
            else:
                found["yarn"] = path

    if len(found) > 1:
        raise RepoHygieneError(
            f"multiple JS lockfiles present: {sorted(found)} — this is a repo hygiene "
            f"problem to escalate, not something to pick a winner for"
        )
    if not found:
        return None
    manager, lockfile_path = next(iter(found.items()))
    ecosystem = "yarn" if manager == "yarn-berry" else manager
    return DetectedEcosystem(ecosystem=ecosystem, manifest=lockfile_path.parent / "package.json")


def detect_java_build(root: Path) -> DetectedEcosystem | None:
    for path in _walk(root):
        if path.name == "pom.xml":
            return DetectedEcosystem(ecosystem="maven", manifest=path)
    for path in _walk(root):
        if path.name in {"build.gradle", "build.gradle.kts"}:
            return DetectedEcosystem(ecosystem="gradle", manifest=path)
    return None


def detect_ecosystems(root: Path) -> list[DetectedEcosystem]:
    results = []
    java = detect_java_build(root)
    if java:
        results.append(java)
    js = detect_js_manager(root)
    if js:
        results.append(js)
    return results
