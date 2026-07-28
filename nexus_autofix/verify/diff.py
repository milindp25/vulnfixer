from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class DiffClass(str, Enum):
    MANIFEST_ONLY = "MANIFEST_ONLY"
    SOURCE_TOUCHED = "SOURCE_TOUCHED"
    SUSPICIOUS = "SUSPICIOUS"


@dataclass(frozen=True)
class DiffResult:
    classification: DiffClass
    changed_files: list[str]
    suspicious_reasons: list[str] = field(default_factory=list)


MANIFEST_FILENAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "build.gradle", "build.gradle.kts", "pom.xml", "libs.versions.toml",
}

TEST_SKIP_PATTERNS = [
    ("@Disabled", re.compile(r"@Disabled\b")),
    ("@Ignore", re.compile(r"@Ignore\b")),
    # Match enabled=false anywhere inside the annotation args, not just as the
    # sole/first arg -- @Test(groups="flaky", enabled = false) must still hit.
    ("@Test(enabled=false)", re.compile(r"@Test\([^)]*\benabled\s*=\s*false\b[^)]*\)")),
    ("it.skip(", re.compile(r"\bit\.skip\(")),
    ("xit(", re.compile(r"\bxit\(")),
    ("describe.skip(", re.compile(r"describe\.skip\(")),
    # Bare substring match is intentional: this also catches pytest.mark.skipif(...)
    # and pytest.mark.skip(reason="...") -- a few extra false positives on skipif
    # are fine, missing a real skip is not.
    ("pytest.mark.skip", re.compile(r"pytest\.mark\.skip")),
    ("t.Skip(", re.compile(r"\bt\.Skip\(")),
]

SUSPICIOUS_TEXT_PATTERNS = [
    ("resolutionStrategy.force added", re.compile(r"resolutionStrategy\.force")),
    ("--legacy-peer-deps present", re.compile(r"legacy-peer-deps")),
    ("open/dynamic version range", re.compile(r'[\d]+\.\+|latest\.release|\[\d[^,]*,\s*\d[^)]*\)')),
]

TEST_PATH_HINT = re.compile(r"(^|/)(test|tests|__tests__|spec)(/|$)", re.IGNORECASE)
TEST_FILENAME_PATTERN = re.compile(
    r"(Test\.java$|Tests\.java$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|^test_.*\.py$|_test\.py$)"
)

WAIVER_HINT = re.compile(r"(waiver|suppress)", re.IGNORECASE)
EXCLUDE_ADDED_PATTERN = re.compile(r"^\+.*\bexclude\b", re.MULTILINE)


def _run_git(args: list[str], repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(repo_root), capture_output=True, encoding="utf-8",
        errors="replace", check=True,
    )
    return proc.stdout


def _looks_like_test_file(path: str) -> bool:
    return bool(TEST_PATH_HINT.search(path) or TEST_FILENAME_PATTERN.search(Path(path).name))


def _is_emptied(full_path: Path) -> bool:
    # A file "emptied" to only whitespace is functionally the same as a
    # zero-byte delete for a test file -- checking st_size == 0 alone would
    # miss it, and the whole point of this module is not missing things.
    if not full_path.exists():
        return False
    return full_path.read_text(encoding="utf-8", errors="replace").strip() == ""


def _deleted_or_emptied_test_files(repo_root: Path, base_ref: str) -> list[str]:
    status_output = _run_git(["diff", "--name-status", base_ref], repo_root)
    flagged: list[str] = []
    for line in status_output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status, path = parts[0], parts[-1]

        if status.startswith("R"):
            # A rename that walks a test file out of test-shaped territory
            # (FooTest.java -> Foo.java.bak) removes it from test discovery
            # just as effectively as a delete would, without showing up as
            # a "D" status.
            old_path = parts[1] if len(parts) == 3 else None
            if old_path and _looks_like_test_file(old_path) and not _looks_like_test_file(path):
                flagged.append(f"{old_path} deleted (renamed to non-test path {path})")
            continue

        if not _looks_like_test_file(path):
            continue

        if status.startswith("D"):
            flagged.append(path)
        elif status.startswith("M") and _is_emptied(repo_root / path):
            flagged.append(f"{path} deleted (emptied to whitespace-only content)")
    return flagged


def _is_manifest_or_lockfile(path: str) -> bool:
    name = Path(path).name
    return name in MANIFEST_FILENAMES or name.endswith(".lock")


def _untracked_files(repo_root: Path) -> list[str]:
    output = _run_git(["ls-files", "--others", "--exclude-standard"], repo_root)
    return [line for line in output.splitlines() if line]


def _synthesize_untracked_patch(repo_root: Path, untracked_paths: list[str]) -> str:
    # `git diff` only ever looks at tracked content, so a brand-new file the
    # agent adds but never `git add`s is otherwise invisible to this whole
    # module -- a much bigger false-negative hole than any single regex.
    # Render each untracked file as an all-additions patch chunk so both the
    # file-list and the text-pattern checks below see it exactly as they
    # would see a real `git add`ed new file.
    chunks = []
    for rel_path in untracked_paths:
        full_path = repo_root / rel_path
        if not full_path.is_file():
            continue
        text = full_path.read_text(encoding="utf-8", errors="replace")
        plus_lines = "\n".join(f"+{line}" for line in text.splitlines())
        chunks.append(
            f"diff --git a/{rel_path} b/{rel_path}\nnew file mode 100644\n"
            f"--- /dev/null\n+++ b/{rel_path}\n{plus_lines}\n"
        )
    return "\n".join(chunks)


def classify_diff(repo_root: Path, base_ref: str = "HEAD") -> DiffResult:
    tracked_changed = [
        line for line in _run_git(["diff", "--name-only", base_ref], repo_root).splitlines() if line
    ]
    untracked = _untracked_files(repo_root)
    changed_files = tracked_changed + [f for f in untracked if f not in tracked_changed]

    patch = _run_git(["diff", base_ref], repo_root)
    patch += "\n" + _synthesize_untracked_patch(repo_root, untracked)

    reasons: list[str] = []

    if ".trident/build.yaml" in changed_files:
        reasons.append(".trident/build.yaml modified — the agent must never change the declared toolchain")

    deleted_or_emptied = _deleted_or_emptied_test_files(repo_root, base_ref)
    if deleted_or_emptied:
        reasons.append(f"test file(s) deleted or emptied: {', '.join(deleted_or_emptied)}")

    for label, pattern in TEST_SKIP_PATTERNS:
        if pattern.search(patch):
            reasons.append(f"test-disabling marker added: {label}")

    for label, pattern in SUSPICIOUS_TEXT_PATTERNS:
        if pattern.search(patch):
            reasons.append(label)

    if any(WAIVER_HINT.search(f) for f in changed_files):
        reasons.append("Nexus IQ policy waiver/suppression file created or modified")

    if any(f == ".gitignore" or f.startswith(".github/workflows/") for f in changed_files):
        reasons.append(".gitignore or CI config modified")

    if EXCLUDE_ADDED_PATTERN.search(patch):
        reasons.append("dependency exclude added (heuristic — review before trusting this alone)")

    if reasons:
        return DiffResult(classification=DiffClass.SUSPICIOUS, changed_files=changed_files, suspicious_reasons=reasons)

    if changed_files and all(_is_manifest_or_lockfile(f) for f in changed_files):
        return DiffResult(classification=DiffClass.MANIFEST_ONLY, changed_files=changed_files)

    return DiffResult(classification=DiffClass.SOURCE_TOUCHED, changed_files=changed_files)
