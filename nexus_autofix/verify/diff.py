"""Classify a working-tree diff as MANIFEST_ONLY / SOURCE_TOUCHED / SUSPICIOUS.

SUSPICIOUS aborts the whole remediation run before anything is pushed, so the
bias throughout this module is deliberate: a false positive costs one human
glance, a false negative ships a silently-disabled test suite.

Known residual limitations (documented, not fixed here):

* A test *method body* being gutted while the class/file stays non-empty is not
  detected. Catching that would require real per-language AST parsing, which is
  well beyond the scope of this module.
* Text-pattern scanning is line/regex based, not a real unified-diff parser, so
  pathological patches (added lines whose content itself looks like a diff
  header) can confuse attribution. Detection still errs toward flagging.
"""

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

# Files that are too big to be worth pulling into memory for regex scanning.
# Anything above this is surfaced for manual review instead of silently skipped.
MAX_SCAN_BYTES = 4 * 1024 * 1024
# How much of a file to sniff for NUL bytes before deciding it is binary.
BINARY_SNIFF_BYTES = 8192

TEST_SKIP_PATTERNS = [
    ("@Disabled", re.compile(r"@Disabled\b")),
    ("@Ignore", re.compile(r"@Ignore\b")),
    # A single regex cannot balance parens, so instead of trying to stay inside
    # `@Test(...)` with `[^)]*` (which breaks the moment an argument contains a
    # nested call like `timeOut = getTimeout()`), match `enabled = false` inside
    # a bounded window after an `@...Test(` opener. The `[^;]` guard keeps the
    # window from wandering across statement boundaries.
    ("@Test(enabled=false)", re.compile(r"@(?:\w+\.)*\w*Test\s*\([^;]{0,240}?\benabled\s*=\s*false\b", re.DOTALL)),
    ("it.skip(", re.compile(r"\bit\.skip\(")),
    ("test.skip(", re.compile(r"\btest\.skip\(")),
    ("xit(", re.compile(r"\bxit\(")),
    ("describe.skip(", re.compile(r"\bdescribe\.skip\(")),
    # `.only()` disables every *other* test in the file, which is at least as
    # dangerous as skipping one test.
    (".only(", re.compile(r"\b(?:it|test|describe|context)\.only\(")),
    ("xdescribe(/xcontext(", re.compile(r"\bx(?:describe|context)\(")),
    # Bare substring match is intentional: this also catches pytest.mark.skipif(...)
    # and pytest.mark.skip(reason="...") -- a few extra false positives on skipif
    # are fine, missing a real skip is not.
    ("pytest.mark.skip", re.compile(r"pytest\.mark\.skip")),
    ("pytest.skip(", re.compile(r"\bpytest\.skip\(")),
    ("@unittest.skip", re.compile(r"@unittest\.skip")),
    ("t.Skip(", re.compile(r"\bt\.Skip(?:Now|f)?\(")),
    ("gradle test { enabled = false }", re.compile(r"\btest\s*\{[^}]{0,400}?\benabled\s*=\s*false\b")),
    ("gradle onlyIf { false }", re.compile(r"\bonlyIf\s*\{\s*false\b")),
    ("maven <skipTests>true</skipTests>", re.compile(r"<skipTests>\s*true\s*</skipTests>", re.IGNORECASE)),
    ("maven <skip>true</skip>", re.compile(r"<skip>\s*true\s*</skip>", re.IGNORECASE)),
]

SUSPICIOUS_TEXT_PATTERNS = [
    ("--legacy-peer-deps present", re.compile(r"legacy-peer-deps")),
]

TEST_PATH_HINT = re.compile(
    r"(^|/)(test|tests|__tests__|spec|specs|integrationTest|integration-test"
    r"|androidTest|testFixtures)(/|$)",
    re.IGNORECASE,
)
TEST_FILENAME_PATTERN = re.compile(
    r"("
    r"(Test|Tests|Spec|Specs|IT|ITCase|ITSpec)\.(java|kt|kts|scala|groovy)$"
    r"|_test\.go$"
    r"|\.test\.[jt]sx?$|\.spec\.[jt]sx?$"
    r"|^test_.*\.py$|_test\.py$"
    r")"
)

WAIVER_HINT = re.compile(
    r"(waiver|suppress|allowlist|whitelist|false.?positive|nexus.?iq|clm-policy)",
    re.IGNORECASE,
)
# Only ever applied to already-extracted added ("+") lines, so it does not need
# its own `^\+` anchor any more.
EXCLUDE_ADDED_PATTERN = re.compile(r"\bexclude\b")

CI_CONFIG_PATTERNS = [
    # .gitignore at ANY depth, not just the repo root.
    re.compile(r"(^|/)\.gitignore$"),
    re.compile(r"(^|/)\.github/workflows/"),
    re.compile(r"(^|/)\.gitlab-ci\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]*jenkinsfile[^/]*$", re.IGNORECASE),
    re.compile(r"(^|/)azure-pipelines[^/]*\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)\.circleci/config\.ya?ml$", re.IGNORECASE),
]

TRIDENT_PATH = re.compile(r"(^|/)\.trident/")

# --- open/dynamic version-range detection -----------------------------------
#
# The previous pattern matched bare code anywhere in the diff and fired on
# ordinary things like `return calc(arr[0], 2);`. Detection is now gated twice:
# the file has to look like a dependency manifest/lockfile, AND the candidate
# value has to be extracted from a manifest-shaped construct (quoted value,
# `<version>` tag, or a `name: value` / `name = value` pair).

_VERSION_CONTEXT_NAMES = {
    "pom.xml", "package.json", "package-lock.json", "composer.json",
    "requirements.txt", "go.mod", "gemfile", "cargo.toml", "ivy.xml",
    "build.xml", "gradle.properties", "settings.gradle", "settings.gradle.kts",
}
_VERSION_CONTEXT_SUFFIXES = (".lock", ".gradle", ".gradle.kts", ".versions.toml")

_XML_VERSION_TAG = re.compile(r"<version>([^<]*)</version>", re.IGNORECASE)
_QUOTED_STRING = re.compile(r"\"([^\"\n]*)\"|'([^'\n]*)'")
_NAME_VALUE_PAIR = re.compile(r"^[\s\-]*[\"']?[\w.\-/@]+[\"']?\s*[:=]\s*(\S.*?)[,;]?\s*$")

# Deliberately case-sensitive: `LATEST`/`RELEASE` are the Maven keywords, while
# a lowercase "release" is far more likely to be a Gradle build variant name.
_OPEN_VERSION_VALUE = re.compile(
    r"""\s*(?:
          \*                                       # npm "*"
        | [xX]                                     # npm "x"
        | \+                                       # gradle bare "+"
        | latest(?:\.(?:release|integration))?     # npm "latest" / gradle latest.release
        | LATEST | RELEASE                         # maven keywords
        | \d[\w.\-]*\.\+                           # gradle 1.2.+
        | [\[(]\s*[\w.\-]*\s*,\s*[\w.\-]*\s*[\])]  # maven [1.0,2.0) / (1.0,2.0]
    )\s*""",
    re.VERBOSE,
)

RESOLUTION_STRATEGY = re.compile(r"\bresolutionStrategy\b")
FORCE_TOKEN = re.compile(r"\bforce\b")
# How many added lines after `resolutionStrategy` still count as "inside" the
# block form: `resolutionStrategy {\n    force '...'\n}`.
RESOLUTION_STRATEGY_SPAN = 10


def _run_git(args: list[str], repo_root: Path) -> str:
    # core.quotePath=false stops git from C-escaping non-ASCII paths
    # ("Caf\303\251Test.java"), which would otherwise be handed straight to
    # Path() and silently fail to resolve.
    proc = subprocess.run(
        ["git", "-c", "core.quotePath=false", *args], cwd=str(repo_root),
        capture_output=True, encoding="utf-8", errors="replace", check=True,
    )
    return proc.stdout


def _unquote_git_path(path: str) -> str:
    """Undo git's C-style quoting for paths it still chooses to quote."""
    p = path.strip()
    if len(p) < 2 or p[0] != '"' or p[-1] != '"':
        return path
    inner = p[1:-1]
    try:
        return (
            inner.encode("utf-8", "surrogateescape")
            .decode("unicode_escape")
            .encode("latin-1")
            .decode("utf-8")
        )
    except (UnicodeDecodeError, UnicodeEncodeError):
        return inner


def _strip_diff_prefix(token: str) -> str:
    path = _unquote_git_path(token)
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _looks_like_test_file(path: str) -> bool:
    return bool(TEST_PATH_HINT.search(path) or TEST_FILENAME_PATTERN.search(Path(path).name))


def _is_version_context_file(path: str) -> bool:
    name = Path(path).name
    lower = name.lower()
    if name in MANIFEST_FILENAMES or lower in _VERSION_CONTEXT_NAMES:
        return True
    return lower.endswith(_VERSION_CONTEXT_SUFFIXES)


def _read_text_safely(full_path: Path) -> tuple[str | None, str | None]:
    """Return (text, error_reason).

    text is None with error_reason None for binary files (nothing to scan, and
    not suspicious in itself). A non-None error_reason means the file could not
    be inspected and the caller must treat that as suspicious rather than as a
    pass -- an unreadable file must never crash or silently clear the gate.
    """
    try:
        size = full_path.stat().st_size
    except OSError as exc:
        return None, f"could not be inspected ({type(exc).__name__})"
    if size > MAX_SCAN_BYTES:
        return None, (
            f"is {size} bytes, above the {MAX_SCAN_BYTES}-byte inspection cap "
            f"— review manually"
        )
    try:
        raw = full_path.read_bytes()
    except OSError as exc:
        return None, f"could not be read ({type(exc).__name__})"
    if b"\x00" in raw[:BINARY_SNIFF_BYTES]:
        return None, None
    return raw.decode("utf-8", errors="replace"), None


def _emptied_state(full_path: Path) -> tuple[bool, str | None]:
    """Return (is_emptied, error_reason).

    A file "emptied" to only whitespace is functionally the same as a zero-byte
    delete for a test file -- checking st_size == 0 alone would miss it.
    """
    if not full_path.exists():
        # git told us this path changed, so failing to resolve it on disk means
        # something is wrong (mangled/quoted path, symlink, race). Never let
        # that read as "not emptied, therefore fine".
        return False, "changed according to git but could not be resolved on disk"
    text, error = _read_text_safely(full_path)
    if error is not None:
        return False, error
    if text is None:
        return False, None  # binary file: definitionally not whitespace-only
    return text.strip() == "", None


def _deleted_or_emptied_test_files(
    repo_root: Path, base_ref: str, untracked: list[str] | None = None
) -> list[str]:
    status_output = _run_git(["diff", "--name-status", base_ref], repo_root)
    flagged: list[str] = []
    for line in status_output.splitlines():
        if not line.strip():
            continue
        parts = [_unquote_git_path(p) for p in line.split("\t")]
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
        elif status.startswith(("M", "A", "C", "T")):
            emptied, error = _emptied_state(repo_root / path)
            if error is not None:
                flagged.append(f"{path} {error}")
            elif emptied:
                flagged.append(f"{path} deleted (emptied to whitespace-only content)")

    # Untracked files never appear in `git diff --name-status`, so a brand-new
    # test file written as whitespace-only content would otherwise be invisible
    # to this structural check entirely.
    for rel_path in untracked or []:
        if not _looks_like_test_file(rel_path):
            continue
        emptied, error = _emptied_state(repo_root / rel_path)
        if error is not None:
            flagged.append(f"{rel_path} {error}")
        elif emptied:
            flagged.append(f"{rel_path} added as an empty/whitespace-only test file")
    return flagged


def _is_manifest_or_lockfile(path: str) -> bool:
    name = Path(path).name
    return name in MANIFEST_FILENAMES or name.endswith(".lock")


def _untracked_files(repo_root: Path) -> list[str]:
    output = _run_git(["ls-files", "--others", "--exclude-standard"], repo_root)
    return [_unquote_git_path(line) for line in output.splitlines() if line]


def _added_lines_by_file(patch: str) -> dict[str, list[str]]:
    """Map each file in a unified diff to the content of its added ("+") lines.

    Only `+` lines are collected -- never context or removed lines. Scanning the
    whole patch text would flag the *removal* of an `@Disabled` annotation (a
    `-@Disabled` line) as if a test had just been disabled, which is exactly
    backwards.
    """
    result: dict[str, list[str]] = {}
    current: str | None = None
    old_path: str | None = None
    prev_was_old_header = False

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current = None
            old_path = None
            prev_was_old_header = False
            continue
        if line.startswith("--- "):
            token = line[4:].strip()
            old_path = None if token == "/dev/null" else _strip_diff_prefix(token)
            prev_was_old_header = True
            continue
        # `+++` is only a file header immediately after a `---` header; anywhere
        # else it is an added line whose content happens to start with "++".
        if prev_was_old_header and line.startswith("+++ "):
            token = line[4:].strip()
            current = old_path if token == "/dev/null" else _strip_diff_prefix(token)
            if current is not None:
                result.setdefault(current, [])
            prev_was_old_header = False
            continue
        prev_was_old_header = False
        if line.startswith("+") and current is not None:
            result[current].append(line[1:])
    return result


def _untracked_added_lines(
    repo_root: Path, untracked_paths: list[str]
) -> tuple[dict[str, list[str]], list[str]]:
    """Treat untracked files as all-additions so they get the same scrutiny.

    `git diff` only ever looks at tracked content, so a brand-new file the agent
    adds but never `git add`s is otherwise invisible to this whole module -- a
    much bigger false-negative hole than any single regex.
    """
    added: dict[str, list[str]] = {}
    reasons: list[str] = []
    for rel_path in untracked_paths:
        full_path = repo_root / rel_path
        if not full_path.is_file():
            continue
        text, error = _read_text_safely(full_path)
        if error is not None:
            reasons.append(f"{rel_path}: new file {error}")
            continue
        if text is None:
            continue  # binary: no text pattern can meaningfully match
        added[rel_path] = text.splitlines()
    return added, reasons


def _resolution_strategy_force(added_lines: list[str]) -> bool:
    """Catch both `resolutionStrategy.force ...` and the multi-line block form."""
    pending = -1
    for index, line in enumerate(added_lines):
        if RESOLUTION_STRATEGY.search(line):
            if FORCE_TOKEN.search(line):
                return True
            pending = index
        elif pending >= 0 and index - pending <= RESOLUTION_STRATEGY_SPAN:
            if FORCE_TOKEN.search(line):
                return True
    return False


def _version_value_candidates(line: str) -> list[str]:
    candidates: list[str] = []
    for match in _XML_VERSION_TAG.finditer(line):
        candidates.append(match.group(1))
    for match in _QUOTED_STRING.finditer(line):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        candidates.append(value)
        # Gradle shorthand coordinates: 'group:name:version'
        if value.count(":") >= 2:
            candidates.append(value.rsplit(":", 1)[-1])
    pair = _NAME_VALUE_PAIR.match(line)
    if pair:
        value = pair.group(1).strip().strip("\"'")
        candidates.append(value)
        if value.count(":") >= 2:
            candidates.append(value.rsplit(":", 1)[-1])
    return candidates


def _open_version_ranges(path: str, added_lines: list[str]) -> list[str]:
    if not _is_version_context_file(path):
        return []
    hits: list[str] = []
    for line in added_lines:
        for candidate in _version_value_candidates(line):
            if candidate and _OPEN_VERSION_VALUE.fullmatch(candidate):
                if candidate not in hits:
                    hits.append(candidate)
    return hits


def _config_or_ci_reason(path: str) -> str | None:
    if any(pattern.search(path) for pattern in CI_CONFIG_PATTERNS):
        return f"{path}: .gitignore or CI config modified"
    return None


def _trident_reason(path: str) -> str | None:
    if not TRIDENT_PATH.search(path) and not path.startswith(".trident/"):
        return None
    if Path(path).name == "build.yaml":
        return f"{path}: .trident/build.yaml modified — the agent must never change the declared toolchain"
    return f"{path}: file under .trident/ modified — the agent must never change the declared toolchain"


def classify_diff(repo_root: Path, base_ref: str = "HEAD") -> DiffResult:
    tracked_changed = [
        _unquote_git_path(line)
        for line in _run_git(["diff", "--name-only", base_ref], repo_root).splitlines()
        if line
    ]
    untracked = _untracked_files(repo_root)
    changed_files = tracked_changed + [f for f in untracked if f not in tracked_changed]

    patch = _run_git(["diff", base_ref], repo_root)
    added_by_file = _added_lines_by_file(patch)
    untracked_added, read_reasons = _untracked_added_lines(repo_root, untracked)
    added_by_file.update(untracked_added)

    reasons: list[str] = []
    reasons.extend(read_reasons)

    for path in changed_files:
        trident = _trident_reason(path)
        if trident:
            reasons.append(trident)

    deleted_or_emptied = _deleted_or_emptied_test_files(repo_root, base_ref, untracked)
    if deleted_or_emptied:
        reasons.append(f"test file(s) deleted or emptied: {', '.join(deleted_or_emptied)}")

    for path in sorted(added_by_file):
        added_lines = added_by_file[path]
        if not added_lines:
            continue
        added_text = "\n".join(added_lines)

        for label, pattern in TEST_SKIP_PATTERNS:
            if pattern.search(added_text):
                reasons.append(f"{path}: test-disabling marker added: {label}")

        for label, pattern in SUSPICIOUS_TEXT_PATTERNS:
            if pattern.search(added_text):
                reasons.append(f"{path}: {label}")

        if _resolution_strategy_force(added_lines):
            reasons.append(f"{path}: resolutionStrategy force added")

        for value in _open_version_ranges(path, added_lines):
            reasons.append(f"{path}: open/dynamic version range: {value}")

        if EXCLUDE_ADDED_PATTERN.search(added_text):
            reasons.append(
                f"{path}: dependency exclude added (heuristic — review before trusting this alone)"
            )

    for path in changed_files:
        if WAIVER_HINT.search(path):
            reasons.append(f"{path}: Nexus IQ policy waiver/suppression file created or modified")
        config = _config_or_ci_reason(path)
        if config:
            reasons.append(config)

    # Preserve order but never report the same reason twice.
    deduped = list(dict.fromkeys(reasons))

    if deduped:
        return DiffResult(
            classification=DiffClass.SUSPICIOUS,
            changed_files=changed_files,
            suspicious_reasons=deduped,
        )

    if changed_files and all(_is_manifest_or_lockfile(f) for f in changed_files):
        return DiffResult(classification=DiffClass.MANIFEST_ONLY, changed_files=changed_files)

    return DiffResult(classification=DiffClass.SOURCE_TOUCHED, changed_files=changed_files)
