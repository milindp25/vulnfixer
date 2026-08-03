"""Scan a built application with the Nexus IQ CLI jar.

The alternative to `sourceControlEvaluation`, and a materially deeper one. The SCM scan
reads what is committed, so for Maven and Gradle it sees the *declared* dependencies —
`pom.xml` and `build.gradle` name direct dependencies only, and the transitive closure
exists nowhere in the repository. The CLI scans a build output directory and fingerprints
the artifacts actually there, so it sees the whole resolved classpath.

(npm is the exception that makes the difference visible: `package-lock.json` enumerates
the full pinned tree, so the SCM scan already sees transitives for those repos. Which is
why the same tool reports transitive findings on a Node repo and none on a Gradle one.)

The trade is that it needs a **built** application. No build, no artifacts, no scan.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from nexus_autofix.iq.client import _report_id_from_url

log = logging.getLogger(__name__)

RESULT_FILENAME = "iq-scan-result.json"


class IQCLIScanError(RuntimeError):
    """The CLI did not produce a usable report — distinct from a failing policy."""


@dataclass(frozen=True)
class CLIScanResult:
    report_id: str
    policy_action: str
    result_file: Path


def _redact(args: list[str]) -> str:
    """Render the command for the log with the credentials removed.

    `-a user:password` is passed on the argv, which is visible to anyone who can list
    processes on this machine. That is how the CLI is designed and how their pipeline
    already invokes it, so it is not something this tool can fix — but it must not also
    end up written to a file that gets attached to a ticket.
    """
    redacted = list(args)
    for i, arg in enumerate(redacted):
        if arg in ("-a", "--authentication") and i + 1 < len(redacted):
            redacted[i + 1] = "***:***"
    return " ".join(redacted)


def _find_report_url(node: object) -> str | None:
    """Search the result file for anything that looks like a report URL.

    Deliberately structural rather than keyed on `reportDataUrl`/`reportHtmlUrl`. The
    exact result-file schema varies by CLI version and is not verified here against the
    version in use, so hardcoding a field name would turn a harmless naming difference
    into "the scan produced nothing". Any string carrying a report path will do, because
    `_report_id_from_url` already understands every shape IQ emits.
    """
    if isinstance(node, str):
        if "/report" in node and _report_id_from_url(node):
            return node
        return None
    if isinstance(node, dict):
        # Prefer the data URL when several are present: it is the API form, so it is the
        # one whose shape is verified against a live instance.
        for key in ("reportDataUrl", "reportHtmlUrl", "reportPdfUrl"):
            value = node.get(key)
            if isinstance(value, str) and _report_id_from_url(value):
                return value
        for value in node.values():
            found = _find_report_url(value)
            if found:
                return found
        return None
    if isinstance(node, list):
        for value in node:
            found = _find_report_url(value)
            if found:
                return found
    return None


def run_cli_scan(
    jar_path: Path,
    scan_target: Path,
    app_id: str,
    iq_url: str,
    username: str,
    password: str,
    stage_id: str,
    result_file: Path,
    timeout_seconds: int,
    java_executable: str = "java",
) -> CLIScanResult:
    """Run the IQ CLI over `scan_target` and return the resulting report id.

    Mirrors the invocation already in use in CI:

        java -jar <jar> -i <app> -r <result.json> -s <iq-url> -a <user:pass> -t <stage> <target>
    """
    if not jar_path.is_file():
        raise IQCLIScanError(
            f"Nexus IQ CLI jar not found at {jar_path}. Set `iq_cli_jar` in config.yml to "
            "the jar your pipeline uses."
        )
    if not scan_target.exists():
        raise IQCLIScanError(
            f"nothing to scan at {scan_target}. The CLI reads build output, so the "
            "application has to be built before it can be scanned."
        )
    result_file.parent.mkdir(parents=True, exist_ok=True)
    if result_file.exists():
        # A stale file from a previous run would otherwise be parsed as this run's result.
        result_file.unlink()

    args = [
        java_executable, "-jar", str(jar_path),
        "-i", app_id,
        "-r", str(result_file),
        "-s", iq_url,
        "-a", f"{username}:{password}",
        "-t", stage_id,
        str(scan_target),
    ]
    log.info("IQ CLI scan: %s", _redact(args))
    proc = subprocess.run(
        args, capture_output=True, encoding="utf-8", errors="replace",
        timeout=timeout_seconds,
    )
    log.debug("IQ CLI stdout:\n%s\nstderr:\n%s", proc.stdout or "", proc.stderr or "")

    if not result_file.is_file():
        # Only now does the exit code carry information: with no result file there is
        # nothing to distinguish a failing policy from a broken invocation.
        raise IQCLIScanError(
            f"the IQ CLI exited {proc.returncode} and wrote no result file to "
            f"{result_file}.\n  stdout: {(proc.stdout or '').strip()[-2000:]}\n"
            f"  stderr: {(proc.stderr or '').strip()[-2000:]}"
        )

    raw = result_file.read_text(encoding="utf-8")
    log.info("IQ CLI result file %s:\n%s", result_file, raw[:4000])
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IQCLIScanError(f"the IQ CLI result file at {result_file} is not JSON: {exc}") from exc

    report_url = _find_report_url(body)
    if not report_url:
        raise IQCLIScanError(
            f"no report URL in the IQ CLI result file at {result_file}. The full contents "
            "are logged at INFO just above — the report id is read from any field holding "
            "a URL containing '/report'."
        )
    report_id = _report_id_from_url(report_url)
    policy_action = str(body.get("policyAction") or "")

    # A non-zero exit is the NORMAL outcome for an application with a failing policy —
    # which is exactly the application this tool exists to fix. Treating it as an error
    # would make the tool refuse precisely the repos it is for. With a report in hand the
    # exit code is a policy verdict, not a failure, so it is recorded and not acted on.
    log.info(
        "IQ CLI scan finished: report %s, policyAction=%s, exit=%s",
        report_id, policy_action or "(not stated)", proc.returncode,
    )
    return CLIScanResult(
        report_id=report_id, policy_action=policy_action, result_file=result_file
    )
