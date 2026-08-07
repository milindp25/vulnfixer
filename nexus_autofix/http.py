"""TLS configuration for outbound HTTPS (Nexus IQ and GitHub).

Corporate networks frequently terminate TLS at an inspecting proxy that presents its own
root CA. Python does not use the OS trust store by default, so requests fails with
``SSLCertVerificationError`` even though a browser on the same machine is fine.

Three ways to resolve it, best first:

1. ``pip install truststore`` — Python then uses the operating system's trust store, which
   already contains your corporate CA. Nothing to configure; this module activates it
   automatically when the package is present. Best option on a managed Windows machine.
2. ``NEXUSFIX_CA_BUNDLE=/path/to/corporate-ca.pem`` — point at the CA bundle explicitly.
   (``REQUESTS_CA_BUNDLE`` and ``CURL_CA_BUNDLE`` are honoured natively by requests too.)
   Or set ``NEXUSFIX_CA_BUNDLE_URL`` and have it fetched once and cached instead of
   curl-ing it by hand on every machine — see ``ensure_ca_bundle``, and set
   ``NEXUSFIX_CA_BUNDLE_SHA256`` with it.
3. ``NEXUSFIX_INSECURE_SKIP_TLS_VERIFY=true`` — last resort. Disables certificate
   verification entirely, which means the connection can no longer be authenticated and
   the IQ token you send over it is exposed to anyone able to intercept the traffic. It
   logs a warning on every run and should be a stopgap while you obtain the CA, not a
   permanent setting.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

import requests

log = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}

_truststore_state: str | None = None

#: Filename for a CA bundle fetched by `ensure_ca_bundle`.
CA_BUNDLE_FILENAME = "corporate-ca.pem"

#: What a PEM bundle has to start with. Checked because the realistic failure is not a
#: corrupt download — it is an authenticating proxy answering with an HTML sign-in page,
#: which saves happily and then fails later as an unintelligible SSL error.
_PEM_MARKER = b"-----BEGIN CERTIFICATE-----"


class CABundleError(RuntimeError):
    """The CA bundle could not be fetched or is not a CA bundle."""


def _insecure_requested() -> bool:
    return os.environ.get("NEXUSFIX_INSECURE_SKIP_TLS_VERIFY", "").strip().lower() in _TRUTHY


def try_enable_os_trust_store() -> str:
    """Route TLS verification through the OS trust store if `truststore` is installed.

    Returns a short status string for logging. Safe to call repeatedly.
    """
    global _truststore_state
    if _truststore_state is not None:
        return _truststore_state
    if _insecure_requested():
        _truststore_state = "skipped (verification disabled)"
        return _truststore_state
    try:
        import truststore  # noqa: PLC0415 — optional dependency, imported on demand
    except ImportError:
        _truststore_state = "unavailable (pip install truststore to use the OS trust store)"
        return _truststore_state
    try:
        truststore.inject_into_ssl()
        _truststore_state = "enabled"
        log.info("TLS: using the operating system trust store via truststore")
    except Exception as exc:  # pragma: no cover - defensive; injection is normally total
        _truststore_state = f"failed ({exc})"
        log.warning("TLS: truststore is installed but could not be activated: %s", exc)
    return _truststore_state


def tls_verify() -> bool | str:
    """The value to hand requests' ``verify=``: a CA bundle path, or False to disable."""
    if _insecure_requested():
        return False
    return os.environ.get("NEXUSFIX_CA_BUNDLE") or True


def warn_if_insecure() -> None:
    """Log a single, unmissable warning when certificate verification is off."""
    if not _insecure_requested():
        return
    log.warning(
        "TLS CERTIFICATE VERIFICATION IS DISABLED (NEXUSFIX_INSECURE_SKIP_TLS_VERIFY). "
        "Connections to Nexus IQ and GitHub cannot be authenticated, and the credentials "
        "sent over them are exposed to anyone able to intercept the traffic. Use this only "
        "as a stopgap — prefer NEXUSFIX_CA_BUNDLE or `pip install truststore`."
    )
    # requests emits one InsecureRequestWarning per call; the warning above says it better.
    try:
        import urllib3  # noqa: PLC0415

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:  # pragma: no cover - urllib3 is a requests dependency
        pass


def make_session() -> requests.Session:
    """A requests session with this machine's TLS settings already applied."""
    session = requests.Session()
    session.verify = tls_verify()
    return session


def ensure_ca_bundle(cache_dir: Path) -> Path | None:
    """Fetch the corporate CA bundle once, then reuse it on every later run.

    Saves re-running the `curl` by hand on each new machine. Set in `.env`:

        NEXUSFIX_CA_BUNDLE_URL=https://pki.corp.example.com/corporate-root-ca.pem
        NEXUSFIX_CA_BUNDLE_SHA256=<the sha256 it logs on the first download>

    The file lands in `cache_dir` — under the workspace root, NOT the repository — so it
    is outside any git working tree and cannot be committed by accident. Present file, no
    download: normal runs make no network call for it.

    On success `NEXUSFIX_CA_BUNDLE` is exported into this process, so `tls_verify` and
    every session built afterwards pick it up with nothing else to configure.

    **The bootstrap fetch cannot verify the certificate it is fetching.** That is not an
    oversight — the whole reason this exists is that the machine has no CA capable of
    verifying the proxy yet, so requiring verification here would only ever fail. The
    checksum is what makes it safe, and is the reason it is worth setting: without one,
    anything on the path can hand you a CA bundle that your later, "verified" connections
    to Nexus IQ would then trust completely. An explicit `NEXUSFIX_CA_BUNDLE` pointing at a
    file you placed yourself is always better, and always wins over this.
    """
    configured = (os.environ.get("NEXUSFIX_CA_BUNDLE") or "").strip()
    if configured and Path(configured).is_file():
        return Path(configured)

    url = (os.environ.get("NEXUSFIX_CA_BUNDLE_URL") or "").strip()
    if not url:
        if configured:
            # Set but missing. Silently downloading over it would be worse; requests would
            # fail later with an error that never mentions the path being wrong.
            log.warning(
                "NEXUSFIX_CA_BUNDLE points at %s, which does not exist. Either correct it, "
                "or set NEXUSFIX_CA_BUNDLE_URL to have the bundle fetched automatically.",
                configured,
            )
        return None

    target = Path(configured) if configured else cache_dir / CA_BUNDLE_FILENAME
    if target.is_file():
        os.environ["NEXUSFIX_CA_BUNDLE"] = str(target)
        log.debug("CA bundle already present at %s", target)
        return target

    if not url.lower().startswith("https://"):
        raise CABundleError(f"refusing to download a CA bundle over a non-HTTPS URL: {url}")

    expected = (os.environ.get("NEXUSFIX_CA_BUNDLE_SHA256") or "").strip().lower()
    log.info("CA bundle not found at %s — downloading from %s", target, url)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Same temporary-then-move dance as the IQ CLI jar: an interrupted download must not
    # leave a truncated file that looks present and breaks TLS on every later run.
    partial = target.with_suffix(target.suffix + ".partial")
    digest = hashlib.sha256()
    try:
        with requests.Session() as session:
            # verify=False deliberately — see the docstring. There is no CA to verify with.
            session.verify = False
            response = session.get(url, stream=True, timeout=120)
            response.raise_for_status()
            with partial.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1 << 16):
                    if chunk:
                        digest.update(chunk)
                        handle.write(chunk)
    except Exception as exc:
        partial.unlink(missing_ok=True)
        raise CABundleError(f"could not download the CA bundle from {url}: {exc}") from exc

    actual = digest.hexdigest()
    if expected and actual != expected:
        partial.unlink(missing_ok=True)
        raise CABundleError(
            f"the CA bundle downloaded from {url} does not match the expected checksum.\n"
            f"  expected sha256: {expected}\n  actual sha256:   {actual}\n"
            "Nothing was installed. Either the URL is serving something different than it "
            "was, or NEXUSFIX_CA_BUNDLE_SHA256 is stale."
        )

    head = partial.read_bytes()[:4096]
    if _PEM_MARKER not in head:
        partial.unlink(missing_ok=True)
        raise CABundleError(
            f"what {url} returned is not a PEM certificate bundle — no "
            f"'{_PEM_MARKER.decode()}' in it.\n"
            "  An authenticating proxy answering with a sign-in page is the usual cause. "
            "Fetch it in a browser, check what you get, and set NEXUSFIX_CA_BUNDLE to a "
            "copy you saved yourself."
        )

    partial.replace(target)
    os.environ["NEXUSFIX_CA_BUNDLE"] = str(target)
    if expected:
        log.info("CA bundle installed at %s (checksum verified)", target)
    else:
        log.warning(
            "downloaded a CA bundle with no checksum to verify it against (sha256 of what "
            "arrived: %s). It was fetched WITHOUT certificate verification, because there "
            "was no CA to verify with — so nothing yet establishes that this is your "
            "organisation's CA rather than one substituted in transit, and every later "
            "'verified' connection will trust whatever it contains. Set "
            "NEXUSFIX_CA_BUNDLE_SHA256 to the value above so a change is caught.",
            actual,
        )
    return target
