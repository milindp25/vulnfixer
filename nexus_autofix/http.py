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
3. ``NEXUSFIX_INSECURE_SKIP_TLS_VERIFY=true`` — last resort. Disables certificate
   verification entirely, which means the connection can no longer be authenticated and
   the IQ token you send over it is exposed to anyone able to intercept the traffic. It
   logs a warning on every run and should be a stopgap while you obtain the CA, not a
   permanent setting.
"""

from __future__ import annotations

import logging
import os

import requests

log = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}

_truststore_state: str | None = None


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
