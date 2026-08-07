"""Fetching the corporate CA bundle once, instead of curl-ing it by hand every time."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nexus_autofix.http import CA_BUNDLE_FILENAME, CABundleError, ensure_ca_bundle

PEM = b"-----BEGIN CERTIFICATE-----\nMIIBase64Here\n-----END CERTIFICATE-----\n"
# sha256 of PEM, computed rather than pasted so the test cannot drift from the constant.
PEM_SHA256 = __import__("hashlib").sha256(PEM).hexdigest()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("NEXUSFIX_CA_BUNDLE", "NEXUSFIX_CA_BUNDLE_URL", "NEXUSFIX_CA_BUNDLE_SHA256"):
        monkeypatch.delenv(var, raising=False)


def _response(body=PEM, status=200):
    response = MagicMock()
    response.iter_content.return_value = [body]
    response.raise_for_status.side_effect = None if status == 200 else RuntimeError("HTTP 404")
    return response


def _session(response):
    session = MagicMock()
    session.__enter__.return_value = session
    session.get.return_value = response
    return session


def test_nothing_configured_does_nothing(tmp_path):
    assert ensure_ca_bundle(tmp_path) is None


def test_an_existing_explicit_bundle_is_used_as_is(tmp_path, monkeypatch):
    existing = tmp_path / "mine.pem"
    existing.write_bytes(PEM)
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE", str(existing))

    with patch("nexus_autofix.http.requests.Session") as session:
        assert ensure_ca_bundle(tmp_path) == existing
        session.assert_not_called()


def test_it_downloads_once_and_exports_the_path(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")
    import os

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response())):
        path = ensure_ca_bundle(tmp_path)

    assert path == tmp_path / CA_BUNDLE_FILENAME
    assert path.read_bytes() == PEM
    # Exported so tls_verify and every later session pick it up with no other setup.
    assert os.environ["NEXUSFIX_CA_BUNDLE"] == str(path)


def test_a_present_bundle_is_never_re_fetched(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")
    (tmp_path / CA_BUNDLE_FILENAME).write_bytes(PEM)

    with patch("nexus_autofix.http.requests.Session") as session:
        assert ensure_ca_bundle(tmp_path) == tmp_path / CA_BUNDLE_FILENAME
        session.assert_not_called()


def test_the_bootstrap_fetch_does_not_verify(tmp_path, monkeypatch):
    """Not an oversight — there is no CA to verify with, which is the problem being fixed.

    Pinned by a test because it looks exactly like a security bug, and someone will
    eventually "fix" it into a download that can never succeed on the machines it exists
    for.
    """
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")
    session = _session(_response())

    with patch("nexus_autofix.http.requests.Session", return_value=session):
        ensure_ca_bundle(tmp_path)

    assert session.verify is False


def test_a_matching_checksum_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_SHA256", PEM_SHA256.upper())

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response())):
        assert ensure_ca_bundle(tmp_path).read_bytes() == PEM


def test_a_wrong_checksum_installs_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_SHA256", "0" * 64)

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response())), \
         pytest.raises(CABundleError) as exc:
        ensure_ca_bundle(tmp_path)

    assert "does not match the expected checksum" in str(exc.value)
    assert not (tmp_path / CA_BUNDLE_FILENAME).exists()
    assert not list(tmp_path.glob("*.partial"))


def test_a_proxy_sign_in_page_is_refused(tmp_path, monkeypatch):
    """The realistic failure: an authenticating proxy answers with HTML, which saves fine
    and then breaks TLS later with an error that names nothing useful."""
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")
    html = b"<!doctype html><html><body>Please sign in</body></html>"

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response(html))), \
         pytest.raises(CABundleError) as exc:
        ensure_ca_bundle(tmp_path)

    assert "not a PEM certificate bundle" in str(exc.value)
    assert not (tmp_path / CA_BUNDLE_FILENAME).exists()


def test_plain_http_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "http://pki.corp.example.com/ca.pem")
    with pytest.raises(CABundleError) as exc:
        ensure_ca_bundle(tmp_path)
    assert "non-HTTPS" in str(exc.value)


def test_a_failed_download_leaves_nothing_behind(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")

    with patch("nexus_autofix.http.requests.Session",
               return_value=_session(_response(status=404))), \
         pytest.raises(CABundleError) as exc:
        ensure_ca_bundle(tmp_path)

    assert "could not download the CA bundle" in str(exc.value)
    assert not list(tmp_path.glob("*"))


def test_a_missing_explicit_bundle_with_a_url_downloads_to_that_path(tmp_path, monkeypatch):
    target = tmp_path / "certs" / "corp.pem"
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE", str(target))
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response())):
        assert ensure_ca_bundle(tmp_path) == target
    assert target.read_bytes() == PEM


def test_a_missing_explicit_bundle_without_a_url_warns_rather_than_failing(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE", str(tmp_path / "not-there.pem"))
    with caplog.at_level("WARNING"):
        assert ensure_ca_bundle(tmp_path) is None
    assert "does not exist" in caplog.text


def test_a_windows_style_path_is_handled(tmp_path, monkeypatch):
    """Backslash paths must survive being read back out of .env.

    Not hypothetical on Windows, where every configured path looks like this.
    """
    target = tmp_path / "certs" / "corp.pem"
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE", str(target).replace("/", "\\") if "\\" in str(target)
                       else str(target))
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE_URL", "https://pki.corp.example.com/ca.pem")

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response())):
        result = ensure_ca_bundle(tmp_path)

    assert result.read_bytes() == PEM


def test_the_url_is_read_from_dotenv_with_no_shell_export(tmp_path, monkeypatch):
    """The whole reason there is no `export` / `$env:` difference to get wrong.

    python-dotenv reads `.env` inside the process and `ensure_ca_bundle` exports the result
    into `os.environ` itself, so Git Bash, PowerShell, cmd and zsh all take the identical
    code path — no shell is involved at any point.

    This also pins an ordering that would otherwise fail silently: `.env` must be loaded
    BEFORE the TLS setup runs, or the URL is invisible and the download never happens.
    """
    import os as os_mod

    from nexus_autofix import cli as cli_mod
    from nexus_autofix.config import load_secrets
    from nexus_autofix.http import tls_verify

    workspace = tmp_path / "ws"
    (tmp_path / ".env").write_text(
        "NEXUSFIX_IQ_URL=https://iq.example.com\n"
        "NEXUSFIX_IQ_USERNAME=u\nNEXUSFIX_IQ_PASSWORD=p\n"
        f"NEXUSFIX_WORKSPACE_ROOT={workspace}\n"
        "NEXUSFIX_CA_BUNDLE_URL=https://pki.corp.example.com/ca.pem\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    for var in ("NEXUSFIX_WORKSPACE_ROOT", "NEXUSFIX_IQ_URL", "NEXUSFIX_IQ_USERNAME",
                "NEXUSFIX_IQ_PASSWORD"):
        monkeypatch.delenv(var, raising=False)

    with patch("nexus_autofix.http.requests.Session", return_value=_session(_response())):
        cli_mod._setup_tls(load_secrets())

    landed = workspace / "tools" / "corporate-ca.pem"
    assert landed.is_file()
    assert os_mod.environ["NEXUSFIX_CA_BUNDLE"] == str(landed)
    # And every later request verifies against it.
    assert tls_verify() == str(landed)
