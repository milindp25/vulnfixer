from datetime import date

from nexus_autofix.repo.descriptor import SecurityFixDescriptor, read_descriptor, unexpired_suppressions, write_descriptor


def test_write_then_read_round_trips(tmp_path):
    path = tmp_path / ".security-fix.yml"
    descriptor = SecurityFixDescriptor(nexus_app_id="payments-core", gate="pre-pr", auto_merge="manifest_only")
    write_descriptor(path, descriptor)
    loaded = read_descriptor(path)
    assert loaded.nexus_app_id == "payments-core"
    assert loaded.gate == "pre-pr"


def test_read_missing_file_returns_none(tmp_path):
    assert read_descriptor(tmp_path / "missing.yml") is None


def test_unexpired_suppressions_excludes_past_expiry():
    descriptor = SecurityFixDescriptor(
        nexus_app_id="x",
        suppress=[
            {"component": "log4j-api", "reason": "shaded", "expires": "2026-10-01"},
            {"component": "old-lib", "reason": "stale", "expires": "2020-01-01"},
        ],
    )
    result = unexpired_suppressions(descriptor, today=date(2026, 7, 28))
    assert result == {"log4j-api"}


def test_unexpired_suppressions_with_no_descriptor_is_empty():
    assert unexpired_suppressions(None, today=date(2026, 7, 28)) == set()
