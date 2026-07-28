from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from nexus_autofix.publish.branch import sweep_stale_branches


def test_sweep_deletes_stale_branch_with_no_open_pr():
    old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")

    def fake_get(url, headers=None, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if url.endswith("/branches"):
            resp.json.return_value = [
                {"name": "autofix/nexus/old-run", "commit": {"url": "https://api.github.com/commit/old"}},
                {"name": "main", "commit": {"url": "https://api.github.com/commit/main"}},
            ]
        elif url.endswith("/pulls"):
            resp.json.return_value = []
        elif "commit/old" in url:
            resp.json.return_value = {"commit": {"committer": {"date": old_date}}}
        return resp

    with patch("nexus_autofix.publish.branch.requests.get", side_effect=fake_get), \
         patch("nexus_autofix.publish.branch.requests.delete") as mock_delete:
        mock_delete.return_value.raise_for_status.return_value = None
        deleted = sweep_stale_branches("https://api.github.com", "tok", "org", "repo", older_than_days=7)

    assert deleted == ["autofix/nexus/old-run"]
    mock_delete.assert_called_once()


def test_sweep_skips_branch_with_open_pr():
    old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")

    def fake_get(url, headers=None, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if url.endswith("/branches"):
            resp.json.return_value = [{"name": "autofix/nexus/has-pr", "commit": {"url": "https://api.github.com/commit/x"}}]
        elif url.endswith("/pulls"):
            resp.json.return_value = [{"head": {"ref": "autofix/nexus/has-pr"}}]
        elif "commit/x" in url:
            resp.json.return_value = {"commit": {"committer": {"date": old_date}}}
        return resp

    with patch("nexus_autofix.publish.branch.requests.get", side_effect=fake_get), \
         patch("nexus_autofix.publish.branch.requests.delete") as mock_delete:
        deleted = sweep_stale_branches("https://api.github.com", "tok", "org", "repo", older_than_days=7)

    assert deleted == []
    mock_delete.assert_not_called()
