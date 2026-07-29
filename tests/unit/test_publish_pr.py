from unittest.mock import patch

from nexus_autofix.publish.pr import open_pull_request


def test_open_pull_request_posts_expected_payload_and_returns_number_and_url():
    with patch("nexus_autofix.publish.pr.requests.post") as mock_post:
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {"number": 42, "html_url": "https://github.com/org/repo/pull/42"}

        result = open_pull_request(
            api_url="https://api.github.com", token="tok", owner="org", repo="repo",
            head_branch="autofix/nexus/run-1", base_branch="main",
            title="fix: bump commons-text", body="details",
        )

    assert result.number == 42
    assert result.url == "https://github.com/org/repo/pull/42"
    call = mock_post.call_args
    assert call.kwargs["json"]["head"] == "autofix/nexus/run-1"
    assert call.kwargs["json"]["base"] == "main"
