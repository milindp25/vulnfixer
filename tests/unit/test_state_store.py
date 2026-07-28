from nexus_autofix.state.store import StateStore


def test_run_lifecycle_round_trips(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.start_run("run-1", "payments-core", "autofix/nexus/run-1", "2026-07-28T00:00:00Z")
    store.record_finding("run-1", "commons-text", "pkg:maven/x/y@1.9", "1.9", "1.10.0", "actionable")
    store.record_attempt("run-1", 1, True, True, "MANIFEST_ONLY")
    store.finish_run("run-1", "FIXED", commit_sha="abc123")

    cursor = store._conn.execute("SELECT outcome, commit_sha FROM runs WHERE run_id = ?", ("run-1",))
    outcome, commit_sha = cursor.fetchone()
    assert outcome == "FIXED"
    assert commit_sha == "abc123"

    findings = store._conn.execute("SELECT component, disposition FROM findings WHERE run_id = ?", ("run-1",)).fetchall()
    assert findings == [("commons-text", "actionable")]

    attempts = store._conn.execute("SELECT attempt_number, build_success FROM attempts WHERE run_id = ?", ("run-1",)).fetchall()
    assert attempts == [(1, 1)]

    store.close()


def test_creates_parent_directories(tmp_path):
    nested = tmp_path / "a" / "b" / "state.db"
    store = StateStore(nested)
    assert nested.exists()
    store.close()
