from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT,
    outcome TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    component TEXT NOT NULL,
    package_url TEXT NOT NULL,
    current_version TEXT NOT NULL,
    target_version TEXT,
    disposition TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    attempt_number INTEGER NOT NULL,
    build_success INTEGER,
    test_success INTEGER,
    diff_classification TEXT
);
"""


class StateStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def start_run(self, run_id: str, app_id: str, branch: str, created_at: str) -> None:
        self._conn.execute(
            "INSERT INTO runs (run_id, app_id, branch, created_at) VALUES (?, ?, ?, ?)",
            (run_id, app_id, branch, created_at),
        )
        self._conn.commit()

    def record_finding(
        self, run_id: str, component: str, package_url: str, current_version: str,
        target_version: str | None, disposition: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO findings (run_id, component, package_url, current_version, target_version, disposition) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, component, package_url, current_version, target_version, disposition),
        )
        self._conn.commit()

    def record_attempt(
        self, run_id: str, attempt_number: int, build_success: bool | None,
        test_success: bool | None, diff_classification: str | None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO attempts (run_id, attempt_number, build_success, test_success, diff_classification) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, attempt_number, build_success, test_success, diff_classification),
        )
        self._conn.commit()

    def finish_run(self, run_id: str, outcome: str, commit_sha: str | None = None) -> None:
        self._conn.execute(
            "UPDATE runs SET outcome = ?, commit_sha = COALESCE(?, commit_sha) WHERE run_id = ?",
            (outcome, commit_sha, run_id),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
