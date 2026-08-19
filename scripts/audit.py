from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id          TEXT PRIMARY KEY,
    source_file     TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    row_count       INTEGER,
    status          TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS detection_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES pipeline_runs(run_id),
    column_name     TEXT NOT NULL,
    entity_type     TEXT,
    tier            TEXT,
    tags            TEXT,       -- JSON list
    confidence      REAL,
    sample_hits     INTEGER,
    sample_size     INTEGER,
    logged_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS masking_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES pipeline_runs(run_id),
    column_name     TEXT NOT NULL,
    strategy        TEXT NOT NULL,
    rows_masked     INTEGER NOT NULL,
    logged_at       TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditLog:
    db_path: str = "audit_log.sqlite3"

    def __post_init__(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # -- run lifecycle ----------------------------------------------------

    def start_run(self, run_id: str, source_file: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "INSERT INTO pipeline_runs (run_id, source_file, started_at, status) "
                "VALUES (?, ?, ?, 'running')",
                (run_id, source_file, _now()),
            )
            conn.commit()

    def finish_run(self, run_id: str, row_count: int, status: str = "success") -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE pipeline_runs SET finished_at = ?, row_count = ?, status = ? "
                "WHERE run_id = ?",
                (_now(), row_count, status, run_id),
            )
            conn.commit()

    # -- events -------------------------------------------------------------

    def log_detection(
        self,
        run_id: str,
        column_name: str,
        entity_type: Optional[str],
        tier: Optional[str],
        tags: List[str],
        confidence: float,
        sample_hits: int,
        sample_size: int,
    ) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "INSERT INTO detection_events "
                "(run_id, column_name, entity_type, tier, tags, confidence, "
                " sample_hits, sample_size, logged_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run_id, column_name, entity_type, tier, json.dumps(tags),
                    confidence, sample_hits, sample_size, _now(),
                ),
            )
            conn.commit()

    def log_masking(self, run_id: str, column_name: str, strategy: str, rows_masked: int) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "INSERT INTO masking_events "
                "(run_id, column_name, strategy, rows_masked, logged_at) VALUES (?,?,?,?,?)",
                (run_id, column_name, strategy, rows_masked, _now()),
            )
            conn.commit()

    # -- queries --------------------------------------------------------

    def run_history(self, source_file: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM pipeline_runs"
        params: tuple = ()
        if source_file:
            query += " WHERE source_file = ?"
            params = (source_file,)
        query += " ORDER BY started_at DESC"
        with closing(self._connect()) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def events_for_run(self, run_id: str) -> Dict[str, List[Dict[str, Any]]]:
        with closing(self._connect()) as conn:
            conn.row_factory = sqlite3.Row
            detections = [
                dict(r) for r in conn.execute(
                    "SELECT * FROM detection_events WHERE run_id = ?", (run_id,)
                ).fetchall()
            ]
            maskings = [
                dict(r) for r in conn.execute(
                    "SELECT * FROM masking_events WHERE run_id = ?", (run_id,)
                ).fetchall()
            ]
            return {"detections": detections, "maskings": maskings}
