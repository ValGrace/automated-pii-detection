from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS catalog_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file     TEXT NOT NULL,
    column_name     TEXT NOT NULL,
    entity_type     TEXT,
    tier            TEXT,
    tags            TEXT,           -- comma-separated
    masked_column   TEXT,
    run_id          TEXT,
    updated_at      TEXT NOT NULL,
    UNIQUE(source_file, column_name)
);

CREATE TABLE IF NOT EXISTS grants (
    role            TEXT NOT NULL,
    source_file     TEXT NOT NULL,
    column_name     TEXT NOT NULL,
    granted_at      TEXT NOT NULL,
    PRIMARY KEY (role, source_file, column_name)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class MetadataCatalog:
    db_path: str = "metadata_catalog.sqlite3"

    def __post_init__(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def upsert_column(
        self,
        source_file: str,
        column_name: str,
        entity_type: Optional[str],
        tier: Optional[str],
        tags: List[str],
        masked_column: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO catalog_entries
                    (source_file, column_name, entity_type, tier, tags,
                     masked_column, run_id, updated_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(source_file, column_name) DO UPDATE SET
                    entity_type=excluded.entity_type,
                    tier=excluded.tier,
                    tags=excluded.tags,
                    masked_column=excluded.masked_column,
                    run_id=excluded.run_id,
                    updated_at=excluded.updated_at
                """,
                (
                    source_file, column_name, entity_type, tier,
                    ",".join(tags), masked_column, run_id, _now(),
                ),
            )
            conn.commit()

    def restricted_columns(self, source_file: Optional[str] = None) -> List[Dict]:
        query = "SELECT * FROM catalog_entries WHERE tags LIKE '%#RESTRICTED%'"
        params: tuple = ()
        if source_file:
            query += " AND source_file = ?"
            params = (source_file,)
        with closing(self._connect()) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def grant(self, role: str, source_file: str, column_name: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO grants (role, source_file, column_name, granted_at) "
                "VALUES (?,?,?,?)",
                (role, source_file, column_name, _now()),
            )
            conn.commit()

    def can_access(self, role: str, source_file: str, column_name: str) -> bool:
        """RESTRICTED columns require an explicit grant for the role;
        everything else is accessible by default."""
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT tags FROM catalog_entries WHERE source_file=? AND column_name=?",
                (source_file, column_name),
            ).fetchone()
            if row is None or "#RESTRICTED" not in (row[0] or ""):
                return True
            granted = conn.execute(
                "SELECT 1 FROM grants WHERE role=? AND source_file=? AND column_name=?",
                (role, source_file, column_name),
            ).fetchone()
            return granted is not None

    def lineage(self, source_file: str) -> List[Dict]:
        with closing(self._connect()) as conn:
            conn.row_factory = sqlite3.Row
            return [
                dict(r) for r in conn.execute(
                    "SELECT column_name, masked_column, run_id, tags "
                    "FROM catalog_entries WHERE source_file = ?",
                    (source_file,),
                ).fetchall()
            ]
