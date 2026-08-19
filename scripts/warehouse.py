from __future__ import annotations

from pathlib import Path
from typing import Optional
import duckdb

def load_masked_file(
        masked_path: str,
        table_name: str,
        db_path: str = "warehouse.duckdb",
        if_exists: str = "replace",
) -> None:
    path = Path(masked_path)
    if not path.exists():
        raise FileNotFoundError(f"Masked file not found: {masked_path}")

    reader = "read_csv_auto" if path.suffix.lower() == ".csv" else "read_json_auto"

    con = duckdb.connect(db_path)
    
    try:
        if if_exists == "replace":
            con.execute(f"DROP TABLE IF EXISTS {table_name}")
            con.execute(
                f"CREATE TABLE {table_name} AS SELECT * FROM {reader}('{path.as_posix()})"
            )
        elif if_exists == "append":
            con.execute(
                f"INSERT INTO {table_name} SELECT * FROM {reader}('{path.as_posix()}')"
            )
        else:
            raise ValueError("if _exists must be 'replace' or 'append'")
    finally:
        con.close()

def query(db_path: str, sql: str):
    con = duckdb.connect(db_path, read_only=True)
    try:
        return con.execute(sql).fetchdf()

    finally:
        con.close()