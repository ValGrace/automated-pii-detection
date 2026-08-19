from __future__ import annotations
from datetime import datetime

from airflow import DAG
from airflow.operators.python import PythonOperator

from scripts import run_pipeline
from scripts.warehouse import load_masked_file

RAW_DATA_DIR = "/opt/airflow/data/raw"
OUTPUT_DIR = "/opt/airflow/data/masked"
WAREHOUSE_DB = "/opt/airflow/data/warehouse.duckdb"
SOURCE_FILE = f"{RAW_DATA_DIR}/customer_registrations.csv"


def _scan_and_mask(**context) -> None:
    result = run_pipeline(
        input_path=SOURCE_FILE,
        output_dir=OUTPUT_DIR,
        # Shared audit/catalog stores across every scheduled run, so the
        # compliance trail spans the full ingestion history, not just
        # one run.
        audit_db_path=f"{OUTPUT_DIR}/audit_log.sqlite3",
        catalog_db_path=f"{OUTPUT_DIR}/metadata_catalog.sqlite3",
    )
    # Push paths to XCom for the downstream task.
    context["ti"].xcom_push(key="masked_file", value=result["masked_file"])
    context["ti"].xcom_push(key="run_id", value=result["run_id"])


def _load_to_warehouse(**context) -> None:
    masked_file = context["ti"].xcom_pull(key="masked_file", task_ids="scan_and_mask")
    load_masked_file(
        masked_path=masked_file,
        table_name="customer_registrations",
        db_path=WAREHOUSE_DB,
        if_exists="append",
    )


with DAG(
    dag_id="pii_detection_and_masking_pipeline",
    description="Scan raw registrations for PII, mask, tag, and load into the warehouse.",
    schedule="@daily",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    tags=["compliance", "pii", "dpa"],
) as dag:

    scan_and_mask = PythonOperator(
        task_id="scan_and_mask",
        python_callable=_scan_and_mask,
    )

    load_to_warehouse = PythonOperator(
        task_id="load_to_warehouse",
        python_callable=_load_to_warehouse,
    )

    scan_and_mask >> load_to_warehouse
