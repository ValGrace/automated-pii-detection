from __future__ import annotations
import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from detectors import scan_text
from tagging import tag_entity, tier_for
from masking import TokenVault, mask_value

@dataclass
class ColumnReport:
    column: str
    detected_entity: Optional[str]
    confidence: float
    tier: Optional[str]
    tags: List[str] = field(default_factory=list)
    sample_hits: int = 0
    sample_size: int = 0

@dataclass
class ScanReport:
    source_file: str
    row_count: int
    columns: List[ColumnReport]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

def _load_rows(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    if path.suffix.lower() == ".json":
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = [data]
        return data
    raise ValueError(f"Unsupoorted file type: {path.suffix}. Use .csv or .json")


def _write_rows(path: Path, rows: List[Dict[str, Any]]) -> None:
    if path.suffix.lower() == ".csv":
        if not rows:
            path.write_text("")
            return 
        fieldnames = list(rows[0].keys())
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    elif path.suffix.lower() == ".json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, default=str)

    else:
        raise ValueError(f"Unsupported file type: {path.suffix}. Use .csv or .json")

def scan_file(
        path: str,
        sample_size: int = 50,
        min_confidence: float = 0.5
) -> ScanReport:
    p = Path(path)
    rows = _load_rows(p)
    if not rows:
        return ScanReport(source_file=str(p), row_count=0, columns=[])
    columns = list(rows[0].keys())
    reports: List[ColumnReport] = []

    for col in columns:
        values = [str(r.get(col, "")) for r in rows[:sample_size] if r.get(col)]
        votes: Counter = Counter()
        confidences: Dict[str, List[float]] = {}
        hits = 0

        header_hint = col.replace("_", " ")
        for v in values:
            probe_text = f"{header_hint}: {v}"
            matches = scan_text(probe_text, min_confidence=min_confidence)

            full_cell_matches = [
                m for m in matches
                if m.value == v or (m.end - m.start) >= len(v) * 0.6
            ]

            if full_cell_matches:
                hits +=1
                best = max(full_cell_matches, key=lambda m: m.confidence)
                votes[best.entity_type] += 1
                confidences.setdefault(best.entity_type, []).append(best.confidence)
        if votes:
            entity_type, _ = votes.most_common(1)[0]
            avg_conf = sum(confidences[entity_type]) / len(confidences[entity_type])
            tier = tier_for(entity_type)
            reports.append(
                ColumnReport(
                    column=col,
                    detected_entity=entity_type,
                    confidence=round(avg_conf, 2),
                    tier=tier,
                    tags=tag_entity(entity_type),
                    sample_hits=hits,
                    sample_size=len(values)

                )
            )
        else:
            reports.append(
                ColumnReport(
                    column=col,
                    detected_entity=None,
                    confidence=0.0,
                    tier=None,
                    tags=[],
                    sample_hits=0,
                    sample_size=len(values)
                )
            )
    return ScanReport(source_file=str(p), row_count=len(rows), columns=reports)

def run_pipeline(
        input_path: str,
        output_path: str,
        sample_size: int = 50,
        min_confidence: float = 0.5,
        salt: str = "Change me per deployment",
        strategy_overrides: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    strategy_overrides = strategy_overrides or []
    in_path = Path(input_path)
    out_dir = Path(output_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    report = scan_file(in_path, sample_size=sample_size, min_confidence=min_confidence)
    rows = _load_rows(in_path)
    vault = TokenVault()

    flagged = {c.column: c for c in report.columns if c.detected_entity}

    for row in rows:
        for col, col_report in flagged.items():
            if row.get(col) in (None, ""):
                continue
            override = strategy_overrides.get(col)
            row[col] = mask_value(
                value=row[col],
                entity_type=col_report.detected_entity,
                tier=col_report.tier,
                salt=salt,
                strateg=override,
                vault=vault,
            )
    masked_path = out_dir / f"masked_{in_path.name}"
    report_path = out_dir / f"{in_path.stem}_pii_report.json"

    _write_rows(masked_path, rows)
    report_path.write_text(json.dumps(report.to_dict(), indent=2))

    return {
        "masked_file": str(masked_path),
        "report_file": str(report_path),
    }


