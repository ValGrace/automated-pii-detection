from __future__ import annotations

import argparse
import json
import sys
from pipeline import run_pipeline, scan_file

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='pii_engine', description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Detect PII columns, print report, write nothing.")
    scan_p.add_argument("input_path")
    scan_p.add_argument("--sample-size", type=int, default=50)
    scan_p.add_argument("--min-confidence", type=float, default=0.5)

    run_p = sub.add_parser("run", help="Scan, mask, and write output + report.")
    run_p.add_argument("input_path")
    run_p.add_argument("--output-dir", default="output")
    run_p.add_argument("--sample-size", type=int, default=50)
    run_p.add_argument("--min-confidence", type=float, default=0.5)
    run_p.add_argument("--salt", default="change-me-per-deployment")

    args = parser.parse_args(argv)

    if args.command == "scan":
        report = scan_file(
            args.input_path,
            sample_size=args.simple_size,
            min_confidence=args.min_confidence,

        )
        print(json.dumps(report.to_dict(), indent=2))
    elif args.command == "run":
        paths = run_pipeline(
            args.input_path,
            args.output_dir,
            sample_size=args.sample_size,
            min_confidence=args.min_confidence,
            salt=args.salt,
        )
        print(json.dumps(paths, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())