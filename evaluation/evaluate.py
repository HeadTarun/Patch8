#!/usr/bin/env python3
"""Evaluate case-level detection against a labeled CWE manifest."""

import csv
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from scanner import analyze


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: evaluate.py PROJECT_ROOT MANIFEST.csv RESULTS.csv")
        return 2
    root, manifest, output = map(Path, sys.argv[1:])
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    with manifest.open(newline="", encoding="utf-8") as stream:
        for case in csv.DictReader(stream):
            path = (root / case["path"]).resolve()
            if not path.is_relative_to(root.resolve()):
                raise ValueError(f"Manifest path escapes project root: {case['path']}")
            if path.is_file():
                with tempfile.TemporaryDirectory() as temporary:
                    isolated_case = Path(temporary) / path.name
                    shutil.copy2(path, isolated_case)
                    report = analyze(Path(temporary))
            else:
                report = analyze(path)
            expected = case["expected_cwe"]
            found = any(item["cwe"]["id"] == expected for item in report["findings"] if item.get("cwe"))
            vulnerable = case["vulnerable"].strip().lower() == "true"
            key = "tp" if found and vulnerable else "fp" if found else "fn" if vulnerable else "tn"
            counts[expected][key] += 1
    with output.open("w", newline="", encoding="utf-8") as stream:
        fields = ["cwe", "tp", "fp", "fn", "tn", "precision", "recall"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for cwe, row in sorted(counts.items()):
            precision = row["tp"] / (row["tp"] + row["fp"]) if row["tp"] + row["fp"] else 0
            recall = row["tp"] / (row["tp"] + row["fn"]) if row["tp"] + row["fn"] else 0
            writer.writerow({"cwe": cwe, **row, "precision": f"{precision:.3f}", "recall": f"{recall:.3f}"})
    print(f"Wrote CWE metrics to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
