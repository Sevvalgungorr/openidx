#!/usr/bin/env python3
"""Report the shape of a Semgrep JSON file before it is uploaded.

Importers commonly index straight into ``extra.metadata`` and map severity
through a fixed table, so a finding without metadata, or carrying a severity
outside the known set, makes the import raise and the API answer HTTP 500 with
no detail. When that happens the pipeline log is the only evidence available,
so print the shape up front: a failed upload can then be explained without
re-running anything or reading server logs.

This lives in a file rather than inline in the pipeline YAML because embedded
multi-line Python repeatedly broke YAML parsing.

Usage: semgrep-report-shape.py <semgrep.json>
Exit code is always 0: this is diagnostics, not a gate.
"""
import json
import sys

# What a DefectDojo-style Semgrep parser accepts before raising ValueError.
KNOWN_SEVERITIES = {"CRITICAL", "ERROR", "HIGH", "WARNING", "MEDIUM", "LOW", "INFO"}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: semgrep-report-shape.py <semgrep.json>", file=sys.stderr)
        return 0
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"  could not read report: {exc}")
        return 0

    results = report.get("results") or []
    print(f"  findings: {len(results)}")

    severities = sorted(
        {
            (item.get("extra") or {}).get("severity")
            for item in results
            if (item.get("extra") or {}).get("severity")
        }
    )
    print(f"  severities: {', '.join(severities) if severities else 'none'}")

    unknown = [s for s in severities if s.upper() not in KNOWN_SEVERITIES]
    if unknown:
        print(f"  UNKNOWN severities (may fail the import): {', '.join(unknown)}")

    missing_metadata = [
        item.get("check_id", "?")
        for item in results
        if not (item.get("extra") or {}).get("metadata")
    ]
    print(f"  findings without extra.metadata: {len(missing_metadata)}")
    for check_id in missing_metadata[:5]:
        print(f"   - {check_id}")
    if missing_metadata:
        print("  a parser that indexes extra.metadata directly will raise on these")

    extra_sections = [k for k in report if k not in ("version", "results", "errors", "paths")]
    if extra_sections:
        print(f"  diagnostic sections present: {', '.join(extra_sections)}")
        print("  set SLIM_REPORT=true to drop them if the importer rejects the file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
