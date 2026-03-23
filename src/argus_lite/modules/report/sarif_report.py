"""SARIF 2.1.0 report generator for CI/CD integration."""

from __future__ import annotations

import json
from pathlib import Path

from argus_lite.models.finding import Finding
from argus_lite.models.scan import ScanResult

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

# Map our severity to SARIF level
_LEVEL_MAP = {
    "INFO": "note",
    "LOW": "warning",
}


def _finding_to_rule(f: Finding) -> dict:
    return {
        "id": f.type,
        "name": f.title,
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.description},
        "help": {"text": f.remediation, "markdown": f"**Fix:** {f.remediation}"},
        "defaultConfiguration": {"level": _LEVEL_MAP.get(f.severity, "note")},
    }


def _finding_to_result(f: Finding) -> dict:
    return {
        "ruleId": f.type,
        "level": _LEVEL_MAP.get(f.severity, "note"),
        "message": {"text": f"{f.title}: {f.description}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"https://{f.asset}",
                        "uriBaseId": "TARGETROOT",
                    }
                }
            }
        ],
        "properties": {
            "source": f.source,
            "evidence": f.evidence,
            "severity": f.severity,
        },
    }


def generate_sarif_report(scan: ScanResult) -> str:
    """Generate SARIF 2.1.0 JSON string from ScanResult."""
    # Deduplicate rules by type
    seen_rules: dict[str, dict] = {}
    for f in scan.findings:
        if f.type not in seen_rules:
            seen_rules[f.type] = _finding_to_rule(f)

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/cortexc0de/argus-lite",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": [_finding_to_result(f) for f in scan.findings],
                "invocations": [
                    {
                        "executionSuccessful": scan.status == "completed",
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)


def write_sarif_report(scan: ScanResult, path: Path) -> None:
    """Write SARIF report to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_sarif_report(scan))
