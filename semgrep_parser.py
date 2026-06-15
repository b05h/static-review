import json
import re

def extract_cwe_ids(cwe_list):
    ids = []

    for item in cwe_list:
        match = re.search(r"CWE-\d+", item)
        if match:
            ids.append(match.group())

    return ids

def parse_semgrep_results(json_file):
    with open(json_file, "r", encoding="utf-16") as f:
        data = json.load(f)

    findings = []

    for result in data.get("results", []):
        finding = {
            "rule_id": result.get("check_id"),
            "file": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "severity": result.get("extra", {}).get("severity"),
            "message": result.get("extra", {}).get("message"),

            "cwe": extract_cwe_ids(
                        result.get("extra", {})
                        .get("metadata", {})
                        .get("cwe", []),
            ),

            "owasp": result.get("extra", {})
                          .get("metadata", {})
                          .get("owasp", []),

            "vulnerability_class": result.get("extra", {})
                                        .get("metadata", {})
                                        .get("vulnerability_class", []),

            "likelihood": result.get("extra", {})
                                .get("metadata", {})
                                .get("likelihood"),

            "impact": result.get("extra", {})
                            .get("metadata", {})
                            .get("impact"),

            "confidence": result.get("extra", {})
                                .get("metadata", {})
                                .get("confidence"),

            "references": result.get("extra", {})
                                .get("metadata", {})
                                .get("references", [])
        }

        findings.append(finding)

    return findings