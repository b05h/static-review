from semgrep_parser import parse_semgrep_results

findings = parse_semgrep_results("findings.json")

for finding in findings:
    print("=" * 50)

    for key, value in finding.items():
        print(f"{key}: {value}")