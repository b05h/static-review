import json
import re
import os
from reviewer import CodeReviewer

def get_code_context(file_path, target_line, context_lines=2):
    if not os.path.exists(file_path):
        return f"// Error: Could not locate source file at {file_path}"
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        start_idx = max(0, target_line - 1 - context_lines)
        end_idx = min(len(lines), target_line + context_lines)
        
        snippet = "".join(lines[start_idx:end_idx]).strip()
        return snippet
    except Exception as e:
        return f"// Error reading file: {str(e)}"

def parse_semgrep_json(file_path="findings.json"):
    if not os.path.exists(file_path):
        print(f"Error: Could not find '{file_path}'.")
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
            
    parsed_findings = []
    seen_signatures = set()
    
    for result in data.get("results", []):
        target_file = result.get("path", "")
        line_number = result.get("start", {}).get("line", 0)
        
        # Base Extractions
        cwe_id = "Unknown"
        extra_data = result.get("extra", {})
        metadata = extra_data.get("metadata", {})
        
        cwes = metadata.get("cwe", [])
        if cwes and isinstance(cwes, list):
            cwe_match = re.search(r"(CWE-\d+)", cwes[0], re.IGNORECASE)
            if cwe_match:
                cwe_id = cwe_match.group(1).upper()

                # NEW LOGIC: Check if we've already logged this CWE within 5 lines
                is_duplicate = False
                for signature in seen_signatures:
                    seen_file, seen_line, seen_cwe = signature.split(":")
                    if target_file == seen_file and cwe_id == seen_cwe:
                        if abs(line_number - int(seen_line)) <= 5:
                            is_duplicate = True
                            break
                            
                if is_duplicate:
                    continue
                        
        finding_signature = f"{target_file}:{line_number}:{cwe_id}"
        if finding_signature in seen_signatures:
            continue
        seen_signatures.add(finding_signature)
                
        vulnerable_code = get_code_context(target_file, line_number, context_lines=10)
        
        # --- NEW: Advanced Threat Metadata Extraction ---
        severity = extra_data.get("severity", "UNKNOWN")
        likelihood = metadata.get("likelihood", "UNKNOWN")
        impact = metadata.get("impact", "UNKNOWN")
        references = metadata.get("references", [])
                
        parsed_findings.append({
            "file": target_file,
            "line": line_number,
            "cwe": cwe_id,
            "code": vulnerable_code,
            "severity": severity,
            "likelihood": likelihood,
            "impact": impact,
            "references": references
        })
        
    return parsed_findings

def run_pipeline():
    print("1. Parsing Semgrep findings...")
    findings = parse_semgrep_json("findings.json")
    
    if not findings:
        print("No findings to process. Exiting.")
        return

    print(f"Found {len(findings)} unique vulnerabilities. Initializing AI Code Reviewer...\n")
    reviewer = CodeReviewer(model_name="qwen2.5:7b")
    
    for idx, finding in enumerate(findings, 1):
        print(f"--- Reviewing Finding {idx}/{len(findings)} ---")
        print(f"Target: {finding['cwe']} (Severity: {finding['severity']}) in {finding['file']} at line {finding['line']}\n")
        
        # Pass the new data payload to the reviewer
        review_output = reviewer.generate_secure_fix(
            file_path=finding["file"],
            cwe_id=finding["cwe"],
            line_number=finding["line"],
            vulnerable_code=finding["code"],
            severity=finding["severity"],
            likelihood=finding["likelihood"],
            impact=finding["impact"],
            references=finding["references"]
        )
        
        print("\n================ AI SECURE FIX ================")
        print(review_output)
        print("===============================================\n")

if __name__ == "__main__":
    run_pipeline()