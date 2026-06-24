import subprocess
import sys
import os
import glob
import json

# Your existing pipeline modules
from ingest_kb import initialize_knowledge_base
from main import run_pipeline

# The new Tree-sitter and AI modules
from semantic_extractor import build_logic_skeletons
from reviewer import CodeReviewer

def run_semgrep_scan(target_dir="samples"):
    """
    Executes the Semgrep CLI command exactly as you would in the terminal
    and pipes the output directly into findings.json.
    """
    print("==================================================")
    print(f"[STEP 1A] Running Static Code Analysis on '{target_dir}/'")
    print("==================================================")
    
    if not os.path.exists(target_dir):
        print(f"Error: The target directory '{target_dir}' does not exist.")
        return False
    
    try:
        command = f"semgrep scan --config ./rules/ {target_dir} --json > findings.json"
        
        result = subprocess.run(
            command, 
            shell=True, 
            text=True, 
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace"
        )
        
        if result.returncode not in [0, 1]:
            print(f"Semgrep Error:\n{result.stderr}")
            return False
            
        print("Semgrep scan complete! Output saved to findings.json.\n")
        return True
        
    except Exception as e:
        print(f"Failed to execute Semgrep: {str(e)}")
        return False

def run_tree_sitter_extraction(target_dir="samples"):
    """
    Uses Tree-sitter natively to parse all Java files and extract 
    logic skeletons for authorization auditing.
    """
    print("==================================================")
    print(f"[STEP 1B] Running Tree-sitter Semantic Extractor")
    print("==================================================")
    
    direct_files = glob.glob(f"{target_dir}/*.java")
    nested_files = glob.glob(f"{target_dir}/**/*.java", recursive=True)
    java_files = list(set(direct_files + nested_files))
    all_skeletons = []
    
    for file_path in java_files:
        skeletons = build_logic_skeletons(file_path)
        if skeletons:
            for skel in skeletons:
                all_skeletons.append({"file": file_path, "skeleton": skel})
                
    print(f"Extracted {len(all_skeletons)} logic skeletons for business logic review.\n")
    return all_skeletons

import json # Ensure json is imported at the top of run.py

def run_gitleaks_scan(target_dir="samples"):
    """
    Executes the Gitleaks CLI to scan for high-entropy strings and hardcoded secrets.
    Uses --no-git to scan the raw directory even if it isn't a Git repository.
    """
    print("==================================================")
    print(f"[STEP 1C] Running Entropy/Secret Scan (Gitleaks)")
    print("==================================================")
    
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Absolute path to gitleaks.exe (assumed to live beside this script)
        gitleaks_bin = os.path.join(current_dir, "gitleaks.exe")

        # Resolve the target directory to an absolute path relative to this script
        target_abs = os.path.abspath(os.path.join(current_dir, target_dir))

        # Verify the file actually exists before trying to run it
        if not os.path.exists(gitleaks_bin):
            print(f"🚨 GITLEAKS ERROR: Cannot find executable at:\n{gitleaks_bin}")
            print("Ensure you placed the gitleaks.exe file into this folder.\n")
            return False

        # Wrap the paths in quotes to handle any spaces in Windows folder names
        command = (
            f'"{gitleaks_bin}" detect --no-git '
            f'--source "{target_abs}" --report-format json '
            f'--report-path gitleaks_findings.json'
        )

        # Capture both stdout and stderr as text
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        # If the process produced stderr or a non-zero exit code, print it for diagnostics
        if result.returncode not in [0, 1]:
            print("🚨 GITLEAKS ERROR: Execution crashed.")
            if result.stderr:
                print("--- STDERR ---")
                print(result.stderr)
            return False

        # Success: check for output file
        if os.path.exists("gitleaks_findings.json"):
            print("Gitleaks scan complete! Output saved to gitleaks_findings.json.\n")
            return True

        if result.stdout:
            print("Gitleaks completed but no report found. STDOUT:")
            print(result.stdout)

        print("Gitleaks ran successfully, but found 0 secrets.\n")
        return False
        
    except Exception as e:
        print(f"Failed to execute Gitleaks: {str(e)}")
        return False

def execute_master_pipeline():
    
    # 1A. Trigger the Syntax Scanner (Semgrep)
    if not run_semgrep_scan():
        print("Pipeline aborted at Step 1A.")
        sys.exit(1)
        
    # 1B. Trigger the Semantic Extractor (Tree-sitter)
    logic_skeletons = run_tree_sitter_extraction()

    # 1C. Trigger the Secret Scanner (Gitleaks)
    run_gitleaks_scan()
        
    # 2. Trigger the Database Ingestion (Static Rules)
    print("==================================================")
    print("[STEP 2] Updating Vector Database (Chroma DB)")
    print("==================================================")
    initialize_knowledge_base()
    print("\n")
    
    # 3A. Trigger the AI Reviewer for Structural Bugs
    print("==================================================")
    print("[STEP 3A] Executing AI Code Reviewer (Semgrep Findings)")
    print("==================================================")
    run_pipeline() 
    reviewer = CodeReviewer(model_name="qwen2.5:7b")
    
    # 3B. Trigger the AI Reviewer for Business Logic Flaws
    print("\n==================================================")
    print("[STEP 3B] Executing AI Logic Auditor (Tree-sitter Skeletons)")
    print("==================================================")
    
    if logic_skeletons:
        
        for item in logic_skeletons:
            print(f"[*] Auditing endpoint in: {item['file']}")
            
            ai_verdict = reviewer.evaluate_logic_skeleton(item['skeleton'], item['file'])
            
            if ai_verdict and ai_verdict.get("is_vulnerable"):
                print(f"   🚨 LOGIC FLAW: {ai_verdict.get('cwe_id')} ({ai_verdict.get('confidence_level')} confidence)")
                print(f"   Reason: {ai_verdict.get('reasoning')}\n")
            else:
                print("   ✅ Logic appears secure.\n")
    else:
        print("No web endpoints found to analyze for logic flaws.")

# 3C. Trigger the AI Reviewer for Hardcoded Secrets
    print("\n==================================================")
    print("[STEP 3C] Executing AI Secret Remediator (Gitleaks Findings)")
    print("==================================================")
    if os.path.exists("gitleaks_findings.json"):
        with open("gitleaks_findings.json", "r", encoding="utf-8") as f:
            try:
                gitleaks_data = json.load(f)
            except json.JSONDecodeError:
                gitleaks_data = []

        if gitleaks_data:
            for finding in gitleaks_data:
                target_file = finding.get("File", "Unknown")
                line_num = finding.get("StartLine", 0)
                rule_id = finding.get("RuleID", "Generic Secret")
                snippet = finding.get("Match", "Hidden by scanner")

                print(f"[*] Found {rule_id} in {target_file} at line {line_num}")
                fix = reviewer.generate_secret_remediation(target_file, line_num, rule_id, snippet)
                
                print("\n================ AI SECURE FIX ================")
                print(fix)
                print("===============================================\n")
        else:
            print("   ✅ No hardcoded secrets detected.\n")
    
    print("\n==================================================")
    print("         PIPELINE COMPLETED SUCCESSFULLY          ")
    print("==================================================")

if __name__ == "__main__":
    execute_master_pipeline()