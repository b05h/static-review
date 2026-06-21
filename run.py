import subprocess
import sys
import os
from ingest_kb import initialize_knowledge_base
from main import run_pipeline

def run_semgrep_scan(target_dir="samples"):
    """
    Executes the Semgrep CLI command exactly as you would in the terminal
    and pipes the output directly into findings.json.
    """
    print("==================================================")
    print(f"[STEP 1/3] Running Static Code Analysis on '{target_dir}/'")
    print("==================================================")
    
    if not os.path.exists(target_dir):
        print(f"Error: The target directory '{target_dir}' does not exist.")
        return False
    
    try:
        command = f"semgrep scan --config auto {target_dir} --json > findings.json"
        
        # THE FIX: Added encoding="utf-8" and errors="replace". 
        # This forces Python to safely read Semgrep's terminal output without crashing
        # on Windows charmap limitations.
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
        print("Make sure Semgrep is installed and accessible in your system PATH.")
        return False

def execute_master_pipeline():
    # 1. Trigger the Scanner
    if not run_semgrep_scan():
        print("Pipeline aborted at Step 1.")
        sys.exit(1)
        
    # 2. Trigger the Database Ingestion
    print("==================================================")
    print("[STEP 2/3] Updating Vector Database (Chroma DB)")
    print("==================================================")
    initialize_knowledge_base()
    print("\n")
    
    # 3. Trigger the AI Reviewer
    print("==================================================")
    print("[STEP 3/3] Executing AI Code Reviewer (Qwen 2.5)")
    print("==================================================")
    run_pipeline()
    
    print("\n==================================================")
    print("         PIPELINE COMPLETED SUCCESSFULLY          ")
    print("==================================================")

if __name__ == "__main__":
    execute_master_pipeline()