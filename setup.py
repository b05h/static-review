import os
import subprocess
import sys

def print_header(title):
    print("\n" + "="*50)
    print(f" ⚙️  {title}")
    print("="*50)

def run_command(command, error_msg):
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"\n🚨 ERROR: {error_msg}")
        return False

def setup_environment():
    print_header("Environment Setup")
    
    # 1. Install Python Dependencies
    print("[1/5] Installing Python dependencies from requirements.txt...")
    if not os.path.exists("requirements.txt"):
        print("🚨 ERROR: requirements.txt not found!")
        sys.exit(1)
        
    if not run_command(f"{sys.executable} -m pip install -r requirements.txt", "Failed to install pip requirements."):
        sys.exit(1)

    # 2. Setup Folder Structure
    print("\n[2/5] Building local directory structures...")
    directories = ["samples", "rules", "chroma_db"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"  -> Verified directory: ./{directory}/")

    # 3. Verify Gitleaks Binary
    print("\n[3/5] Verifying external security binaries...")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    gitleaks_bin = os.path.join(current_dir, "gitleaks.exe") # Change to "gitleaks" if primarily targeting Linux/Mac
    
    if os.path.exists(gitleaks_bin):
        print("  -> ✅ Gitleaks binary detected.")
    else:
        print(f"  -> ⚠️  WARNING: gitleaks.exe not found in root directory.")
        print("     Track C (Secrets Scanning) will fail until you place the binary here.")

    # 4. Pull Local LLMs via Ollama
    print("\n[4/5] Configuring Local AI Models (Requires Internet for initial pull)...")
    models = ["qwen2.5:3b", "qwen2.5:7b"]
    for model in models:
        print(f"  -> Pulling {model}...")
        run_command(f"ollama pull {model}", f"Failed to pull {model}. Is Ollama installed and running?")

    # 5. Final Verification
    print_header("Setup Complete!")
    print("System is configured and ready for offline execution.")
    print("\nTo launch the DevSecOps Dashboard, run:")
    print("  streamlit run app.py\n")

if __name__ == "__main__":
    setup_environment()