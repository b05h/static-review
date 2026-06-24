import streamlit as st
import os
import json
import glob
import pandas as pd
import altair as alt

# Import your existing pipeline modules
from ingest_kb import initialize_knowledge_base
from semantic_extractor import build_logic_skeletons
from reviewer import CodeReviewer
from run import run_semgrep_scan, run_gitleaks_scan
from main import parse_semgrep_json

# --- UI CONFIGURATION ---
st.set_page_config(page_title="AI-Augmented Code Scanner", page_icon="🛡️", layout="wide")

st.title("🛡️ :blue[AI-Augmented Multi-Phase Static Code Security Scanner]")

st.markdown("An autonomous security pipeline utilizing **Semgrep**, **Tree-sitter**, **Gitleaks**, and **Qwen 2.5**.")

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("⚙️ Pipeline Controls")
    target_dir = st.text_input("Target Directory:", value="samples")
    model_choice = st.selectbox("AI Model Engine:", ["qwen2.5:7b", "qwen2.5:3b"])
    
    st.divider()
    st.markdown("**Active Engines:**")
    st.markdown("- 🔍 Syntax: `Semgrep`\n- 🧠 Semantic: `Tree-sitter`\n- 🔑 Entropy: `Gitleaks`")
    
    st.divider()
    start_scan = st.button("🚀 Initiate Security Sweep", use_container_width=True, type="primary")

# --- MAIN DASHBOARD LOGIC ---
if start_scan:
    st.divider()
    
    # 1. Create an empty placeholder at the top. 
    # We will fill this with the Executive Summary and Graph AFTER the scan finishes.
    summary_placeholder = st.empty()
    
    # Tracking variables for the summary
    findings_list = []
    sast_count = 0
    logic_count = 0
    secrets_count = 0

    reviewer = CodeReviewer(model_name=model_choice)

    # ==========================================
    # PHASE 1: SAST (Track A)
    # ==========================================
    st.header("Phase 1: Static Application Security Testing", divider="blue")
    st.caption("Scanning for syntax-level vulnerabilities and cryptographic failures.")
    
    with st.spinner("Executing SAST sweep via Semgrep..."):
        if run_semgrep_scan(target_dir):
            findings = parse_semgrep_json("findings.json")
            if findings:
                sast_count = len(findings)
                initialize_knowledge_base() 
                
                for idx, finding in enumerate(findings):
                    anchor_name = f"sast-flaw-{idx}"
                    filename = os.path.basename(finding['file'])
                    findings_list.append({"title": f"SAST: {finding['cwe']} in {filename}", "anchor": anchor_name})
                    
                    with st.container(border=True):
                        # Colored Title
                        st.subheader(f":red[🚨 {finding['cwe']}]", anchor=anchor_name)
                        
                        col1, col2 = st.columns(2)
                        col1.markdown(f"**📂 File:** `{finding['file']}`")
                        col2.markdown(f"**🔢 Line:** `{finding['line']}`")
                        
                        st.code(finding['code'], language="java")
                        
                        # Colored Header, Standard Text
                        st.markdown("**:blue[🧠 AI Secure Remediation:]**")
                        with st.spinner("Generating a secure fix..."):
                            fix = reviewer.generate_secure_fix(
                                file_path=finding["file"],
                                cwe_id=finding["cwe"],
                                line_number=finding["line"],
                                vulnerable_code=finding["code"]
                            )
                            st.markdown(fix)
            else:
                st.success("✅ No SAST vulnerabilities detected.")
        else:
            st.error("Semgrep scan failed. Check terminal for details.")

    # ==========================================
    # PHASE 2: BUSINESS LOGIC (Track B)
    # ==========================================
    st.header("Phase 2: Business Logic & Authorization Auditing", divider="violet")
    st.caption("Extracting ASTs to evaluate endpoint authorization and access control logic.")
    
    with st.spinner("Auditing semantic logic via Tree-sitter..."):
        direct = glob.glob(f"{target_dir}/*.java")
        nested = glob.glob(f"{target_dir}/**/*.java", recursive=True)
        java_files = list(set(direct + nested))
        
        for file_path in java_files:
            skeletons = build_logic_skeletons(file_path)
            if skeletons:
                for skel in skeletons:
                    ai_verdict = reviewer.evaluate_logic_skeleton(skel, file_path)
                    
                    if ai_verdict and ai_verdict.get("is_vulnerable"):
                        logic_count += 1
                        anchor_name = f"logic-flaw-{logic_count}"
                        filename = os.path.basename(file_path)
                        findings_list.append({"title": f"Logic: {ai_verdict.get('cwe_id')} in {filename}", "anchor": anchor_name})
                        
                        with st.container(border=True):
                            # Colored Title
                            st.subheader(f":violet[🧠 {ai_verdict.get('cwe_id')}]", anchor=anchor_name)
                            st.markdown(f"**📂 File:** `{file_path}`")
                            st.markdown(f"**Confidence Level:** `{ai_verdict.get('confidence_level').title()}`")
                            
                            # Colored Header, Standard Text
                            st.markdown("**:violet[AI Analysis & Reasoning:]**")
                            st.markdown(ai_verdict.get('reasoning'))
                                
                            st.markdown("**:gray[Extracted Endpoint Logic:]**")
                            st.code(skel, language="markdown")
        
        if logic_count == 0:
            st.success("✅ No business logic or authorization flaws detected.")

    # ==========================================
    # PHASE 3: SECRETS SCANNING (Track C)
    # ==========================================
    st.header("Phase 3: Hardcoded Secrets & Credential Exposure", divider="red")
    st.caption("Scanning for high-entropy strings, tokens, and private keys via Gitleaks.")
    
    with st.spinner("Executing entropy scan..."):
        run_gitleaks_scan(target_dir)
        
        if os.path.exists("gitleaks_findings.json"):
            try:
                with open("gitleaks_findings.json", "r", encoding="utf-8") as f:
                    gitleaks_data = json.load(f)
            except:
                gitleaks_data = []

            if gitleaks_data:
                secrets_count = len(gitleaks_data)
                for idx, finding in enumerate(gitleaks_data):
                    anchor_name = f"secret-flaw-{idx}"
                    rule_id = finding.get("RuleID", "Secret")
                    target_file = finding.get("File", "Unknown")
                    filename = os.path.basename(target_file)
                    
                    findings_list.append({"title": f"Secret: {rule_id} in {filename}", "anchor": anchor_name})
                    
                    with st.container(border=True):
                        # Colored Title
                        st.subheader(f":red[🔑 Leak: {rule_id}]", anchor=anchor_name)
                        
                        col1, col2 = st.columns(2)
                        col1.markdown(f"**📂 File:** `{target_file}`")
                        col2.markdown(f"**🔢 Line:** `{finding.get('StartLine', 0)}`")
                        
                        st.code(finding.get("Match", ""), language="java")
                        
                        # Colored Header, Standard Text
                        st.markdown("**:green[🛡️ Secure Vault Remediation:]**")
                        with st.spinner("Generating environment variable mapping..."):
                            fix = reviewer.generate_secret_remediation(
                                target_file, finding.get("StartLine", 0), rule_id, finding.get("Match", "")
                            )
                            st.markdown(fix)
            else:
                st.success("✅ No hardcoded secrets detected.")
        else:
            st.success("✅ No hardcoded secrets detected.")
            
    # ==========================================
    # POPULATE TOP SUMMARY DASHBOARD
    # ==========================================
    with summary_placeholder.container():
        st.subheader("📊 Executive Summary & Quick Navigation", divider="gray")
        
        # Split the top area into a list of links (left) and the graph (right)
        sum_col1, sum_col2 = st.columns([3, 2])
        
        with sum_col1:
            if not findings_list:
                st.success("✅ Perfect Scan! No vulnerabilities detected across any phase.")
            else:
                st.markdown("**Detected Vulnerabilities (Click to Jump):**")
                for item in findings_list:
                    # Markdown syntax for anchor links
                    st.markdown(f"- [{item['title']}](#{item['anchor']})")
                    
        with sum_col2:
            # Create a lean, multi-colored horizontal bar chart using Altair
            chart_data = pd.DataFrame({
                "Phase": ["Phase 1: SAST", "Phase 2: Logic", "Phase 3: Secrets"],
                "Count": [sast_count, logic_count, secrets_count]
            })
            
            lean_chart = alt.Chart(chart_data).mark_bar(size=20).encode(
                x=alt.X('Count:Q', title='', axis=alt.Axis(tickMinStep=1)),
                y=alt.Y('Phase:N', title='', sort=None, axis=alt.Axis(labelLimit=150)),
                # Use a built-in category color scheme for multiple colors
                color=alt.Color('Phase:N', legend=None, scale=alt.Scale(scheme='category10')),
                tooltip=['Phase', 'Count']
            ).properties(height=150) # Keeps the chart small and lean
            
            st.altair_chart(lean_chart, use_container_width=True)