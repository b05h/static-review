import json
import ollama
from rag import SecurityKnowledgeBase

class CodeReviewer:
    def __init__(self, model_name="qwen2.5:7b"):
        self.model_name = model_name
        self.kb = SecurityKnowledgeBase()

    # ==========================================
    # TRACK A: SEMGREP (Structural Code Fixes)
    # ==========================================
    def generate_secure_fix(self, file_path, cwe_id, line_number, vulnerable_code, severity="UNKNOWN", likelihood="UNKNOWN", impact="UNKNOWN", references=None):
        owasp_context = self.kb.get_context_for_vulnerability(cwe_id)
        
        if not owasp_context:
            owasp_context = "No specific company security standard defined for this vulnerability yet. Use general secure coding best practices."

        ref_string = "\n".join([f"- {ref}" for ref in references]) if references else "None provided."

        prompt = f"""You are an elite automated secure code reviewer. Your task is to rewrite vulnerable code snippets according to strict industry standards.

[VULNERABILITY ALERT]
File: {file_path}
Line: {line_number}
Detected Flaw: {cwe_id}

[THREAT INTELLIGENCE]
Severity: {severity}
Likelihood: {likelihood}
Impact: {impact}

Contextual Note: Adjust your rigor based on these metrics. If Impact or Severity is HIGH, you must ensure the fix is absolutely airtight, leaving zero margin for edge-case exploits.

[MANDATORY SECURITY RULES FROM KNOWLEDGE BASE]
{owasp_context}

[VULNERABLE CODE SNIPPET]
--- START JAVA CODE ---
{vulnerable_code}
--- END JAVA CODE ---

[INSTRUCTIONS]
1. Analyze the vulnerable code snippet and identify how it violates the mandatory security rules provided above.
2. Provide a brief, direct explanation of the flaw (1-2 sentences).
3. Provide the completely rewritten, secure version of the code. 
4. Ensure your fix strictly complies with the instructions in the Remediation Standard. Do not introduce any other external dependencies unless explicitly instructed.
5. If helpful, briefly mention how the fix mitigates the specific 'Likelihood' or 'Impact' listed in the Threat Intelligence section.

Respond in clean Markdown format with a section for 'Analysis' and a section for 'Secure Fix' containing the code block."""

        print(f"Sending prompt to local model '{self.model_name}' via Ollama...")
        
        try:
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                options={
                    "temperature": 0.1,
                    "top_p": 0.9
                }
            )
            return response['response']
            
        except Exception as e:
            return f"Error communicating with local Ollama server: {str(e)}"

    # ==========================================
    # TRACK B: TREE-SITTER (Business Logic Audit)
    # ==========================================
    def evaluate_logic_skeleton(self, endpoint_skeleton, file_path):
        """
        Takes an endpoint skeleton, embeds it on the fly to get RAG context, 
        and forces the LLM to output a JSON evaluation of the business logic.
        """
        # 1. On-the-fly RAG search using the new method in rag.py
        rag_context = self.kb.retrieve_cwe_rules_from_skeleton(endpoint_skeleton)
        
        prompt = f"""
        You are an expert Application Security Engineer auditing a codebase for Business Logic Flaws, specifically Broken Access Control and Insecure Direct Object References (IDOR).

        [ENDPOINT SKELETON]
        File: {file_path}
        {endpoint_skeleton}

        [COMPANY MITIGATION STANDARDS (RAG CONTEXT)]
        {rag_context}

        [INSTRUCTIONS]
        Analyze the endpoint skeleton. Look for high-privilege actions (like deleting, fetching, or modifying data) that lack corresponding security annotations (e.g., @PreAuthorize, @RolesAllowed) or fail to check if the user requesting the action actually owns the data.
        
        You must output your decision strictly as a valid JSON object matching this exact schema:
        {{
            "is_vulnerable": true or false,
            "cwe_id": "string (e.g., CWE-284, CWE-639, or null)",
            "confidence_level": "string (HIGH, MEDIUM, LOW)",
            "reasoning": "string (1-2 sentences explaining why the logic is broken or why it is secure)"
        }}
        """

        print(f"Auditing logic skeleton with '{self.model_name}'...")
        
        try:
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                format="json", # IMPORTANT: This forces Ollama to return raw, valid JSON
                options={
                    "temperature": 0.1, # Keep logic strict
                    "top_p": 0.9
                }
            )
            
            raw_output = response['response'].strip()
            
            # The 'format="json"' parameter guarantees valid JSON, so we can parse it directly
            decision = json.loads(raw_output)
            return decision

        except json.JSONDecodeError:
            print("   [-] Error: LLM did not return valid JSON.")
            return None
        except Exception as e:
            print(f"   [-] AI Execution Error: {str(e)}")
            return None
        
        
    # ==========================================
    # TRACK C: GITLEAKS (Credential Remediation)
    # ==========================================
    def generate_secret_remediation(self, file_path, line_number, rule_id, secret_snippet):
        """
        Takes a Gitleaks finding and forces the LLM to rewrite the code 
        using secure environment variables.
        """
        prompt = f"""You are an elite Application Security Engineer responding to a critical credential leak.

[CREDENTIAL EXPOSURE ALERT]
File: {file_path}
Line: {line_number}
Detection Rule: {rule_id}

[EXPOSED SNIPPET]
{secret_snippet}

[INSTRUCTIONS]
1. Briefly explain why hardcoding this specific type of secret ({rule_id}) is a critical risk.
2. Provide a completely rewritten, secure version of the code that fetches this value from an environment variable (e.g., System.getenv() in Java) or a secure properties configuration.
3. You MUST remove the actual hardcoded secret from your code output entirely.

Respond in clean Markdown format with a section for 'Analysis' and a section for 'Secure Fix' containing the code block."""

        print(f"   [*] Remediating exposed {rule_id} with '{self.model_name}'...")
        try:
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                options={"temperature": 0.1, "top_p": 0.9}
            )
            return response['response']
        except Exception as e:
            return f"Error communicating with local Ollama server: {str(e)}"

# ==========================================
# EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    reviewer = CodeReviewer(model_name="qwen2.5:7b")
    
    print("==================================================")
    print("TESTING TRACK A: SEMGREP FINDING")
    print("==================================================")
    ai_review = reviewer.generate_secure_fix(
        file_path="samples/Test.java",
        cwe_id="CWE-89",
        line_number=14,
        vulnerable_code='String query = "SELECT * FROM users WHERE username = \'" + userInput + "\'";\nStatement stmt = connection.createStatement();\nResultSet rs = stmt.executeQuery(query);',
        severity="ERROR",
        likelihood="HIGH",
        impact="HIGH",
        references=["https://owasp.org/Top10/A03_2021-Injection"]
    )
    print(ai_review)
    
    print("\n==================================================")
    print("TESTING TRACK B: TREE-SITTER LOGIC SKELETON")
    print("==================================================")
    mock_skeleton = """
    [ENDPOINT SKELETON]
    - Route: @DeleteMapping("/profile/{id}")
    - Method Name: deleteProfile
    - Input Parameters: (HttpServletRequest request, @PathVariable String id)
    - Security Annotations: None detected on method.
    - Key Actions:
      - repository.deleteById(id);
    """
    
    decision = reviewer.evaluate_logic_skeleton(mock_skeleton, "samples/UserController.java")
    if decision:
        print(json.dumps(decision, indent=4))