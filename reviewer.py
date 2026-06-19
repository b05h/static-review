import ollama
from rag import SecurityKnowledgeBase

class CodeReviewer:
    def __init__(self, model_name="qwen2.5:3b"):
        self.model_name = model_name
        self.kb = SecurityKnowledgeBase()

    def generate_secure_fix(self, file_path, cwe_id, line_number, vulnerable_code):
        owasp_context = self.kb.get_context_for_vulnerability(cwe_id)
        
        if not owasp_context:
            print(f"Proceeding with generic LLM review (No local KB context found for {cwe_id}).")
            owasp_context = "No specific company security standard defined for this vulnerability yet. Use general secure coding best practices."

        prompt = f"""You are an elite automated secure code reviewer. Your task is to rewrite vulnerable code snippets according to strict industry standards.

[VULNERABILITY ALERT]
File: {file_path}
Line: {line_number}
Detected Flaw: {cwe_id}

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
# EXECUTION BLOCK (So the file actually runs)
# ==========================================
if __name__ == "__main__":
    # Initialize the reviewer
    reviewer = CodeReviewer(model_name="qwen2.5:3b")
    
    # Simulate a finding sent from your Semgrep parser
    target_file = "samples/Test.java"
    detected_cwe = "CWE-89"
    target_line = 14
    broken_java_code = 'String query = "SELECT * FROM users WHERE username = \'" + userInput + "\'";\nStatement stmt = connection.createStatement();\nResultSet rs = stmt.executeQuery(query);'
    
    print("Starting simulated Code Review...\n")
    
    # Run the automated review
    ai_review = reviewer.generate_secure_fix(
        file_path=target_file,
        cwe_id=detected_cwe,
        line_number=target_line,
        vulnerable_code=broken_java_code
    )
    
    print("\n================ AI REVIEW OUTPUT ================")
    print(ai_review)
    print("==================================================")