import chromadb

class SecurityKnowledgeBase:
    def __init__(self, db_path="./chroma_db"):
        # Connect to the local database we just created
        self.client = chromadb.PersistentClient(path=db_path)
        
        # Open the specific collection where our OWASP data lives
        self.collection = self.client.get_collection(name="owasp_kb")

    def get_context_for_vulnerability(self, cwe_id):
        """
        Searches Chroma DB for a specific CWE ID and returns the problem and fix.
        """
        print(f"Searching Knowledge Base for {cwe_id}...")
        
        # Use a metadata filter to get the exact match, bypassing fuzzy search
        results = self.collection.get(
            where={"cwe_id": cwe_id}
        )

        # Check if we actually found a match in our database
        if results and len(results['documents']) > 0:
            print("Match found in Knowledge Base!")
            # Return the text we formatted during the ingest step
            return results['documents'][0]
        else:
            print(f"No OWASP mitigation found for {cwe_id}.")
            return None

# --- Quick Test Block ---
# If you run `python rag.py` directly, it will test the database lookup.
if __name__ == "__main__":
    # Simulate Semgrep finding a SQL Injection
    kb = SecurityKnowledgeBase()
    
    test_cwe = "CWE-89"
    context = kb.get_context_for_vulnerability(test_cwe)
    
    if context:
        print("\n--- WHAT THE LLM WILL SEE ---")
        print(context)
        print("-----------------------------\n")