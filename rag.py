import chromadb
from chromadb.utils import embedding_functions

class SecurityKnowledgeBase:
    def __init__(self, db_path="./chroma_db"):
        # Initialize the embedding function used during ingestion
        self.embedding_func = embedding_functions.DefaultEmbeddingFunction()
        
        # Connect to the local database
        self.client = chromadb.PersistentClient(path=db_path)
        
        # Open the collection WITH the embedding function attached
        # (This is required so the Tree-sitter semantic search works later)
        self.collection = self.client.get_collection(
            name="owasp_kb", 
            embedding_function=self.embedding_func
        )

    # ==========================================
    # TRACK A: SEMGREP LOGIC (Exact Metadata Match)
    # ==========================================
    def get_context_for_vulnerability(self, cwe_id):
        """
        Searches Chroma DB for a specific CWE ID. 
        Used when Semgrep already knows the exact vulnerability.
        """
        print(f"   [*] Exact Match Search for {cwe_id}...")
        
        # Bypasses fuzzy search, goes straight for the metadata ID
        results = self.collection.get(
            where={"cwe_id": cwe_id}
        )

        if results and len(results['documents']) > 0:
            return results['documents'][0]
        else:
            return None

    # ==========================================
    # TRACK B: TREE-SITTER LOGIC (Semantic Search)
    # ==========================================
    def retrieve_cwe_rules_from_skeleton(self, endpoint_skeleton, n_results=1):
        """
        Takes the Tree-sitter logic skeleton, embeds it on the fly, and 
        semantically searches Chroma DB for the closest matching OWASP rule.
        """
        print(f"   [*] Semantic Search for Logic Skeleton...")
        try:
            # Uses vector embedding to find the conceptual match
            results = self.collection.query(
                query_texts=[endpoint_skeleton],
                n_results=n_results
            )
            
            if results['documents'] and len(results['documents'][0]) > 0:
                retrieved_doc = results['documents'][0][0]
                metadata = results['metadatas'][0][0]
                
                print(f"   [+] Semantic Match: {metadata.get('cwe_id', 'Unknown')} - {metadata.get('title', 'Rule')}")
                return retrieved_doc
            else:
                return "No specific framework rules retrieved."
                
        except Exception as e:
            print(f"   [-] RAG Retrieval Error: {str(e)}")
            return "Error accessing knowledge base."

# --- Quick Test Block ---
if __name__ == "__main__":
    kb = SecurityKnowledgeBase()
    
    print("\n--- TESTING TRACK A (SEMGREP) ---")
    exact_context = kb.get_context_for_vulnerability("CWE-89")
    if exact_context:
        print("Success: Retrieved exact match for CWE-89.")
    else:
        print("Not found.")
    
    print("\n--- TESTING TRACK B (TREE-SITTER) ---")
    test_skeleton = "[ENDPOINT SKELETON]\nRoute: @DeleteMapping('/user/{id}')\nSecurity Annotations: None"
    semantic_context = kb.retrieve_cwe_rules_from_skeleton(test_skeleton)
    print(semantic_context)