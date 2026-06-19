import json
import chromadb

def initialize_knowledge_base():
    # 1. Initialize local persistent Chroma DB client
    # This creates a folder on your local disk to store the vector data safely offline
    client = chromadb.PersistentClient(path="./chroma_db")
    
    # 2. Create or get the collection
    collection = client.get_or_create_collection(name="owasp_kb")
    
    # 3. Load your combined JSON file
    json_path = "rag_docs/owasp_kb.json"
    with open(json_path, "r") as f:
        kb_data = json.load(f)
        
    documents = []
    metadatas = []
    ids = []
    
    # 4. Process each CWE entry for the database
    for cwe_id, content in kb_data.items():
        # Combine the problem and mitigation text so the LLM gets full context in one search
        full_context_text = (
            f"Vulnerability: {content['name']}\n"
            f"Category: {content['owasp_category']}\n"
            f"Problem Explanation: {content['problem_explanation']}\n"
            f"Remediation Standard: {content['mitigation_name']}\n"
            f"Fix Instructions: {content['mitigation_description']}"
        )
        
        documents.append(full_context_text)
        
        # Add metadata tags so we can do strict lookups by CWE
        metadatas.append({
            "cwe_id": cwe_id,
            "mitre_technique": content["mitre_technique"],
            "owasp_category": content["owasp_category"],
            "url": content["url"]
        })
        
        ids.append(f"kb_{cwe_id.lower()}")
        
    # 5. Insert data into Chroma DB
    # Chroma handles tokenizing and generating embeddings locally automatically
    collection.add(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )
    
    print(f"Successfully initialized Chroma DB with {len(documents)} vulnerabilities.")

if __name__ == "__main__":
    initialize_knowledge_base()