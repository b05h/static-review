import json
import chromadb
import os
import glob

def initialize_knowledge_base():
    # 1. Initialize local persistent Chroma DB client
    # This creates a folder on your local disk to store the vector data safely offline
    client = chromadb.PersistentClient(path="./chroma_db")
    
    # 2. Create or get the collection
    collection = client.get_or_create_collection(name="owasp_kb")
        
    documents = []
    metadatas = []
    ids = []
    
    target_folder = "rag_docs"
    search_pattern = os.path.join(target_folder, "*.json")
    json_files = glob.glob(search_pattern)
    
    if not json_files:
        print(f"Error: No JSON files found in '{target_folder}/'. Please check your folder structure.")
        return

    print(f"3. Found {len(json_files)} knowledge base files. Processing...\n")
    
    # Loop through every file found by glob
    for file_path in json_files:
        print(f"   -> Reading {file_path}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                kb_data = json.load(f)


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
        except json.JSONDecodeError:
            print(f"   [WARNING] Skipping {file_path}: Invalid JSON format. Check for missing commas.")

    print(f"\n4. Ingesting {len(documents)} total vulnerabilities into Chroma DB...")
        
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