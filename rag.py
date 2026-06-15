import os

def load_docs(dir_path=None):
    if dir_path is None:
        dir_path = os.path.join(os.path.dirname(__file__), 'rag_docs')
    docs = {}
    if not os.path.isdir(dir_path):
        return docs
    for nm in os.listdir(dir_path):
        path = os.path.join(dir_path, nm)
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as fh:
                docs[nm] = fh.read()
    return docs
