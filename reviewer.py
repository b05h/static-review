from scanner import scan
from rag import load_docs


def review(path='.'):
    docs = load_docs()
    findings = scan(path)
    return {'findings': findings, 'docs': docs}


if __name__ == '__main__':
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(json.dumps(review(target), indent=2))
