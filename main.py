from reviewer import review
import json
import sys

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(json.dumps(review(target), indent=2))
