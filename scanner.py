#!/usr/bin/env python3
import os
import sys

def scan(path='.'):
    findings = []
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith('.java') or f.endswith('.py'):
                fp = os.path.join(root, f)
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                        text = fh.read().lower()
                        if 'password' in text or 'secret' in text:
                            findings.append((fp, 'possible hardcoded secret'))
                except Exception:
                    continue
    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    for p, msg in scan(target):
        print(f"{p}: {msg}")
