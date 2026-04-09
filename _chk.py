"""Проверить script.js."""
import re
with open(r'C:\D\_git\falogviewerv2\web\static\script.js', 'r', encoding='utf-8') as f:
    content = f.read()

for m in ['addTargetRow', 'loadMachinesFile', 'manual-targets', 'use_machines_file']:
    print(f"\n=== {m} ===")
    for match in re.finditer(m, content):
        line = content[:match.start()].count('\n') + 1
        start = content.rfind('\n', max(0, match.start()-40), match.start())
        end = content.find('\n', match.end())
        if end < 0: end = len(content)
        if start < 0: start = 0
        print(f"  L{line}: {content[start:end].strip()}")
