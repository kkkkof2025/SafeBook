import os, re, sys

# Force UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

docs = 'X:/c/ai/Safe/docs'

# 1. Chapter stats
chapters = {}
for d in sorted(os.listdir(docs)):
    dpath = os.path.join(docs, d)
    if not os.path.isdir(dpath):
        continue
    files = [f for f in os.listdir(dpath) if f.endswith('.md')]
    if not files:
        continue
    chapters[d] = files

print('=== CHAPTERS ===')
for d, files in sorted(chapters.items()):
    bar = '#' * len(files)
    print(f'  {d:30s} [{len(files):2d}] {bar}')

total = sum(len(v) for v in chapters.values())
print(f'\nTotal: {total} articles in {len(chapters)} chapters')

# 2. Check mkdocs nav coverage
with open('X:/c/ai/Safe/mkdocs.yml', 'r', encoding='utf-8') as f:
    mkdocs = f.read()

all_doc_files = set()
for d, files in chapters.items():
    for f in files:
        all_doc_files.add(f'{d}/{f}')

in_nav = set()
for d, files in chapters.items():
    for f in files:
        if f'{d}/{f}' in mkdocs:
            in_nav.add(f'{d}/{f}')

missing = all_doc_files - in_nav
print(f'\nNav coverage: {len(in_nav)}/{len(all_doc_files)}')
if missing:
    print('Missing from nav:')
    for m in sorted(missing):
        print(f'  {m}')

# 3. Build warnings
import subprocess
result = subprocess.run(['mkdocs', 'build', '--clean'],
                       cwd='X:/c/ai/Safe',
                       capture_output=True, timeout=60)
output = (result.stdout + b'\n' + result.stderr).decode('utf-8', 'replace')
warnings = [l for l in output.split('\n') if 'WARNING' in l]
notfound = [l for l in warnings if 'not found' in l.lower()]
orphan = [l for l in warnings if 'not included' in l.lower()]
print(f'\nBuild warnings: {len(warnings)} total')
print(f'  Not found links: {len(notfound)}')
print(f'  Orphan pages: {len(orphan)}')
for w in notfound:
    print(f'    {w.strip()[:150]}')
for w in orphan:
    print(f'    {w.strip()[:150]}')
