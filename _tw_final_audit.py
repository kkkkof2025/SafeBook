import os, re, sys
sys.stdout.reconfigure(encoding='utf-8')

docs = 'X:/c/ai/Safe/docs'

# 1. Full stats
chapters = {}
thin = []
total_size = 0
total_files = 0

for root, dirs, files in os.walk(docs):
    for fname in files:
        if not fname.endswith('.md') or fname == 'SUMMARY.md':
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, docs).replace('\\', '/')
        size = os.path.getsize(fpath)
        total_size += size
        total_files += 1

        dname = rel.split('/')[0]
        if dname not in chapters:
            chapters[dname] = {'count': 0, 'total_size': 0}
        chapters[dname]['count'] += 1
        chapters[dname]['total_size'] += size

        if size < 2000 and fname != 'index.md':
            thin.append((size, rel))

print('=== FINAL AUDIT ===')
print(f'Total: {total_files} articles, {len(chapters)} chapters')
print(f'Total size: {total_size/1024:.1f} KB')
print(f'\nThin articles (<2KB): {len(thin)}')
for size, rel in sorted(thin):
    print(f'  {size:5d}B  {rel}')

# Build warnings
import subprocess
result = subprocess.run(['mkdocs', 'build', '--clean'],
                       cwd='X:/c/ai/Safe',
                       capture_output=True, timeout=120)
output = (result.stdout + b'\n' + result.stderr).decode('utf-8', 'replace')
warnings = [l for l in output.split('\n') if 'WARNING' in l]
notfound = [l for l in warnings if 'not found' in l.lower()]
orphan = [l for l in warnings if 'not included' in l.lower()]

print(f'\nBuild warnings: {len(warnings)}')
print(f'  Not found: {len(notfound)}')
print(f'  Orphan: {len(orphan)}')
for w in notfound:
    print(f'    {w.strip()[:150]}')
