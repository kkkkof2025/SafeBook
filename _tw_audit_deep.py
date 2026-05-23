import os, re, json, subprocess, collections

docs = 'X:/c/ai/Safe/docs'

# 1. Per-chapter stats
chapters = collections.defaultdict(lambda: {'count': 0, 'size': 0, 'files': [], 'thin': []})
root_files = []

for root, dirs, files in os.walk(docs):
    for fname in files:
        if not fname.endswith('.md'):
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, docs).replace('\\', '/')
        size = os.path.getsize(fpath)

        if '/' not in rel:  # root level
            root_files.append((size, rel))
            continue

        ch = rel.split('/')[0]
        chapters[ch]['count'] += 1
        chapters[ch]['size'] += size
        chapters[ch]['files'].append((size, rel))

        if size < 3000 and fname != 'index.md':
            chapters[ch]['thin'].append((size, rel))

# Report
total = sum(c['count'] for c in chapters.values()) + len(root_files)
total_kb = sum(c['size'] for c in chapters.values()) + sum(s for s,_ in root_files)

print(f'Total: {total} articles in {len(chapters)} chapters + {len(root_files)} root files = {total_kb/1024:.1f} KB\n')

# Chapters with < 5 articles
shallow = []
for name, info in sorted(chapters.items()):
    if info['count'] < 5:
        shallow.append((name, info['count']))
print(f'Shallow chapters (<5 articles): {len(shallow)}')
for name, cnt in shallow:
    print(f'  {name}: {cnt} articles')

# Still thin after expansion (<3KB, not index)
all_thin = []
for name, info in chapters.items():
    for size, rel in info['thin']:
        if size < 3000:
            all_thin.append((size, rel))
print(f'\nThin articles (<3KB): {len(all_thin)}')
for size, rel in sorted(all_thin):
    print(f'  {size:5d}B  {rel}')

# 2. Articles without code blocks (no ```)
no_code = []
for root, dirs, files in os.walk(docs):
    for fname in files:
        if not fname.endswith('.md') or fname == 'index.md' or fname == 'SUMMARY.md':
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, docs).replace('\\', '/')
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        if '```' not in content and '~~~' not in content:
            no_code.append(rel)

print(f'\nArticles without code blocks: {len(no_code)}')
for rel in sorted(no_code)[:15]:
    print(f'  {rel}')
if len(no_code) > 15:
    print(f'  ... and {len(no_code)-15} more')

# 3. Missing prev/next links
missing_nav_links = []
for root, dirs, files in os.walk(docs):
    for fname in sorted(files):
        if not fname.endswith('.md') or fname == 'index.md' or fname == 'SUMMARY.md':
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, docs).replace('\\', '/')
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        has_prev = re.search(r'\*上一篇', content)
        has_next = re.search(r'\*下一篇', content)
        if not has_prev or not has_next:
            missing_nav_links.append((rel, bool(has_prev), bool(has_next)))

print(f'\nMissing prev/next links: {len(missing_nav_links)}')
for rel, has_p, has_n in missing_nav_links[:20]:
    missing = []
    if not has_p: missing.append('prev')
    if not has_n: missing.append('next')
    print(f'  {rel} (missing: {", ".join(missing)})')
if len(missing_nav_links) > 20:
    print(f'  ... and {len(missing_nav_links)-20} more')

# 4. Build warnings
result = subprocess.run(['mkdocs', 'build', '--clean'], cwd='X:/c/ai/Safe',
                       capture_output=True, timeout=180)
output = (result.stderr + b'\n' + result.stdout).decode('utf-8', 'replace')
warnings = [l.strip() for l in output.split('\n') if 'WARNING' in l]
print(f'\nBuild warnings: {len(warnings)}')
for w in warnings[:15]:
    print(f'  {w[:200]}')
