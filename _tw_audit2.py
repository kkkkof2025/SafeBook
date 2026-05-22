import os, re, sys
sys.stdout.reconfigure(encoding='utf-8')

docs = 'X:/c/ai/Safe/docs'

# Phase 1: Content quality audit
print("=== CONTENT QUALITY AUDIT ===")
thin_articles = []
no_code = []
no_table = []

for root, dirs, files in os.walk(docs):
    for fname in files:
        if not fname.endswith('.md') or fname == 'SUMMARY.md':
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, docs).replace('\\', '/')
        
        size = os.path.getsize(fpath)
        
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        lines = content.split('\n')
        code_blocks = len(re.findall(r'```', content)) // 2
        has_table = '|' in content and '---' in content
        has_yaml = '```yaml' in content or '```yml' in content
        has_code = code_blocks > 0
        headings = len(re.findall(r'^#{1,4} ', content, re.MULTILINE))
        
        # Skip index.md files (they're navigation)
        if fname == 'index.md':
            continue
            
        if size < 2000:
            thin_articles.append((rel, size))
        if not has_code:
            no_code.append(rel)

# Report
if thin_articles:
    print(f'\nVery short articles (<2KB): {len(thin_articles)}')
    for rel, size in sorted(thin_articles):
        print(f'  {rel} ({size}B)')

print(f'\nArticles without code examples: {len(no_code)}')

# Phase 2: Check README TODO
print("\n=== README TODO CHECK ===")
with open('X:/c/ai/Safe/README.md', 'r', encoding='utf-8') as f:
    readme = f.read()

# Find TODO section
todo_match = re.search(r'## .*TODO|## .*待办|## .*计划|## .*路线图', readme, re.IGNORECASE)
if todo_match:
    print(f"Found TODO section at: {todo_match.group()}")
    # Extract items after the TODO header
    
print("\n=== CHECKS DONE ===")
