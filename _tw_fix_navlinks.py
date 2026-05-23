import os, re

docs = 'X:/c/ai/Safe/docs'

# Step 1: Collect all files per directory (sorted)
dirs = {}
for root, dirs_, files in os.walk(docs):
    md_files = sorted([f for f in files if f.endswith('.md') and f not in ('index.md', 'SUMMARY.md')])
    if md_files:
        rel_dir = os.path.relpath(root, docs).replace('\\', '/')
        dirs[rel_dir] = md_files

# Step 2: For each file, add prev/next links
count = 0
for rel_dir, files in sorted(dirs.items()):
    for i, fname in enumerate(files):
        fpath = os.path.join(docs, rel_dir, fname)
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()

        modified = False

        # Add prev link
        if i > 0:
            prev_file = files[i-1]
            prev_title = prev_file
            # Try to extract title from prev file
            try:
                with open(os.path.join(docs, rel_dir, prev_file), 'r', encoding='utf-8') as pf:
                    first = pf.readline().strip().lstrip('#').strip()
                if first and len(first) < 50:
                    prev_title = first
            except:
                pass

            prev_link = f'\n\n*上一篇：[{prev_title}]({prev_file})*'

            if '*上一篇' not in content:
                content = content.rstrip() + prev_link + '\n'
                modified = True
                count += 1

        # Add next link
        if i < len(files) - 1:
            next_file = files[i+1]
            next_title = next_file
            try:
                with open(os.path.join(docs, rel_dir, next_file), 'r', encoding='utf-8') as nf:
                    first = nf.readline().strip().lstrip('#').strip()
                if first and len(first) < 50:
                    next_title = first
            except:
                pass

            next_link = f'\n\n*下一篇：[{next_title}]({next_file})*'

            if '*下一篇' not in content:
                content = content.rstrip() + next_link + '\n'
                modified = True
                count += 1

        if modified:
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(content)

print(f'Fixed {count} missing prev/next links across {len(dirs)} directories')
