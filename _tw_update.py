import re, os

docs = 'docs'

# Add to nav
with open('mkdocs.yml', 'r', encoding='utf-8') as f:
    nav_text = f.read()

# Add secure-coding/03-code-review.md to the secure-coding section
secure_anchor = 'secure-coding/02-secure-coding-web.md'
if secure_anchor in nav_text:
    pos = nav_text.find(secure_anchor)
    rest = nav_text[pos:]
    next_section = re.search(r'\n  - [^\s].*?:\n', rest)
    if next_section:
        insert_pos = pos + next_section.start()
    else:
        insert_pos = len(nav_text)
    # Find last line before next section
    lines = nav_text[:insert_pos].split('\n')
    new_entry = '      - secure-coding/03-code-review.md'
    lines.append(new_entry)
    nav_text = '\n'.join(lines) + nav_text[insert_pos:]
    print('Added secure-coding/03-code-review.md')

# Add blockchain-security/05-mev-deep.md
blockchain_anchor = 'blockchain-security/04-mev-frontrunning.md'
if blockchain_anchor in nav_text:
    pos = nav_text.find(blockchain_anchor)
    rest = nav_text[pos:]
    next_section = re.search(r'\n  - [^\s].*?:\n', rest)
    if next_section:
        insert_pos = pos + next_section.start()
    else:
        insert_pos = len(nav_text)
    lines = nav_text[:insert_pos].split('\n')
    new_entry = '      - blockchain-security/05-mev-deep.md'
    lines.append(new_entry)
    nav_text = '\n'.join(lines) + nav_text[insert_pos:]
    print('Added blockchain-security/05-mev-deep.md')

with open('mkdocs.yml', 'w', encoding='utf-8') as f:
    f.write(nav_text)

# Fix prev/next: mark end-of-chapter on mev-deep
fpath = os.path.join(docs, 'blockchain-security/05-mev-deep.md')
with open(fpath, 'r', encoding='utf-8') as f:
    content = f.read()
content = content.replace(
    '*上一篇：[DeFi 安全分析](02-defi-security.md)*',
    '*上一篇：[MEV 前端跑](04-mev-frontrunning.md)*'
)
with open(fpath, 'w', encoding='utf-8') as f:
    f.write(content)

print('Links fixed')
