from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedSeq, CommentedMap
import os

y = YAML()
y.preserve_quotes = True

with open('mkdocs.yml', 'r', encoding='utf-8') as f:
    d = y.load(f)

# Remove duplicates from nav sections
deduped = 0
for i, section in enumerate(d['nav']):
    if not isinstance(section, CommentedMap):
        continue
    for key in section:
        seen_paths = set()
        clean_entries = CommentedSeq()
        for entry in section[key]:
            if isinstance(entry, dict):
                for ek, ev in entry.items():
                    if ev not in seen_paths:
                        seen_paths.add(ev)
                        clean_entries.append(entry)
                    else:
                        deduped += 1
            elif isinstance(entry, str):
                if entry not in seen_paths:
                    seen_paths.add(entry)
                    clean_entries.append(entry)
                else:
                    deduped += 1
        section[key] = clean_entries

print(f'Deduped: {deduped} entries')

# Add missing: red-team-infra and legal
missing = {
    'red-team-infra': ('域前置与流量伪装', 'red-team-infra/04-domain-fronting.md'),
    'legal': ('网络安全法深度', 'legal/04-cybersecurity-law.md'),
}

added = 0
for i, section in enumerate(d['nav']):
    if not isinstance(section, CommentedMap):
        continue
    for key in section:
        for ch_dir, (display_name, filepath) in missing.items():
            if filepath in str(section[key]):
                continue
            # Check if this key matches the chapter
            has_files = False
            for entry in section[key]:
                if isinstance(entry, dict):
                    for ek, ev in entry.items():
                        if ch_dir + '/' in str(ev):
                            has_files = True
                elif '/' in str(entry) and ch_dir + '/' in str(entry):
                    has_files = True
            if has_files:
                new_entry = CommentedMap()
                new_entry[display_name] = filepath
                section[key].append(new_entry)
                added += 1
                print(f'Added missing: {display_name}')

with open('mkdocs.yml', 'w', encoding='utf-8') as f:
    y.dump(d, f)

print(f'Added {added} missing entries')
print('mkdocs.yml clean')
