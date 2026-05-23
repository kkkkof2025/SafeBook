from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

y = YAML()
y.preserve_quotes = True

with open('mkdocs.yml', 'r', encoding='utf-8') as f:
    d = y.load(f)

# Find the threat-intel nav section
target_idx = None
for i, section in enumerate(d['nav']):
    if isinstance(section, dict):
        for key in section:
            pass  # skip
    elif isinstance(section, CommentedMap):
        for key in section:
            if 'threat-intel' in str(key).lower() or '威胁情报' in str(key):
                target_idx = i
                print(f'Found at nav[{i}]: key="{key}"')
                # Print all entries
                for j, entry in enumerate(section[key]):
                    if isinstance(entry, dict):
                        for ek, ev in entry.items():
                            print(f'  [{j}] {ek}: {ev}')
                    else:
                        print(f'  [{j}] {entry}')
                break
    if target_idx is not None:
        break

if target_idx is None:
    # Print all nav entries to find it
    for i, section in enumerate(d['nav']):
        if isinstance(section, dict):
            for key in section:
                if 'threat' in str(key).lower():
                    print(f'nav[{i}] key="{key}"')
                for j, entry in enumerate(section[key]):
                    if isinstance(entry, dict):
                        for ek, ev in entry.items():
                            if 'threat' in str(ek).lower() or 'threat' in str(ev).lower():
                                print(f'  [{j}] {ek}: {ev}')
                    elif isinstance(entry, str) and 'threat' in entry.lower():
                        print(f'  [{j}] {entry}')
