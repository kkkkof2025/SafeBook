from ruamel.yaml import YAML

y = YAML()
y.preserve_quotes = True

with open('mkdocs.yml', 'r', encoding='utf-8') as f:
    d = y.load(f)

# Replace nav[0] (threat-intel section) with merged entries
from ruamel.yaml.comments import CommentedSeq, CommentedMap

new_section = CommentedSeq()
new_title = '威胁情报'
new_entries = [
    ('威胁情报', 'threat-intelligence/index.md'),
    ('威胁情报概述 IOC 与 TTP', 'threat-intelligence/01-threat-intel-intro.md'),
    ('威胁情报平台 TIP 与自动化', 'threat-intelligence/02-tip-automation.md'),
    ('威胁情报分析实战', 'threat-intelligence/03-threat-intel-analysis.md'),
    ('MITRE ATT&CK 与威胁情报', 'threat-intelligence/04-mitre-attack.md'),
    ('威胁狩猎与攻击模拟', 'threat-intelligence/05-threat-hunting.md'),
    ('威胁情报生命周期', 'threat-intelligence/06-lifecycle.md'),
]

entry_map = CommentedMap()
for display, path in new_entries:
    entry_map[display] = path

new_section.append(entry_map)

d['nav'][0] = new_section

with open('mkdocs.yml', 'w', encoding='utf-8') as f:
    y.dump(d, f)

print('mkdocs.yml updated successfully')
