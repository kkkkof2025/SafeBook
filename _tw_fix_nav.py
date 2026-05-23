with open('mkdocs.yml', 'r', encoding='utf-8') as f:
    content = f.read()

# The threat-intel nav section - replace old mixed entries
old_block = '      - 威胁情报概述：threat-intel/index.md\n      - 威胁情报概述: threat-intelligence/index.md\n      - MITRE ATT&CK 与威胁情报: threat-intelligence/01-threat-intel.md\n      - 威胁狩猎与攻击模拟: threat-intelligence/02-threat-hunting.md\n      - threat-intel/03-threat-intel-analysis.md\n      - threat-intel/02-tip-automation.md\n      - threat-intelligence/03-threat-intel-lifecycle.md\n      - threat-intel/01-threat-intel-intro.md'

new_block = '      - 威胁情报: threat-intelligence/index.md\n      - 威胁情报概述 IOC 与 TTP: threat-intelligence/01-threat-intel-intro.md\n      - 威胁情报平台 TIP 与自动化: threat-intelligence/02-tip-automation.md\n      - 威胁情报分析实战: threat-intelligence/03-threat-intel-analysis.md\n      - MITRE ATT&CK 与威胁情报: threat-intelligence/04-mitre-attack.md\n      - 威胁狩猎与攻击模拟: threat-intelligence/05-threat-hunting.md\n      - 威胁情报生命周期: threat-intelligence/06-lifecycle.md'

if old_block in content:
    content = content.replace(old_block, new_block)
    print('Nav block replaced!')
else:
    print('Trying alternate match...')
    lines = content.split('\n')
    start = None
    for i, line in enumerate(lines):
        if 'threat-intel/index.md' in line or 'threat-intelligence/index.md' in line:
            if start is None:
                start = i
            if 'threat-intel/01-threat-intel-intro.md' in line:
                end = i
                print(f'Found nav section at lines {start}-{end}')
                for j in range(start, end+1):
                    print(f'  {j}: {lines[j]}')
                # Replace this section
                before = '\n'.join(lines[:start])
                after = '\n'.join(lines[end+1:])
                content = before + '\n' + new_block + '\n' + after
                break

with open('mkdocs.yml', 'w', encoding='utf-8') as f:
    f.write(content)
print('mkdocs.yml updated')
