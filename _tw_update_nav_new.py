from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedSeq, CommentedMap
import os

y = YAML()
y.preserve_quotes = True

with open('mkdocs.yml', 'r', encoding='utf-8') as f:
    d = y.load(f)

# New files to add per chapter
additions = {
    '5g-security': ('5G 安全架构深度', '5g-security/04-5g-security-architecture.md'),
    'aws-security': ('AWS 安全最佳实践', 'aws-security/04-aws-best-practices.md'),
    'china-laws': ('数据安全法实战合规', 'china-laws/04-data-security-law.md'),
    'compliance': ('SOC 2 审计实战', 'compliance/04-soc2-audit.md'),
    'deception': ('蜜罐部署实战', 'deception/04-honeypot-deployment.md'),
    'hardware-security': ('HSM 与 TPM 实践', 'hardware-security/04-hsm-tpm.md'),
    'hvv': ('HVV 实战工具与技巧', 'hvv/04-hvv-tools.md'),
    'iam': ('零信任架构实践', 'iam/05-zero-trust.md'),
    'learning': ('安全认证完全指南', 'learning/04-certifications.md'),
    'legal': ('网络安全法深度', 'legal/04-cybersecurity-law.md'),
    'quantum-security': ('后量子密码迁移', 'quantum-security/04-pqc-migration.md'),
    'red-team': ('C2 框架对比与选型', 'red-team/04-c2-frameworks.md'),
    'red-team-infra': ('域前置与流量伪装', 'red-team-infra/04-domain-fronting.md'),
    'sm-crypto': ('国密算法应用指南', 'sm-crypto/04-sm-application-guide.md'),
}

# Find and update each chapter's nav section
updated = 0
for i, section in enumerate(d['nav']):
    if not isinstance(section, CommentedMap):
        continue
    for key in section:
        for ch_dir, (display_name, filepath) in additions.items():
            # Check if this section is for this chapter
            if ch_dir + '/' in str(section[key][-1]).lower() or \
               ch_dir in str(key).lower():
                # Check if file already in nav
                already_there = False
                for entry in section[key]:
                    if isinstance(entry, dict):
                        for ek, ev in entry.items():
                            if filepath in str(ev):
                                already_there = True
                    elif filepath in str(entry):
                        already_there = True

                if not already_there:
                    new_entry = CommentedMap()
                    new_entry[display_name] = filepath
                    section[key].append(new_entry)
                    updated += 1
                    print(f'Added {display_name} to {ch_dir}')

print(f'\nTotal nav entries added: {updated}')

with open('mkdocs.yml', 'w', encoding='utf-8') as f:
    y.dump(d, f)

print('mkdocs.yml updated')
