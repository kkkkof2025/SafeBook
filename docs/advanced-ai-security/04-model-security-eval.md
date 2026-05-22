# AI 模型安全评估

## 概述

AI 模型的安全评估与传统应用安全评估有根本不同——攻击面包括训练数据投毒、模型提取、对抗样本和提示注入。这让模型评估变成了一个全新的安全工程挑战。

---

## 1. 模型安全评估框架

```
AI 模型安全评估维度:

  L1 — 数据安全
    ├── 训练数据投毒检测
    ├── 数据泄露风险 (Membership Inference)
    ├── 偏置 (Bias) 审计
    └── 数据溯源 (Provenance)

  L2 — 模型安全
    ├── 对抗鲁棒性 (Adversarial Robustness)
    ├── 模型提取攻击防御
    ├── 后门检测 (Backdoor)
    └── 模型逆向 (Model Inversion)

  L3 — 推理安全
    ├── Prompt Injection 检测
    ├── 越狱 (Jailbreak) 检测
    ├── PII 泄露防御
    └── 有害内容过滤

  L4 — 基础设施安全
    ├── GPU 集群访问控制
    ├── 模型权重加密
    ├── 推理 API 速率限制
    └── 供应链安全
```

---

## 2. 对抗样本攻击与检测

### 2.1 对抗样本生成

```python
import torch
import torch.nn as nn

class AdversarialEvaluator:
    """模型对抗鲁棒性评估"""

    @staticmethod
    def fgsm_attack(model, image, label, epsilon=0.03):
        """
        FGSM (Fast Gradient Sign Method)
        在梯度方向上添加微小扰动
        """
        image.requires_grad = True
        output = model(image)
        loss = nn.CrossEntropyLoss()(output, label)
        model.zero_grad()
        loss.backward()

        # 扰动大小: epsilon
        perturbed = image + epsilon * image.grad.sign()
        # 约束到有效像素范围
        perturbed = torch.clamp(perturbed, 0, 1)

        return perturbed

    @staticmethod
    def pgd_attack(model, image, label, epsilon=0.03, alpha=0.01, steps=40):
        """
        PGD (Projected Gradient Descent)
        多次迭代 FGSM，攻击更强
        """
        perturbed = image.clone().detach()
        original = image.clone().detach()

        for _ in range(steps):
            perturbed.requires_grad = True
            output = model(perturbed)
            loss = nn.CrossEntropyLoss()(output, label)
            model.zero_grad()
            loss.backward()

            # 梯度上升
            perturbed = perturbed + alpha * perturbed.grad.sign()

            # 投影回 epsilon-ball
            perturbation = torch.clamp(perturbed - original, -epsilon, epsilon)
            perturbed = original + perturbation
            perturbed = torch.clamp(perturbed, 0, 1)

        return perturbed.detach()

    @staticmethod
    def evaluate_robustness(model, dataset, attack_fn, epsilon_values):
        """评估模型在不同 epsilon 下的鲁棒性"""
        results = {}
        for eps in epsilon_values:
            correct = 0
            total = 0
            for image, label in dataset:
                perturbed = attack_fn(model, image, label, epsilon=eps)
                output = model(perturbed)
                if output.argmax() == label:
                    correct += 1
                total += 1
            results[eps] = correct / total
        return results
```

### 2.2 防御技术

```python
class AdversarialDefense:
    """对抗样本防御"""

    @staticmethod
    def adversarial_training(model, train_loader, epochs=5):
        """
        对抗训练 (当前最有效的防御)
        在训练时注入对抗样本
        """
        for epoch in range(epochs):
            for images, labels in train_loader:
                # 生成对抗样本
                perturbed = AdversarialEvaluator.fgsm_attack(
                    model, images, labels
                )

                # 同时用干净样本和对抗样本训练
                optimizer.zero_grad()
                loss_clean = loss_fn(model(images), labels)
                loss_adv = loss_fn(model(perturbed), labels)
                loss = 0.5 * loss_clean + 0.5 * loss_adv
                loss.backward()
                optimizer.step()

    @staticmethod
    def input_transformation(image):
        """
        输入变换防御
        - JPEG 压缩
        - 随机缩放
        - 位深度降低
        这些变换破坏对抗扰动
        """
        import torchvision.transforms as T

        transform = T.Compose([
            T.RandomResizedCrop(224, scale=(0.9, 1.0)),
            T.ColorJitter(brightness=0.1, contrast=0.1),
            T.GaussianBlur(kernel_size=3)
        ])

        return transform(image)
```

---

## 3. Membership Inference 攻击

```python
class MembershipInferenceEvaluator:
    """
    评估模型是否会泄露"此人/此数据是否在训练集中"

    攻击原理:
    - 训练集中的样本通常置信度更高
    - 攻击者训练"影子模型"来学习这个模式
    """

    def evaluate_mia_risk(self, model, train_data, test_data):
        """成员推断风险评估"""

        # 1. 获取模型对所有样本的预测置信度
        train_confidences = self._get_confidences(model, train_data)
        test_confidences = self._get_confidences(model, test_data)

        # 2. 训练二分类器区分
        features = np.concatenate([
            train_confidences, test_confidences
        ])
        labels = np.concatenate([
            np.ones(len(train_confidences)),     # 训练集=1
            np.zeros(len(test_confidences))      # 测试集=0
        ])

        # 简单基线: 如果模型对训练数据的置信度显著更高
        train_avg = np.mean(train_confidences)
        test_avg = np.mean(test_confidences)

        gap = train_avg - test_avg

        risk_level = 'LOW' if gap < 0.05 else (
            'MEDIUM' if gap < 0.15 else 'HIGH'
        )

        return {
            'confidence_gap': float(gap),
            'risk_level': risk_level,
            'recommendation': (
                '正常' if risk_level == 'LOW'
                else '考虑差分隐私训练'
            )
        }

    def _get_confidences(self, model, data):
        confidences = []
        for x, _ in data:
            with torch.no_grad():
                output = torch.softmax(model(x), dim=1)
                confidences.append(output.max().item())
        return confidences
```

---

## 4. 评估清单

```yaml
AI 模型安全评估 Checklist:

  数据安全:
    - [ ] 训练数据投毒检测（异常样本分析）
    - [ ] 数据去重与清洗
    - [ ] PII 过滤验证
    - [ ] 数据来源可追溯

  模型鲁棒性:
    - [ ] 对抗鲁棒性评分（FGSM/PGD 测试）
    - [ ] 门控权重分析（异常激活检测）
    - [ ] 模型后门扫描
    - [ ] 成员推断风险 < 0.10

  推理安全:
    - [ ] Prompt Injection 探测（跨场景）
    - [ ] 越狱探测（DAN/角色扮演等）
    - [ ] 有害内容输出过滤
    - [ ] 速率限制 + 滥用检测

  运维安全:
    - [ ] 模型访问审计日志
    - [ ] API 认证与授权
    - [ ] 模型签名验证
    - [ ] 模型版本回滚机制
```

---

*上一篇：[AI 红队](03-ai-redteam.md)*
