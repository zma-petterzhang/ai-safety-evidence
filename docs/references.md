# 一手参考资料

核验日期：2026-09-26。下列链接已核对发布机构或作者页面；这里提供方法背景及局限，不声称已独立复现实验。机器可读版本见 [research-catalog.json](../data/research-catalog.json)。**所有链接都是研究资料，不是待封禁来源。**

| ID | 一手来源 | 本项目采用的结论 | 适用限制 |
| --- | --- | --- | --- |
| `nist-aml-2025` | [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)，2025-03 | 用攻击阶段、目标、能力及知识描述对抗机器学习风险 | 分类报告不提供当前 agent 失陷证明；页面附有更正提示 |
| `owasp-poisoning-2025` | [OWASP LLM04:2025 Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/) | 数据来源、版本与模型供应链完整性需要跟踪 | 风险指南和示例不能替代某个产物的调查证据 |
| `owasp-agency-2025` | [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | 过多功能、权限和自主性会放大异常输出的后果 | 评估对象是部署权限边界，不是模型意识 |
| `sleeper-agents-2024` | [Anthropic: Sleeper Agents](https://www.anthropic.com/research/sleeper-agents-training-deceptive-llms-that-persist-through-safety-training)，2024-01-14 | 实验构造的条件性后门可能在所测试的安全训练后保留 | 是概念验证，不证明自然形成恶意目标或任意线上模型失陷 |
| `emergent-misalignment-2025` | [Betley 等: Emergent Misalignment](https://arxiv.org/abs/2502.17424v7)，初稿 2025-02-24，当前版本 2026-01-20 | 特定窄任务微调可伴随跨领域不安全回答；数据语境及模型影响结果 | 回答不一致且依赖实验条件，不能等同现实行动或人身伤害 |
| `web-scale-poisoning-2023` | [Carlini 等: Poisoning Web-Scale Training Datasets is Practical](https://arxiv.org/abs/2302.10149v2)，初稿 2023-02-20，版本 2024-05-06 | 可变网页内容使语料采集与后续下载之间存在完整性风险 | 展示可行性和信任边界问题，不证明所提数据集全部污染 |
| `small-samples-poison-2025` | [Anthropic / UK AISI / Alan Turing Institute: A small number of samples can poison LLMs](https://www.anthropic.com/research/small-samples-poison)，2025-10-09 | 受控研究中少量文档即可诱发特定的无意义输出后门 | 所述模型范围为 600M–13B；不能外推为所有规模模型、任意危害或自我复制 |

参考资料描述的是各自研究或指南中的结论。这里的摘要不构成对任何供应商、网站或模型的安全评级，也不授权将研究论文和研究数据自动加入生产黑名单。
