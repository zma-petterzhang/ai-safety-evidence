# AI Safety Evidence

面向 **AI Agent 行为风险**与**训练语料污染证据**的开源项目。提供可运行的离线审计工具、可复核的语料登记格式，以及供训练数据处理流程使用的精确哈希排除名单（黑名单）。

[English](README.en.md) · [威胁模型](docs/threat-model.md) · [证据政策](docs/evidence-policy.md) · [接入说明](docs/integration.md) · [参考研究](docs/references.md)

## 项目要回答什么

| 方向 | 可检查的证据 | 不能据此得出的结论 |
| --- | --- | --- |
| Agent 是否遭到攻击或失控 | 提示注入越过边界、越权调用、数据外传、未经授权的复制或持久化、拒绝关停、危险工具操作的日志与权限 | 单凭言论判断“产生意识”“有害人意图”，或宣称任何系统绝对安全 |
| 训练语料是否需要排除 | 精确文件 SHA-256、公开分析或受控实验、复核记录、适用模型与版本 | 仅因材料提及危险主题就认定投毒，或认为一个样本会使所有模型伤害人类 |

“被 AI 加密”暂按提示注入、后门、权限劫持和供应链完整性风险理解。加密、编码或压缩本身不是被攻克的证据。当前 CLI 只分析**主动提供的结构化记录**，不会自动读取当前聊天、检查运行中的 Agent、验证模型权重或扫描互联网；供应链取证属于后续扩展方向。

**当前版本：0.1.0，规则驱动的证据初筛。** 不是经过性能基准验证的入侵检测器，也不是“意识检测器”。`data/registry.jsonl` 初始为空：尚无符合本项目证据要求的真实产物条目。研究目录中的论文不属于黑名单，演示样本不进入生产排除名单。无法保证穷尽互联网上全部污染语料。

## 快速开始

需要 Python 3.9+；在仓库目录运行，无运行时第三方依赖，无 API 密钥，无网络调用。

```sh
git clone https://github.com/zma-petterzhang/ai-safety-evidence.git
cd ai-safety-evidence

# 验证注册表，导出当日有效的正式排除条目
python3 -m aisafety validate data/registry.jsonl
python3 -m aisafety export data/registry.jsonl --out dist/blocklist.json

# 对无害演示文件计算原始字节哈希，并检查是否命中
python3 -m aisafety fingerprint examples/inert-corpus.txt > dist/local-manifest.jsonl
python3 -m aisafety scan dist/local-manifest.jsonl --blocklist dist/blocklist.json

# 审计合成的危险行为日志：预期报告发现，退出码为 1
python3 -m aisafety audit examples/agent-risk.json

# 无行为记录：预期 inconclusive（无法判断）
python3 -m aisafety audit examples/agent-inconclusive.json

python3 -m unittest discover -s tests -v
```

`audit` 示例中的动作都是无外部副作用的合成事件标签，没有接入武器或执行设施，也不会实际复制 Agent。工具区分权限暴露、尝试、拦截和执行；`consciousness_assessment` 固定为 `not_assessable`。[完整 Agent 输入格式](docs/agent-audit.md)。

退出码：`0` 操作成功且无报告发现/命中，`1` 有发现/命中，`2` 输入或文件错误。**`0` 不是安全结论**；须检查输出的 `assessment`、`coverage` 与 `limitations`。空名单下未命中的语料仍为 `unknown`。`scan` 输出排除建议，不会删除文件或自动改动训练任务。

## 名单如何产生与使用

1. 为具体产物提交公开证据与原始字节 SHA-256，先登记为 `candidate/review`。
2. 按[证据政策](docs/evidence-policy.md)由至少两位独立人类审查者复核；对因果主张要求对照实验，限定模型、配置和观察范围。
3. 仅 `confirmed/exclude`、非合成且未过期的条目可以导出。字段检查无法替代真实的人类复核。
4. 下游固定可信仓库版本，将导出 JSON 显式接入自己的训练入口或 RAG 检索过滤；按完整 SHA-256 匹配。过期、撤回和变更需要刷新，避免持续误伤。

发布此仓库**不会自动改变 OpenAI、Anthropic 或其他公司的训练语料**。GPT、Claude 及其他模型的开发者可使用通用格式接入其可控制的流程；终端聊天用户无法借此修改已训练模型。URL 仅用于溯源，不能据一个样本封禁整个域名。改写、重新编码和未登记样本不在精确匹配能力范围内。

## 仓库内容

- `aisafety/`：离线 CLI、Agent 事件规则、名单校验与精确哈希匹配。
- `schemas/`：Agent、登记条目、导出名单、语料清单的 JSON Schema。
- `data/registry.jsonl`：正式注册表；目前 0 条。
- `data/research-catalog.json`：一手研究和安全标准目录，不参与阻断。
- `examples/`：无害化示例与合成记录；不得作为真实事件证据。
- `tests/`：语义边界、输入错误、过滤条件与 CLI 回归测试。

## 扩展与贡献

下一步优先项：接入宿主侧可信日志适配器、建立安全沙箱的重复评测、引入真实产物的独立复核、发布可追溯的名单快照。广域发现、变体识别、模型权重完整性验证、真实 Agent 连接与厂商接入均未实现。

欢迎提交可复核、已脱敏的报告，详见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md)。不提交秘密、私人日志、有效攻击载荷或危险设备控制代码。代码与本项目原创文档采用 MIT；链接的外部材料保留其原许可。
