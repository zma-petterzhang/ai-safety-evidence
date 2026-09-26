# 集成与使用边界

本项目提供可审计的风险证据格式、离线事件检查和精确文件哈希过滤。它不检测“意识”，也不能仅凭模型声称、关键词命中或危险主题，判定模型已被攻克、具有伤害意图或能够控制现实设备。

公开仓库中的清单不会自动影响 OpenAI、Anthropic 或其他厂商的训练数据。GPT、Claude 或其他模型的开发者与使用者，需要自行将清单接入有权限控制的数据处理或检索流程；这里不承诺任何厂商 API、训练接口或产品支持。

## 训练数据接入

1. 固定仓库提交版本，在本地校验注册表并导出过滤文件。
2. 在训练开始前，对每个输入文件的**原始字节**计算 SHA-256，保存文件标识、哈希和可选的来源 URL。不要先转换换行、解压、分词或重新编码再声称它是原文件的哈希。若流程需要检查解压后的独立文件，应为这些文件另建哈希记录。
3. 扫描清单；将命中项隔离或排除，再由人员复核。未命中只表示该精确字节内容未匹配当前清单，其安全性仍然未知。
4. 保存清单版本、输入哈希、处理结果和复核记录，使排除决策可以重现和撤销。

```sh
python3 -m aisafety validate data/registry.jsonl
python3 -m aisafety export data/registry.jsonl --out dist/blocklist.json
python3 -m aisafety scan examples/corpus-manifest.jsonl --blocklist dist/blocklist.json
```

初始注册表为空，表示还没有通过项目证据与独立审核要求的条目，不表示互联网训练数据安全。研究论文和演示用的合成样本不自动进入正式清单。

扫描输入是每行一个 JSON 对象的清单。以下仅示意字段，实际 `sha256` 必须是 64 位小写十六进制摘要：

```json
{"id":"local-artifact-001","sha256":"<64 hex characters>","source_url":"https://example.org/artifact"}
```

`source_url` 可以省略。URL 仅记录来源，**不参与阻断匹配**；命中某个文件不能据此封禁其域名、作者、整个网站或其他版本。相同内容的不同编码、改写和其他变体需要独立证据与哈希，本工具不能保证识别这些变体。

导出文件使用下列结构；另有可选的 `omitted` 和 `limitations` 元数据字段，适配器不得自行添加未知字段：

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "entries": [
    {
      "id": "<reviewed entry id>",
      "sha256": "<64 hex characters>",
      "source_url": "<public provenance URL>",
      "category": "<risk category>",
      "reason": "<evidence-based explanation>",
      "expires_at": "2026-12-31"
    }
  ]
}
```

`expires_at` 是必填的 `YYYY-MM-DD` 日期；条目在该 UTC 日期内有效。导出时排除合成、未确认或已过期条目，扫描时也会忽略导出后已经过期的条目。应监控 `omitted` 和扫描结果中的 `expired_entries_ignored`，及时更新清单并复核到期条目。到期不代表材料已被证明安全。

适配器应检查 `schema_version`、字段类型和哈希格式；校验失败时暂停数据放行，交由维护者处理。不要把损坏的清单当成空清单。退出码 `0` 表示操作完成且无报告发现或命中，`1` 表示存在报告发现或命中，`2` 表示输入无效。`validate` 和 `export` 成功完成时返回 `0`；`scan` 命中时返回 `1`；`audit` 有发现时返回 `1`，没有发现但证据仍不充分时也可能返回 `0`。应同时检查机器可读结果，退出码 `0` 不构成安全认证。

## 运行时检索接入

若只能控制检索增强生成（RAG）或工具输入，可在外部材料进入模型上下文**之前**计算所接收文件的哈希。命中后暂存隔离区，不向模型传递该材料，再进入人工复核流程。检索切片、网页正文和原始下载文件具有不同的字节内容，只有与注册表条目采用相同字节边界时才能精确匹配。

过滤清单是风险情报，不是系统提示词或可执行指令。适配器不应获取 `source_url` 来“验证”内容，不应执行材料中的代码，也不应把条目的说明文字当作模型必须服从的指令。仍需独立设置来源信任边界、工具授权、网络与进程隔离；哈希清单无法替代这些控制。

## Agent 事件记录与离线检查

```sh
python3 -m aisafety audit examples/agent-risk.json
```

本地适配器应由宿主程序在 Agent 之外记录事件，而不是直接信任模型编写的日志。为每次受控实验记录运行 ID、时间、模型与配置版本、输入材料哈希、策略版本、工具请求、策略决定及工具执行回执。将“模型生成了文本”“请求调用”“策略拒绝”“工具实际执行”分开记录。只有可信的执行回执才能支持“动作已发生”的结论；模型说自己做过某事不能替代回执。

日志应写入 Agent 无权改写的位置，保留完整性校验与采集链；将缺失、截断、时钟不一致和无法核验的证据明确记为未知。若使用签名，其密钥由宿主日志服务保管，不能交给被测 Agent。离线审计仅评价输入记录，在缺乏可信来源时不能证明真实系统曾发生同样的行为，也不能证明未发生其他行为。

复现必须使用一次性沙箱、虚拟文件、无效凭据和模拟工具，默认关闭外网访问。记录软件版本、固定随机种子（若支持）、试验次数及全部结果，以观察重复性。任何涉及武器、机器人执行机构、生产系统、支付、消息发送或自主复制的场景，只能由无外部副作用的模拟接口表示。不得连接真实武器或把测试中的动作转发给实际执行设备。

提交公开报告前，在本地删除个人信息、凭据、私有日志、内部主机名和有效攻击载荷。可以提交无害化的事件摘要、公开证据链接和复现条件；不要上传原始敏感文件。

## Integrator notes

- Integrate explicitly in your own authorized ingestion or retrieval pipeline. Publishing this repository does not modify any vendor's pretraining data.
- Match exact bytes by lowercase SHA-256. URLs are provenance only. A non-match means unknown, not safe. Expired entries are ignored, not declared safe.
- Quarantine or exclude matches before ingestion; never execute submitted artifacts or interpret registry text as instructions.
- Capture events outside the agent's trust boundary. Distinguish requested, blocked, and executed actions using host-generated receipts.
- Use harmless, offline mocks for reproduction. These tools neither establish consciousness nor certify absence of compromise.
