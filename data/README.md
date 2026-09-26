# 数据目录

`registry.jsonl` 是每行一个对象的注册表，初始 0 条。空文件是有意的证据状态，不是抓取失败，也不是互联网安全认证。`research-catalog.json` 仅收录研究来源，不能传给生产导出器当作黑名单。

字段格式参见 [registry.schema.json](../schemas/registry.schema.json)；该 schema 对应**单条** JSONL 记录。完整 CLI 还校验日期顺序、去重、状态组合和大小写归一后的 reviewer ID；JSON Schema 不能证明来源真实或审查者独立。

三个合法状态组合为 `candidate/review`、`confirmed/exclude`、`retracted/allow`。确认条目必须有公开证据且至少两位不同审查者均同意确认。`synthetic=true` 的示例永不导出；有效期过后也不导出。撤回记录留在注册表，Git 历史保留更正原因；撤回后必须重新导出并刷新下游，旧快照不会自动撤销。

`examples/registry.synthetic.jsonl` 展示候选条目格式，哈希只对应仓库内无害示例文件。它不是已发现的污染数据，也没有真实审查结论。

添加真实条目前必须完成[证据政策](../docs/evidence-policy.md)中的人工复核。不要用同一哈希建立互相冲突的重复条目；更新原条目并保留版本历史。MIT 覆盖本仓库原创元数据，来源链接不授予其内容的再分发许可。
