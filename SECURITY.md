# 安全范围与报告

本项目用于防御性、离线的风险证据整理和检查。检测结果不等同于对模型意识、意图、现实执行能力或系统是否已被攻克的判断。未命中与未发现异常也不构成安全证明。

## 报告项目漏洞

若发现本工具可能执行不可信内容、泄露数据、绕过校验或将未审核材料发布到正式清单，请先停止相关本地运行。

如果仓库启用了 GitHub 私密漏洞报告，可使用 Security 页面中的私密报告入口。否则，请仅在公开 issue 中提供不含利用细节的最小摘要，请维护者指定私密联系渠道。当前文档不承诺响应时限或奖励计划。

任何公开 issue、附件、提交或日志中均不得包含有效凭据、个人信息、私人对话、内部系统细节、私有原始日志或可直接使用的攻击载荷。需要复现时，优先提交最小化的无害样本、预期结果和实际结果。

## 报告语料与 Agent 风险

使用对应的 issue 模板提交待核实报告。提交报告不意味着风险已被确认，也不会自动生成黑名单条目。正式条目需要精确文件 SHA-256、公开可核验的支持证据和独立复核。仅有主题、关键词、来源域名或模型自述不足以纳入清单。

本项目不自动下载提交的 URL，不收集或执行真实攻击载荷，不连接真实武器、生产 Agent、凭据或外部执行设备。行为复现必须在隔离沙箱中使用无副作用的模拟工具。

公开清单只能对已审核的特定字节内容提供风险提示，无法列尽互联网上的污染内容，也不能证明某一文件能使任何模型产生特定意图或行为。撤销、更正和证据异议应保留可追溯的审核记录。

## English summary

Report sensitive vulnerabilities privately when a private channel is available. Never attach secrets, private raw logs, personal data, or live attack payloads to public reports. Corpus reports are unverified submissions until independently reviewed. All reproduction must use harmless offline mocks; no real weapons or external actuators are in scope.
