<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP 最初可用版本：La Vida for OpenClaw

公开作者：Wang Lu。状态：**首个可用记忆实现，实验性预发布。**

这一版先把单用户记忆闭环做成可复现入口：本地 Core 保存身份与已批准记忆，OpenClaw 使用限定空间的凭证检索或提出候选，Owner 在插件之外审核批准或拒绝。

## 保留的核心内容

| 能力 | 本版范围 |
|---|---|
| 身份连续性 | 本地 Avatar 标识与密钥，重启不重新创建身份 |
| 本地状态 | SQLite 持久化，正文和来源由 Core 管理 |
| 访问范围 | general、life、work；插件每个绑定固定一个空间 |
| 提案与确认 | 候选不等于有效记忆；Owner 独立确认 |
| 检索 | 默认按权限做字面检索，最多返回限定数量 |
| OpenClaw 接口 | status、search、propose 三个工具 |
| 基础权限 | 可信宿主 Owner 标记、会话绑定、凭证到期和撤销 |

组件版本沿用 Core 0.2.0、La Vida 0.3.4；白皮书参考 v0.4.2。没有把实现重新编号成 0.1.0，也不声明完整白皮书合规。

## 简化的是首发入口

插件和 Core 源码原样保留。默认关闭自动提案、Ollama 语义检索和后台归档，先验证人工请求与确认闭环。它们仍作为可选扩展存在。没有删除权限、来源校验或 Owner 确认来减少步骤。

多成员、家庭共享、公司管理、跨平台安全迁移、完整 Workflow 学习、MCP、宠物界面和结算列为后续路线，不能当作本版已可用功能。

## 使用和发布

1. [全新安装及闭环演示](docs/INSTALL_CN.md)：新建独立数据，不操作现有 NAS 数据卷。
2. [验证范围](docs/VALIDATION.md)：区分本地测试、既有 NAS 实测与新安装待测。
3. [Release 说明草稿](docs/RELEASE_NOTES.md)：使用独立 tag `lavida-openclaw-v0.3.4`，避免覆盖协议 `v0.3.0`。
4. [许可范围](LICENSE_SCOPE.md)：代码 Apache-2.0，文档 CC BY 4.0，保留原有商标政策。

此包不含个人记忆、运行数据库、凭证、私钥、NAS 备份或 OpenClaw 完整宿主源码。SHA256SUMS 是完整性校验，不是发布者签名。
