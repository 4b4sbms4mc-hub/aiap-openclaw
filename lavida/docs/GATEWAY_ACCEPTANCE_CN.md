<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# 真实 Gateway 新安装与隔离恢复验收

作者：Wang Lu。2026-11-09 由 Codex 执行。组件保持 La Vida 0.3.4 / Core 0.2.0，未改变插件或 Core 行为，也未重新发布或覆盖既有 tag。

本次补足了真实 OpenClaw 的发布包安装与恢复后 HTTP 工具调用证据。测试使用官方 npm `openclaw@2026.9.4`、Node 24.22.1、Python 3.12.14，在 macOS 隔离临时目录中运行真实 Core 和真实 Gateway。未全局安装、注册服务、读取个人配置、使用个人数据或调用外部模型。临时服务停止后删除所有生成的状态、密钥、凭证及备份。

## 测试过程

1. 打包当前 `lavida/`，验证 ZIP 内每个 SHA256SUMS 条目，使用其中原始 `.tgz` 进行真正的 `openclaw plugins install`。安装前目标为空，安装后才设置 memory slot。`--force` 在这个一次性空目录中仅确认已核验本地包的来源。
2. 创建独立 Core 身份和单 general 空间 adapter 凭证；仅监听 loopback。Gateway 使用随机 operator token。Owner 凭证不交给插件。
3. 通过真实 `POST /tools/invoke` 调用 status、propose、search。Gateway 从认证结果生成 Owner 上下文，测试不伪造 senderIsOwner、不替换宿主注册、权限或事件分发实现。
4. 验证错误 Gateway token 返回 401、未绑定会话返回 404；候选批准前不可召回、Owner 独立审核批准后可召回；待批准和已拒绝候选、life 空间有效记录均不能从 general 绑定召回。
5. 停止 Gateway 与 Core，复制整个测试状态至快照，再恢复到另一目录。验证逐文件摘要和 SQLite integrity_check。原目录改名离线；恢复配置仅调整路径、端口和 Core URL，防止误连原实例。
6. 真实 Gateway 再次调用恢复后的 Core，验证 Avatar、原记忆 ID、版本、正文一致和本地签名有效；待批准、拒绝与跨空间内容仍不可召回；恢复后新候选也能经独立 Owner 批准后检索。

测试脚本中 Owner 审核是独立 Core HTTP 管理客户端，功能等同于 CLI review/decide；没有通过插件自行批准。恢复沿用同一份停机快照中的授权，不构成“从任意旧备份恢复后仍具备当前撤销语义”的保证。

## 复现

在全新开发目录安装 Python 依赖和符合要求的 Node。OpenClaw 可以位于本机临时目录或虚拟机，不需要注册系统服务。以下 npm prefix 目录应为空，只存测试依赖：

```sh
python -m pip install -r lavida/core/requirements.txt
npm install --prefix /absolute/temporary/host --ignore-scripts --no-audit --no-fund openclaw@2026.9.4
python scripts/package_lavida.py
python scripts/check_openclaw_gateway.py \
  --openclaw-entry /absolute/temporary/host/node_modules/openclaw/openclaw.mjs \
  --release-zip dist/LaVida_for_OpenClaw_0.3.4.zip \
  --output .validation/gateway.json
```

输出仅包含组件版本、测试包摘要、检查结果与限制，不含记忆正文、身份、凭证或原始 Gateway 日志。无成功报告、进程退出、超时、任何断言失败都不能视为通过。CI 对每次相关 PR/main 变更执行同样的真实 Gateway 测试，另保留独立 Core Docker 测试。

## 仍未覆盖

- 对话模型在完整 agent turn 中自行选择并调用工具。
- Docker/NAS 的完整 OpenClaw 新安装与恢复；现有 Docker CI 只证明 Core 部分。
- 多成员、组织治理、完整生命周期与删除/撤销传播。
- 跨 Runtime 安全迁移、Owner 远程证明和历史备份的当前授权重评估。

自动候选和语义检索仍默认关闭；本轮没有新增兼容等级或完整 AIAP 合规声明。原发布 ZIP 的历史 CI_VALIDATION.json 保留原结果；新证据由当前源码和 CI 单独记录。
