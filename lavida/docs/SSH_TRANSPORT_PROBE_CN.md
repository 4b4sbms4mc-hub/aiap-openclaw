<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# 专用 SSH 通道探针与创建式安装

作者：Wang Lu。2026-11-10。受限连通性探针已由操作员按明确批准安装到 NAS，并通过真实 Mac 公钥认证、nonce/UID探针与命令拒绝验收。探针不打开 Core、Docker、数据库或源私钥，不提供源观察、见证证明或恢复授权。成功响应始终包含 `source_observation_available=false`；现有恢复验证不会接受它作为证明。

## 入口与协议

`ssh_transport_probe.py` 由强制命令以账号自身身份运行，Python 使用 `-I`；要求 `SSH_ORIGINAL_COMMAND` 精确等于预留的 `aiap-source-proof-v1`，只有 `op=probe` 可用。最多1024字节、5秒输入等待，严格校验字段、重复键和64位小写十六进制 nonce，只响应版本、nonce、UID及不可提供源观察的标记。输入没有文件路径、容器或可执行命令字段。

Mac 的 `ssh_probe_client.py` 使用既有专用 agent 和主机固定参数准备得到的可信 argv，限定响应2048字节、总等待最多15秒，验证 nonce、预期 UID 和明确的 false 标记；超时、异常、超量和非零退出均拒绝，错误不转发远端原始输出。此函数不能接收邮件等不可信来源拼出的 argv。本次真实 NAS 调用已取得对应批准并完成上述设备验收；扩大命令或数据访问仍须另行形成具体方案。

## 安装及回退边界

`ssh_probe_install.py` 的 CLI 只接受固定目标 `/usr/local/bin/aiap-ssh-probe-v1.py`，没有测试用目录投影参数。默认只检查计划，不写入；apply/rollback 另要求匹配的明确批准摘要。计划固定账号 UID/GID/home、公钥、来源 IPv4、NAS 主机公钥摘要、两份已核对的配置摘要和 helper 摘要。目标 Python 路径为 `/usr/bin/python3`。

安装前检查真实账号、配置内容、引用目录的文件集合、公开主机公钥，以及目录属主/权限和冲突；配置或目录漂移、符号链接、硬链接和既有 `.ssh`/helper 均拒绝。只新增一个 root 所有0644的 helper、一个账号所有0700的 `.ssh` 与一个0600的授权文件。授权行固定 `restrict`、来源地址和强制 Python 命令。root 只写固定系统 helper；账号文件通过子进程清空附加组、setgid/setuid 后，以账号自身权限创建，并用目录 fd 和排他、不跟随链接的打开方式操作。没有 sudoers、Docker组、守护服务、NAS镜像或 Core 数据变更。

回退先以账号身份删除内容和权限仍与计划吻合的授权文件，再删除摘要相符的 helper。额外 `.ssh` 文件保留；授权文件被改动则停止，绝不覆盖其他条目。helper 已改动时先撤销已核对的授权行，再保留该文件并报告。创建步骤不是跨目录事务；断电、不可捕获终止或部分失败后可能留下目录/helper，需要按确切状态检查或回退，不得反复覆盖安装。

已存在账号的 shell/PAM 启动行为仍由 NAS 管理；强制命令不是独立账号沙箱，也不赋予整个账号只有探针权限。配置文本和编译默认值还不能证明运行中的 daemon 采用哪个授权文件。安装不会修改 sshd 配置或重启服务；安装后必须以固定主机公钥实际认证并做负例验收，认证失败就不宣称接入完成。

[Debian Bookworm sshd_config(5)](https://manpages.debian.org/bookworm/openssh-server/sshd_config.5.en.html) 说明默认授权文件位置及 Include/首个值的行为；这里只用它形成明确的默认路径假设，运行验证另做。[该版本 sshd(8)](https://manpages.debian.org/bookworm/openssh-server/sshd.8.en.html) 定义 restrict、from、command 公钥选项，用于限制这条公钥。

## 验证与执行归属

13项新单元/子进程测试令 scripts/tests 合计180项，涵盖严格请求、命令拒绝、字段/nonce/UID绑定、输入输出大小和超时。原生 Keychain 不在这些新增测试中读写。

Linux CI 另启动仅监听回环的临时 sshd，使用合成账号、临时主机/客户端密钥和投影文件树，验证真实公钥认证、强制命令、错误密钥、PTY/转发/用户 rc 拒绝、账号与 root 文件属主、冲突、修改文件回退拒绝及正常回退。该实验没有 NAS 连接；NAS原生验收另行记录，不能混为同一证据。测试依赖的 openssh-server 只安装在临时 CI runner；以实际 CI 结果为准。

LM Studio `qwen2.5-coder-14b-instruct-mlx` 提供测试案例草案，但错误接受32位/大写 nonce并捏造UID，未通过验收、未采纳。Codex直接完成协议、安装器、客户端和测试；当前没有已配置的硅基流动调用入口/凭据，本轮未调用云端模型。模型任务结束、确认idle后才卸载，并核对已无加载模型。

## 真实 NAS / Mac 验收（2026-11-10）

操作员按冻结方案完成 NAS 安装，后因 Mac 来源地址变化，经当前对话明确指令更新为单一固定来源；未扩大为网段。Codex 使用受保护入口，先核对批准、计划/本地代码摘要、目的地/公钥绑定与实际来源，再从 Mac 钥匙串读取原有独立SSH凭据，通过短时私有agent进行真实NAS认证。正向响应的随机nonce及预期UID校验成功；`id`负例精确返回拒绝对象及退出2。结果在agent清理后才保存，真实流程退出0。

真实NAS本轮只验收这些正向及命令拒绝行为。PTY、转发、用户rc及错误密钥的负例仍以独立CI实验为证据，未宣称本轮NAS重复实测。源观察能力仍明确false，未读取Core/数据库/源私钥，未启用源签名、见证服务或恢复验证，未改sudoers/Docker/sshd配置或重启服务。具体设备、账号、公钥、地址与私有摘要不进入公开仓库。

原来源变更前的Mac尝试被本地地址保护检查拒绝，发生在目标凭据读取和网络连接之前；不把那次停止当作认证失败或通过。最新成功记录另存，不覆盖历史批准/停止证据。实际执行归属：NAS安装由操作员完成，Mac验收、记录与文档复核由Codex直接执行/本地工具完成，此次未调用模型。
