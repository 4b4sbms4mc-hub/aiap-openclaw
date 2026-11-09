<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# NAS 专用 SSH 身份准备

作者：Wang Lu。2026-11-10。操作员选择使用现有 NAS 登录账号加专用受限公钥。Mac SSH 身份和客户端参数已完成；随后经操作员针对单条凭据明确批准，真实 SSH 凭据已在本 Mac 创建，并通过独立短时 agent 自检及新进程读回。未连接 NAS、安装 authorized_keys/sudoers 或启动证明服务。

## 两种密钥分工

已经按明确批准实际创建的见证签名凭据用于签署见证证明；本模块不把它交给 SSH。`scripts/keychain_ssh_identity.py` 为 NAS 登录准备另一条固定服务 `aiap.mac-witness.ssh.v1`，binding 包含目标 IP、端口、用户、已由操作员确认的主机公钥/指纹及 generation。账户是 binding 的 SHA256，私有记录校验独立 profile 与公钥。既有见证服务仍固定原 namespace，两种身份不能因配置字段混用。

CLI 默认只输出公开计划，不访问钥匙串。只有明确 `--confirm-create` 才原子新增条目，并回读、载入独立短时 agent 和签名自检；重复拒绝，不删除、覆盖或重登记。真实创建已取得针对这一条登录凭据的单独确认；操作员之前对见证签名凭据的批准不扩大为 NAS 登录凭据授权。

私钥仅在 Keychain、Python 内存与本次独立 OpenSSH agent 内存中出现。通过私有 Unix socket 按 SSH agent 协议加载密钥，不用未加密私钥文件、命令行参数、stdout 或 askpass 输出。agent 目录 0700、socket 0600，不使用或更改用户日常 agent；默认及每钥约束均限制最多 60 秒，结束或可捕获异常/中断时终止进程并清理 socket/临时目录。SIGKILL 等不可捕获终止不保证清理进程/目录，agent 内密钥仍受寿命约束；不能据此宣称任意崩溃清理或内存清零保证，也不是硬件不可导出密钥。

协议依据：[RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html) 的 SSH string、Ed25519 添加、寿命约束和签名消息。实现按该协议与真实 OpenSSH agent 交互，不实现自定义远程密码学。

## 参数准备与实际认证边界

客户端参数固定目标与一个证明命令，使用独立 agent、公钥文件和只有预登记服务器公钥的 known_hosts。开启严格主机检查，拒绝自动更新主机钥匙；只启用公钥认证，关闭密码、交互键盘、GSSAPI、hostbased、agent/端口转发和 PTY；不读取用户或全局 ssh_config。只把公开文件放入临时目录。

可以用公钥文件选择 agent 中的对应私钥，也可以用 `ssh -G` 在不连接服务器的情况下校验参数，这是 [OpenSSH ssh(1)](https://man.openbsd.org/ssh.1) 定义的行为。本轮只做这种配置解析；没有把它当作已通过 NAS 登录或受限命令验收。

目的地固定在本客户端构建参数时执行；未实现 agent 的 destination/session-bind 扩展。NAS 上的强制命令、公钥 restrict 选项、受控证明帮助器和必要 sudo 授权仍需具体安装包与单独验收。现阶段新增的公钥尚未获得任何 NAS 登录权限，也不能宣称普通 Ed25519 公钥本身天然只有某个命令的权限。服务请求的响应大小、超时、签名元数据处理及远程证明端点也仍待实现。

## 实际验收范围

10 项新测试让 scripts/tests 合计 159 项。测试 Keychain 使用明确注入的内存 store；真实系统 ssh-agent 完成添加、列举、签名、寿命到期和退出清理测试。覆盖默认 CLI 计划模式、显式创建、重复保留、缺失/拒绝/损坏无替代、字节帧边界与 bool 偏移拒绝、主机指纹和字段注入拒绝、namespace/角色隔离，以及 `ssh -G` 的无连接配置验证。所有临时密钥均为合成测试身份。

准备阶段在真实 Mac 做过新 namespace 随机不存在条目的只读探测；批准后使用原子新增接口创建一条凭据，真实 agent 签名与清理、新进程再次读回和自检均通过，仅保存权限 0600 的公开配置。已有批准的见证凭据在 namespace 重构后仍能读回和完成签名自检，原公钥不变。NAS 主机公钥从既有 known_hosts 读取，并与先前操作员确认的指纹比较，未使用 keyscan 或自动接纳新钥匙。具体设备/账号/指纹只在私有工作区，不进入公开仓库。

执行归属：LM Studio `qwen2.5-coder-14b-instruct-mlx` 提供 SSH 字节字符串辅助函数草案；Codex 复核后补齐 raw 类型与 bool 偏移限制，完成身份、原生 namespace、真实 agent、参数准备和测试。未调用云端模型。
