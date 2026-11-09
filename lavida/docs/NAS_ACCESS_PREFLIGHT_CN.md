<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# NAS 受限接入前只读预检

作者：Wang Lu。2026-11-10。`scripts/inspect_nas_access.sh` 在 Linux NAS 的 root 终端运行，参数为目标用户名、Mac 客户端 IPv4、NAS IPv4、Core 容器名。它只收集为安装方案所需的元数据，不安装公钥、修改权限或服务。

## 输出范围

- 账号 UID/GID、home、shell；home、`.ssh`、候选 `authorized_keys` 的属主、模式及数字 ACL；候选为符号链接时报告，不读取文件正文。账号查询先过滤密码字段，授权文件条目不输出。
- `getent/stat/sshd/visudo/timeout/install/sha256sum/flock/docker` 是否可用；这些路径不代表相关授权已配置。
- `sshd -G -C` 默认配置的选定公钥认证设置和授权路径；`AuthorizedKeysCommand`、`ForceCommand` 只输出存在与否，命令参数、环境变量和主机私钥路径不输出。
- 可取得时输出 root 所属 sshd 进程的公开 `-f` 路径提示及是否存在 `-o` 参数；不输出整条进程命令，不按该提示运行其他程序。
- 固定本机 Docker socket 下已知容器的名称、镜像 ID、运行状态、容器用户以及 `/data` 挂载元数据；不输出 Env、记忆、私钥或 token，不创建或重启容器。

[OpenSSH sshd(8)](https://man.openbsd.org/sshd) 区分配置解析 `-G` 与额外执行主机密钥检查的 `-T/-t`。本脚本仅使用 `-G`；版本不支持时报告 unavailable，不退回 `-T/-t`。结束标记说明采集脚本没有更改配置，不代表每个字段都可取得或受限登录已经通过。

## 配置范围限制

输出始终标明 `default_configuration_only_runtime_flags_and_reverse_hostname_not_verified`。传入的 Match 上下文使用客户端 IP 作为 host；尚未验证反向解析主机名、实际连接来源、运行中 daemon 的自定义 `-f/-o` 或其他启动方式。进程提示仅辅助操作员复核，不构成完整运行配置证明。默认 `AuthorizedKeysFile` 也可能含模板或多条路径；脚本不自行展开后读取条目。

若输出 unavailable、存在自定义配置、外部授权命令、强制命令或路径异常，先补充只读信息，不能据此直接覆盖现有授权。安装包必须在这些信息核实后给出确切变更、冲突拒绝、验收与回退，并取得对应生产变更批准。

## 验证与执行归属

四项合成测试覆盖输出过滤、敏感值不泄漏、账号文件内容不变、输入拒绝、符号链接报告以及不支持 `-G` 时不调用 `-T/-t`。它们验证采集器边界，实际 NAS 输出仍需操作员执行后复核。

LM Studio `qwen2.5-coder-14b-instruct-mlx` 提供过 awk 草案；初稿分隔符错误，修订稿将命令存在性分支提前过滤，均未通过 Codex 审查，未采纳为最终过滤器。Codex 直接完成过滤器、采集器及测试；未调用云端模型。
