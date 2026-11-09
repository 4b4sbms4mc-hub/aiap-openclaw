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

## 静态文本补查

实际 NAS 返回过 `SSH_CONFIG_STATUS=unavailable_no_T_or_t_fallback`。这表示配置解析未成功，不能单凭此状态确定是版本不支持还是其他解析问题；也不能默认候选 `.ssh/authorized_keys` 就是运行中使用的授权路径。

`scripts/inspect_sshd_config_static.awk` 只过滤标准输入，不打开其他文件、不执行命令，也不调用 sshd。它显示六项认证/授权设置，保留多路径与认证方法列表；`Include` 只显示路径引用，`Match` 只标记存在，均不解析。外部公钥查找命令和强制命令仅显示是否存在；其他指令、环境变量、私钥块及过长/含控制字符行不输出。每份输入最多处理4096行、每行2048字符。

操作员入口仅读取固定的默认配置文件及常见 `.d/*.conf` 文件，拒绝符号链接和非 root 属主文件；有大小上限和单文件超时。它不会按 Include 引用自动打开其他文件，也不会把静态行当成合并后的有效值。未知 Include、自定义启动配置、Match 块和厂商默认仍须复核，不能直接覆盖账号授权。`PREFLIGHT_DONE_NO_CONFIGURATION_CHANGED` 只表示采集器完成，没有安装或激活。

[OpenSSH sshd_config(5)](https://man.openbsd.org/sshd_config) 说明配置可通过 `-f` 改换、关键字大小写不敏感、参数可带引号，以及默认取值规则。此工具仅提供文本清单，不重写这些运行语义；未根据当前新版手册推断 NAS 旧版默认行为。

补查执行归属：LM Studio `qwen2.5-coder-14b-instruct-mlx` 初稿未满足 POSIX、保留多值和命令脱敏要求，修订出现重复且偏离任务，未采纳；Codex直接完成最终过滤器及四项测试。当前环境未配置硅基流动 API 凭据，也无对应可调用连接器，本轮未调用云端模型。
