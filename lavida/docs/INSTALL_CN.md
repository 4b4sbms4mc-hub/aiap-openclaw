# 全新安装：先 Core，后 OpenClaw

这是供新用户复现的入口，不是当前 NAS 的升级或恢复指令。Python 3.12 / Docker Compose v2 为参考环境；插件要求 Node >=22 并支持 node:sqlite，实际目标为 OpenClaw 2026.9.4。镜像构建需要访问 Python 镜像和依赖源；不提供完整离线镜像。

## 1. 单独启动 Core

在解压根目录逐条执行：

```sh
docker compose build
docker compose run --rm core init
docker compose up -d
docker compose exec core python -m aiap_core session --credential-file /data/owner-credentials.json
```

首次 init 产生新的本地 Avatar 与私有凭证；重复 init 拒绝覆盖。项目名 aiap-mvp，命名卷 aiap-mvp_core-data；Core 只连接内部网络，不发布宿主端口。Owner 管理命令通过 docker compose exec 执行；OpenClaw 加入同一内部网络后访问 aiap-mvp-core:8042。宿主无权用户不能读取私钥的保证取决于主机部署；此版本不防御主机管理员。

## 2. 独立验证提案与确认

先用合成内容演示：

```sh
docker compose exec core python -m aiap_core propose --credential-file /data/owner-credentials.json --space space:general --text 'DEMO_RELEASE: I prefer concise answers.'
docker compose exec core python -m aiap_core search --credential-file /data/owner-credentials.json --space space:general --query DEMO_RELEASE
```

此时应无命中。用实际 delta_id 替换 DELTA_ID，先 review，检查内容再选择 approve：

```sh
docker compose exec core python -m aiap_core review --credential-file /data/owner-credentials.json --delta-id DELTA_ID
docker compose exec core python -m aiap_core decide --credential-file /data/owner-credentials.json --delta-id DELTA_ID --approve
docker compose exec core python -m aiap_core search --credential-file /data/owner-credentials.json --space space:general --query DEMO_RELEASE
```

不加 --approve 是拒绝。批准后记录实际 memory ID/revision，重启 Core 后再次查询应保留它们。

## 3. 接入现有 OpenClaw 容器

以下以容器名 openclaw、持久状态挂载 /home/node/.openclaw 为示例。先核实实际挂载、运行 UID/GID、版本和配置路径；不同路径须调整。安装前保存现有 OpenClaw 配置与 memory 插槽值，备份不要上传 GitHub。

在 Core 签发独立的单空间 adapter 凭证，默认有效期 7 天：

```sh
docker compose exec core python -m aiap_core grant --spaces space:general --purpose lavida-memory --runtime openclaw-main --output /data/lavida-main.json
```

创建持久私有目录并传入凭证。命令通过管道传输，不将 token 打印到终端。core owner 凭证不得交给 OpenClaw：

```sh
ocl_uid=$(docker exec openclaw id -u)
ocl_gid=$(docker exec openclaw id -g)
docker exec --user 0 openclaw sh -c 'mkdir -p /home/node/.openclaw/lavida-credentials; chmod 700 /home/node/.openclaw/lavida-credentials; chown "$1:$2" /home/node/.openclaw/lavida-credentials' sh "$ocl_uid" "$ocl_gid"
```

单独执行下列凭证传输命令，使用支持 pipefail 的 Bash：

```bash
set -o pipefail
docker compose exec -T core cat /data/lavida-main.json | docker exec -i --user 0 openclaw sh -c 'umask 077; cat > /home/node/.openclaw/lavida-credentials/main.json; chmod 600 /home/node/.openclaw/lavida-credentials/main.json; chown "$1:$2" /home/node/.openclaw/lavida-credentials/main.json' sh "$ocl_uid" "$ocl_gid"
```

把 OpenClaw 连接到 Core 的私有网络，然后安装本地插件：

```sh
docker network connect aiap-mvp-local openclaw
docker cp lavida-aiap-0.3.4.tgz openclaw:/tmp/lavida-aiap-0.3.4.tgz
docker exec openclaw openclaw plugins install /tmp/lavida-aiap-0.3.4.tgz --accept-capabilities
```

这是首次安装入口；如果插件已经存在，不要直接覆盖，按当前版本另行安排升级。已有网络连接也不要重复执行 network connect。

根据 Core 的 session 输出，将 config.example.json 中 avatarId 替换为实际值；把插件 entry 和 memory slot 合并到现有配置，保留其他配置，不整份覆盖。baseUrl 指向 aiap-mvp-core:8042，自动提案关闭，绑定只允许 agent:main:main。配置中只存凭证路径。

```sh
docker restart -t 30 openclaw
docker exec openclaw openclaw plugins inspect lavida-aiap --runtime --json
```

应实际加载 0.3.4 并注册三个工具。只在绑定的 Owner 主会话调用 status，再请求 propose 一条合成偏好。候选阶段搜索不命中；在 Core CLI review/approve 后搜索应返回同一记录。

当前新建 Dashboard 会话不会自动绑定。缺少可信 Owner 标记、非绑定会话或沙箱上下文不会开放工具。不要用配置绕过身份检查。

## 4. 保留与回退

恢复原 memory 插槽并禁用 La Vida 可回退 OpenClaw 接口；保留 Core 数据卷。不执行 docker compose down -v。源程序不导入既有 Markdown 或聊天记录，不自动创建生活/工作会话绑定。

语义检索、自动提案、完整生命周期、备份恢复及撤销后上下文清理分别验收。本安装路径和 Compose 打包尚未经过新的 Docker/NAS 全新安装复测，已验证的既有部署见 VALIDATION.md。
