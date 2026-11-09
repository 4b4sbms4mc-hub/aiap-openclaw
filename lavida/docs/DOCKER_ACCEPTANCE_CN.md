<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# 隔离 Docker 夹具验收

作者：Wang Lu。此夹具验证真实 OpenClaw 与 Core 在 Docker 内的新安装和停机恢复，补充本机/Ubuntu 虚拟机证据。它不是生产部署镜像，不替换既有 NAS 数据或配置。

镜像基于 Node 24.22.1，安装 Python 虚拟环境和固定 OpenClaw 2026.9.4，然后从源码打包当前 La Vida 候选。构建阶段需要网络；运行阶段使用 `--network none`、只读根文件系统、临时可写目录、非 root 用户、全部 capabilities 移除且不公开端口。

一个容器内运行两个独立真实进程，通过 loopback 连接 Gateway 与 Core。验收同 `check_openclaw_gateway.py`：真实插件安装、认证与绑定会话拒绝、候选与有效记忆区分、Owner 独立批准、空间隔离、停机快照、摘要/SQLite/签名、原目录离线后的恢复及新提案闭环。模型探针默认不运行，`--network none` 也不能连接宿主 LM Studio。

```sh
docker build -f scripts/Dockerfile.gateway-acceptance -t aiap-gateway-acceptance .
docker create --name aiap-gateway-acceptance --network none --read-only \
  --tmpfs /tmp:rw,nosuid,mode=1777,size=256m \
  --tmpfs /reports:rw,nosuid,mode=1777,size=8m \
  --cap-drop ALL --security-opt no-new-privileges aiap-gateway-acceptance
docker start -a aiap-gateway-acceptance
docker inspect --format '{{.State.ExitCode}}' aiap-gateway-acceptance
docker rm -f aiap-gateway-acceptance
docker image rm aiap-gateway-acceptance
```

必须检查退出码为 0 且 JSON 报告为 passed。输出不含私有状态；所有状态位于临时挂载中，删除容器时销毁。命令仅针对这里命名的测试容器，不应对既有部署执行。

CI 与真实本地模型测试分开记录。该结果不证明跨容器生产网络、真实 NAS 恢复、Docker 内模型推理、跨 Runtime 安全迁移或当前撤销记录应用于历史备份。生产拓扑仍需在明确目标与范围后单独验收。
