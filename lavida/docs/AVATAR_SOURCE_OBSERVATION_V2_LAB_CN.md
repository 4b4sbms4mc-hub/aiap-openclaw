<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Avatar Key 源观察 v2 隔离实验

本候选仅供合成数据实验，未接入 SSH、真实 Core、Mac 钥匙串或生产恢复。

v1 保持不变。v2 显式导入 `recovery_avatar_observation`：profile 为
`x-aiap-live-source-observation-v2`，签名域为 `AIAP-LIVE-SOURCE-OBSERVATION-v2\0`。
检查点及 Owner 签署的登记仍走既有严格验证；观察签名改用该登记绑定的 Avatar 公钥。
源端只读取合成 `avatar-key.pem`，不读取 Owner 私钥，不提供任意内容签名。

验证覆盖既有可用性、只读快照、旁文件拒绝、过期/重放、Schema/身份绑定、回退限制，
另验证 Owner 私钥缺失不影响观察、Owner 私钥替代 Avatar 密钥被拒绝、v1/v2 交叉验证失败。
逻辑分离并不代表硬件隔离；Avatar 密钥轮换/撤销的新登记仍需独立可信更新，旧 pin 不自动升级。
不会使用 v1 验证失败后的自动降级或自动尝试 v2。该模块的见证证明沿用实验见证格式，
不表示已有生产兼容；原有v1 RPC保持不变。

运行：

```sh
python -m unittest discover -s scripts/tests -p test_recovery_avatar_observation.py -v
sh scripts/run_nas_avatar_observation_lab.sh
```

NAS 入口只检查本地已有镜像，不拉取/构建镜像；复制公共代码到临时目录后运行临时受限容器，
无网络、只读根目录、无生产数据卷、无服务重启；运行结束清理临时副本。
测试使用临时生成的身份和密钥，不应把真实目录作为 fixture。

限制与 v1 相同：证明只是采样时刻观察，不是写租约；无法发现见证离线期间从未观察的整体回退，
不能阻止采样后普通写入或源与见证联合回退。正常 NAS 写入不依赖 Mac 在线。
生产接入仍需要专门检查点登记/更新、最小权限安装与回退审阅；本次不授权这些操作。

## 独立 v2 实验消息链

`source_avatar_observation_rpc.py` 使用 `x-aiap-source-observation-rpc-v2`，仅选择预登记pin，并在发出/接收时调用Avatar v2验证器。`source_avatar_observation_transport.py`提供显式`fetch_avatar_observation`客户端，沿用1024字节请求、4096字节响应和最多15秒直接子进程等待边界。调用者不能通过字段选择签名版本或任意路径，v1/v2请求及响应不互认，不自动降级。

新增14项消息/子进程测试，总227项；已完成的NAS21项实测只覆盖观察生产者，不能冒称已在NAS验收这两个新模块。两模块没有CLI监听器/安装器，不读取真实NAS或钥匙串，也不改变生产探针。
