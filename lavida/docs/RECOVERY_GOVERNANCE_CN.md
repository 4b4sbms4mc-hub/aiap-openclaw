<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# 旧备份隔离恢复治理实验

作者：Wang Lu。2026-11-09。此实验属于仓库开发工具，不是 Core Service 的新网络接口、生产恢复承诺或 Secure Avatar Transfer 实现。Core 0.2.0 与插件 0.3.5 源码候选版本不变。

`scripts/recovery_guard.py` 验证一个保守的单 Owner 恢复子集：旧备份提供数据，独立取得的当前治理检查点决定哪些记录仍可激活。旧凭据一律失效；旧会话视图、历史正文和候选不恢复。检查点缺失、过期、身份不符、摘要或签名失败时不激活目标目录。所有演示和测试仅使用合成数据与新隔离目录。

## 信任和时效

检查点使用本地 Owner Key 对完整载荷作 Ed25519 签名，绑定当前签名 Core、空间策略版本、删除 tombstone、撤销 epoch 和有效期，最长 24 小时、默认 1 小时。它不携带记忆正文、私钥或认证 token；对象标识、索引和删除元数据本身仍敏感，输出文件权限为 0600。

**签名和哈希不能自行证明检查点是最新的。** 操作者必须从可信当前状态源独立取得检查点及其 SHA256，并在备份之外保护这个 pin。工具要求显式传入 pin，拒绝使用位于旧备份内部的检查点。有效期只限制窗口，不消除窗口内的回退风险；从同一旧备份抄出检查点和摘要不构成当前授权依据。

导出检查点后，源端发生的新撤销或删除不会自动同步到恢复实例。激活前必须重新确认检查点仍代表当前权威状态；无法确认时只能隔离保存，不能据旧签名推定仍有权限。此实验没有远程见证、单调计数服务或跨设备 Owner 验证，也不解决宿主机管理员攻击。

## 恢复规则

1. 只支持当前已知 SQLite Schema、单 Owner、general/life/work 三空间和纯记忆索引。未知表、关键扩展、Core 摘要或程序性索引拒绝，不能静默丢弃安全语义。
2. 校验旧数据库完整性、本地签名、身份、记录正文摘要及数据库行的归属/空间/版本；旧密钥必须对应已固定检查点的公钥，轮换不匹配时拒绝。
3. 仅保留当前 Core 索引中 ID、版本、空间策略和 SHA256 全部一致的有效记录。已删除、过时、未知或不匹配对象排除；当前索引有而备份缺失的内容计入缺失，不拿旧版本冒充最新内容。
4. 应用当前 tombstone；备份已有删除记录若在检查点中丢失或回退，拒绝恢复。正文、历史、待审批载荷、旧视图和旧审计副本均清除，并执行 SQLite VACUUM；原备份保持只读且不被修改。
5. 所有旧 grant 都标记撤销，包括旧 Owner grant 和未撤销的旧 adapter grant。不复制旧凭据文件，只在新目录签发新的 Owner 维护凭据；适配器需要重新显式授权。旧候选不会因恢复而得到审批。
6. 重建签名 Core，版本高于检查点版本，增加撤销 epoch。使用私有暂存目录；完整检查与最后一次时效判断成功后，才发布到预留的空目标目录。已有目标不覆盖，失败时不发布部分状态。

`restore_guarantee` 仅描述当前**记忆索引**：全部可用为 `complete-for-current-memory-index`，否则为 `partial-current-memory-index`。即使前者也不代表完整 AIAP、离线依赖闭包、外部向量/派生副本或生产恢复已完成。不能恢复的更新记录应从可信状态源另行取得。

## 隔离环境中的使用

以下命令仅供已准备的合成测试环境。检查点输出目录应独立受控；恢复目标的父目录须归当前用户所有且不可被组或其他用户写入。快照应在源服务停止后制作；本工具拒绝带 WAL/SHM/journal 旁文件的输入，并以 immutable 只读模式打开，避免重放日志或更改源快照。不要直接将运行中的 SQLite 文件当作一致备份。

```sh
python scripts/recovery_guard.py checkpoint \
  --data-dir /isolated/current-core \
  --output /trusted-controls/current-checkpoint.json

python scripts/recovery_guard.py restore \
  --snapshot /isolated/old-snapshot \
  --checkpoint /trusted-controls/current-checkpoint.json \
  --checkpoint-sha256 CURRENT_INDEPENDENTLY_VERIFIED_SHA256 \
  --target /isolated/new-recovery
```

`CURRENT_INDEPENDENTLY_VERIFIED_SHA256` 必须替换为可信渠道独立记录的摘要，不能采用不可信备份附带的值。新 Owner 凭据仅写入新目录，控制台不打印秘密。先检查报告和缺失数量，再在明确范围内为适配器签发新 grant；本实验不自动重连 Gateway 或操作 NAS。

## 验证结果与来源

本地 17 项恢复测试通过，覆盖删除/旧版本排除、历史与候选正文清理、旧凭据全部失效、新凭据的批准闭环、检查点不含正文或秘密、摘要/签名/时效/身份/行空间篡改、已知回退、未知 Schema、符号链接、已有目标保护及恢复过程中到期的拒绝。实际 CLI 恢复后启动新的 Core HTTP 进程，确认旧 token 返回 401、旧候选不存在而保留记录可查。测试核对源备份文件摘要未变化。

LM Studio `qwen2.5-coder-14b-instruct-mlx` 提供风险测试类别草案；Codex 复核并修正其对部分恢复的建议，直接实现工具、测试与验收。未调用云端模型。GitHub CI 单独运行这些测试；它们与既有 Core、插件和 Gateway/Docker 测试的覆盖范围分别记录。
