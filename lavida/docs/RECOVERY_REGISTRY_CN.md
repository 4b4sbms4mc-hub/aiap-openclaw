# Core 离线检查点登记

登记是恢复前的一个管理步骤。它保存此登记库已接受的检查点摘要和治理版本，用来拒绝之后提交给同一登记库的已知回退。登记命令本身不联系源端，不签发证明，也不读取备份。

## 管理入口

从 Core 源码环境运行。以下占位符应替换为操作员核准的本地路径和独立取得的 SHA-256：

```sh
python -m aiap_core --data-dir "$CORE_DATA" recovery --registry-dir "$REGISTRY" \
  init --enrollment-sha256 "$ENROLLMENT_SHA256"

python -m aiap_core --data-dir "$CORE_DATA" recovery --registry-dir "$REGISTRY" \
  register --checkpoint "$CHECKPOINT" --checkpoint-sha256 "$CHECKPOINT_SHA256"

python -m aiap_core --data-dir "$CORE_DATA" recovery --registry-dir "$REGISTRY" status

python -m aiap_core --data-dir "$CORE_DATA" recovery --registry-dir "$REGISTRY" \
  review --checkpoint "$CHECKPOINT"
```

- `CORE_DATA` 指现有 Core 数据目录。登记命令不打开其中的文件。
- `REGISTRY` 是由本地操作员独立保管的目录，必须在 Core 数据目录和所有恢复备份之外。首次初始化要求该目录不存在、其父目录归当前用户所有且他人不可写。运行时需要可信的本地文件系统和路径。登记库缺失、损坏时停止；不要从备份重建登记后把它当作原有的防回退记录。
- `ENROLLMENT_SHA256` 固定的是规范化登记文档（含 Owner 签名）的摘要，`CHECKPOINT_SHA256` 固定的是检查点文件原始字节的摘要。两项都应来自备份之外的独立可信渠道。仅从待恢复的备份计算摘要，不能建立信任。

登记核验检查点签名、登记签名、Core 签名及有效期，拒绝 Core 修订号或撤销序号下降，也拒绝在两者都不变时出现不同的治理内容。相同文件在有效期内重复登记不会改写登记时间。新签发的同治理检查点可推进登记，但签发时间须晚于上一次。登记只保留最近一个头及独立固定的登记摘要；检查点文件应另行保管。

状态中的 `within-validity-window` 只表示本机时钟落在已登记检查点的有效窗口内。即使登记成功，`source_currentness_verified` 和 `restore_authorized` 都为 `false`。这个登记库不能感知从未收到的删除或撤销，不能防止它自身被整库替换或回退，也不会生成独立见证。后续恢复必须另外取得新鲜且绑定同一检查点的证明。原离线恢复工具仍为单独入口；随新版源码使用时，需配套新版 Core 模块。

`review` 用登记库中的摘要重新核对检查点文件、签名、有效期以及治理摘要和版本，输出记忆索引和删除记录的数量。它不接受临时替换的摘要，不读取备份，也不改变登记。若登记在核对后发生变化，后续恢复仍需重新确认登记和实时来源。

## 实时核对和隔离恢复

```sh
python -m aiap_core --data-dir "$CORE_DATA" recovery --registry-dir "$REGISTRY" \
  review-live --checkpoint "$CHECKPOINT" --observer-executable "$OBSERVER"

python -m aiap_core --data-dir "$CORE_DATA" recovery --registry-dir "$REGISTRY" \
  restore-isolated --checkpoint "$CHECKPOINT" --observer-executable "$OBSERVER" \
  --snapshot "$BACKUP" --snapshot-sha256 "$BACKUP_SHA256" --target "$NEW_COPY"
```

- `OBSERVER` 是操作员独立配置并审阅的可执行文件，以绝对路径提供。应置于可信目录，且在 Core、登记库、备份和恢复目标之外。当通过网络连接来源时，启动器负责认证对端并使用受限观察命令。Core 不安装 SSH、密钥或服务。启动器从 stdin 接收一份 `x-aiap-source-observation-rpc-v2` 请求，返回一份同格式的 `observed` 响应；不得打印提示、日志或要求交互。Core 只传随机挑战和检查点摘要，不传路径、正文或凭据，并限制等待时间和回复大小。
- `BACKUP` 是独立保管、不会再写入的一致性快照，目录归当前用户且为私有。快照包含 `core.sqlite3` 和两份与登记身份匹配的签名密钥，不能带 SQLite 旁文件。`BACKUP_SHA256` 来自可信备份记录。目标必须是独立的新目录，不会覆盖已有目录。
- `review-live` 验证 Avatar v2 签名、随机挑战、登记绑定和有效期，返回采样与到期时间。它给出采样时刻的证明，`restore_authorized` 仍为 `false`。
- `restore-isolated` 是操作员显式发起的本地操作。读取备份前验证一次，准备好私有副本后复核备份摘要，再使用新挑战取得第二份证明。等待回复时不锁登记库；最后核验通过后锁住登记头，确认在登记未变且证明有效时发布目录。缺失或过期的证明、登记变化、摘要不符都会阻止发布。

恢复结果持久写在副本内的 `recovery-report.json`，包括最新证明的时间、治理摘要、恢复数量和撤销数量。终端退出后可从该报告确认结果。部分恢复会明确列出缺失数量；新 Owner 凭据仅留在副本。命令不启动 HTTP 服务，也不切换 Gateway。验证截至采样时刻；它没有锁定源端写入，也不能证明之后没有删除或撤销。实际 NAS 传输和生产切换仍需分别配置与审阅。
