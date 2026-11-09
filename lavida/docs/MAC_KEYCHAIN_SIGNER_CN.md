<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Mac 钥匙串签名器：准备与明确创建分开

作者：Wang Lu。2026-11-09。可审阅的本机签名器入口已在操作员明确批准后，实际为目标 NAS 绑定新增一条见证签名凭据，读取及随机挑战签名自检、独立新进程公开配置读回均通过。未登记生产见证、修改既有信任根或启动网络服务；具体身份与指纹保留在私有工作区。

## 固定目标与创建行为

`scripts/keychain_witness_signer.py` 默认只输出公开计划，不访问钥匙串。输入是严格限定字段的 binding：Avatar 引用、enrollment SHA256 和 generation；服务固定为 `aiap.mac-witness.signer.v1`，账户为 binding 的 SHA256，不能借配置改成其他凭据服务。真实设备引用与 generation 保存在私有工作区，不提交公开仓库。

只有显式 `--confirm-create` 才生成一把 Ed25519 见证密钥，通过 macOS Security Framework 的原子 `SecItemAdd` 新增一条通用凭据，随后读取校验并进行随机挑战签名自检。返回的配置只含公钥和 binding/条目引用，私钥不进入项目文件、日志、标准输出、邮件或 NAS；序列化的私钥仅在 Python 进程内存和系统钥匙串条目中出现。进程内存清零、不可导出硬件密钥和 Secure Enclave 不在本实现保证内。

原生绑定使用可选依赖 `scripts/requirements-witness-macos.txt` 中固定的 keyring 25.7.0。直接调用 `SecItemAdd`，不调用该版本会先删除既有条目的 `set_password`；重复条目返回错误，绝不覆盖、删除、换钥或重新登记。读取使用精确服务/账户且不允许交互式解锁；缺失、锁定、权限拒绝、错误绑定、损坏记录或不支持的平台一律拒绝，没有文件或其他 backend 自动回退。

上游实现与原生接口依据：[keyring 25.7.0 macOS backend](https://github.com/jaraco/keyring/blob/v25.7.0/keyring/backends/macOS/__init__.py)、[原生 API 绑定及 set 的删除行为](https://github.com/jaraco/keyring/blob/v25.7.0/keyring/backends/macOS/api.py)。本实现使用独立 CFData、对象所有权释放和只新增操作，未调用上游的删除/更新接口。

## 与持久见证的连接

`KeychainWitnessSigner` 公开 `public_key()` 和 `sign()`，后者只接受现有见证签名域，每次签名重新读取并校验条目，不缓存私钥。它可以作为 `DurableLiveWitness` 的外部 signer；签名时钥匙串不可用，持久头事务会回滚，不返回新证明。

`--inspect-existing` 只恢复并核对已存在条目的公开配置，不创建替代密钥。若新增成功但读取自检或响应失败，条目可能已存在；必须先复核，不自动删除或再次生成。同一 binding 的重复创建明确失败。停用时先停止使用该 signer，保留条目供审查；本工具不提供删除接口。

## 实际验证范围

10 项新增测试使用显式注入的内存测试 store，不写系统钥匙串。覆盖默认 CLI 仅输出计划、显式创建开关、重复创建保留原密钥、重开/签名和公开配置不含私钥、缺失/拒绝无回退、绑定与私钥记录篡改、签名域限制、原生重复状态映射、非 Mac 拒绝，以及与持久见证的真实签名/提交整合。随后经过具体配置明确批准，真实 macOS 原子新增、回读、签名自检和独立进程读回均已通过；不能由此推断所有 Mac 的访问策略相同。当前加 SSH 身份准备后 scripts/tests 合计 159 项。

生产操作前应展示具体 binding、服务/账户、已验收代码版本、当前用户默认钥匙串、创建命令及公开配置保存位置，取得针对该范围的明确确认。该确认仅覆盖这一个本机签名凭据，不自动授权 NAS 私钥读取、SSH/sudo 权限变更、见证服务部署、信任根替换或恢复激活。

执行归属：LM Studio `qwen2.5-coder-14b-instruct-mlx` 提供测试专用 FakeStore 草案并经 Codex 复核采用；Codex 直接完成原生只新增操作、签名器、整合与安全边界测试和本机只读探测。未调用云端模型。
