# Runtime 与 SDK

`egrio-runtime` 是 Core 与平台资源的唯一生命周期边界：它持有 Core generation、平台能力事务、
租约、检查点、packet 任务与恢复。`egrio-sdk` 只负责装配与进程内租约协调。本文还记录捕获层切换、
桌面配置操作、平台装配以及两个非 GUI 宿主（`egrio-service`、`egrio-daemon`）。crate 职责与依赖
规则见[架构总览](overview.md)，Core 内部见[Core 数据面](core.md)，桌面宿主见[桌面宿主](desktop.md)。

## 模块布局

`runtime.rs` 定义 `Runtime`、能力端口与控制状态，事务按职责分在 `runtime/` 下：

- `start.rs`、`reload.rs`、`stop.rs` — 三种生命周期事务及其补偿；
- `capability_plan.rs` — 事务按租约顺序 prepare、apply 与 restore 的能力计划；
- `checkpoints.rs` — 事务的检查点持久化，以及上一进程留下的检查点的恢复；
- `core_control.rs` — Runtime 持有的 Core：读取、实时更新、连接切换与 quiesce，以及 start、reload、stop 里 Core 的那一半；
- `packet.rs` 与 `task.rs` — packet 数据面任务及其受管任务；
- `health.rs` — 平台会话的连接健康 watcher；
- `configuration.rs` — [桌面配置操作](#桌面配置操作与生效状态)；
- `outcome.rs` — 各事务的报告与错误。

## 租约与检查点

`egrio-runtime` 公开 Runtime 身份/代次/生命周期值，以及平台独占租约和恢复检查点的结构化契约。
`CheckpointStore` 是必须报告 create/replace/delete 失败的异步端口；检查点使用 revision
compare-and-swap，`Committed` 记录在验证恢复并删除前仍属于 unresolved。

`egrio-sdk` 提供进程内 `PlatformLeaseCoordinator`、显式注入 `CheckpointStore` 的
`EgrioSdkBuilder`、用于测试或临时宿主的 `InMemoryCheckpointStore`、使用原子替换和 revision
compare-and-swap 的持久化 `FileCheckpointStore`，以及从 unresolved checkpoint 原子重建
`recovery-required` 租约的启动屏障。租约请求本身不取得资源，`LeaseGrant` 的 Drop 不释放资源，
恢复批次冲突时不会留下部分保留。运行中 Runtime 的 grant 可以在同一 coordinator 临界区原子扩展为
严格超集；冲突不会留下部分新增 key，未修改 OS 的预留可以缩回，已修改后则必须提交
verified-restore 证据。

`FileCheckpointStore` 每条记录一个文件。写入先把内容写进临时文件并刷到磁盘，再改名替换，Unix 上随后同步
目录（改名与删除不同步目录就可能在断电后丢失；不支持同步目录的文件系统略过这一步）：改名是文件系统立即
记入日志的元数据，内容却还在缓存里，不先刷盘的话断电会留下一个名字正确而内容为空的记录。所以崩溃或断电
留下的要么是原记录、要么是完整的新记录。解不出的记录（内容损坏，或另一个构建以别的 schema 写下）让
`list_unresolved` 以 `Corrupt` 失败并写明文件，不会被跳过：跳过等于隐瞒一份没人恢复的 OS 改动。这样的记录
等多久也解不出，也恢复不了任何东西，宿主可以先调用 `set_aside_unreadable` 把它们改名为
`<id>.json.unreadable` 移出存储；桌面在启动时这样做并记入日志（见[启动](desktop.md#启动)），`egrio-node`
不调用，照常报错。

SDK 可以创建和登记相互隔离的 Runtime 实例，只允许移除已经验证为 `Stopped` 的实例。启动屏障从
unresolved checkpoint 重建恢复租约并调用 Runtime 的统一逆序恢复执行器；验证恢复后删除检查点并
释放租约。启动恢复要求每个 restore report `verified=true`；显式错误或未验证报告都会把已进入
`Restoring`/`Recovering` 的 checkpoint 与租约退回 `RecoveryRequired`，同一 SDK 实例可以幂等重试，
持久状态不会卡在过渡 phase。

## 平台能力端口

Runtime 定义五个互相独立的平台能力端口：`PacketCapture`、`SystemProxyControl`、`RouteControl`、
`DnsControl` 和 `FirewallControl`。支持状态和失败使用结构化能力类型；平台缺少能力时必须报告
`unsupported`；无法识别的 checkpoint/lease 归为 `CapabilityKind::Unknown`。SDK 提供仅用于契约
测试和临时宿主的 `InMemoryPlatform`，其可变能力状态按实例隔离，并支持确定性的
apply/observe/restore 与就绪驱动的内存 packet 设备。某一层能否启用只由它的能力事务回答，
不存在就绪报告、预检或诊断快照这类旁路探测。

## Core 与启动输入

每个 Runtime 实例内嵌自己的 `RuntimeCore`，它是 Core generation 的唯一 owner；不存在 Runtime
之外的 Core 协调器。`RuntimeSpec` 声明 Runtime-owned `RuntimeCoreSpec`，`SystemProxySpec` 的
endpoint 可以引用该 generation 实际绑定的 `CoreListener`。宿主通过 `EgrioSdkBuilder::core_config`
注入 `CoreConfigSource`；start 事务固定先加载 profile/egress、编译唯一 `NativeCoreDevice` 并绑定
listener，再解析依赖 listener 的平台设置，之后才取得租约、预写 checkpoint 和调用 OS adapter，
因此 listener bind 失败不会留下租约、checkpoint 或平台 mutation。

`EgrioSdk` 创建的 Runtime 把事务（start、reload、stop、配置操作、quiesce）派到 SDK 的第一个 Core 执行器，
捕获的每个队列的包泵各派到一个执行器（`Runtime::with_executors`）。每个执行器是只有一个工作线程的 Tokio
多线程运行时（线程名 `egrio-core-<序号>`）：Core 的控制工作与一个队列的包泵派生的任务（relay、
上游、DNS、UDP 会话）都在所在执行器的这一个线程上运行，阻塞工作仍进执行器的阻塞线程池，宿主自己的运行时（GUI
的 IPC 与界面命令）不与它们共用线程。执行器的个数取捕获能分流的队列数（`PacketCapture::queue_limit`：Linux
的多队列 TUN 为内核上限 256，Wintun 与 utun 为 1）、进程可用的核数与 8 中最小的，没有捕获的
SDK 一个；Runtime 请捕获打开至多这么多个队列。每份数据都要在包泵、relay、上游 socket 与 quinn 的任务之间
交接；把同一队列的任务留在同一线程可减少线程停驻与唤醒，多流峰值由多个捕获队列分担。SDK 必须比
它创建的 Runtime 活得久：SDK 释放时它的执行器随之结束。

`RuntimeCoreSpec.listen_port_fallback` 让一个被占用或被系统保留的混合端口让位：Core 依次尝试它之上
的 64 个端口，都不行时由系统分配，并在 `NativeCoreStatus.listener_fallback` 记下请求的地址、原因
（`in-use` 被其他程序占用，`reserved` 被系统保留或被独占）和系统错误。端点校验接受这个记录过的替代
端口，系统代理跟随实际绑定的端口；spec 里始终记请求的地址，因此下次启动仍先试配置的端口。桌面开启
此项，daemon 与服务端角色不开启，端口不可用时启动失败并写明地址、原因和换端口的提示。

桌面宿主在真正 start/restart 前通过 `core_start_spec` 固定活动 Profile 的最终配置快照，把本次
监听地址写入 `RuntimeCoreSpec`；Core profile、IPv6 egress 和规则 provider 物化使用同一个快照，复制
旧 topology 进行配置重启时也重新执行此步骤。快照里的 profile 由随后的那次 Core 启动取走，只能取一次：
Core 编译后没有别的读者，宿主留下的只是运行中这一代还会被问到的几项（profile id、Fake-IP 网段、
监听与 TUN 路由设置、捕获 MTU）；没有经过 `core_start_spec` 的启动因此被拒绝，而不是用上一次准备时
读到的配置。[捕获层切换](#捕获层切换)在运行中的 Runtime 上
reload，继承当前 Core spec，不重新加载监听设置。字段来源、缺省值和写入契约见
[配置档案存储](profile-store.md#取值规则与作用域)；Core 只接收结构化配置，不读取 YAML 或 GUI
应用设置。

数据面遥测来自同一 Runtime Core，只在实例已提交为 `Running` 时通过
`Runtime::core_traffic_telemetry_snapshot` 暴露，宿主不会把 Created、Reloading、Degraded 或
Stopping 的数据面呈现为活动实例。轮询的宿主改用 `core_traffic_telemetry_since` 并保存返回的
`TelemetryCursor`：每次只取活动连接与游标之后的结束记录（session registry 为每条结束记录编号，
最近 512 条），游标属于另一个 Core 代次时从头开始，避免每次重建整个结束记录环。listener 与 packet ingress 共享同一 Core session
registry：连接 id 统一带 `core-<generation>-` 前缀并以 `inbound` 区分入口；特权服务与 Network
Extension 都没有第二个遥测来源。

## 生命周期事务

Runtime 对全部能力使用同一事务计划：`start` 在首次能力修改前原子取得全部进程内租约并预写包含
所有能力/附加租约的检查点，按确定顺序应用；只有结构化 apply report 的 `verified=true` 才能继续，
`Ok` 但未验证与显式 apply error 一样触发包含当前能力的逆序恢复。`reload` 对同一 Runtime ID 计算
Core 与平台能力的 topology diff，在 union lease 下准备并应用 added/changed 资源、逆序恢复 removed
资源，再把 checkpoint 和 grant 收缩到目标集合；目标无平台能力时删除 checkpoint 并完整释放租约。
只有 Core、平台、checkpoint 和 lease 全部完成后才发布一个新代次；失败保持旧 spec/generation，
能够验证回滚时恢复上一提交，否则进入 `Degraded` 并保留实际 checkpoint 与 `recovery-required`
租约。`stop` 幂等逆序恢复 Runtime 启动前的原始平台基线、删除检查点并释放全部租约。能力已恢复
但 checkpoint 删除或其他收尾失败时，Runtime 报告 `capabilities_restored=true`，控制态保留
`RecoveryRequired` phase 与对应租约，同一实例后续 `stop` 会进入 recovery transition 并重试收尾，
不能通过新建 Core 或丢弃记录绕过恢复。

`Degraded` 时的 `reload` 是原地恢复：目标必须保留现有 Core，且只能去掉、不能新增或改变资源；
被去掉的资源逆序恢复，其余保持已提交状态，提交后回到 `Running`，宿主再以普通 reload 增长。
保留可变资源只在平台会话丢失后、且尚无事务触及能力时允许，并且只保留不在该会话内的系统代理：
connection-health 断连，或 packet data plane 自行结束（服务或 OS 隧道结束了它）时，Runtime 记下
会话丢失并通过 `subscribe_session_loss` 广播，
PacketCapture/Firewall/Route/DNS 经新会话恢复（服务随旧连接释放的状态按幂等恢复处理），租约由
`resume`（Recovering→Held）后收缩到保留集合，checkpoint 改写为只含保留能力的 `Committed`。其他
降级原因不能担保任何资源，只能收缩到 Core。

Runtime 控制态持有当前 Core 的精确 `RuntimeCoreGeneration`。Core 只由 start 或 reload 事务启动：
事务开始时若已有 Core 在运行，它不属于这个事务，启动被拒绝。spec 带着 Core 在各种能力组合之间
reload 时（包括收缩回 core-only）同一代 Core 保持运行；完整 stop 后、或 reload 到不含 Core 的 spec
时它停止。Core cleanup 发生在 OS restore、
checkpoint 删除和 lease 释放之后；若仅 Core stop 失败，Runtime 进入可重试 `Degraded`，但
checkpoint/lease 不会被伪造为 OS recovery ownership。start/reload/stop 都在 detached transaction
task 中运行，调用方 future 被取消不会打断已开始的事务。`RuntimeDomainReport` 使用统一资源词汇
区分 Core 和 platform 的 applied、retained、restored、rolled-back 与 recovery-required；同一 undo
栈和提交门覆盖全部平台能力，任一恢复无法验证都会保留实际 checkpoint/lease 并进入 `Degraded`。

宿主停用前调用 `Runtime::quiesce_core` 时，Runtime 先请求受管停止并取消、join packet pump，再
封闭 Core 并等待旧连接排空，避免关闭后的 Core 被仍运行的包泵误记为设备故障。停止阶段的真实
设备故障仍返回错误，Core 仍保持封闭；调用方取消不会打断该 detached 事务或丢失任务所有权。随后
`stop` 继续负责 OS 恢复和 checkpoint/lease 收尾。

进程崩溃不执行任何清理：从崩溃到下一次启动恢复之间，系统代理仍指向已停止的 listener，各平台
TUN 资源的去留见对应平台文档；下一次启动由 SDK 启动屏障消费 unresolved checkpoint。

## 包数据面

桌面 OS 接管由 `PacketCapture` 与 Route/DNS/Firewall/SystemProxy 能力的事务表达。平台 adapter
持有设备、OS 配置和恢复机制；Runtime 持有租约、唯一 Core、`NativeCorePacketDataPlane`、取消与
join。平台设备不实现代理协议、规则、Fake-IP 或 TCP/UDP relay。

Packet capture 的数据面是双向 `PacketDataPlane`（由 SDK builder 显式注入）；它本身不进入 Runtime
规约或持久化检查点，但 packet capture 规约必须同时声明 `RuntimeCoreSpec`。每个 generation 只
编译一个 `NativeCoreDevice`：listener session 通过 `start_on_device` 绑定在该设备上，Runtime 再请
adapter 打开至多执行器个数的队列（`PacketCapture::open`），把返回的 `PacketCaptureOpen` 的各队列与执行器
逐一配对，连同同一设备传给 `PacketDataPlane::run`，停止只通过 `CancellationToken`。`NativeCorePacketDataPlane` 是无状态单元类型，不保存、替换或热应用
第二份 Core；listener、packet pump、DNS/fake-IP 和连接遥测共享同一 session registry。TUN 是否
开启不影响 Core 启动输入：start 或 reload 都可以在运行中的 Core 上增删 PacketCapture。prepare
PacketCapture 之前，Runtime 以 adapter 的 `reserved_addresses()`（TUN 接口与虚拟 DNS 地址）校验
当前 Core 的 fake-IP 池，可能分配到其中任一地址时在任何 OS 变更前拒绝。设备契约、包泵、分片与
进程归因属于 Core，见[Core 数据面](core.md#包设备与包泵)。

默认路由可以把一组目的网段留在隧道外（`IpPrefix`，主机位为零），它们沿用系统原有路由，流量不经
Core：自己安装默认路由的 capture（macOS 的 utun 服务）用 `PacketCaptureSettings.excluded_prefixes`，
单独的 Route 能力用 `RouteSettings.excluded_prefixes`，防泄漏的 Firewall 能力以
`FirewallSettings.excluded_prefixes` 得知同一组目的地。规约要求排除只出现在请求了默认路由的能力上、Firewall 的与
路由排除的完全相同、
每组至多 256 项；prepare 路由或 capture 之前，Runtime 还拒绝覆盖 TUN 自身地址或当前 Core fake-IP 池
（含其 IPv6 投影）的排除，因为路由到隧道外的 fake 地址到不了回答它的 Core。reload 可以只改变运行中
capture 的排除：Runtime 校验后调用 `PacketCapture::update_excluded_prefixes`，设备与包泵保留，capture
的原 checkpoint 仍负责恢复（排除随隧道会话结束），失败时以原设置再调用一次补偿；capture 的其他设置
改变仍需要 stop/start。各平台的实现见平台文档。

Firewall 能力（`FirewallSettings.kill_switch`）是 TUN 运行时的防泄漏规则，不当 kill switch：只拦截从物理出口
（以太网、Wi-Fi、PPP、移动宽带）绕过隧道发出的 DNS、隧道不承载的 IPv6 与隧道外到 fake IP 的连接
（`FirewallSettings.fake_ip_prefixes`，Core 的 fake-IP 池及其 IPv6 投影，宿主以 `IpPrefix::fake_ip_pool` 从启动 Core
的配置取得：桌面取自配置快照，无界面的 `linux-tun-run` 取自它运行的配置），其他软件特意从隧道外发出的流量（其他
VPN 的连接与它发进自己隧道的 DNS、绑定接口的 socket）照常通行，所以 Tailscale 的 MagicDNS 开着 TUN 照常解析；
规则随隧道会话结束，Egrio 停止或崩溃后网络回到没有它时的样子。实现见
[Windows](../platforms/windows.md#子系统) 与 [Linux](../platforms/linux.md#出口dns-与防火墙)。macOS 不需要这一层，
fake IP 一项由 capture 自己承担：宿主在没有 Firewall 能力时把同一个池放进 `PacketCaptureSettings.fake_ip_prefixes`
（主机位为零，改变时 capture 重开），见 [macOS](../platforms/macos.md#网络设置与捕获范围)。

`CoreStartInputs.capture` 显式提供 `NativeCoreCaptureConfig`，编译设备时与 profile、egress、
socket guard 一起消费；packet plane 不覆盖它，也不私有编译一份默认 DNS 捕获配置。其 IP 层 `mtu`
与 `PacketCaptureSettings.mtu` 必须相同，合法范围是双栈链路的 1280..65535。Runtime 在
prepare/apply 前核对，保留同一 Core 的 reload 不能改 MTU，更改时先 stop/start 重建 Core。桌面在
一个准备快照中同时保存 profile、捕获意图和 MTU，TCP 引擎与 UDP/DNS 回包均使用这一个值。
公开 Core `apply_config` 同样在发布前拒绝非法或不同 MTU，并通过 `Result` 报错，不退回旧值冒充
成功；仅更改 profile/egress 的 API 保留已有 capture 契约。各平台的 DNS 捕获模式由平台文档维护。

设备级 health probe spawn 是幂等的，listener 与 packet 入口均可无条件请求而只产生一个 scheduler。
捕获能力附带的默认路由等次级租约会与能力检查点一起持久化。`runtime/task.rs` 的受管任务服务
packet worker：运行结果、显式停止事实与任务身份由同一所有者记录，运行中意外返回、错误或 panic
主动触发 `Degraded`，旧任务通知不能改写替换后的任务。结果在 worker 返回时定格，资源释放与 join
是后续屏障；stop 不能事后把已经发生的失败改成预期取消。启动提交期间任务退出也走既有补偿事务，
不能发布成功代次。

packet report 完成即可通过 `take_packet_report` 读取，每次完成只发布一次，包含故障前的包计数；
未消费报告可跨重启保留。stop 取消泵的 token 并 join，超时保留任务所有权供后续重试。取消从不令
设备失败，因此停止时出现的致命错误是真实数据面故障，会使该次 stop 失败并保留报告；已经在停止前
退出的任务，其故障保留在报告中，不妨碍已验证的 OS 恢复释放租约。

## 捕获层切换

产品只有系统代理与 TUN 模式两个独立开关，定义见[架构总览](overview.md#捕获模型)。
`egrio-platform` 的 `CaptureLayers`/`CaptureSupport` 是唯一的层模型；层状态的唯一事实是已提交的
Runtime spec：`system_proxy` 对应 `spec.platform.system_proxy`，`tun` 对应
`spec.platform.packet_capture`，桌面不保存模式或会话投影。

`DesktopRuntime::apply_capture_layers` 是三个桌面平台共用的唯一切换路径，各平台只提供把层映射为
spec 的纯函数：系统代理层是端点指向 Core listener 的 `SystemProxySpec`；TUN 层是平台的
PacketCapture，Windows 与 Linux 另带 Route、DNS 与防泄漏的 Firewall，macOS
的 capture 自带路由与 DNS。任一层开启时 spec 含 Runtime-owned Core。配置档案排除的目的地
（[TUN 排除](profile-store.md#tun-排除的目的地)）由共用路径放在安装默认路由的能力上：Windows 与 Linux
是 Route（Firewall 得知同一组），macOS 是 capture 本身；start 按快照中的模式取值，运行中
的切换按 Core 当前的模式取值。切换规则：

- Runtime 运行中：reload 到目标 spec 并继承当前 Core spec。Core generation、listener、DNS 缓存、
  Fake-IP 池与未变化层的 OS 资源保留；reload 失败由 Runtime 补偿回已提交的层，补偿失败进入
  `Degraded`。reload 新增 TUN 后，若 TUN 关闭期间有 Core 拨号未受出口保护（macOS 绑定器的
  `take_unbound`、Linux 标记 guard 的 `take_unmarked`），桌面切断全部 Core 连接
  （见 [macOS 出口环路隔离](../platforms/macos.md#出口环路隔离)）；
- Runtime 未运行：先由 `core_start_spec` 固定配置快照，再以目标 spec start；
- 目标为空：stop；
- Runtime `Degraded`：先以“已提交的层去掉 TUN”原地恢复（见[生命周期事务](#生命周期事务)），
  保留系统代理与 Core，再按 Running 规则切换；Runtime 拒绝原地恢复（降级并非平台会话丢失）时才
  stop 后按目标 start；原地恢复的能力恢复失败则保持 `Degraded`，留给下一次尝试。

平台会话丢失（服务停止或崩溃）后，桌面自动恢复
TUN：`watch_session_loss` 订阅 Runtime 的会话丢失事件，发出 `tun-session` 通知
（interrupted/recovered/failed）并在 `CaptureStatus.tun_interruption` 中报告原因；随后在用户过渡
锁内就绪 TUN 环境并重新应用已提交的层，按 0/2/5/15 秒共尝试四次。期间系统代理与 Core 持续服务；
用户的切换会结束这些尝试，任一次成功的切换都清除中断原因。

窗口与托盘都经 `commands/capture.rs` 以“切换某一层”的意图请求，在用户过渡锁内按已提交的层解析
目标，因此并发的另一次切换不会被陈旧状态覆盖；Windows 系统代理 yield 走同一路径。开启 TUN 前
先确保 `tun_environment.rs` 中的一次性环境就绪。

## 桌面配置操作与生效状态

桌面局部配置使用 `profile_configuration.rs` 的类型化意图和 `Runtime::configure`，不借用完整档案
保存，也不因任何错误就停止 Runtime。操作按语义分类，不分析整份配置的差异：

| 操作 | 执行边界 |
| --- | --- |
| Select 节点、流量模式、全局出口 | 原地发布 Core 策略，保留同一 Core、规则索引、listener 和 packet 入口；提交前路由 epoch 里还没定下路由的流被取消，已经在跑的会话逐条判断。TCP：拿它当初那次决策的输入与地址（规则不变，所以同一条规则再次命中）向新策略问一遍，经策略组解析出的节点与它正在走的那个相同就继续跑并转到新 epoch，不同就结束并当即向客户端复位。UDP：按每个 identity 的既定决策重新解析（EIM，它的数据报本来每次都这样解析），有一个 identity 改道就整条关闭、下一个数据报重建，否则连出口端口一起留着。DNS 代际只在它读的那部分策略变了时重建——流量模式、全局出口、IPv6 开关；重建就退休旧代际连同它的缓存，正在经它解析目标的 UDP 会话也随之整表关闭。选择节点不重建：服务实时读策略组的选择。TUN 运行中且配置档案排除了目的地时，进入全局模式前先 reload 去掉排除，失败则不切换；其他模式切换在 Core 策略提交后 reload 到新模式的排除，失败时报告等待应用，TUN 仍捕获这些目的地。 |
| 设置页 IPv6 解析（写入来源 `ipv6`） | 原地更新同一 Core 的 DNS 解析策略；macOS/Linux packet adapter 继续捕获双栈，不借开关更改捕获网络设置或重启设备。 |
| 设置页 allow-lan（写入来源 `allow-lan`） | 同端口局部重载本地监听组件；保留 Core、规则、loopback 会话和 packet 入口。 |
| mixed-port、显式 bind-address、活动档案切换、整份 YAML 保存、规则页编辑 | 完整 Runtime 重启；非活动档案或已停止 Runtime 只保存，不隐式启动网络。 |
| 系统代理、TUN 模式、退出/恢复 | 走[捕获层切换](#捕获层切换)或退出 stop，不作为局部策略更新。 |
| 主题、语言、窗口等宿主设置 | 不进入网络控制面。 |

同样修改来源的 `ipv6`，设置页开关只改写这一键并局部生效，编辑器保存整份 YAML 是整体替换，二者
有意采用不同类别。配置事务在 Core 的线程上运行，宿主交来的保存（写配置文件）放进阻塞线程池执行，
避免文件 I/O 阻塞包泵与会话任务。
完整重启是这些操作本身的计划，不是局部更新失败后的兜底；局部更新失败不会暗中改走完整重启。
新增配置功能必须在后端登记以下内容，并复用已有资源能力，不新增界面里的生命周期逻辑或第二套协调器：

| 必须声明 | 内容 |
| --- | --- |
| 操作和作用域 | 参数类型、profile/资源身份、基础版本、校验规则 |
| 执行类别 | 原地更新、组件重载、完整重启或捕获层切换，及分类原因 |
| 持久来源 | 修改哪个既有配置字段或记录；不建立第二份覆盖设置 |
| 影响集合 | 受影响的策略、缓存、连接、队列与组件，以及必须保持的长期资源 |
| 执行计划 | 准备、提交点、依赖顺序、观察方式、旧资源完成凭据 |
| 故障策略 | 提交前失败、部分提交、回复丢失、清理超时与可逆补偿的行为 |

`DesktopRuntime` 的用户切换锁（`begin_user_transition`）保护产品写入与传播，已接纳的局部操作由 owned task
执行，发起它的窗口关闭不会撤销其收尾责任。Runtime 配置协调器复用 operation lock，并用 semaphore 限制最多 16 个已接纳请求（包括
执行中和等待中的请求）；已退休、尚未完成的配置 ticket 最多保留 16 个，超限在持久化前拒绝新操作。
队列限制属于 Runtime 配置入口，不代表应用的所有操作都有同一上限。

Core 将生命周期与 routing epoch 分开：`prepare_policy_update` 校验候选，提交在准入边界一次发布
选择/模式/IPv6，并捕获旧 epoch 的 `RetirementTicket`。ticket 等待旧握手、sniff、拨号和 TCP/UDP
任务；新流不延长这次等待。捕获流量只经 packet device 进入，packet pump 绑定 device lifetime，每个
新会话从当前设备原子取得快照与 epoch，切策略不会停止 pump，也不会复用旧 DIRECT 会话。规则索引和
不受变更影响的静态资源共享；IPv6 解析策略变化隔离 DNS 缓存并撤销旧 egress policy lease，避免新
查询复用旧解析结果或 carrier。发送路径是 flow gate → route read，发布方不得反向持 route write 等
flow gate；提交临界区只发布、撤销准入并取得旧集合，逐流清理、writer 等待与 join 在释放写锁后
执行。清理超时由 Runtime 接管 ticket 并持续回收，不谎报成功、不停止父入口。

结果区分 `NoChange`、`SavedInactive` / `SavedStopped`、`Rejected`、`PendingApply`、`Applied`、
`AppliedCleanupPending` 和 `Degraded`。保存后的未应用、未知结果和局部降级不会伪装
成失败前状态，也不会暗中重启整个 Runtime。未确认的提交阻止后续网络配置提交，其他 Core 修改入口
及 topology reload 也执行同一检查；有效状态已确认但清理未完成时可在 ticket 上限内继续。Runtime
继续观察和回收，桌面按最终状态广播刷新事件。停止/退出仍走资源恢复流程，不会被未完成配置永久
挡住。

节点、模式与网络开关展示 effective 状态；Core policy 携带 profile ID，只有与当前档案一致才覆盖其
持久目标。原生状态事件同步刷新这些有效值，停止后显示持久目标。desired 流量策略从当前档案读取。
成功无提示，未完成与失败按 phase 展示。网络开关写入来源时的 CAS 与改写边界见
[配置档案存储](profile-store.md#取值规则与作用域)。

selector 更新在 Runtime operation lock 后排队，与 start/reload 竞争时不会丢弃已持久化的选择。
操作结果带 `applied`、`generation` 和 `error`；live Core 传播失败时桌面保留持久选择，并向
用户报告运行面已过期。

allow-lan 的 accept actor 与已接受连接分开管理，控制 channel 有界。关闭 LAN 时撤销非 loopback
新旧入站及未完成握手；同端口重绑允许短暂 accept 间隙，新绑定失败尝试恢复旧地址，结果报告实际
绑定和清理状态。恢复失败只降级监听组件，不停止 Core 或 packet 入口；不改用随机端口、始终
wildcard 或 SO_REUSEPORT。替代端口生效时，改范围针对请求的端口，实际作用在替代端口上，记录里的请求
地址随之换到新范围。依赖本机代理端点的 system proxy 与 checkpoint 更新也属于该组件计划，
默认 loopback/wildcard 的本机目标归一化为 loopback。

## 平台装配

三个桌面平台都只创建一个固定 ID 的 Runtime，系统代理、TUN 及两者组合的 topology 都由它管理，
层切换经[捕获层切换](#捕获层切换)在该 Runtime 上 reload，所有层关闭则停止。每个平台的宿主随
Core 启动输入提供进程归因扫描器，该代 Core 的归因 worker 同时服务系统代理 listener 与 TUN 流。

`DesktopRuntime` 只经 `DesktopHost` 契约使用平台：创建固定 Runtime、把层映射为 spec、TUN 关闭时
Core 的捕获 MTU、不读配置地恢复上一进程留下的 checkpoint、首个 Runtime 前的准备、TUN 关闭期间
未受出口保护的 Core 拨号、无 Core 时探测的出口，以及任一层开启期间持有的后台活动（macOS 借此
避开 App Nap）。三个平台共用一个准入边界：层切换、配置操作、完整档案保存与启动初始化先取得准入；
退出取得同一 mutex 后设置 closing，等已开始的事务完成再 stop，之后的准入明确报错，用户 stop 不受
准入限制。恢复失败不会重新开放准入，后续退出仍能取得同一 mutex 重试清理；后台活动只在 OS 资源
确认恢复后释放。

- **Windows**：`EgrioSdkBuilder::windows_service` 装配经命名管道连接 `egrio-service` 的四个远程
  能力端口（PacketCapture/Firewall/Route/DNS）与 connection-health，另注入本进程的
  `WindowsSystemProxyAdapter` 与 `WindowsFlowScanner`。远程端口始终在装配中，connection-health
  watcher 只在当前 spec 实际请求远程能力时运行；core-only 与纯系统代理 topology 不因服务断开而
  降级。WinINET adapter 的 reassert/yield 经单消费者非阻塞通道交给桌面的后台任务，yield 经捕获层
  切换只移除系统代理层。adapter 与服务行为见 [Windows 平台](../platforms/windows.md)。
- **Linux**：桌面以登录用户运行，为固定 `LINUX_RUNTIME_ID` 注入持久化 `FileCheckpointStore`、
  Core config source（出口 guard 为 `ServiceMarkingSocketGuard`，扫描器为 procfs
  `LinuxFlowScanner`）、经 `EgrioSdkBuilder::linux_service` 绑定 root 助手的四个远程能力端口与
  connection-health，以及本进程的 `LinuxSystemProxyAdapter`。root 运行的 Linux CLI 在进程内经
  SDK 装配 `LinuxTun`。设备、标记、DNS、防火墙、助手安装与恢复见 [Linux 平台](../platforms/linux.md)。
- **macOS**：桌面以登录用户运行，为固定 `MACOS_RUNTIME_ID` 装配持久化 `FileCheckpointStore`、Core
  config source（出口 guard 为隧道打开期间才绑定的 `MacosEgressInterfaceBinder`，扫描器为 libproc
  `MacosFlowScanner`）、经 `EgrioSdkBuilder::macos_service` 绑定 launchd 服务的 PacketCapture 端口与
  connection-health，以及本进程的 `MacosSystemProxyAdapter`。服务建立 utun、进 utun 的路由与默认解析器
  并交出 utun 的描述符，Runtime 负责唯一 packet pump
  与任务终止。机制见 [macOS 平台](../platforms/macos.md)。

## 特权服务

`egrio-service` 是独立的特权能力宿主：Windows 服务、Linux root 助手与 macOS launchd 服务。它只实现
远程能力端口，不托管 Runtime 或 Core。`bin/egrio-service.rs` 是服务二进制；`client.rs`、`protocol.rs`、
`framing.rs`、`transport.rs`、`session.rs`、`remote.rs` 是平台中立的控制协议与 SDK 侧远程适配器
`ServicePlatform`；`unix/` 是 Linux 与 macOS 共用的 Unix socket 传输（对端凭据、描述符随应答帧传递）。socket
本机用户都能连接、每条连接一个线程，所以被策略拒绝的对端只有 2 秒发出它那条会得到认证错误的请求并收走应答，
同时至多 16 个这样的对端在等，超出的直接断开：不能使用服务的进程因此占不住它的线程；起不了线程时只结束
那一条连接，服务照常接受下一条；Windows 的命名管道传输同样每条连接一个线程，认出客户端之前的代价同样有界，
见 [Windows 平台](../platforms/windows.md#特权服务)；
`windows/`、`linux/` 与 `macos/` 是各平台的服务宿主、对端认证、能力处理与包通道。

SDK 装配时 `ControlClient` 不连接服务，首次远程能力请求才建立并认证会话；初始化失败不缓存，取消或
Drop 会关闭部分连接。同一连接服务各能力端口和 packet 设备的交付。控制协议版本为 major 7，握手
拒绝其他 major，不保留兼容回退；打开包会话的结果按平台区分：Windows 为共享内存环句柄与服务持有的
TUN 接口索引，Linux 为服务替该用户创建的 TUN 接口与物理解析器快照，macOS 为 utun 的接口名与索引，
utun socket 的描述符随这一应答帧传来（SCM_RIGHTS）。能力顺序固定为
capture → firewall → route → dns，逆序恢复。断连经 connection-health 端口一次性降级为
`Degraded`（保留 checkpoint 与租约）。服务有 10 秒应答 Hello、60 秒应答一条请求（最慢的是打开隧道，系统可能
先要安装适配器的驱动）；过时就认定它不再应答，客户端关闭连接，会话按丢失处理——连接本身建得起来并不说明服务
在服务，而一条等不到应答的请求会让排在它后面的一切陪着等，退出也在其中。会话随连接结束（服务停止、崩溃或更新）后，下一次请求建立新
会话，与应用重启得到的会话相同；服务已随旧连接释放其资源，connection-health 跟随当前会话。桌面在
关闭或恢复含 TUN 的层时同样先就绪 TUN 环境（Windows 启动已停止的服务），就绪失败不阻止关闭，由
恢复本身报告错误并保留检查点。重载检查点使用可选回滚载荷保存上一已提交状态，成功提交后清除临时
载荷，同时保留最初恢复基线。

`ServicePlatform` 的 Route/DNS/Firewall 与 PacketCapture 请求映射平台中立，打开包会话后的通道
附着在各平台模块：`windows/channel.rs` 映射共享内存环并按服务持有的适配器索引激活出口绑定，
`linux/channel.rs` 附着服务以本用户为属主创建的 TUN（设备不存在时报错，不让 `TUNSETIFF` 新建）并
以服务读取的物理解析器激活 `LinuxTunEgress`，`macos/channel.rs` 在请求打开之前以捕获前的系统解析器
激活 `MacosTunEgress`、收下 utun 描述符交给 `MacosTunDevice`，并把要公布的系统代理发给打开的隧道。
本 crate 拥有的行为契约：

- `shared_memory` 的 SPSC 双环把桌面客户端当作不可信共享内存对端：环几何在映射共享前私有绑定、
  此后从不回读共享头；所有共享游标与描述符先做私有 volatile 快照，再按私有几何取模与校验；违反
  SPSC 记账的头尾关系一律折叠为 `CorruptState`。恶意客户端最多破坏自己的包流或让自己的会话报错
  （service 端表现为 pump 错误，随断连降级回收），不可能把 service 的访问引出映射；
  `tests/shared_memory_adversary.rs` 用金丝雀映射钉住该包含性。
- 每个环头带消费者与生产者的等待标志。一侧停驻前先置起自己的标志，经 SeqCst 栅栏后复查环，环已变化
  就不停驻；另一侧推进游标后经栅栏读取标志，只在标志置起时清除它并发出对应的自动复位事件。空间信号
  还要等环排空到低水位：至多一半描述符与一半 payload 在用，且容得下最大包。两侧的栅栏保证至少一方
  看到对方，唤醒不会丢失；多余的信号只让下一次停驻立即返回并复查。被破坏的游标按已排空处理，生产者
  重试时自己遇到损坏，而不是永久停驻。
- 桌面端 `RemoteWindowsPacketDevice` 只做非阻塞环操作：RX 空返回 `None`，TX 满返回 `Full`；泵停驻
  时先按兴趣置起等待标志，环已就绪就立即返回，否则登记服务端 RX-data/TX-space 事件的一次性线程池
  等待，触发后留下 `Notify` 许可，被其他分支抢先的停驻也不会丢失唤醒。
- Windows 宿主每个控制连接一个线程；隧道是机器级的，归打开包会话的会话，别的会话在它持有期间不能改动
  适配器上的路由、DNS 与过滤器，进程级操作锁使不同会话的请求不交错。packet 会话是 per-connection 资源
  （客户端断连即 stop）；WFP 防泄漏会话放在
  `WindowsServiceResources` 里并记着它保护的 packet 会话，那个会话结束（断连、显式关闭、包泵出错）时服务关闭
  它，Egrio 不在时网络回到没有它时的样子；服务进程退出时动态 WFP 会话由 BFE 释放。packet capture 的 restore
  拒绝在防火墙会话仍活跃时关闭捕获，保证正常拆除按逆序发生。
- Linux 宿主每个控制连接一个线程和一个 `LinuxTun` 能力集；TUN 资源是机器级的（接口名、路由表、
  规则优先级与 nftables 表各一），由所有权 token 在会话间仲裁，进程级操作锁使不同会话的检查与
  变更不交错。会话资源随连接结束释放：该会话发出且未 restore 的 DNS、路由、防泄漏规则与设备 checkpoint
  依次 restore，桌面崩溃后网络回到没有 Egrio 时的样子。
  服务进程停止或崩溃时不做清理，持久 TUN、规则、链路 DNS 与 nftables 表留在内核，直到下一个服务
  实例启动：它在服务任何连接之前按各会话记在状态目录里的 checkpoint 释放它们，桌面若还在，再经新实例
  按会话丢失恢复。`tests/linux_service_session.rs` 是默认忽略的虚拟机端到端
  检查（root 运行服务、允许的普通用户运行测试）。

服务宿主的认证、安装与 OS 机制见 [Windows 平台](../platforms/windows.md#特权服务)、
[Linux 平台](../platforms/linux.md#特权助手)与[macOS 平台](../platforms/macos.md#产品身份签名与服务安装)。

## 非 GUI 宿主

`egrio-daemon` 承载命令行与服务端两个角色，由 cargo feature 选择。默认 `capture` feature 引入三个
桌面平台适配器 crate，编译 `egrio-node` CLI 与特权服务生命周期；`server` feature 选择仅含 Core 的
服务端角色并启用 `egrio-core/server`，以 `--no-default-features --features server` 构建时不链接任何
平台捕获适配器。`fd_limit`、`memory_reclaim`、`profile_handoff`、`validation` 与 `server` 两个角色都编译，其余模块
位于 `capture` feature 后。

- `server.rs` — 服务端组合宿主：`ServerConfig`（JSON：监听/DNS 地址、IPv6 开关、要提供服务的
  `RuntimeProfile`，以及可选的 Shadowsocks、Trojan、Hysteria2 入站）、无条件启用开放代理安全底线
  的 `server_egress`、`start`/`run`/`load_config`。它只组合 `CoreSessionManager`，不链接捕获适配器；
- `cli/` — `egrio-node` 的诊断与运行命令。命令主体只加载参数/配置、调用 SDK/Runtime 或平台 API、
  打印报告。`cli/core.rs` 的 `run_foreground` 通过 `egrio-sdk::EgrioSdk` 装配 core-only Runtime，
  `cli/core_config.rs` 负责 JSON/YAML `RuntimeConfig` 加载与默认 Profile 物化；`cli/commands/linux.rs`
  以 root 在进程内经 SDK 装配 `LinuxTun`、packet plane、DNS/firewall 能力与 `FileCheckpointStore`；
  系统代理命令只读取状态，mutation 只经 Runtime adapter。Windows 服务宿主动词属于 `egrio-service`；
- `privileged_service/` — 桌面侧的特权服务生命周期：Windows SCM 状态、注册的可执行文件、启动与
  当前用户能否控制服务的探测，以及一次性 UAC bootstrap；Linux systemd 单元状态与一次性 `pkexec`
  安装；macOS 经 SMAppService 注册应用包里的 launchd 服务、读取注册状态并打开“登录项”设置。Windows
  与 Linux 服务的注册与删除只由 `egrio-service` 自己的命令完成，能力执行只经 Runtime SDK 到达
  `egrio-service`，都不经此模块；
- `fd_limit.rs` — `raise_fd_soft_limit`，为长期运行的宿主入口点提供进程级 fd 余量；
- `memory_reclaim.rs` — `start_memory_reclaim`：Linux（glibc）上把突发流量释放后仍留在分配器里的内存交还
  系统。glibc 把释放的块留在各个 arena 中，只从主堆顶端归还页面；宿主入口点（桌面、`egrio-node` 命令与服务端
  角色）各起一个线程，每分钟调用一次 `malloc_trim(0)`（malloc_trim(3)：自 glibc 2.8 起也释放 arena 中间的
  空闲页）。分配器是进程级状态，与 fd 余量一样不归 Core；其他平台的分配器
  自行归还；
- `profile_handoff.rs` — CLI 与验证使用的运行时配置档案文件加载，以及默认 DIRECT 配置档案；
- `validation.rs` — 内存 stub 上游 Core 端到端证明本地监听器路径，不触碰系统状态；
- `bin/egrio-server.rs`（`required-features = ["server"]`）与 `bin/egrio-node.rs`
  （`required-features = ["capture", "server"]`）。`egrio-node` 是另外两个入口的并集：
  `server <config>` 运行服务端角色，其他调用委托给捕获 CLI。
