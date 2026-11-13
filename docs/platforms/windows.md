# Windows 平台

Windows 的 TUN 模式由特权服务 `egrio-service` 持有 Wintun 适配器、路由、接口 DNS 与 WFP 防泄漏过滤，
桌面进程持有 Runtime、Core 与数据面；系统代理是桌面进程内的 WinINET 能力。WFP 只使用无需本项目分发签名
驱动的过滤与只读事件诊断，不设计 callout 驱动、内核分类或包修改。

## 所有权

```text
桌面进程（用户会话）                       特权服务（SYSTEM，egrio-service）
Runtime：能力事务、checkpoint、租约         远程能力端口宿主：Wintun 适配器
  + WinINET SystemProxy adapter               （随包会话 create-or-open/消失）、
Core：规则、出站、绑定接口出口               路由、WFP 动态会话、接口 DNS
数据面：device pump、TCP 引擎、UDP、虚拟 DNS  服务侧包泵：Wintun ↔ 共享环
UI：产品配置与 Runtime 状态投影
```

服务的内部名称为 `EgrioService`，可执行文件为 `egrio-service.exe`。桌面进程经认证控制协议（named
pipe 上的 SID/PID 绑定与 `DuplicateHandle` 句柄交付）请求服务执行 Wintun/路由/DNS/WFP 的
prepare/apply/observe/restore；包会话打开后，服务以 Wintun ↔ 共享内存双 SPSC 环搬运 packet payload，
每个包只拷贝一次：收到的包在 Wintun 仍持有时直接写入共享环，发出的包从共享环直接写入 Wintun 分配的发送
包；控制管道从不承载 payload。协议与环的通用契约见 [Runtime 特权服务](../architecture/runtime.md#特权服务)。

## 特权服务

TUN 模式的一次性环境就绪只取决于：`EgrioService` 正在运行，其注册命令行中的可执行文件就是桌面同
目录的 `egrio-service.exe`（服务只接纳它旁边的 `egrio.exe` 与它自己），且 `wintun.dll` 在该目录中。桌面只读
SCM 状态与注册命令行，不加载 wintun.dll、不打开适配器；适配器、驱动与地址冲突属于服务打开包会话时
的校验，错误经控制协议返回。未就绪时，开启 TUN 先由当前用户启动已在本目录注册的服务，否则经一次 UAC
运行 `egrio-service bootstrap-windows-service`：安装或把注册指向本目录、授予交互用户启停权限并启动；
若注册原先指向其他命令，先停止仍在运行的旧进程再启动。关闭 TUN 不在桌面回收适配器，服务创建的适配器
随包会话释放。以管理员运行 `egrio-service uninstall-windows-service` 停止服务并删除注册；注册不存在时
什么也不做。注册名称、显示名称、命令行形状与这些命令名只在 `egrio-platform-windows` 的
`service_layout.rs` 定义；bootstrap 与卸载都拒绝改动命令行不是 `egrio-service.exe run-windows-service`
的同名服务。

控制连接经命名管道 `\\.\pipe\egrio-<服务名>-privileged-control`。服务从绑定起始终持有一个等客户端的管道实例：
第一个以 `FILE_FLAG_FIRST_PIPE_INSTANCE` 创建，名字已被占用就失败；此后每接到一个客户端，先创建下一个实例
再把已连接的那个交出去，所以管道名从不空出。再创建实例需要 `FILE_CREATE_PIPE_INSTANCE`，管道的 ACL 只把它
给 SYSTEM 与管理员，已认证用户只有数据读写，别的进程因此无法充当这个名字的服务端。两端都以重叠 I/O 打开：
读、写与 `ConnectNamedPipe` 各自等在自己的手动复位事件上，同时等着该结束这次等待的东西——服务停止、
包会话故障、截止时间、连接关闭——没有轮询；被抢先的操作先经 `CancelIoEx` 取回、等它完成后才返回，因为在那
之前 `OVERLAPPED` 与缓冲区仍归系统写。

每条连接是一个会话，在自己的线程上服务。本机用户都能连接管道，所以认出客户端之前一条连接的代价有界：
accept 线程按系统在连接时记下的客户端进程（`GetNamedPipeClientProcessId`）核对可执行文件，不是服务旁边的
`egrio.exe` 或服务自己就当场断开，不等它发任何东西；被接纳的客户端有 5 秒发出首帧（Hello），同时至多 16 个
这样的客户端在等，超出的直接断开。`ImpersonateNamedPipeClient` 要在服务从管道读过数据之后才可用，所以先读
首帧，再核对管道客户端的用户 SID 与该进程的一致，然后才分发首帧。accept 连续失败时按 100 ms 起加倍到 5 秒
的间隔重试并记日志。

机器只有一条隧道：适配器及其上的路由、DNS 与过滤器归打开包会话的那个会话。它持有期间，别的会话在机器上
什么也没有：observe 回报没有活动；prepare 记下空基线，因为把持有者的状态记成自己的基线，自己 restore 时就会把它
放回去；apply 与打开包会话被拒绝，其中打开会先等持有者至多 3 秒，让正在退出的上一个桌面把隧道交出来；restore
回报没有可恢复的——那个会话自己的隧道早已随它的包会话关闭，适配器带走了上面的一切。各会话的请求与会话的
结束由一把进程级操作锁串行。服务停止时，每个会话的等待都被停止事件打断，各自释放所持有的，
服务等它们结束后才报告已停止。

`OpenPacketCapture.settings.mtu` 显式传递桌面/Core 的 Wintun MTU（默认 65535，Wintun 单包的上限），服务以该值
打开设备。
TUN 是不上线路的末端链路，Core 自己终结 TCP 并重新分段，不在其上再封装 IP，所以 MTU 既不必为隧道
开销留余量，也不受物理链路限制：被捕获的客户端按接口 MTU 协商 MSS，MTU 越大，同样的字节经 Wintun、
共享环与 TCP 引擎的包越少，而这条路径的开销主要按包计。远端经 PMTUD 选定的 UDP 报文都小于物理 MTU，
进入 TUN 时不必 Core [源分片](../architecture/core.md#源分片)。open 的响应除共享环句柄外还返回服务持有的 TUN 适配器
接口索引，桌面据此做出口绑定而无需打开适配器。共享内存 ABI 不随控制协议版本变化。两侧只在对端置起
等待标志时才发 data/space 事件，满载时跨进程唤醒按半环而不是按包发生，协议见
[Runtime 特权服务](../architecture/runtime.md#特权服务)；Wintun 的发送环同样只在驱动停驻等待时发信号
（`WintunSendPacket` 检查环的 `Alertable`，[Wintun 源码](https://git.zx2c4.com/wintun/tree/api/session.c)），
所以一批包只有一次唤醒。Wintun 的发送环没有可用空间事件，服务写线程在
发送环满时以高精度可等待计时器（`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`）1 ms 后重试：服务从不调用
`timeBeginPeriod`，自 Windows 10 2004 起这样的进程里普通的 1 ms 等待要持续一个默认计时器周期（约 15.6 ms）。

Wintun 0.14.1（当前的官方发布版）发布发送包时先以 release 写入环尾、再读读取方的 alertable 标志，驱动
置起该标志后再读环尾，两侧都没有全屏障。x86 可以重排这两对写读，两侧于是各读到对方的旧值：驱动带着
未读的包睡下，直到下一次发送才被唤醒，结束一个突发的包（例如上传窗口里最后一个 ACK）就要等对端重传超时。上游已在
[ec0a6b98](https://git.zx2c4.com/wintun/commit/?id=ec0a6b98456fe1ba52567bb2add4bbf5f64315a1)（2026-03）
给两侧各补一道屏障，尚未发布。服务写线程在 TX 环排空后 1 ms 内没有新包，就发送一个首部校验和故意写错的
IPv4 头：此时驱动置起的标志早已可见，这次发送必定唤醒它，此前未读的包随之送达，而主机静默丢弃首部校验和
错误的数据报（RFC 1122 §3.2.1.2）。Wintun 适配器的接收计数与 IP 首部错误计数因此随突发增长；去掉它的
条件见[待办](../backlog.md#wintun-唤醒竞争)。

生产 packet 会话只接受本次 open 由服务创建并持有的 Wintun 适配器。预先存在的同名适配器在写入
IPv4/IPv6 地址、接口 metric/MTU 或启动 packet 会话前 fail-closed，因为 checkpoint 不保存该外部适配器
的完整接口基线，也无法证明其 owner。服务持有的适配器在最后一个 owning handle 释放时连同这些接口级
修改一起消失，因此不需要把易失接口基线持久化到 Runtime checkpoint。

适配器是否存在必须依据供应商 API 的失败码判断。锁定的 `wintun 0.5.1` wrapper 只有在原生
`WintunOpenAdapter` 返回空句柄时才返回精确 sentinel `WintunOpenAdapter failed`；平台层仅对该 sentinel
通过同一 DLL 再做一次原生确认并立即读取 `GetLastError`。wrapper 的 `Io`/元数据转换或任何未知错误不得
再次打开适配器，必须直接 fail-closed，避免把已成功打开后的接口查询失败变成二次打开和错误的 absent
结论。只有 `ERROR_NOT_FOUND` 才可解释为“当前没有可打开的 present 匹配”；供应商实现会忽略部分枚举/
属性失败并最终返回该码，因此它不是物理设备绝对不存在的证明。权限、驱动、接口索引或其余错误一律作为
观察/恢复错误上抛；probe 失败不得折叠为空集合、跳过清理或生成 `restored=true`。依据为 Wintun 官方
[adapter.c](https://git.zx2c4.com/wintun/tree/api/adapter.c) 与
[wintun.h](https://git.zx2c4.com/wintun/tree/api/wintun.h)。

崩溃处置按 owner 区分，TUN 不在时网络总是回到没有 Egrio 时的样子。WFP 动态会话随它保护的 packet 会话
结束：显式 restore、桌面控制连接断开（桌面崩溃）或包泵出错停止时，服务关闭这个会话，BFE 随之释放其中的
过滤器；服务或 engine 退出时 BFE 同样释放。服务创建的适配器随最后一个 owning handle 释放并带走接口路由/DNS。
包泵工作线程不是因停止而退出时（Wintun 会话结束，例如适配器被禁用，`WintunReceivePacket` 返回
`ERROR_HANDLE_EOF`）报告一次故障：服务关闭防泄漏过滤并写入服务日志，接着结束这条控制连接的会话，像桌面断开时
一样撤销它持有的一切，停止已出错的 packet 会话照常成功。桌面于是像服务丢失时一样提示 TUN 中断，并经新会话
（新的适配器）原地恢复 TUN，故障之后的过滤器更新被拒绝。IPC health 失败使 Runtime 进入
Degraded 并停止桌面 packet 任务，但不会在已断开的同一 client 上假定 OS restore 成功。诊断可枚举 Egrio provider
下的过滤器（`netsh wfp show state`、provider `2d606d68-04e0-4562-aa73-01fabf004a40`，或只读 observe）并定位仍存活的
owning `egrio-service.exe`。活跃动态会话对象不能由另一 engine 会话删除，只能通过显式 restore 或终止 owning engine
整批释放。

TUN 开启时服务停止或崩溃，适配器、其路由与 DNS 随服务会话消失，动态 WFP 会话也随进程结束；系统代理与
桌面 Core 不受影响。桌面立即提示 TUN 中断，启动服务后经新会话原地恢复 TUN（见
[捕获层切换](../architecture/runtime.md#捕获层切换)），系统代理与 Core generation 保持。

## 系统代理与恢复

Windows OS 恢复事实只在 Runtime checkpoint。SDK 启动时由 `recover_unresolved` 枚举 unresolved
checkpoint、重建不可用租约，并按 system-proxy → DNS → route → firewall → capture 的逆序恢复；桌面不持久化捕获层或会话投影。服务启动
不做孤儿清扫，可靠的残留恢复路径只有消费 unresolved checkpoint。

运行期 WinINET 的唯一 owner 是 Runtime 注入的 `WindowsSystemProxyAdapter`：checkpoint 保存带 schema
版本的完整 WinINET 基线与期望 loopback listener，apply 后精确 observe，restore 先 stop+join watcher，
再检查外部接管并恢复/复验基线。adapter 私有 watcher 使用 `RegNotifyChangeKeyValue` 监视
`HKCU\...\Internet Settings`，所有 restore/reload/stop 都先在生命周期门内 stop+join watcher。前三次
短窗外部覆盖只 reassert 期望 listener 且不替换原 checkpoint；第四次产生 yield 事件，桌面经捕获层切换
只移除系统代理层：TUN 仍开时在同一 Runtime 上 reload 并只收缩系统代理能力与租约，否则停止 Runtime；
失败保留 checkpoint 和 recovery-required 租约。mutation 原语不从 crate 根重导出，daemon、CLI 与
桌面应用都不能绕过 Runtime 修改 WinINET。

退出时统一 Runtime stop 恢复系统代理、停止 TUN、恢复路由/DNS/WFP，不会留下指向已停止 listener 的
设置；拆除失败时保留检查点，由下一次启动恢复。桌面崩溃时适配器、路由与 WFP 过滤器随服务会话消失，网络
按物理路由直连；WinINET 仍指向已停止的 listener，直到重新启动后恢复。

## 连接矩阵

下表是 `v6 = auto` 解析为 tunnel 时 TUN 模式必须满足的契约。改变任意一行的行为都属于设计变更，必须在同一
提交中更新此表。

| # | 场景 | 路径 | 机制 |
|---|---|---|---|
| 1 | 可感知代理的应用 TCP（浏览器） | WinINET → mixed 端口 → 规则 | 系统代理与 TUN 同开；允许 loopback v4+v6 |
| 2 | 任意应用 TCP v4 → 互联网 | 捕获路由 → TUN → TCP 引擎 → 规则 | DIRECT 出口绑定 `IP_UNICAST_IF` |
| 3 | 应用 UDP（QUIC/语音/游戏） | TUN → Core UDP 会话 → 节点 UDP associate 或 DIRECT 套接字 | 每个客户端二元组一个会话 |
| 4 | P2P 打洞（STUN） | 同 #3；经同一出站的远端共用同一映射，经名字（fake IP）的与经地址的一样；接受任意远端的回复 | EIM+EIF；fake IP 的回包按它解析到并认领的地址映射回 fake IP；严格全局模式下名字经全局出口解析，同样共用映射；只配置了 `system` 时名字由节点解析，每个 fake IP 另有映射（见 [DNS 配置来源](../architecture/profile-store.md#dns-配置来源)） |
| 5 | 存在物理 v6 时的 TCP/UDP v6 | 与 v4 对称 | `IPV6_UNICAST_IF` DIRECT 出口 |
| 6 | 不存在物理 v6 时的 TCP/UDP v6 | 不应答 AAAA + WFP 阻断 v6（回环、LAN 范围与排除的目的地除外）+ 状态警告 | v6 策略 = block |
| 7 | 同子网或跨子网 LAN | 同链路流量留在物理网络；跨子网流量进入 TUN → PRIVATE→DIRECT → 绑定接口的 DIRECT 出口 | WFP 不拦截；到 LAN 解析器的 dst:53 被阻断 |
| 8 | 入站服务（RDP/SMB 服务端） | 不设入站过滤器；回复遵循 strong-host 源地址绑定从物理 NIC 发出 | 不使用 `IP_PKTINFO` 的通配 UDP 服务端是已知边界情况 |
| 9 | Egrio 自身出口 | 绑定接口；自己的 dst:53 由 WFP app-id 放行 | 不使用主机路由 |
| 10 | DNS | 接口 DNS = TUN 虚拟 DNS；劫持任意 dst:53；DIRECT 域名通过物理接口执行真实解析 | 双地址族 fake-IP |
| 11 | ICMP echo | 走 DIRECT 的目标（fake IP 按其域名）经物理上行中继，经代理的 fake IP 在本地应答，其余丢弃并计数 | 桌面经 IP Helper 以物理上行的地址发出 |
| 12 | Loopback | 从不捕获，始终允许 | 无路由 |
| 13 | 绑定物理接口或其地址的 socket（其他 VPN 的底层连接、开 TUN 前已建立的连接）、比捕获路由更具体的路由（其他 VPN 的隧道） | 不进 TUN，从物理网卡或其他接口直接出去 | WFP 不拦截；连 fake IP 立即失败，物理网卡上的 dst:53 被阻断，发进其他 VPN 适配器的放行 |
| 14 | 浏览器 WebRTC | 无摄像头/麦克风授权时只在默认路由的接口（Wintun）收集候选（RFC 8828 Mode 2），STUN 经 TUN；本机地址以 mDNS 名字代替 | 公网候选只有出口的地址 |

只开系统代理时按定义属于部分捕获：只有 WinINET 加 mixed 端口，没有 WFP 和路由，不遵循系统代理的
应用直接出站。Core 的 `packet/probe.rs` 以确定性探针覆盖 #3、#4 与 #10 的语义。

## 子系统

**出口绑定。** 每个物理出口套接字都通过 Core 的出口抽象创建，并在 connect 之前绑定到其地址族当前的
默认物理接口：`IP_UNICAST_IF`（网络字节序接口索引）/ `IPV6_UNICAST_IF`（主机字节序）；绑定后的套接字
对任意目的地址和两个地址族都不会形成环路，因此
不需要代理端点主机路由或固定出口源地址。每个地址族的默认接口属于持续维护的网络状态：
`WindowsNetworkState`（`wintun/network_state.rs`）在路由表中按最长前缀/最低有效 metric 选取，并用
自有适配器的实时索引（由已存储的 `NET_LUID_LH` 解析）将其排除。服务每个包会话都新建适配器，因此每次
打开 TUN 都以服务返回的接口索引新建一份状态，并把所选物理上行接口的 IPv4 DNS 与 IPv6 姿态作为 Core
的出口 overlay。上行 DNS 经 `GetAdaptersAddresses`（`IP_ADAPTER_ADDRESSES_LH.FirstDnsServerAddress`）
按接口读取，排除回环、组播和 Wintun 虚拟解析器；捕获路由生效后系统解析器指回捕获 DNS，所以上行没有
可用 IPv4 DNS 时 TUN 层应用失败。TUN 关闭后绑定器不再绑定、overlay 撤销，Core 保持运行并回到系统
解析器。`WindowsTunEgress` 第一次被用到时注册唯一一个 `WindowsNetworkChangeMonitor`，此后与它同寿：
`NotifyRouteChange2`、`NotifyIpInterfaceChange` 与 `NotifyUnicastIpAddressChange`（均为 `AF_UNSPEC`）
任一触发都重新推导，换网与拔线改变路由，接口跃点变化（包括 Windows 按链路速度调整的自动跃点）只改
接口、不触发路由通知，新的 DHCP 租约改变地址。不同订阅的回调可能同时运行，推导因此串行，每次都读取
实时状态。TUN 开启时先刷新该会话的状态：上行变化时 overlay 改用新上行的 IPv4 DNS，旧网络的解析器
通常在新网络不可达；新上行没有可用 DNS 时保留原有解析器。只改 DNS 服务器而路由、接口与地址都不变时，
要到下一次事件才生效。然后不论 TUN 是否开启，都把各族上行与物理接口（与上行选择相同的接口资格）的
非链路本地地址（`GetUnicastIpAddressTable`）作为 `EgressNetwork` 发给 Core；Core 据此结束本地地址或
所绑接口已经消失的连接、把 Hysteria2 的载体迁到当前上行，见 [Core 模块布局](../architecture/core.md#模块布局)的
`egress/network.rs`。绑定器只读取，因此新拨号立即采用接口变化；仍然可用的已有连接留在原接口上，连接表
的出口接口是拨号时的元数据。按
索引排除自有适配器，才能保证安装捕获路由（`0.0.0.0/2`、`64.0.0.0/2`、`128.0.0.0/2`、`192.0.0.0/2`，
metric 1，前缀长于物理 `/0`）后选择仍然正确。接口资格取决于结构（已启用 + 硬件地址 + 真实 NIC
类型），不依赖适配器名称；Hyper-V vEthernet 上行可被接受，TUN 按 NIC 类型拒绝。这是同一
`EgressSocketGuard` 契约的 Windows 实现。

**IPv6 姿态。** `resolve_windows_ipv6_mode` 是适配器 v6、Core 出口 v6、捕获路由与 WFP 计划共用的唯一
IPv6 姿态解析点：`Auto` 在有物理 IPv6 默认路由时隧道化，否则阻断；姿态为 tunnel、block 或 off，捕获
活动时始终恰好强制执行 tunnel 或 block 之一。GUI 的 IPv6 开关与 TUN 姿态取交集
（`effective = TUN capability && app setting`），关闭后可在同一捕获会话重新开启，但不会把捕获前判定不
可用的 IPv6 强行启用；Dashboard 的姿态从活动 TUN 的快照与本 generation 的请求策略解析，不在活动 TUN
上重新探测。

**UDP。** UDP 会话语义（端点独立映射与过滤、会话上限与空闲回收）由 Core 的 UDP 会话表实现，见
[Core 数据面](../architecture/core.md#模块布局)；节点自身的 NAT 行为不受本项目控制。出口 socket 不开接收合并
（URO，`UDP_RECV_MAX_COALESCED_SIZE`，[IPPROTO_UDP 选项](https://learn.microsoft.com/windows/win32/winsock/ipproto-udp-socket-options)）：
[quinn-rs/quinn#2041](https://github.com/quinn-rs/quinn/issues/2041) 报告部分 Windows 11 24H2 机器合并了数据报却
不报段长，数据报边界会丢，原因未定；启用前可先用两个本地 socket 互发探测。Wintun 交来的是单个包，上行没有可整串
发出的列车，发送分段（USO，`UDP_SEND_MSG_SIZE`）因此也不用。

**DNS。** 虚拟 DNS 地址与适配器地址不同：IPv4 使用接口前缀中的下一个可用地址；tunnel 姿态还追加
`adapter_address6 + 1`，block/off 只保留 `EGRIO_WINTUN_DNS` 所代表的显式配置；桌面复用同一排序、去重和
溢出检查 helper（`windows_runtime_interface_dns_servers`）。接口 NameServer 写入使用
`SetInterfaceDnsSettings` 与 `DNS_INTERFACE_SETTINGS` VERSION1：IPv4 调用使用
`DNS_SETTING_NAMESERVER`，IPv6 调用使用 `DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6`；apply/restore 始终
分别发送两族，空族也显式清理。observer 调用
`GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES)`，按 `IfIndex`/`Ipv6IfIndex` 定位
Wintun 并遍历 `FirstDnsServerAddress`，排序去重后与事务期望精确比较；Windows 在空 IPv6 DNS 上可能返回
`fec0:0:0:ffff::1`、`::2`、`::3` 兼容性占位项，observer 只过滤这三项。适配器存在时 restore 重新写入
checkpoint 基线并观察；桌面崩溃已使适配器消失时，接口级 DNS 随接口消失，restore 不再调用 Set。捕获会
劫持所有被捕获的 UDP/53 查询，因此多适配器主机即使通过物理适配器的 DNS 服务器解析，仍会得到 fake-IP
应答而不会泄漏真实地址；接口 DNS 只负责引导常见路径。发往虚拟 DNS 目标的 TCP/53 在 accept 时由 Core
DNS 引擎以带帧格式的流应答。Core 出口 DNS 过滤掉虚拟 DNS 地址。虚拟 DNS 与 fake-IP 地址池都支持
双地址族：A/AAAA 共用一个稳定槽，AAAA 从 `fd11:5ca1:ab1e:1::/111` 返回虚假 v6，使域名规则对偏好 v6
的应用仍然有效；IPv6 未启用时 AAAA 返回空 NOERROR。Core 不内置域名特判，需要真实地址的域名写入配置的
`fake-ip-filter`（严格全局模式不适用，见 [Core DNS](../architecture/core.md#模块布局)）。DoH 就是普通
TCP/UDP 443，仅过滤型 WFP 不对其特殊处理。

**WFP 防泄漏过滤。** TUN 运行时只拦截泄漏，不当 kill switch：一个动态会话、一个 provider 以及流量和 DNS
sublayer，所有对象都以 provider GUID 标记，便于枚举。会话随它保护的 packet 会话结束（见[特权服务](#特权服务)），
所以 Egrio 停止或崩溃后不留任何过滤器。过滤器只有这些，其余流量一概不拦：

- DNS sublayer 阻断从物理接口发出的 dst:53，Egrio 自身（app-id）除外，v4 与 v6（off 姿态只有 v4）。物理接口按
  `FWPM_CONDITION_INTERFACE_TYPE` 的 IANA 类型（`MIB_IF_ROW2.Type`，Ipifcons.h）认：以太网 6、PPP 23、Wi-Fi 71、
  WiMax 237、移动宽带 243 与 244，同一字段的相邻条件按“或”计算（`FWPM_FILTER0`）。Windows 的解析器向所有接口的
  DNS 服务器并行查询，没有这一项时开着 TUN 的每个查询也同时发往物理网卡的解析器（见[验证状态](#验证状态)），先到的
  真实或被污染的应答会绕过 fake IP；到 LAN 与排除网段的 dst:53 同样被阻断。Wintun 适配器（Egrio 的与其他 VPN 的）
  是 `IF_TYPE_PROP_VIRTUAL`（53），发进去的 DNS 不受影响：Tailscale 的 MagicDNS 经 NRPT 把 tailnet 名字交给它适配器
  上的 `100.100.100.100`，照常解析。
- 流量 sublayer 阻断 Wintun 之外到 Core fake-IP 池及其 IPv6 投影的连接（`FirewallSettings.fake_ip_prefixes`，桌面
  从启动 Core 的同一份配置快照取得；IPv6 投影只在 tunnel 姿态），Wintun 接口许可的权重高于它。绕过隧道的程序也经
  系统解析器拿到 fake IP，放行的话连接要等到超时，被阻断则立即失败，能换一条路解析域名的程序随即恢复。Tailscale
  就是这样：它的拨号先连 fake IP，失败后才经 DERP 的引导 DNS 查真实地址，而登记请求只等 10 秒，fake IP 的连接要
  21 秒才超时，不拦的话它开着 TUN 冷启动一直上不了线（见[验证状态](#验证状态)）。
- block 姿态下 IPv6 不进隧道，流量 sublayer 阻断全部 v6，只放行 `::1`、链路本地与组播范围（DHCPv6、RA、LAN
  发现）和排除的 v6 目的网段：不变量是捕获活动时全局 v6 出口要么进入隧道，要么被阻断。

不拦截的流量：捕获路由把所有没有指定接口的 socket 送进 Wintun，从隧道外出去的只有特意如此的，例如绑定物理接口
（`IP_UNICAST_IF`）或其地址的 socket（自带防环路的 VPN 的底层连接）、比捕获路由更具体的路由带走的目的地（其他
VPN 的隧道）、LAN 与排除的目的地，以及开 TUN 前已建立的连接，它们都照常通行。DNS 阻断只覆盖物理接口，保留其他 VPN 的 DNS 路径。
浏览器的 WebRTC 在没有摄像头/麦克风授权时只用默认路由的接口收集候选（RFC 8828 的 Mode 2），开着 TUN 时
就是 Wintun，STUN 经隧道，公网候选是出口的地址。不设 `RECV_ACCEPT` 过滤器，入站服务不受影响。
ICMP echo 中继由桌面经 IP Helper（`IcmpSendEcho2Ex` / `Icmp6SendEcho2`）以物理上行的地址为源同步发出，没有
过滤器挡它。`netsh wfp show filters` 不列出被上方更宽许可遮住的阻断，即使 `verbose=on`；核对过滤器用
`netsh wfp show state`。

**排除的目的地。** `RouteSettings.excluded_prefixes` 中的网段不进入 TUN：捕获路由从 IPv4 的四个 `/2`
和 IPv6 的两个 `/1` 中减去这些网段，含排除网段的那条路由逐级对半拆分到排除网段为止、保留不含它的
一半，被排除覆盖的路由整条不装。排除的目的地于是不匹配任何捕获路由，沿用系统原有路由（物理默认路由
或更具体的路由，包括其他 VPN 的路由），不需要跟踪网关，换网也自然跟随。一个 `/n` 排除最多增加 `n`
条路由，每个地址族至多 4096 条，超出时整个路由能力失败而不是少装。WFP 只在 block 姿态的 v6 阻断下为 v6
排除网段加许可；DNS sublayer 不为它们开例外，到排除网段的 dst:53 仍被阻断。

排除集合可以在 TUN 运行中改变（切换分流模式或 Profile 时），路由与防泄漏过滤原地更新，不重建适配器，
经 TUN 的连接不受影响。路由的 apply 与 restore 都把适配器上 Egrio 安装（`MIB_IPPROTO_NETMGMT`）的
路由调整为目标集合：先补上缺少的、再删除多余的，仍被捕获的目的地任何时刻都有路由；apply 的目标是
新算出的拆分，并核对每条都已出现在路由表中，restore 的目标是 checkpoint 基线（启动时为空，原地更新
时为更新前的拆分），各族路由表只读取一次。防泄漏过滤已开启时，新的过滤器计划在同一个动态 session 的一个
WFP 显式事务中补上新增的过滤器、删除不再需要的，事务失败则保留原集合，没有空档；checkpoint
同时保存 prepare 时生效的设置，回滚时按它重建被替换的过滤器
（[FwpmTransactionBegin0](https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0)、
[FwpmFilterDeleteById0](https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterdeletebyid0)：
动态 session 只能删除自己添加的对象）。

**数据面。** 桌面设备 `RemoteWindowsPacketDevice` 只在共享环上做非阻塞的收发，不执行逐包路由、
会话查询或中继，这些都在 Core 的包泵与 TCP 引擎里；泵无进展而停驻时，置起环的等待标志后按读/写兴趣以
`RegisterWaitForSingleObject`（`WT_EXECUTEONLYONCE`）登记服务端 RX-data/TX-space 自动复位事件的一次性
线程池等待，触发后转成异步唤醒。

**计时器精度。** 桌面进程在整个生命周期持有 1 ms 计时器精度，`egrio-node run` 的前台 Core 也在运行
期间持有（`FineTimerResolution`）。自 Windows 10 2004 起，进程要自己调用 `timeBeginPeriod` 才能得到比
系统默认约 15.6 ms 更细的计时器，别的进程把硬件时钟调快也不算数；普通等待受进程的计时器精度限制。Core 的 QUIC 在 ACK 稀疏时靠计时器唤醒发送节奏，默认精度下快速或突发
的上传跟不上速率，BBR 爬升也更慢。Windows 11 对窗口被遮挡、最小化或隐藏的进程不保证该精度，桌面常驻
托盘时正是这种状态，所以持有时还以 `SetProcessInformation(ProcessPowerThrottling)` 让进程退出计时器
精度节流。代价是功耗：Microsoft 的计时器白皮书称 1 ms 精度最多可使电池续航缩短 25%，取决于硬件。电池和节能模式下
同样保持开启，功耗影响仍需按设备与电源状态验证。

**进程归因。** 桌面进程内的 `WindowsFlowScanner` 读取 IP Helper owner-PID 表（`GetExtendedTcpTable` /
`GetExtendedUdpTable`，`AF_INET` 与 `AF_INET6`，双栈映射行折回 IPv4），并经 `OpenProcess`
（`PROCESS_QUERY_LIMITED_INFORMATION`）、`GetProcessTimes` 与 `QueryFullProcessImageNameW` 取得镜像
路径；路径按 PID + 创建时间缓存，避免 PID 复用后指向错误程序。TCP 要求精确四元组，UDP 先精确绑定再
同族通配，多个 owner 或共享端口保持未知。非提权桌面无法读取提权进程的映像，这类连接保持未知。缓存、
门控与新连接重查由 [Core 进程归因](../architecture/core.md#进程归因)负责；特权服务不参与，控制协议
不承载进程或网络快照请求。

## 代码结构

`egrio-platform-windows`：

- `wintun/` — `WindowsWintunConfig` 规范化与环境覆盖；使用规范 CIDR 键（`windows_wintun_route_cidr_key`）
  的 IPv4 `/2` 与 IPv6 `/1` 捕获路由；按适配器 + `MIB_IPPROTO_NETMGMT` 观察带提供程序标记的捕获路由
  （`windows_wintun_observe_capture_route_keys`），以及接口 DNS 的双族观察
  （`windows_wintun_observe_capture_dns_servers`）；`open_windows_raw_packet_session` 是服务打开包会话
  的入口：create-or-open 适配器、配置 IPv4/IPv6 地址与跃点、设置 MTU、启动 ring 会话，适配器句柄由
  会话 Arc 持有。`mod.rs` 是包会话与适配器的创建，其余按职责分文件：`library.rs`（加载 `wintun.dll`、
  判断适配器是否存在）、`interface.rs`（适配器的地址与接口设置）、`capture_routes.rs`（捕获路由的观察、
  应用与恢复，以及路由表项的增删）、`interface_dns.rs`（接口 DNS）、`physical.rs`（主机路由表、接口元数据
  与物理上行的选取）；
- `wintun/network_state.rs` — `WindowsNetworkState` 与 `WindowsNetworkChangeMonitor`，各地址族物理上行
  接口的单一事实来源；monitor 在 `Drop` 时通过 `CancelMibChangeNotify2` 取消三项通知；
- `egress_binding.rs` — `WindowsTunEgress`（持有网络变化 monitor 与发给 Core 的物理网络）与
  `WindowsEgressInterfaceBinder`（Windows 的 `EgressSocketGuard`，TUN 会话期间中继 ICMP echo）；loopback 目标
  始终跳过，绑定器自身不查询路由表；
- `icmp_echo.rs` — IP Helper 的同步 ICMP echo，以给定的源地址发出；
- `ipv6.rs`、`dns.rs` — IPv6 姿态解析与 Runtime DNS 能力的接口 DNS；
- `process_attribution.rs` — `WindowsFlowScanner`；
- `timer_resolution.rs` — `FineTimerResolution`：`timeBeginPeriod(1)` 与计时器精度节流的退出，`Drop`
  时归还；
- `runtime_system_proxy.rs`、`system_proxy_watch.rs` — Runtime `SystemProxyControl` adapter 与
  `WindowsSystemProxyChangeWatcher`（带配对停止事件的 `RegNotifyChangeKeyValue`，绑定到启用线程，停止
  句柄线程安全）；WinINET status 与 adapter 私有的 snapshot/apply/restore/reassert backend；
- `firewall/` — 防泄漏过滤计划（`windows_firewall_kill_switch_filter_plan`）、动态 WFP 会话、按 provider
  数据标记观察 Egrio 过滤键，以及 `egrio-node windows-wfp-net-events` 使用的只读 net-event 诊断；
  `windows_wfp/` 按职责分文件：`plan.rs`（过滤计划，纯数据）、`conditions.rs`（条件到 WFP 字段的映射）、
  `engine.rs`（打开的引擎：添加与枚举）、`session.rs`（持有计划过滤器的动态会话）、`net_events.rs`（诊断），
  `mod.rs` 留 provider 键与子层配置；
- Runtime 能力级操作 `apply/restore_windows_runtime_routes`、`apply/restore_windows_runtime_dns` 与
  WFP 会话由服务的能力处理器调用。

- `service_layout.rs` — 服务的 SCM 注册：名称（`EGRIO_WINDOWS_SERVICE_NAME` 可覆盖）、显示名称、
  注册命令行及其 Egrio 归属判断、run/bootstrap/uninstall 命令名，以及服务接纳的应用可执行文件名。

`egrio-service` 的 `windows/` 持有服务宿主（`host.rs`：SCM 生命周期、自身的注册与删除、accept 循环与每条
控制连接一个的会话线程）、控制管道（`pipe.rs` 的重叠 I/O 及其等待，`listener.rs` 的服务端实例与客户端接纳，
`transport.rs` 的桌面端）、管道客户端身份门（`identity.rs`：客户端可执行文件须是服务旁边的 `egrio.exe` 或服务
自己，SID 一致性校验）、内核对象创建/跨进程交付与 packet 会话；
`windows/capabilities.rs` 让 WFP 会话随它保护的 packet 会话结束，包泵（`packet_pump.rs`）的工作线程不是因停止
而退出时报告一次故障，服务据此关闭 WFP 会话并置起该会话的故障事件，`windows/host.rs` 的会话线程随即结束
这次控制会话。
桌面侧的状态读取、启动、控制权探测与 UAC bootstrap 在 `egrio-daemon` 的 `privileged_service/`。

## 官方依据

Wintun 供应商文档/头文件；控制管道依据 Microsoft
[`CreateNamedPipe`](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createnamedpipea)（
`FILE_FLAG_FIRST_PIPE_INSTANCE`、各实例须一致与可以不同的参数、再建实例所需的 `FILE_CREATE_PIPE_INSTANCE`）、
[`ConnectNamedPipe`](https://learn.microsoft.com/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)（
重叠模式用手动复位事件，`ERROR_PIPE_CONNECTED` 是已连好的连接，客户端来过又走的实例报 `ERROR_NO_DATA`、须先
`DisconnectNamedPipe` 才能再等）、
[`GetOverlappedResult`](https://learn.microsoft.com/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult) 与
[`CancelIoEx`](https://learn.microsoft.com/windows/win32/fileio/cancelioex-func)（被取消的操作完成之前不得释放或复用它的
`OVERLAPPED`）；`IP_UNICAST_IF` / `IPV6_UNICAST_IF`（ws2ipdef.h 套接字选项，包括文档明确
规定的 v4 选项网络字节序接口索引）；IP Helper 的 `GetIpForwardTable2` / `GetIfEntry2` 路由与接口表、
`ConvertInterfaceIndexToLuid` / `ConvertInterfaceLuidToIndex`、`GetUnicastIpAddressTable` 地址表、
`NotifyRouteChange2` / `NotifyIpInterfaceChange` / `NotifyUnicastIpAddressChange` +
`CancelMibChangeNotify2` 变更通知以及 owner-PID 表；Microsoft
[`SetInterfaceDnsSettings`](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings) /
[`DNS_INTERFACE_SETTINGS`](https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings)
及 Windows SDK `netioapi.h`：VERSION1 是 Set 使用的结构版本，缺省调用作用于 IPv4，`DNS_SETTING_IPV6`
将该次调用切换到 IPv6，因此两族由两次独立 Set 完成；VERSION2/3 新增 supplemental search list/加密 DNS
属性，不是双族 resolver 的前置条件；Microsoft
[`GetAdaptersAddresses`](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)、
[`IP_ADAPTER_ADDRESSES`](https://learn.microsoft.com/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh)
的 `FirstDnsServerAddress` 与
[`IP_ADAPTER_DNS_SERVER_ADDRESS`](https://learn.microsoft.com/windows/win32/api/iptypes/ns-iptypes-ip_adapter_dns_server_address_xp)；
`Fwpm*` 管理 API 及 SDK layer 和 condition 常量，各层可用的条件依据
[Filtering conditions available at each filtering layer](https://learn.microsoft.com/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)
（`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` 支持 `FWPM_CONDITION_IP_PROTOCOL` 与 `FWPM_CONDITION_IP_REMOTE_ADDRESS`）；
IP Helper 的 [`IcmpSendEcho2Ex`](https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2ex)
与 [`Icmp6SendEcho2`](https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmp6sendecho2)（不给事件与
APC 时同步返回收到的回应数，回应缓冲区要容下一个回应结构、请求数据、8 字节 ICMP 错误与一个
`IO_STATUS_BLOCK`）；Microsoft strong/weak host 模型文档；RFC 4787 UDP NAT
行为要求（EIM/EIF）；Microsoft
[`timeBeginPeriod`](https://learn.microsoft.com/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)（Windows 10
2004 起按进程生效，Windows 11 对隐藏窗口的进程不保证）、
[`CreateWaitableTimerExW`](https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerexw)
的 `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`（Windows 10 1803 起，用于几毫秒的延迟不可接受的场合）、
Wintun 的 [`api/session.c`](https://git.zx2c4.com/wintun/tree/api/session.c?h=0.14.1) 与
[`driver/wintun.c`](https://git.zx2c4.com/wintun/tree/driver/wintun.c?h=0.14.1)（0.14.1 的发送与驱动读取路径）、
RFC 1122 §3.2.1.2（主机校验每个数据报的首部校验和并静默丢弃错误者）、
[`SetProcessInformation`](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation)
的 `PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION`（ControlMask 置位、StateMask 清零即始终满足精度请求）
及计时器白皮书
[Timers, Timer Resolution, and Development of Efficient Code](https://download.microsoft.com/download/3/0/2/3027d574-c433-412a-a8b6-5e0a75d5b237/timer-resolution.docx)。

## 桌面应用

桌面应用（见[桌面宿主](../architecture/desktop.md)）在 `desktop/egrio` 的 `windows/` 里经 WinUI 3 实现 egrio-ui 描述的
界面。

- 运行时：应用不打包、依赖框架。系统里装着 Windows App SDK 运行时（框架包），应用旁边的
  `Microsoft.WindowsAppRuntime.Bootstrap.dll` 在运行时载入，经 `MddBootstrapInitialize2`（SDK 的 `MddBootstrap.h`）
  把运行时加进进程的包图，要求 2.x、不低于 2.6.5；没有合适的运行时时引导程序提示下载
  （[未打包应用使用运行时](https://learn.microsoft.com/windows/apps/windows-app-sdk/use-windows-app-sdk-run-time)）。
  `cargo xtask windows-deps` 按 SHA-256 取固定版本的 NuGet 包与 Wintun 0.14.1 的官方签名发布包
  （[wintun.net](https://www.wintun.net/)，允许原样再分发），把引导程序与服务载入的 `wintun.dll` 放到 Windows
  构建旁；`--bindings` 再从包里的元数据按 `windows/bindings.txt` 的过滤表重新生成 `windows/bindings.rs`。
- 清单：`desktop/egrio/windows/egrio.manifest` 由 `build.rs` 链进可执行文件：声明 Windows 10/11 兼容与测过的
  `maxversiontested`（上面的文档要求，缺了 SDK 按 Windows 8 行为工作）、每显示器 DPI 感知 v2、Common Controls 6。
- 应用对象：`Application::Start` 的回调里组合出 `Application`（XAML 项目里 `App` 类的 WinRT 聚合），实现
  `OnLaunched` 与 `IXamlMetadataProvider`（转给 `XamlControlsXamlMetaDataProvider`）；`XamlControlsResources` 合进
  应用资源，Egrio 覆盖的主题资源合在它后面。最后一个窗口关闭时应用不退出（`DispatcherShutdownMode`
  `OnExplicitShutdown`），托盘留着。
- 主窗口：内容扩展进高标题栏（`TitleBarHeightOption.Tall`），标题按钮由系统绘制，消息胶囊与工具区控件是非客户区
  输入的穿透区域、应用图标是图标区域（[标题栏定制](https://learn.microsoft.com/windows/apps/develop/title-bar)）；
  窗口背景是 `MicaBackdrop`。侧栏是左侧的 `NavigationView`；它给内容区的抬起层（`NavigationViewContentBackground`、
  `NavigationViewContentGridBorderThickness`、`NavigationViewContentGridCornerRadius`，见控件的
  `NavigationView_themeresources.xaml`）被覆盖掉，页面直接铺在 Mica 上，同 macOS。窗口关闭（`AppWindow.Closing`）
  与退出时经 `GetWindowPlacement` 记下还原时的位置、尺寸与是否最大化（应用数据目录的 `window-state.json`），下次
  打开前经 `SetWindowPlacement` 放回，落在所有显示器之外的位置由它移回屏幕上（函数文档），最大化在激活后恢复；
  编辑器窗口记尺寸，居中在主窗口上并限制在显示区域的工作区里，最小 480×320。
- 标题栏那一行没有页面标题：网格的列是侧栏上方的应用图标与名称、页面上方的消息胶囊（左边与页面对齐）、空处、
  工具区（依次是流量模式、系统代理与 TUN 模式）与标题按钮下的一列。
- 消息胶囊是标题栏网格里页面上方的按钮，模板只有一个 `ContentPresenter`、没有指针状态，自己不画底面：底面是
  下面的消息面板。指针进入时（`PointerEntered`/`PointerExited`），面板收起又没有未读着色的胶囊里一层 `Border`
  画上 `SubtleFillColorSecondaryBrush`，像无边框按钮的悬停；面板打开或收起后要等指针再次进入才画，打开的面板的
  抬头因此不会单独显出一块。未读时另一层 `Border` 着信息栏的背景画刷（`SystemFillColorCriticalBackgroundBrush`
  等，与标记相同），它和预览文字的不透明度随宽度一起变化。铃铛是符号字体的 Ringer（EA8F），两种字体都有。展开的
  宽度按文字 `Measure` 出的宽度算，不超过工具区前 16 像素；宽度经重复的 `DispatcherQueueTimer`（约 15 ms 一帧）在
  0.25 秒里缓出变化，每一帧同时给面板同样的宽度，两者的边不会错开；`SizeChanged` 随之更新穿透区域。
- 消息面板就是胶囊的底面，收起时与胶囊同样大小、躺在它下面，按浮出控件的样子画（`FlyoutPresenter` 的样式：
  `AcrylicInAppFillColorDefaultBrush` 背景、`SurfaceStrokeColorFlyoutBrush` 1 像素描边，圆角取胶囊高度的一半），
  打开时抬高到 32（[层次与高度](https://learn.microsoft.com/windows/apps/design/signature-experiences/layering)：
  浮出控件高 32、描边 1），收起时落回 0，没有阴影。它与导航视图并排放在窗口的网格里、跨标题栏那一行，标题栏的网格
  排在它后面，把胶囊画在它上面当作抬头；不放进 `SplitView` 的窗格：窗格的裁剪会切掉阴影。弹出层之外的
  `ThemeShadow` 只落在指定的接收者上，接收者不能是投影者的祖先（`ThemeShadow` 文档），这里是页面。面板顶对齐、
  左边经 `TransformToVisual` 对齐胶囊，宽同胶囊；消息放在叠在底面上的另一个 `Border` 里：元素分到的尺寸比内容
  小时按内容的尺寸绘制再裁剪，消息和底面放在一起，底面的圆角下沿会跟着被裁成平的。打开时消息先按打开的宽度
  `Measure` 出高度，变化期间固定成那个尺寸，只被裁去、不重新折行；高度、消息的不透明度与 `Translation` 的
  Z 值在 0.25 秒里按同样的缓出曲线逐帧变化，结束后打开的面板跟随消息的高度（`SizeChanged`）。`MaxHeight` 取 480
  与窗口剩下的高度，网格的星号行在有限高度下按内容测量，面板因此和消息一样高。打开时键盘焦点移到面板里第一个
  能取焦点的控件
  （`FocusManager.FindFirstFocusableElement`），Tab 不会先进侧栏。点按侧栏或页面时，控件没接住的按下经导航视图的
  `PointerPressed` 收起面板；控件接住的按下（标为已处理）不再冒泡，但会把键盘焦点移进导航视图，经 `GotFocus`
  收起；滚动条这类接住按下又不取焦点的控件，点按它时面板留着。点按照常作用于点到的控件。
- 磁贴栅格的 `ItemsWrapGrid` 给每块定宽：`GridView` 的滚动查看器为竖向滚动条留出约 16 像素，网格因此向右伸出
  页面边缘 16 像素加磁贴间距，几块磁贴正好排满一行。可测的磁贴把延迟放进一个 `SubtleButtonStyle` 小按钮，它
  接住自己的点按，`ItemClick` 不再触发；选中的磁贴用 `AccentFillColorDefaultBrush` 画 2 像素的边，内边距少 1
  像素，内容不动。
- 规则表的行可以拖动重排：`CanDragItems`、`CanReorderItems` 与 `AllowDrop` 让列表自己让出空隙；
  `DragItemsCompleted` 结果为移动时，按列表的新次序算出落点（新次序里拖动的行之后第一个没被拖动的行，在原次序
  里的位置），报告给界面，并把这个次序当作显示的次序，界面随后给出同样的次序时屏幕上什么都不变。拖动时别的行
  进入列表项的重排目标状态，WinUI 让它们变淡并缩到 95%（主题资源 `ListViewItemReorderTargetThemeScale`）；应用资源
  把这个缩放覆盖成 1，行保持原大小，只留变淡。
- 一格里带标记的单元格（规则的内容与它的条目数、no-resolve）是一个网格：内容在星号列里、放不下时省略，标记各占一个
  按自身宽度的列，排在这一列的右边。
- 列表与磁贴栅格整表重载时先记下滚动查看器的 `VerticalOffset`，换完内容后 `UpdateLayout` 并以不带动画的
  `ChangeView` 滚回原处。忙碌的按钮保持尺寸：进度环叠在图标的位置，没有图标时叠在标签上，被盖住的图标或标签
  仍占位、不透明度为 0。对话框的 Esc 只按下可用的取消按钮。搜索框固定 240 宽，输入时旁边的控件不动。原地改名的
  文字用节点的文本样式，回车或离开时提交去掉首尾空白、非空且变了的名字，Esc 放弃，之后文字回到界面给的名字、
  键盘离开它；摘要行在形状不变时原地更新，警告标记的提示文字不变就不重设。
- 单实例：`AppInstance.FindOrRegisterForKey` 以数据目录为键，后启动的进程经 `RedirectActivationToAsync` 交给
  已运行的进程（[应用实例化](https://learn.microsoft.com/windows/apps/windows-app-sdk/applifecycle/applifecycle-instancing)）。
- 托盘：隐藏顶层窗口持有通知区域图标（`Shell_NotifyIcon`、`NOTIFYICON_VERSION_4`），菜单是每次打开时新建的
  系统弹出菜单（`TrackPopupMenuEx`、`TPM_RETURNCMD`）；Explorer 重启后按 `TaskbarCreated` 重新加图标。菜单的构造有
  测试：按描述建出真实的菜单，再用 `GetMenuItemInfoW`、`GetMenuStringW` 与 `GetMenuItemID` 读回，核对策略组子菜单里
  的测速项、分隔线、成员的文字（`&` 的转义、制表符后的延迟）、单选勾、勾选与不可用状态，以及每一项的 id 对应的
  动作。透明底雪花 `tray-on.ico` 按系统 DPI 取 `SM_CXSMICON` 的尺寸
  （`GetSystemMetricsForDpi` 配合 `GetDpiForSystem`，见[按 DPI 查询系统度量](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getsystemmetricsfordpi)），
  从 ICO 里选对应的原尺寸图。它与窗口、任务栏按钮用的 `icon.ico` 是两份，图稿见[图标](../../design/icons/README.md)。
  系统代理与 TUN 模式都关时以 `NIM_MODIFY` 换成 `tray-off.ico`。
- 会话结束（注销、重启、关机）：托盘窗口收到 `WM_ENDSESSION`（`wParam` 为真）时像托盘的退出一样退出，并在消息
  处理里转发线程的消息（`PeekMessageW`、`MsgWaitForMultipleObjects`）等退出清理恢复网络设置，最多 4 秒；返回后
  进程随时可能被结束（[关机](https://learn.microsoft.com/windows/win32/shutdown/shutting-down)）。清理完成后进程在
  这次等待里直接结束：在这里结束 WinUI 应用会等它所在的消息循环，自己卡住。
- release 构建是 GUI 子系统程序（`windows_subsystem = "windows"`），启动与开机自启都不开控制台窗口；调试构建
  留着控制台看日志。
- 文件选择用 Windows App SDK 的 `FileOpenPicker`（`Microsoft.Windows.Storage.Pickers`），以窗口 id 打开在窗口上；
  界面没有要求文件类型时过滤表是 `*`，选择器不接受空的过滤表。
- [更新](../architecture/desktop.md#更新)的安装程序与发布页经 `ShellExecuteW` 的 open 动词打开（返回值大于 32 为成功）。
  它等 Windows 提升安装程序时在调用线程上跑一个嵌套的消息循环，`DispatcherQueue` 里排着的工作会在这个循环里运行，
  此时界面运行时正在这次调用里：`mod.rs` 让这些工作记下错过的一次，等调用返回后重新排队；运行时若在提升完成前就
  结束进程，提升出来的安装程序会停在挂起状态。

模块：`mod.rs` 把界面运行时放在 UI 线程、经 `DispatcherQueue` 投递事件，`bootstrap.rs` 载入运行时，`app.rs` 是
应用对象与资源，`instance.rs` 是单实例，`window.rs` 与 `title_bar.rs` 是主窗口外壳（含消息面板）与标题栏区域，
`messages.rs` 是消息胶囊，`window_state.rs` 记住窗口的位置，`widgets.rs`
把组件树实现为元素并执行补丁，`xaml.rs` 把文本样式、色调与图标映射到主题资源与符号字体，`table.rs`、
`tiles.rs` 与 `chart.rs` 是表格、磁贴栅格与流量曲线，`dialog.rs` 与 `keys.rs` 是对话框与它的按键，`popover.rs`
是弹出面板，`editor.rs` 与 `text_editor.rs` 是编辑器窗口与文本框，`picker.rs` 是文件选择，`tray.rs` 是托盘，
`hwnd.rs` 与 `images.rs` 是窗口句柄、缩放、图标与 PNG 解码，`test_control.rs` 是带 `test-control` feature 时的命名
管道控制口（见[测试与验证](../architecture/desktop.md#测试与验证)）。

与 macOS 相比留下的平台差异：危险动作的按钮是默认按钮配危险色的文字，不是红底白字——Windows 自己的应用
（设置、资源管理器）也这样标危险动作；就地改名的字段是 `TextBox`，行里放不下时按字符截断而没有省略号，WinUI 的
文本框不提供省略号截断（只读的文字由 `TextBlock` 显示，照常以省略号截断并在提示里给出全文）；托盘菜单是 Win32 的
菜单（`TrackPopupMenuEx`），选中任一项它都会关闭，所以选测速也关菜单，菜单项也只有文字没有颜色，延迟因此只以
文字显示在项的右侧，不像 macOS 那样按快慢着色。菜单开在壳告诉应用的图标位置（版本 4 通知的 `wparam`），键盘
打开时同样如此；图标在屏幕右半边时菜单向左展开。

## 安装程序

`cargo xtask package` 在 Windows 上生成 `Egrio_<版本>_x64-setup.exe`（`xtask/src/windows.rs`）：编出应用与服务的
release 构建，确认两者都不导入 Visual C++ 运行时的 DLL、服务能运行，再用固定版本的 NSIS（3.13，按 SHA-256 核对官方
发布包，解到 `target/nsis/`）按 `desktop/egrio/windows/installer.nsi` 打包。工作区在 Windows 上静态链接 C 运行时
（`.cargo/config.toml` 的 `+crt-static`），没装 Visual C++ Redistributable 的机器也能启动这两个程序，否则 Windows App
SDK 的部署指南要求非打包应用自己带上它。`build.rs` 把应用图标与版本信息写成资源文件交给链接器，资源管理器、开始菜单、
“已安装的应用”与任务管理器因此显示 Egrio 的图标与名称。

安装程序要求管理员权限，为所有用户安装 `egrio.exe`、`egrio-service.exe`、引导程序、`wintun.dll`、`Egrio-LICENSE.txt`、
`Wintun-LICENSE.txt` 与卸载程序，页面依次是
欢迎（安装或更新，与版本）、安装位置、进度与完成。安装位置首次是 `Program Files\Egrio`，之后是当前安装的位置（卸载登记的
`InstallLocation`），每次都能改，磁盘根目录与已有其他内容的文件夹也可以；“浏览”选中的文件夹后面按 NSIS 的惯例接上
`Egrio`。完成页的“运行 Egrio”默认勾选，经 Explorer 启动应用（`explorer.exe <路径>`），应用于是以登录用户自己的权限
运行，而不是安装程序提升后的权限；“桌面快捷方式”新装时默认勾选，更新时跟随原来有没有，取消则删除。从应用升级时，应用以
`/UPDATE` 运行安装程序：已有安装时不显示页面，只显示进度，装完窗口关闭、经 Explorer 启动应用。静默安装（`/S`）不显示
页面、不启动应用。界面按系统语言显示中文或英文，用系统的界面字体（Microsoft YaHei UI、Segoe UI），文字只写名称与状态。
安装与卸载程序的文件、任务栏图标使用应用图标；页面内的侧栏和页头使用独立的透明底雪花（见[图标](../../design/icons/README.md)）。
侧栏按显示缩放选位图，页头通过 Modern UI 的 `MUI_HEADERIMAGE_BITMAP` 装入并缩放到控件；卸载页复用同一页头。
两者的 GUI 初始化回调按窗口 DPI 载入透明图，只以 `WM_SETICON(ICON_SMALL)` 设置标题栏的小图标；大图标独立。
该图标一直供窗口使用，由安装、卸载进程结束时释放。许可证文本由根目录 [LICENSE](../../LICENSE) 原样安装到安装目录的
`Egrio-LICENSE.txt`。Wintun 使用官方预编译 DLL，从同一份按 SHA-256 校验的官方 ZIP 中取出 `LICENSE.txt`，
原样安装为 `Wintun-LICENSE.txt`，DLL 仍按该许可授权。两份许可文件均按应用文件设置权限，并随卸载删除。
官方依据见 [Wintun 分发说明](https://www.wintun.net/)与
[预编译二进制许可](https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt)。
安装依次：

1. 运行 `runtime.ps1`：当前用户已注册 x64 的 `Microsoft.WindowsAppRuntime.2` 框架包、且不低于应用构建所用的 2.6.5 时
   什么都不做；否则下载微软为这个版本发布的运行时安装程序（Windows App SDK 下载页给的地址），核对它带有效的
   Microsoft Corporation 签名，以 `--quiet` 运行。以管理员身份运行时它为所有用户安装，返回 0 为成功、`0x80070005`
   为无法全系统安装。失败时安装程序给出返回码并继续，应用启动时引导程序会再提示安装运行时。
2. 等当前安装与目标位置里的 `egrio.exe` 退出：从应用升级时，应用把安装程序交给系统后自己退出。等十秒仍在运行，就以
   “Egrio 正在运行”请用户重试或取消，取消则中止，文件不动。
3. 目标位置不是当前安装的位置时，以当前安装的卸载程序静默卸载它，服务注册与登录用户的 `Run` 登录项先记下、随后跟到
   新位置；否则注册的服务运行的是本目录的 `egrio-service.exe` 时先停止它，再写入文件。
4. 写入文件并限定权限。特权服务以 LocalSystem 从安装位置运行，只有管理员能改它运行的东西：Egrio 的每个文件去掉继承的
   权限，只给 SYSTEM 与 Administrators 完全控制、Users 与应用容器（ALL APPLICATION PACKAGES、ALL RESTRICTED APPLICATION
   PACKAGES）读取和运行，即 `Program Files` 的分配（`icacls` 以固定 SID 设置）。安装位置是新建的、空的或只有 Egrio 时，
   目录本身也这样设置、传给其中的文件；否则目录不动，里面其他东西的权限不变。目录里别人放进去的程序与 DLL 不起作用：
   服务只接纳它旁边的 `egrio.exe` 与它自己（见[特权服务](#特权服务)），它的静态导入只从 System32 解析（链接参数
   `/DEPENDENTLOADFLAG:0x800`，`crates/egrio-service/build.rs`），启动时以 `SetDefaultDllDirectories`
   （`LOAD_LIBRARY_SEARCH_SYSTEM32`）让之后按名称加载的库也只找 System32，`wintun.dll` 按完整路径从服务旁边加载。
5. 已有 Egrio 服务注册时（无论指向哪个目录），以本目录的服务运行 `bootstrap-windows-service`，把注册指向这里并
   启动；没有注册时不注册，开启 TUN 时应用照常经 UAC 注册（见[特权服务](#特权服务)）。登录项原先启动的是离开的那个
   安装时，改为启动这里，参数不变。
6. 建开始菜单快捷方式，在“已安装的应用”里登记版本、发布者、图标、安装位置、占用空间与卸载命令。

卸载程序同样先等应用退出；注册的服务运行的是本目录的程序时运行 `uninstall-windows-service`；登录用户的 `Run` 登录项
指向本目录时删除它；再删除 Egrio 的文件（目录空了才删除目录）、快捷方式与登记，应用数据目录留着。安装程序与其中的程序
不做代码签名：下载后运行时 SmartScreen 提示未知发布者、UAC 提示里也没有发布者，按提示继续即可。

依据：[NSIS 文档](https://nsis.sourceforge.io/Docs/)（`RequestExecutionLevel`、`SetRegView`、`nsExec`、`x64.nsh` 的
`IsNativeAMD64`、`/D` 与浏览时接上的文件夹名），[Modern UI 2 文档](https://nsis.sourceforge.io/Docs/Modern%20UI%202/Readme.html)
（页面与完成页选项、GUI 初始化回调、图标与页内位图的独立设置、页头 `FitControl` 缩放与卸载页头的默认复用），
[`LoadImageW`](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-loadimagew)（按尺寸载入 ICO、进程结束时释放）与
[`WM_SETICON`](https://learn.microsoft.com/windows/win32/winmsg/wm-seticon)（独立设置窗口的大、小图标）；
[`icacls`](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls) 与
[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers)；
[`/DEPENDENTLOADFLAG`](https://learn.microsoft.com/cpp/build/reference/dependentloadflag)、
[`SetDefaultDllDirectories`](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories)
与 [Dynamic-Link Library Security](https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-security)；[Windows App SDK 部署指南](https://learn.microsoft.com/windows/apps/windows-app-sdk/deploy-unpackaged-apps)
（安装程序的 `--quiet`、管理员身份的全系统安装、返回码，以及按框架包族、架构与最低版本检查已注册的运行时）与
[下载页](https://learn.microsoft.com/windows/apps/windows-app-sdk/downloads)；
[`Get-AppxPackage`](https://learn.microsoft.com/powershell/module/appx/get-appxpackage)、
[`Get-AuthenticodeSignature`](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature)；
卸载登记的值依据 [Uninstall Registry Key](https://learn.microsoft.com/windows/win32/msi/uninstall-registry-key)；
资源文件依据 Win32 的 [Resource File Formats](https://learn.microsoft.com/windows/win32/menurc/resource-file-formats)
（`RESOURCEHEADER`、`NEWHEADER`、`RESDIR`）、[`VS_VERSIONINFO`](https://learn.microsoft.com/windows/win32/menurc/vs-versioninfo)
与链接器的 [.res 输入](https://learn.microsoft.com/cpp/build/reference/dot-res-files-as-linker-input)；静态 C 运行时依据
Rust 参考的 [`crt-static`](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)。

## 验证状态

验收覆盖 Windows 10 22H2（x64 虚拟环境）与 Windows 11（x64），桌面以非提权用户运行，使用独立数据目录的
release 或调试构建。以下验证状态截至 2026-11-12，不代表所有平台组合均已验收。

- 门禁：`cargo xtask check --full` 通过。控制管道与服务会话覆盖未授权连接拒绝、连接风暴、隧道独占、
  第二会话接手、桌面退出、适配器禁用、服务停止与挂起服务时的超时和检查点恢复；结束后恢复原服务注册与网络基线。
- 捕获层：[捕获层验收](../runbooks/capture-layers.md)覆盖四种层组合、进程规则、负载下切换、WinINET 守护、缺失和
  无效 Wintun DLL 的失败补偿、服务中断恢复、退出及崩溃恢复。退出与恢复后的接口、路由、DNS、WFP、WinINET 和
  检查点逐项与基线核对。
- 数据面：fake IP、IPv4 与 IPv6 TCP/UDP、ICMP echo、广播丢弃、OpenVPN UDP/TCP 链路和链式代理已覆盖；严格全局模式
  经 Trojan、Hysteria2、Shadowsocks 与 SOCKS5 的 STUN 收发可用。同一 UDP socket 经 Trojan 与 Hysteria2 访问不同
  STUN 目的地时，报告同一个节点映射；IPv4 打洞对端收到的数据与该映射一致。
- 路由与共存：排除网段与规则/全局模式切换不重建设备；切换节点保留 DIRECT 会话并结束改道会话。有线与 Wi-Fi 换上行、
  绑定物理接口的流量、Tailscale 重启、MagicDNS、DNS 与 WebRTC 泄漏检查、经移动网络的远程桌面会话均已覆盖。
  远程桌面尚未按仅结束改道会话的最新行为重测，IPv6 解析开关也未重测。
- 稳定性：两小时混合负载覆盖下载、UDP 回显、DNS 周转与周期切换节点；句柄和线程平稳，内存后一小时无持续增长。
  互联网吞吐和丢包受链路条件影响，不能作为平台性能保证。
- 界面：消息胶囊与面板、节点选择与测速、规则拖动、窗口状态与会话结束退出已核对。托盘菜单构造测试
  通过；组测速、选成员和延迟更新尚未在实际展开的菜单里验证。
- 安装程序：release 包覆盖全新安装、改安装位置、目录与文件权限、服务 DLL 加载、卸载保留外来文件、
  静默安装与 `/UPDATE` 后重启。运行时下载与签名验证通过；应用设置页发起升级、缺少 Windows App Runtime 的干净系统
  安装尚未验证。

未覆盖：DERP 地图不带地址的 Tailscale 控制面（例如自建 Headscale）在 TUN 下冷启动；虚拟环境的 IPv6 ICMP echo；
真实指针悬停及其他界面余项。虚拟环境的互联网探针经过宿主网络，不能单独证明直接物理链路上的行为。
未完成范围见[待办](../backlog.md)。
