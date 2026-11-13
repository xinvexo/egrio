# Linux 平台

Linux 的 TUN 模式使用 `/dev/net/tun`，与其他桌面平台复用 Runtime-owned
`NativeCorePacketDataPlane` 和同一 `NativeCoreDevice`。桌面以登录用户运行，设备、策略路由、DNS 与
nftables 由 root 助手（`egrio-service`）执行；系统代理是该用户自己的 GNOME 设置。

## 设备与 Runtime 边界

`LinuxTun::new` 组装四个能力：`LinuxTunCapture`（`PacketCapture`）、`LinuxTunFirewallControl`、
`LinuxTunRouteControl` 与 `LinuxTunDnsControl`，分别注入对应端口。它们共享唯一的
`LinuxTunSession`：prepare 生成的 ownership token、已打开设备的 checkpoint 和各控制的
prepared/applied 状态，所有操作经同一生命周期锁串行。DNS 对 Route 的依赖是显式检查：
Route 尚未 prepare 或 apply 时 DNS prepare 被拒绝，因为虚拟 DNS 主机路由归 Route 所有。
Runtime 先预写各能力的 checkpoint，
再按 Packet → Firewall → Route → DNS 顺序应用，观察成功后才提交。停止逆序恢复并 join 包泵，不通过另一个
provider task 或第二份 Core 搬运 TCP/UDP 会话。

Packet capability 只创建 fd/接口地址/MTU，不隐式安装默认路由或 DNS；默认捕获路由
由独立 Route capability 持有 checkpoint 与租约，避免先改路由再应用防泄漏规则的窗口。
局域网旁路规则先于捕获规则安装、后于它删除：单独留下的捕获规则会把局域网流量送进 TUN，
Core 会以 RST 结束这些它从未承载的连接。

设备是多队列 TUN：每个队列一个非阻塞、非持久的 fd（`IFF_TUN | IFF_NO_PI | IFF_VNET_HDR | IFF_MULTI_QUEUE`），
第一个队列另带 `IFF_TUN_EXCL` 创建设备，其余以同名 `TUNSETIFF` 加入（内核不给已存在的设备 `IFF_TUN_EXCL`，
多队列设备也只接受同样带 `IFF_MULTI_QUEUE` 的队列，见 `drivers/net/tun.c` 的 `tun_set_iff`）。队列数是 Runtime
的执行器数，每个队列由一个执行器上的包泵读写（见 [Runtime](../architecture/runtime.md#core-与启动输入) 与
[Core](../architecture/core.md#包设备与包泵)）。没有 tun packet-info 前缀，每次读写是一个 virtio-net 头加一个
IP 包。接口地址、MTU、路由和独占规则由 Linux adapter 负责，`PacketDevice` 只提供非阻塞 packet I/O 与
`AsyncFd`（epoll）就绪。关闭最后一个队列的 fd 会撤销非持久接口；策略规则等其他资源仍必须按 checkpoint
验证清理。

内核在 TUN 发出一个包时选队列（`tun_automq_select_queue`）：用包的对称流哈希（两个方向相同）查流表，有记录
就用记下的队列，没有就按哈希均分到各队列；用户进程每向一个队列写入一个包，内核把它的哈希记到这个队列
（`tun_flow_update`，记录 3 秒不用即过期，至多 4096 条）。Core 让持有流最少的队列接受新的 TCP 流，由它写出的
SYN|ACK 让内核把这条流记到它的队列，此后这条流的段都由那个包泵读写；两条流的 32 位哈希相撞时共用一条记录，其中
一条会被带到另一条的队列，记录过期或已满时包按哈希选队列，Core 把这样落到别的队列的段转交持有它的引擎（见
[Core](../architecture/core.md#捕获-tcp)）。一个客户端 socket 发往不同远端的
UDP 数据报可能落在不同队列，它们共用一个关联，回包由打开关联的队列写出，此后这些远端的数据报也被记到那个
队列。只有一个队列时内核不算哈希。卸载设置属于设备（`TUNSETOFFLOAD`），各队列相同。

打开后以 `TUNSETOFFLOAD` 依次尝试 `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6`、去掉 USO、只要
`TUN_F_CSUM`（内核拒绝它不认识的位，USO 自 Linux 6.2 起且须两族同开，见 `drivers/net/tun.c` 的 `set_offload`；
标志定义在 `include/uapi/linux/if_tun.h`）。包前的头是 `struct virtio_net_hdr`（`include/uapi/linux/virtio_net.h`，
内核以 `virtio_net_hdr_from_skb`/`virtio_net_hdr_to_skb` 写读，旧式头按主机字节序，即我们支持的小端主机）：
- 读：内核可交来超过 MTU 的 TCP 段（`GSO_TCPV4/6`）、同一 socket 一次发送粘在一起的 UDP 数据报（`GSO_UDP_L4`）
  和只含伪首部和的校验和（`NEEDS_CSUM`）。Core 读 TCP 与 UDP 时不校验校验和，所以 TCP 段原样交给引擎，粘连的
  UDP 带着 `gso_size` 作为一串列车交给 Core（`ReceivedPacket`）。读不懂的帧按丢包处理。
- 写：TCP 引擎的段带 `NEEDS_CSUM`（`csum_start` 为 IP 头长，`csum_offset` 16），校验和字段只含伪首部和，内核本地
  投递时按已校验处理（`CHECKSUM_PARTIAL`），转发出去时由内核补全；其他包头部全零。内核不接受校验和卸载时所有
  头部全零，段的校验和由泵补全。内核接受 USO 时，设备也接受 UDP 列车：同一来源发往同一客户端的一批数据报写成一个
  `GSO_UDP_L4` 帧（`gso_size` 为每个数据报的载荷长，`csum_start` 为 IP 头长，`csum_offset` 6，IP 与 UDP 长度覆盖
  整批，UDP 校验和字段只含伪首部和），内核按 `gso_size` 切成数据报，各自补全长度与校验和后交给客户端
  （`net/ipv4/udp_offload.c` 的 `__udp_gso_segment`）。

包泵自己读的 DIRECT socket（见 [Core](../architecture/core.md#模块布局) 的 `udp.rs`）由出口守卫打开接收合并
（`UDP_GRO`，[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html)，Linux 5.0 起）：同一来源一起到达的数据报
一次 `recvmsg` 读成一个缓冲，控制消息（`SOL_UDP`/`UDP_GRO`，[cmsg(3)](https://man7.org/linux/man-pages/man3/cmsg.3.html)）
给出除最后一个以外每个数据报的长度；读不完整（`MSG_TRUNC`）时整批作废，因为数据报边界已无从分辨。不由包泵读的
socket 不打开，普通读无法分开合并的数据报。这样一批下行数据报只要一次读和一次 TUN 写。上行方向，包泵记下的
DIRECT 流收到的列车由出口守卫以 `UDP_SEGMENT`（同见 udp(7)，Linux 4.18 起）一次发出：`sendmsg` 带
`SOL_UDP`/`UDP_SEGMENT` 控制消息（`u16` 段长），内核按段长切成数据报，出口网卡不能分段时在软件里切
（`net/ipv4/udp_offload.c`）。内核拒绝时（段超过路径 MTU 等）这串逐个发出；没记下的流的列车由 Core 切回各个
数据报（各自修正 IP 与 UDP 长度）走完整路径。

`LinuxTunCapture::open_for_user` 是 Linux 服务代桌面用户打开设备的路径：以
`IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_TUN_EXCL` 创建，再设 `TUNSETOWNER` 为该 uid 与 `TUNSETPERSIST`，
按 `open` 的命令配置 alias、地址与 MTU 并观察，然后关闭自己的 fd。设备由此持久存在、链路无载波，直到属主以
`LinuxTunDevice::attach` 附着各个队列（与自建设备的队列同样的标志，不带 `IFF_TUN_EXCL`；第一个附着的队列把
设备的这些标志改成附着者的，见 `tun_set_iff`）；配置失败时当场删除
该设备，因为 restore 只删除带本次 alias 的设备。它返回接口名、索引、MTU 与打开前读取的物理
解析器，交给用户进程，不激活本进程的出口覆盖。删除持久设备的仍是 PacketCapture restore。

`LinuxTunConfig` 指定接口名、MTU、出口 mark、策略路由 table/priority、DNS 与
防泄漏/allow-lan 策略。MTU 取 65535，tun 驱动允许的最大值（`drivers/net/tun.c` 的 `MAX_MTU`，TUN 没有
链路层头；`ip -d link` 对 tun 设备报告 `minmtu 68 maxmtu 65535`）。TUN 是不上线路的末端链路，Core 自己终结
TCP 并重新分段：本机客户端按接口 MTU 协商 MSS，MTU 越大，同样的字节经 `/dev/net/tun` 的包越少，而这条路径
的开销主要按包计（每个包一次 `read`/`writev`）。

链路以 `txqueuelen 4096` 启用。系统送进 TUN 的包在 tun 驱动的环上等 Core 读取，环的长度取接口的
`tx_queue_len`，满了就丢（`drivers/net/tun.c` 的 `tun_net_xmit`，丢弃原因 `SKB_DROP_REASON_FULL_RING`，计入接口的
TX dropped；运行时改长度经 `NETDEV_CHANGE_TX_QUEUE_LEN` 调整环），默认是 `TUN_READQ_SIZE` 500
（`include/uapi/linux/if_tun.h`）。较大的队列为新流逐条准入留出突发余量，同时保持内核 backlog 有界。

内核让新接口关闭 IPv6 时（`net.ipv6.conf.default.disable_ipv6 = 1`：新接口沿用 `conf/default`，关闭后内核
拒绝该接口的 IPv6 地址与路由，见内核 [ip-sysctl](https://docs.kernel.org/networking/ip-sysctl.html)
的 `disable_ipv6`），TUN 只承载 IPv4：checkpoint 记下这一点，不加 IPv6 地址、策略规则与路由，观察与恢复
都按它进行。Core 出站按 `egrio0` 自己的 `disable_ipv6` 决定是否解析与拨号 IPv6，桌面经助手附着设备时同样
读取这一项。防泄漏规则这时拒绝不经 TUN 的 IPv6，所以只有部分接口开着 IPv6 时也不会从 TUN 外漏出。preflight 当前要求 root 宿主及有效 `CAP_NET_ADMIN`，并检查可读写 `/dev/net/tun`、
`ip`、`nft`、`resolvectl` 和活动的 systemd-resolved；已存在的同名接口、规则优先级、
路由表或 nftables 表会造成冲突，不能 flush/replace 外部资源。

## 出口、DNS 与防火墙

进程内宿主（Linux 服务、root `egrio-node`）的 Core 由 `LinuxTunEgressSocketGuard` 在
connect/send 前对 TCP、UDP、DNS 和代理传输设置 `SO_MARK`；桌面的 Core 经助手的标记端点得到同一
mark。两者都无论 TUN 是否开启都标记：mark 只对 TUN 的策略路由规则有意义，因此仅系统代理时
路由不变，TUN 打开前后建立的 Core 连接都不会被回捕。捕获规则只把未打 mark 的流量送进 TUN：
本次出口 mark 与其他特权软件打了 mark 的流量（例如 wg-quick 全局隧道的加密包）按各自的路由走，
防泄漏规则不拦它们。若也捕获别人的 mark，全局 VPN 的加密包会进入 TUN、被 Core 直连发出后又进入该
VPN，无限循环。缺少所需权限或绑定失败会拒绝拨号，不能回退成未标记
出口。

因此只路由部分网段的 VPN（例如 WireGuard 只路由文档示例网段 `192.0.2.0/24`）可以与 TUN 并存：它的路由在 main
表中由局域网旁路规则保留，未打 mark 的加密包作为普通 UDP 经 Core 转发。用 fwmark 接管默认路由的
全局 VPN 的加密包按它自己的路由从物理网卡出去，不再被拦下（与 TUN 同开时谁捕获未标记的流量取决于两边
策略规则的优先级，未在系统上验证）。

桌面的 Core 出口 guard `ServiceMarkingSocketGuard` 经助手的标记端点 `/run/egrio/mark.sock` 标记每个新
socket：每个请求以 `SCM_RIGHTS` 携带恰好一个描述符，只有 IPv4/IPv6 的 TCP/UDP socket 被设置 Egrio
fwmark，应答为 errno（0 为成功），助手接收的描述符 close-on-exec 并立即关闭，端点只服务允许的 uid。
TUN 关闭时，助手无法标记（未安装、重启中或拒绝该用户）的 socket 不带标记拨号并被记录，宿主开启 TUN
后据 `take_unmarked` 切断全部 Core 连接（见[捕获层切换](../architecture/runtime.md#捕获层切换)）；TUN 开启（出口 overlay 存在）时未标记的 socket 会被自己的 TUN
捕获，标记失败即拨号失败。

PacketCapture 打开设备时（DNS 能力生效前）通过 `resolvectl dns` 捕获物理 DNS IP，剔除
loopback stub 与虚拟 DNS，作为 TUN 活动期间 Core 经受保护 socket 使用的上游；恢复后撤销，
Core 回到系统解析器。TUN 活动期间以 inotify 监视 systemd-resolved 的运行目录 `/run/systemd/resolve`：
任一链路的 DNS 变化（换网、断开、DHCP 更新）都会改写其中的 `resolv.conf`，随即重新读取上游；读不到
可用服务器时保留原有上游。出口本身经 mark 走 main 表，随内核的默认路由切换，无需另行跟随。

Core 的两种 guard 都从 `LinuxTunEgress` 取得物理网络（`network_watch.rs`），第一次被用到后不论 TUN 是否
开启都跟随：rtnetlink socket 订阅链路、地址与路由组播（`RTMGRP_LINK`、`RTMGRP_IPV4/IPV6_IFADDR`、
`RTMGRP_IPV4/IPV6_ROUTE`），一次变化的一串消息合成一次，重新读取 main 表的 unicast 默认路由（`ip -j route
show table main default`，各族取 metric 最小的为上行）与这些路由所在接口在启用且有载波时的非链路本地地址
（getifaddrs）。TUN 的默认路由在它的私有表里，所以 TUN 从不算上行。读到的网络作为 `EgressNetwork` 发给
Core，Core 据此结束本地地址已经消失的连接、把 Hysteria2 的载体迁到新的 socket，见
[Core 模块布局](../architecture/core.md#模块布局)的 `egress/network.rs`。socket 不绑定接口，所以链路仍在、
只是默认路由换了时，未连接的 UDP socket 自然改走新路由，已有的 TCP 连接保留原来的本地地址。

两种 guard 都替 Core 发 ICMP echo（`EgressSocketGuard::echo`）：从 ping socket（`net.ipv4.ping_group_range`
内的组可开，icmp(7)）发出，与其他出口 socket 一样带上出口 mark（进程内设置，或经助手的标记端点，端点也接受
ICMP 数据报 socket）；内核把 echo 的标识换成 socket 自己的，按序号与载荷认应答。实现在共享的
`egrio_platform::ping_socket_echo`。组不在范围内时打不开 socket，echo 没有回应。接口地址 `10.255.255.1/30`、`fd00:6572:6769:6f00::2/64` 与
虚拟 resolver `198.18.0.1` 只在 `config.rs` 定义一次，fake-IP 校验、命令计划与
`linux_tun_core_capture_config()` 都引用这里。DNS capability 只配置本次 TUN link 的服务器
（`DnsSettings.servers` 为空或恰为该虚拟 resolver）、route-only domain `~.`、default-route，以及物理出口 link
（链路类型 `ARPHRD_ETHER` 或 `ARPHRD_PPP`，读自 `/sys/class/net/<link>/type`）与全局设置的全部路由域（DHCP
给的搜索域），一律以 route-only 形式挂在本 link 上，并在 resolved 的状态变化时跟着增减；它不重写已有 link 配置。
resolved 把名字发往路由域标签最多、与它匹配的 link，`~.` 只是兜底：只挂在物理 link 上的域下的名字只会发往那个
link，防泄漏规则又拒绝物理出口上的 DNS，查询失败后 resolved 的 stub 不回应，glibc 在名字没有所查类型的记录后
（IPv6 关闭时的 AAAA）接着试搜索域，就要等满两次超时。两个 link 带同一路由域时，resolved 并行查询并返回第一个
成功的应答，也就是虚拟 resolver 的。其他 VPN 的域（例如 Tailscale 的 MagicDNS 域）不挂上来：它的 TUN 设备不是
物理出口，那里的 DNS 照常放行，只有它的解析器认得的名字由它回答。
恢复撤销本次 link 的 resolver 交接，并独立重读验证。Core start inputs 显式使用
`UdpPortWithVirtualTcpTargets`：UDP/53 按端口捕获，TCP DNS 只在虚拟 resolver
`198.18.0.1:53` 终结，其他 TCP/53 继续普通路由。

Firewall capability 是 TUN 运行时的防泄漏规则，不当 kill switch：一张单独的 nftables 表（output 钩子，优先级
-150，默认放行），批次原子提交。依次放行回环、本次出口 mark 与 TUN，拒绝从物理出口（nft 的 `ether` 与 `ppp`
接口类型：以太网、Wi-Fi 与 PPP，linux/if_arp.h 的 `ARPHRD_ETHER`、`ARPHRD_PPP`）发出的 53/853（到 LAN 与排除网段
的也拒绝），拒绝到 Core fake-IP 池及其 IPv6 投影的连接（`FirewallSettings.fake_ip_prefixes`，在 TUN 外连接立即
失败而不是等到超时）；TUN 只承载 IPv4 时再放行 DHCPv6、邻居发现、LAN 的 v6 范围与排除的 v6 网段后拒绝其余 IPv6。
其他流量都放行：其他软件特意从 TUN 外发出的（其他 VPN 的连接、绑定接口的 socket）照常通行；其他 VPN 的 TUN
设备是 `ARPHRD_NONE`，它发进自己隧道的 DNS 也放行。助手在会话结束（正常关闭或桌面崩溃）
时删除这张表，Egrio 不在时网络回到没有它时的样子。

到本机的入站连接（远程桌面、SSH、端口转发）的回包不进入 TUN。Route 控制在装上捕获规则之前建立自己的
nftables 表 `egrio_<接口>_replies`：prerouting 链（优先级 -150，在 conntrack 的 -200 之后、DNAT 的 -100
之前）把从其他接口到达、目的地是本机地址（`fib daddr type local`）的新连接在 conntrack 上记为 Egrio 出口
mark；本机发出的回包在一条 route 类型的 output 链里取得同一个 packet mark，内核因 mark 改变重新选路，
捕获规则只收未标记的流量，回包于是走 main 表，防泄漏表按出口 mark 放行。端口转发给容器的连接，其回包
经转发而非本机发出，在 prerouting 到达时取得 mark。其他软件已设置的连接 mark 或 packet mark 不改写。
route 链的优先级 -151 先于防泄漏表的 -150：同一优先级的链之间没有确定的先后。restore 先删捕获规则
再删此表，中间没有被捕获的回包。依据：nftables wiki 的
[Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)（route 链在 output
钩子上于 mark 改变时重新路由，其他钩子用 filter 类型；同优先级无序）与
[Netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)（各优先级数值）。

`RouteSettings.excluded_prefixes` 中的网段不进入 TUN：每个网段是 Egrio 路由表里的一条 `throw` 路由，
查表命中它即离开该表、继续后面的规则，目的地于是沿用 main 表的路由；防泄漏规则本来就放行它们，只在 TUN
只承载 IPv4 时以 `ip6 daddr` 集合为排除的 v6 网段开例外，到它们的 53/853 仍被拒绝。观察使用
`ip -j -N`：路由类型打印为数字（`RTN_THROW` 为 9，见内核 `include/uapi/linux/rtnetlink.h`），主机前缀
打印成裸地址并按单个主机解析。排除集合可在 TUN 运行中改变：Route 与 Firewall 控制在已应用
时也能再次 prepare，checkpoint 记下当时生效的设置并标为已应用，只有路由意图（是否装默认路由）不能原地
改变。原地 apply 只增删 `throw` 路由，防泄漏规则在同一个 nftables 事务中删除并重建本表，没有表缺席的
时刻；restore 已应用的 checkpoint 时回到其中的设置，restore 启动时的 checkpoint 才移除整个控制。

## 连接归因

桌面宿主与 Linux daemon 随 Core 启动输入提供 procfs `LinuxFlowScanner`；该代 Core 的归因 worker
同时服务系统代理 listener 的回环客户端与 TUN 流，TUN 开关不影响它。
一次批量扫描读取所需的 `/proc/net/{tcp,tcp6,udp,udp6}` 快照，只为与请求五元组匹配的行
收集 inode，再遍历 `/proc/[pid]/fd` 寻找 `socket:[inode]` 持有者，并在读取
`/proc/[pid]/exe` 后复核该 fd 仍持有同一 inode，防止 PID 复用借用身份。匹配规则与 macOS
一致：TCP 要求本地端口、本地地址（或同族通配）和远端完全一致；UDP 允许未连接 socket；
同一元组有多行（端口复用或 v4 与双栈 v6 并存）、v6 通配 socket 应答 IPv4 流、持有者跨多个
进程、扫描超时或取消时一律保持未知。可见范围是本进程的网络命名空间和 ptrace 可读的进程；
可执行文件路径去掉 `proc_pid_exe(5)` 的 ` (deleted)` 后缀，名称取其文件名。

## checkpoint 与恢复

每次会话生成独立 ownership UUID，写入接口 alias 与 nftables 表 comment；checkpoint
同时保存规范化配置、捕获设置和所有权标识。恢复只处理与该 checkpoint 一致的资源，
发现其他所有者则拒绝清理并保留恢复责任，不删除碰巧同名的外部接口或规则。Packet 与
Route checkpoint 使用同一会话所有权，但各自只声明自己实际控制的设置。restore 的 checkpoint
必须指名本能力集的内核对象：接口名、fwmark、路由表与规则优先级与本能力集配置不一致时，在接触
系统前拒绝。Linux 服务 restore 的 checkpoint 来自桌面用户可写的文件，否则一个伪造的 checkpoint
可以让 root 删除形状相同的外部规则或路由（例如 WireGuard 的 `not fwmark` 规则）。

无 GUI 的 Linux TUN 宿主通过 SDK 装配完整 Runtime、Core config、持久化
`FileCheckpointStore` 和同一 capture/firewall/route/DNS 实例。启动前先恢复 unresolved
checkpoints，失败时不接受新的捕获会话。CLI 暴露 preflight、运行与恢复操作，长期
状态、Core 和包泵均归 Runtime，CLI 只持有宿主与报告打印责任。入口位于
`egrio-node`，例如
`cargo run -p egrio-daemon --features server --bin egrio-node -- linux-tun-preflight`；
运行和恢复分别使用 `linux-tun-run`、`linux-tun-recover`。`egrio-service` 的 Linux 宿主是桌面的
[特权助手](#特权助手)，不承载这些 CLI。

## 桌面系统代理

`LinuxSystemProxyAdapter` 保持独立的 GNOME GSettings capability；HTTP/HTTPS endpoint
引用同一 generation 的 loopback `CoreListener`。它检查
`org.gnome.system.proxy*` schema，保存 baseline 与预期 endpoint，并执行
prepare/apply/observe/restore。该设置仅覆盖使用此 schema 的应用，不替代 TUN。

桌面应用以登录用户运行，使用固定 `LINUX_RUNTIME_ID` 装配 Core 与可选系统代理，TUN、路由、DNS
与防火墙经 Linux 服务（root 助手）执行，系统代理因此写入该用户自己的 GSettings。产品状态只投影
已提交 Runtime topology；profile/selector/IPv6 与遥测也进入同一 Runtime。进程内 `LinuxTun` 只服务 Linux 服务宿主与 root `egrio-node`；单给 Egrio
二进制 file capability 不可行（GTK 拒绝安全执行模式的进程，且不保证 `ip`/`nft` 子进程继承有效
权限），代码不会通过隐式 ambient capability 扩权。

## 特权助手

助手宿主为 `egrio-service run-linux-service`：Unix socket 传输按 `SO_PEERCRED` 的对端 uid 授权（root 与下文名单上
的用户），未授权的 hello 得到认证错误；能力处理器把
Prepare/Apply/Observe/Restore 映射到一个 `LinuxTun` 能力集，`OpenPacketCapture` 创建属主为对端 uid
的持久 TUN 并以 `OwnedTun` 通道返回；另有上文的标记端点，桌面侧的 `MarkClient` 使用同一线格式。会话与资源释放语义见
[Runtime 特权服务](../architecture/runtime.md#特权服务)。

助手由 systemd 单元 `egrio-service.service` 以 root 运行，有两种安装。发行包（[deb](#发行包)）把助手装在应用旁的
`/usr/bin/egrio-service`、单元装在 `/usr/lib/systemd/system/`，文件归包管理器；包外运行的应用（AppImage、构建）
把助手的 root 所有副本装到 `/usr/local/libexec/egrio/egrio-service`、单元写到 `/etc/systemd/system/`，systemd
优先加载这一份（systemd.unit(5) 的单元加载路径），单元从不指向用户可写的构建或应用目录。两种安装的单元文本相同，
只有助手路径不同；包里的单元文件由测试核对与布局写出的一致。助手服务的用户除 root 外列在
`/etc/egrio/allowed-uids`（每行一个 uid），助手在每个连接到来时读取，所以加入用户不必重启。布局常量、单元文本与
安装/卸载命令名只在 `service_layout.rs` 定义。单元为 `Type=notify`：助手绑定 `/run/egrio/service.sock` 与
`mark.sock` 后才发出 `READY=1`，因此启动单元返回时 socket 已可连接；`RuntimeDirectory=egrio` 提供该目录，
`Restart=always` 在崩溃后重启；能力边界只保留 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`，并启用 `NoNewPrivileges`、
`ProtectSystem=strict`、`ProtectHome` 与 `PrivateTmp`。`StateDirectory=egrio`（`/var/lib/egrio`，0700）在单元停止后
仍在，`ProtectSystem=strict` 下可写：每个控制会话把发出而尚未 restore 的 checkpoint 记在 `sessions/` 下自己的文件里
（经临时文件替换，先于它们所指的内核对象），会话释放后删除。助手启动时、绑定 socket 之前，按这些记录释放上一个
进程留下的会话（DNS、路由、防泄漏表，再是设备），所以助手被强杀、崩溃或停止后，桌面即使也不在，下一个实例一
启动网络就回到没有 Egrio 时的样子；桌面若还在，它随后经新实例按会话丢失恢复。只有记录里的会话被释放，
`egrio-node` 等其他宿主的同名资源不受影响。

`egrio-service install-linux-service --allow-uid <uid>` 只能以 root 运行，把 `<uid>` 加入名单。装有发行包时它只
`enable --now` 包里的单元，而且只接受包里的助手执行：别处的副本会遮住包的单元，这时提示改用包里的 Egrio 或先卸载包。
不在包里时它把自身经临时文件替换为上述副本、写入单元，两者有变化才 `daemon-reload`、`enable` 并 `restart`（重启结束
的会话由桌面按会话丢失恢复），否则只 `enable --now`。桌面的 TUN 环境检查（`egrio-daemon` `privileged_service`）要求
名单含当前 uid、单元运行的助手就是应用旁的 `egrio-service`（发行包里两者是同一文件；包外的副本逐字节比较，按两个文件
的大小与修改时间复用比较结果）且 `systemctl is-active` 为 active。单元处于 systemd 自行完成的过渡状态（activating、
deactivating、reloading、refreshing，例如崩溃后 `RestartSec=1` 的自动重启）时，准备环境最多等待 5 秒，崩溃后的会话
恢复因此不需要授权；仍不满足时运行 `pkexec <应用旁的 egrio-service> install-linux-service --allow-uid <当前 uid>`，由
会话的 polkit 代理请求管理员授权（退出码 126 为用户取消，127 为未获授权），再等待单元 active。所以每个用户第一次开启
TUN 时授权一次，发行包的升级不再需要授权。

发行包的安装脚本（`postinst configure`，systemd 没有运行时跳过）运行 `egrio-service install-linux-package`：删除包外
安装的副本与单元（`ExecStart` 指向该副本的那一份），`daemon-reload`、`enable` 并 `restart`，升级因此换上新的助手，名单
保留。卸载脚本（`prerm remove`）运行 `egrio-service uninstall-linux-service`，它同样只能以 root 运行：只要 TUN 资源
（接口、规则优先级、路由表、虚拟 DNS 主机路由或防泄漏表，与打开 TUN 前检查的冲突项相同）仍在内核中就拒绝并
列出它们，卸载随之中止：停止的助手不清理这些资源，只有运行中的助手能恢复（按桌面的 checkpoint，或启动时按自己的
记录），所以要先在 Egrio 中关闭 TUN。否则它 `disable --now` 停止并禁用单元，删除包外安装的副本与单元、名单和会话
记录所在的状态目录；包里的文件由包管理器删除，卸载后的脚本再 `daemon-reload`。没有任何安装时直接成功。包的内容与
打包见[发行包](#发行包)。

## 发行包

`cargo xtask package` 在 x86_64 Linux 上生成 Ubuntu 的 deb（`xtask/src/linux.rs`）：为宿主
（`x86_64-unknown-linux-gnu`）编出应用与助手的 release 构建，在 `target/release/bundle/deb/` 下组装，用
`dpkg-deb --root-owner-group --build` 打成 `egrio_<版本>_amd64.deb`（版本取自工作区）并打印它的路径。包里的文件都归
root，目录、可执行文件与维护脚本为 0755，其余为 0644：

| 包里的路径 | 来源 |
| --- | --- |
| `/usr/bin/egrio`、`/usr/bin/egrio-service` | 应用与助手的 release 构建 |
| `/usr/share/doc/egrio/copyright` | 根目录 `LICENSE` 的完整原文 |
| `/usr/lib/systemd/system/egrio-service.service` | `desktop/egrio/linux/package/` |
| `/usr/share/applications/com.xinvexo.egrio.desktop` | `desktop/egrio/linux/package/` |
| `/usr/share/icons/hicolor/<n>x<n>/apps/com.xinvexo.egrio.png` | `desktop/egrio/icons/<n>x<n>.png`，n 为 32、48、128、256、512 |
| `DEBIAN/postinst`、`DEBIAN/prerm`、`DEBIAN/postrm` | `desktop/egrio/linux/package/` 的 `deb-*` |
| `DEBIAN/control` | 同一目录的模板 `deb-control`，填入版本与 `Installed-Size` |

`Installed-Size` 是各文件按 KiB 向上取整之和，每个目录另计 1 KiB。包依赖 `libc6 (>= 2.39)`、`libgtk-4-1 (>= 4.14)` 与
`libadwaita-1-0 (>= 1.5)`，即 Ubuntu 24.04 的 glibc、GTK 4 与 libadwaita，界面只用后两者在这个版本已有的 API（见
[桌面应用](#桌面应用)）。组装前用 `objdump -T` 核对两个二进制需要的 `GLIBC_` 符号版本都不高于模板里 libc6 的下限，
否则列出超出的符号并失败：在更新的 glibc 上编出的二进制可能需要更新的符号，所以发布的包在 Ubuntu 24.04 上构建（需要
`libgtk-4-dev`、`libadwaita-1-dev`、`binutils` 与 `dpkg`）。组装后先运行包里的 `egrio-service version`，再打包。

桌面文件以应用的 GApplication ID 命名：窗口属于应用时，GTK 把这个 ID 设为 Wayland 的 app ID 与 X11 的
`_GTK_APPLICATION_ID`，GNOME Shell 按它找到同名的桌面文件，把窗口归在 Egrio 名下、显示它的图标，程序坞也就能固定它；
设了 `EGRIO_DATA_DIR` 的开发实例 ID 不同，不对应这个文件。图标名也是这个 ID。桌面文件另有 `Categories=Network;`、
`StartupNotify=true` 与 `SingleMainWindow=true`（只有一个主窗口，GNOME Shell 不提供“新窗口”）。hicolor 主题的图标缓存
由 hicolor-icon-theme（libgtk-4-1 依赖它）的 dpkg 文件触发器更新，维护脚本不处理。

发布的 deb 在 GitHub 的 Ubuntu 24.04 机器上构建（见[发布](../runbooks/release.md)）。[更新](../architecture/desktop.md#更新)
下载的 deb 经 `g_app_info_launch_default_for_uri` 交给桌面打开 deb 的默认程序，没有这样的程序时这次升级失败。

## 官方依据

设备依据 Linux kernel [Universal TUN/TAP device driver](https://docs.kernel.org/networking/tuntap.html)
（多队列见其 Multiqueue tuntap interface）和 UAPI `linux/if_tun.h`，队列的创建、附着与选择依据
`drivers/net/tun.c` 的 `tun_set_iff`、`tun_automq_select_queue` 与 `tun_flow_update`（`MAX_TAP_QUEUES` 256、
`MAX_TAP_FLOWS` 4096、`TUN_FLOW_EXPIRE` 3 秒）；持久用户设备依据同一文档的 `TUNSETPERSIST`/`TUNSETOWNER`，以及
`drivers/net/tun.c` 中附着已有设备时的 `tun_permitted()`（调用者匹配设备属主或属组时放行，
否则要求 `CAP_NET_ADMIN`）；助手安装依据 systemd.service(5)（`Type=notify`、`Restart=`）、
systemd.exec(5)（`RuntimeDirectory=` 在单元停止时删除、`StateDirectory=` 保留且不受 `ProtectSystem=strict` 的只读
限制，以及 `CapabilityBoundingSet=`、`NoNewPrivileges=`、`ProtectSystem=`）、
sd_notify(3)、systemctl(1) 与 pkexec(1)，两种安装的先后依据 systemd.unit(5) 的单元加载路径；发行包依据
[Debian Policy](https://www.debian.org/doc/debian-policy/) 4.7.4 的第 5 章（控制字段，`Installed-Size` 见 5.6.20）、
[第 6 章](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)（维护脚本）与 10.10（属主与权限）、
dpkg-deb(1) 的 `--root-owner-group` 与 deb-triggers(5)；桌面文件依据
[Desktop Entry Specification 1.5](https://specifications.freedesktop.org/desktop-entry/latest/)（应用的文件名是
D-Bus well-known name 形式的反向域名，以及各键的含义），图标依据
[Icon Theme Specification](https://specifications.freedesktop.org/icon-theme/latest/) 的 Installing Application
Icons（装进 hicolor 主题，至少 48×48）；窗口与桌面文件的对应依据 xdg-shell 的 `xdg_toplevel.set_app_id`（app ID
宜与桌面文件的基本名相同）、GTK 4.14 的 `gtkapplication-wayland.c`、`gtkapplication-x11.c` 与 `gdktoplevel-wayland.c`
（属于应用的窗口以 GApplication ID 为 app ID 与 `_GTK_APPLICATION_ID`），以及 GNOME Shell 的 `shell-window-tracker.c`
（先按 WM_CLASS，Wayland 下即 app ID，再按 GApplication ID 找 `<ID>.desktop`）与 `shell-app.c`
（`SingleMainWindow`）；socket mark 依据 Linux `socket(7)` 的 `SO_MARK`；接口、策略
路由与路由表依据 iproute2 `ip-link(8)`、`ip-rule(8)`、`ip-route(8)`；DNS 交接依据
systemd `resolvectl(1)` 的 per-link DNS/domain/default-route/revert，路由域的选择依据
[systemd-resolved.service(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html)
的 Protocols and Routing（标签最多的路由域胜出，并列的 link 并行查询、取第一个成功的应答，`~.` 兜底）；防火墙依据
nftables 的 inet output hook、mark、comment 与原子批处理；网络变化依据 rtnetlink(7)、netlink(7) 的多播组与
getifaddrs(3)。连接归因依据 `proc_pid_net(5)`、
`proc_pid_fd(5)`、`proc_pid_exe(5)`、内核 `Documentation/networking/proc_net_tcp.txt`，以及
`net/ipv4/tcp_ipv4.c`、`net/ipv4/udp.c`、`net/ipv6/tcp_ipv6.c`、`net/ipv6/datagram.c` 中的
`seq_printf` 格式：端点为原始网络序字（IPv4 一个、IPv6 四个 `s6_addr32`）按本机整数打印的
十六进制加主机序端口，inode 为第十列。

## 代码结构

`egrio-platform-linux`：

- `config.rs` — TUN 设备、出口 mark、策略路由、DNS 与防泄漏配置、验证与地址常量；
- `packet_device.rs` — 多队列、非持久、非阻塞 `/dev/net/tun` 的完整 IP packet I/O 与持久设备的队列附着；
- `session.rs` — `LinuxTun` 能力组装与共享 `LinuxTunSession`（ownership、设备 checkpoint、各控制的
  prepared/applied 状态），不拥有 Core 或 packet worker；
- `packet_capture.rs` — `LinuxTunCapture`：验证 settings、生成 ownership checkpoint、打开/观察/恢复
  设备，以及代用户打开持久设备的 `open_for_user`；
- `controls.rs` — `LinuxTunRouteControl`、`LinuxTunDnsControl`、`LinuxTunFirewallControl` 各自的
  settings 校验与 apply/observe/restore，DNS 显式依赖 Route；
- `network_state.rs` — TUN ownership、preflight、接口/地址/MTU 机制；
- `routes.rs`、`dns.rs`、`firewall.rs` — 策略路由（含入站回包的标记表）、systemd-resolved 与 nftables
  防泄漏能力及按所有权的观察/恢复；`nft.rs` 以 ownership comment 认领 Egrio 的 nftables 表并整表
  原子替换；`command.rs` 提供有界命令 runner；
- `egress_guard.rs` — `LinuxTunEgressSocketGuard` 的 `SO_MARK` 保护，以及 TUN 打开时捕获、恢复后撤销的
  物理 DNS overlay 和发给 Core 的物理网络（`LinuxTunEgress`）；
- `network_watch.rs` — rtnetlink 变化通知与物理网络的读取；
- `process_attribution.rs` — procfs `LinuxFlowScanner`；
- `runtime_system_proxy.rs`、`system_proxy.rs` — GNOME GSettings 系统代理能力；
- `service_layout.rs` — 助手的两种安装布局、单元文本与服务用户名单的格式。

仅限 Linux 的 ioctl、socket 和命令行为由 `cfg(target_os = "linux")` 保护，非 Linux 构建仍检查共享
契约。`egrio-service` 的 `linux/` 持有助手宿主、传输认证、能力处理器与标记端点；桌面侧的单元状态与
`pkexec` 安装在 `egrio-daemon` 的 `privileged_service/linux.rs`。

## 桌面应用

桌面应用（见[桌面宿主](../architecture/desktop.md)）在 `desktop/egrio` 的 `linux/` 里经 GTK 4 与 libadwaita 实现
egrio-ui 描述的界面，只用 Ubuntu 24.04 带的 GTK 4.14 与 libadwaita 1.5 已有的 API（`gtk4`
与 `libadwaita` crate 的 `v4_14`、`v1_5` feature），依据 [GTK 4](https://docs.gtk.org/gtk4/) 与
[libadwaita 1.5](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/1.5/) 的文档。

- 构建：需要 GTK 4 与 libadwaita 的开发文件（Ubuntu 的 `libgtk-4-dev`、`libadwaita-1-dev`）。Adwaita 缺的几个符号图标在
  `desktop/egrio/linux/icons/`，`build.rs` 用 GLib 的 `glib-compile-resources` 按 `linux/egrio.gresource.xml`
  编进可执行文件。
- 应用对象：`AdwApplication`，会话总线上的名字是 `com.xinvexo.egrio`，设了 `EGRIO_DATA_DIR` 的开发实例在名字后加数据目录的
  哈希。注册时名字已被同一数据目录运行中的实例占着，就激活它（它显示主窗口）后结束
  （[GApplication](https://docs.gtk.org/gio/class.Application.html) 的唯一性）。没有会话总线时 GApplication 只在本进程
  注册、每个进程都以为自己是唯一的，所以接着取数据目录里的运行锁（见[桌面宿主](../architecture/desktop.md#产品后端)的
  `runtime_owner.rs`），拿不到就记一行日志结束。应用一直保持运行，没有窗口时托盘与 Core
  照常；Ctrl+Q 退出、Ctrl+W 关掉当前窗口（`app.quit` 与 `app.close-window` 两个动作，GNOME 应用的习惯），
  SIGTERM、SIGINT 与 SIGHUP 同托盘的退出一样关掉捕获层再结束。
- 与 macOS 相比的平台差异：设置分组的说明在标题下面而不是旁边，这是 `AdwPreferencesGroup` 的样子，GNOME 的设置也
  如此。
- 主窗口：`AdwApplicationWindow` 里的 `AdwNavigationSplitView`，侧栏与页面各有一个 `AdwHeaderBar`，窗口按钮按
  `gtk-decoration-layout` 排布，圆角与阴影由 libadwaita 画；侧栏固定 180 宽。页面标题栏没有页面标题，起点是一个空的标记，
  末端依次是流量模式与捕获开关。[消息胶囊](../architecture/desktop.md#消息)浮在一个 `GtkOverlay` 里，这个叠层盖住页面的
  标题栏与页面，胶囊在标记所在处、与页面左边对齐、在标题栏里垂直居中（位置由 `get-child-position` 给出），宽度变化不挤动
  标题栏里的任何控件，变化本身由 `AdwTimedAnimation` 过渡；
  铃铛是 Egrio 自带的符号图标。胶囊的按钮自己不画底面，只在面板收起时的悬停（`:hover`）与未读时着色，底色与预览文字的
  不透明度经 CSS 过渡变化。信息级别的底色用调色板的蓝色（`@blue_3`）：Ubuntu 的强调色是橙色，看上去像警告。
- 消息面板就是胶囊的底面：同一个叠层里排在胶囊下面的一个盒子，按弹出层的配色画（`@popover_bg_color`，圆角取胶囊高度的
  一半），收起时与胶囊同样大小；打开时阴影经 CSS 过渡出现，左边缘与宽度跟着胶囊，高度由另一个 `AdwTimedAnimation`
  （0.25 秒，`EaseOutCubic`）从胶囊的高度长到消息的高度，至多到上限并让出窗口的底边距。消息放在叠在底面上的一个
  `GtkScrolledWindow` 里，两个方向都是 `GTK_POLICY_EXTERNAL`：尺寸不跟随内容，比内容小时把内容裁去；变化期间消息固定成
  打开时的宽度与高度（尺寸请求），只被裁去、不重新折行，打开后高度请求放开，列表在上限内自己滚动。两者的位置与尺寸都由
  `get-child-position` 给出；那时叠层正在布局，空处变了要给消息的新宽度就放到空闲回调里再设。不用 `AdwOverlaySplitView`，它的遮罩会吞掉收起面板的
  那次点按（`adw-overlay-split-view.c`）。点按侧栏或页面中面板以外的地方经捕获阶段的手势收起它，点按照常作用于点到的
  控件；标题栏里的控件（胶囊也在其中）不收起它，Esc 与胶囊收起它。
- 窗口状态：主窗口与编辑器窗口的尺寸、主窗口是否最大化存在数据目录的 `window-state.json`，关窗和退出时保存。Wayland
  不告诉应用窗口的位置，不保存位置；托盘点按带来的激活令牌（`xdg-activation-v1`）交给要显示的窗口，窗口才能到前面。
- 对话框是浮在主窗口里的 `AdwDialog`，打开时键盘在第一个文本框（`adw_dialog_set_focus`），可选择的说明文字因此不会被
  整段选中；Esc 按树里的取消按钮，字段里的回车按默认按钮。弹出面板同样以树里回车的按钮为默认按钮
  （`gtk_popover_set_default_widget`）。编辑器是单独的窗口，标题有未保存标记 `•`，Ctrl+S 保存。文件选择用
  `GtkFileDialog`，有桌面门户时经门户。
- 外观：主题偏好设为 `AdwStyleManager` 的 `color-scheme`；文本样式与色调映射到 libadwaita 的样式类与命名颜色，随深浅色
  变化，变动的数字用等宽数字（`numeric`）。单行的文字放不下时省略，悬停说明是全文（`GtkWidget::query-tooltip`）。忙碌的
  按钮把进度环叠在图标上，没有图标时叠在文字上，被盖住的部分照常占位，按钮尺寸不变。
- 列表：表格是 `GtkColumnView`（有表头）或 `GtkListView`，磁贴栅格是 `GtkGridView`，都只为显示的行建控件
  （[列表控件概览](https://docs.gtk.org/gtk4/section-list-widget.html)）；列、表头或行高变了就换一个新的视图。磁贴之间的
  间距是格子的内边距，栅格向外伸出这段内边距，磁贴的边缘因此与页面对齐。选中的磁贴有强调色边；可测速的磁贴第二行
  末尾的延迟是单独的按钮，测速中显示进度环，它的高度固定，测速开始或结束不移动两行文字。带标记的单元格（规则的
  内容与它的条目数、no-resolve）是一行，内容占去标记留下的宽度（`hexpand`）、放不下时省略，标记因此排在这一列的右边。
- 托盘：会话总线上的 StatusNotifierItem 与 dbusmenu（[StatusNotifierItem 规范](https://www.freedesktop.org/wiki/Specifications/StatusNotifierItem/)），
  由 `ksni` 在桌面的 tokio 运行时上提供；GNOME 经 Ubuntu 默认启用的 AppIndicator 扩展显示它，基于 GTK 3 的
  libappindicator 不能载入 GTK 4 进程。dbusmenu 没有延迟列，成员的延迟跟在名字后；选中菜单项后宿主关菜单，组的测速也一样。
  交给 ksni 的菜单项有测试核对：策略组子菜单里的测速项、分隔线、成员的标签（下划线的转义、名字后的延迟）、勾选与
  能不能选。
  雪花图标与 Windows 共用原尺寸图稿，以多种尺寸的透明底像素图（`IconPixmap`）给出，面板按显示尺寸与缩放选择。
  按系统代理与 TUN 模式的开关选择图稿，ksni 随状态更新发出 `NewIcon`；图稿与尺寸见[图标](../../design/icons/README.md)。
- 控制口：`test-control` 构建在数据目录开 `test-control.sock`。GTK 4 不能把合成的输入事件放进事件队列，命令按点按或按键
  到达控件时的效果直接作用于控件（按钮被点按、开关被拨动、下拉项被选中），命令列在 `linux/test_control.rs`。

模块：`mod.rs` 把界面运行时放在主线程、经主上下文投递事件，`window.rs` 是主窗口外壳，`messages.rs` 是标题栏的消息
胶囊与由它长成的消息面板，`widgets.rs` 把组件树实现为控件并执行补丁，`style.rs` 把文本样式、色调与图标映射到 libadwaita 并装入
Egrio 自己的样式，`table.rs` 与 `cells.rs` 是表格与单元格，`tiles.rs` 与 `chart.rs` 是磁贴栅格与流量曲线，`exact.rs`
是定宽定高的容器，`dialog.rs` 是对话框，`editor.rs` 与 `text_editor.rs` 是编辑器窗口、文本框与原地编辑的名称，
`picker.rs` 是文件选择，`tray.rs` 是托盘，`window_state.rs` 是窗口尺寸。

## 验证状态

验收覆盖 Ubuntu 26.04 的 x64 虚拟环境与 GNOME Wayland 桌面，以及 arm64 非 GUI 宿主；发行包在 Ubuntu 24.04
构建和检查。使用独立测试配置、调试或 release 构建。以下验证状态截至 2026-11-12，不代表所有平台组合均已验收。

- 门禁：`cargo xtask check --full` 在 Ubuntu 26.04 通过，`linux_service_session`
  端到端检查通过，结束后网络回到基线。所测 WSL 环境在基线下丢弃较大的环回 UDP 数据报，大报文与分片测试在那里失败，
  因此不能代替完整 Linux 验收。
- 捕获层：GNOME 桌面的[捕获层验收](../runbooks/capture-layers.md)覆盖四种层组合、进程规则、负载下切换、接口重名的
  失败补偿、助手中断恢复、退出及崩溃恢复。系统代理逐值恢复；助手和桌面同时退出后，重启的助手可清除遗留设备、
  策略规则、路由与防火墙状态，无需桌面再次启动。
- 数据面：多队列与单队列 TUN、UDP 卸载、fake IP、IPv4/IPv6 TCP 和 UDP、ICMP echo、MTU 与分片、严格全局模式和
  路由排除已覆盖。经 Trojan 与 Hysteria2 的多目的地 STUN 映射一致，IPv4 打洞已验证。包泵负载与连接风暴已覆盖；
  两小时真实网络探针中，线程、文件描述符与内存未出现持续增长。
- 路由与共存：有线与 Wi-Fi 换上行、睡眠唤醒、WireGuard 部分网段路由、Tailscale 与 MagicDNS、物理接口抓包和 DNS/
  WebRTC 泄漏检查已覆盖。测试链路上按端口选出的路径有明显时延差异，Hysteria2 的路径检查可迁移载体而保持流不断。
  另验证 TCP keepalive 可避免测试 NAT 提前回收空闲映射；这一现象依赖网络，不能作为所有 NAT 的超时描述。
- 界面：Ubuntu 26.04、GTK 4.22、libadwaita 1.9、Xvfb X11 下覆盖消息胶囊与面板动画、节点选择、测速、规则显示、
  路由测试、窗口尺寸恢复、深色外观与退出。托盘菜单构造测试通过；实际桌面上的托盘交互仍未验证。
- 发行包：打包检查覆盖 glibc 2.39 上限、桌面文件、包依赖、文件权限、图标缓存、助手安装与卸载，
  以及接口仍活动时拒绝卸载。Ubuntu 24.04 干净容器安装可解析依赖并找到共享库；Ubuntu 26.04 的 Xvfb 下可启动应用。
  本地更新描述覆盖下载、SHA-256 校验与打开 deb 的程序交接。

未覆盖：来自非 LAN 地址的真实远程桌面会话、Linux 全局模式下的远程桌面会话；Ubuntu 24.04 的 GTK 4.14 与
libadwaita 1.5 下的实际界面、GNOME 中发行包的应用网格与程序坞归属、从发行包装好的桌面开启 TUN、软件中心安装更新，
以及真实指针悬停等界面余项。未完成范围见[待办](../backlog.md)。
