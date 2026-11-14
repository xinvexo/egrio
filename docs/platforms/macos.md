# macOS 平台

## 数据面与所有权

macOS 的 TUN 是特权服务创建的 utun：

```text
egrio-service（launchd 以 root 运行，随应用包分发）
  utun（内核控制 socket）+ 进 utun 的路由（减去排除网段，路由套接字）+ 默认解析器（动态存储会话键）
  --SCM_RIGHTS 交出 utun socket-->
桌面进程：MacosTunDevice（在 utun 上逐包读写）
  <-> Runtime-owned NativeCorePacketDataPlane
  <-> 同一 NativeCoreDevice / TCP / UDP / DNS / rules / outbound
```

桌面以用户身份运行，持有 Core、Runtime 与界面；服务只做需要 root 的部分：创建 utun 并配置地址与
MTU，把每个地址族除首个 /8 外、减去排除网段的地址空间路由进 utun，把虚拟解析器设为系统的
默认解析器（物理网络服务仍是主服务），再把 utun 的 socket 交给桌面，此后报文在 Core 与内核之间直接往来，
不经服务。结构与 Linux（助手打开 TUN、交给桌面）和 Windows（服务持有 Wintun）相同，共用
`egrio-service` 的协议与会话；macOS 没有 Swift 代码与 Network Extension。

`MacosTunDevice` 实现 Runtime 的 packet device；SystemProxy 和 TUN 可以分别开启或组合；显式代理
listener 与 packet pump 共用同一 Runtime generation 的 Core、规则、DNS/Fake-IP、UDP actor 和连接遥测。

utun 上的报文不带应用身份；macOS 宿主随 Core 启动输入提供 `MacosFlowScanner`，
Core 用原始连接五元组（系统代理 listener 的回环客户端同样适用）查询 BSD socket 或
Network.framework 用户态连接的归属，
把真实进程名与可执行路径交给同一个 Core 的规则与
遥测。这是一项尽力而为的本机增强，查询失败不阻止 TUN 捕获，不把未知或多 owner 猜成某个应用。

## 连接归因与应用展示

`process_attribution/` 使用当前 macOS SDK 的 `libproc.h`、`sys/proc_info.h`：
`proc_listpids` 枚举候选，`PROC_PIDLISTFDS` 和 `PROC_PIDFDSOCKETINFO` 读取 TCP/UDP socket，
`PROC_PIDTBSDINFO` 固定进程开始时间，`proc_pidpath` 读取真实可执行文件。
C shim 的 libproc 调用直接使用 SDK 结构体，Rust 只接收自定义小记录。
多数进程没有被查询的 socket，所以每个进程只列一次描述符（直接用剩余容量的缓冲，内核只复制已打开的
描述符，不先问大小），再逐个读 socket；进程身份只在出现候选之后读取。PID 开始时间、路径、socket opaque
identity/generation 及 fd 在候选发布前再次核验：身份在核验前后各读一次，必须一致。
这些是官方 SDK 中标记为 private、可能变化的接口，不宣称为 Apple 永久稳定承诺。
权限依据为 [XNU proc_info.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c)，
端点/opaque socket identity 依据为
[XNU socket_info.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/socket_info.c)。

Safari/WebKit 等程序的 Network.framework 用户态连接不一定存在 BSD socket FD。
每批先由 `native/socket_scan.c` 扫描 BSD 描述符；只有未找到匹配描述符的流才由
`native/userland_flow_scan.c` 通过只读 `net.inet.tcp.pcblist_n` / `net.inet.udp.pcblist_n`
查询内核导出的 nstat 用户态连接。两路共用 `native/flow_shared.c` 的校验、计时与取消辅助，
Rust 负责按剩余预算编排和解析候选，不混入 TUN 控制或 UI 状态。
用户态记录使用原始双端点及 owner/effective PID，后者是系统记录的委托应用身份。
例如 WebKit.Networking 替 Safari 发起连接时，使用系统给出的 Safari PID 和实际路径，
不按共享进程名或父进程猜测。只采纳没有 BSD socket/PCB identity 的用户态记录，普通
BSD socket 仍经过 FD/shared/reuse 检查；候选发布前重读快照，核对唯一五元组、两个 PID 的
UID/开始时间及应用可执行路径，委托变化或多 owner 保持未知。

该私有导出格式的依据为 Apple
[XNU in_pcblist.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcblist.c)
的 `get_pcblist_n`、[ntstat.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/ntstat.c)
的 `nstat_userland_list_snapshot`，以及
[socketvar.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/socketvar.h) /
[in_pcb.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.h) 的导出前缀。
这些前缀不在公开 SDK 中，由 `native/userland_flow_scan.c` 单独解码，检查长度、对齐、
tag 集合、结束记录和容量；截断或不兼容格式拒绝发布。每份快照最多 16 MiB，最多两次
有界读取；两路扫描共用剩余时间预算和取消信号，不新增 entitlement 或特权服务。

当前只发布调用进程 effective UID 的可见连接；普通同用户程序可以归因，其他 UID、
受 MAC/sandbox 限制、共享 FD、多 owner、UDP reuse 或不能判定的 dual-stack wildcard
均保持未知，不借助特权服务或关闭 SIP。TCP 要求原始远端和本地端点匹配；未连接 UDP
只在本地 bind 唯一且未设置 reuse 时采纳。Fake-IP 必须先按原始数值目的地址匹配，不能先
反解成真实地址。短连接关闭后无法从当前快照重建历史发送者，不把当前快照当成逐包认证身份。

缓存、请求队列、扫描 worker 与首包门控属于 Core 的共享归因模块，规则由
[Core 进程归因](../architecture/core.md#进程归因)维护；macOS 只实现一次
批量查询：每批最多 256 查询（按协议与端口排序去重，逐个描述符二分查找是否被查询），BSD 描述符扫描枚举
最多 4096 PID、65536 FD，每路扫描最多 2048 候选（候选缓冲由扫描线程跨批复用），两种数据源和身份复核共同
受 100 ms 扫描预算约束并支持取消。
PCB 快照导出的是 nstat TCP/UDP userland provider，不包含独立的 QUIC userland provider；
浏览器 HTTP/3 连接因此仍可能未知，不能从同时存在的 Safari TCP 连接推断 UDP 归属。
UDP 同端点在正缓存窗口内换 owner 可能短暂陈旧，故不能把进程规则当作安全认证。
BSD 描述符扫描中，未匹配对象自然消失只计入诊断；已匹配候选身份变化、权限、截断或超时
使整批归因保持未知。存在匹配但共享、reuse 或其他歧义的描述符时，不转用用户态快照绕过限制。
用户态快照逐行核验，其他 UID、消失或复用的 PID、委托变化和多 owner 只丢弃对应行；
读取、格式、容量、超时或取消使整路用户态观察不可用，但保留已确认的 BSD socket 身份，
其余流保持未知。整路不完整的摘要以 10 秒一次的速率记录。归因不改变 utun 上的报文。

Core 负责 TCP/UDP 规则和遥测，显示层只消费真实 `identifier + executable path`。
`app_identity.rs`（objc2 调用 Foundation 与 AppKit）使用实际路径的外层 `.app`、`NSBundle executableURL`、
`NSFileManager displayNameAtPath:` 与 `NSWorkspace iconForFile:` 解析本地化名称和 32 像素 PNG 图标；独立
命令行程序使用文件名/文件图标。
无效路径保持未解析，仅缺失路径且给出真实已安装 bundle ID 时才执行 bundle 查询。
浏览器嵌套 helper 可展示外层 bundle；脱离该 bundle 的共享网络进程只有取得系统委托身份
时才能展示调用应用，没有委托证据时不猜测。
前端缓存、分组和去重均以 identifier/path 对为身份，避免两个同名程序串图；缓存/待查分别
最多 512 项，每次查询最多 64 项。归因数据不由 UI 创建或反向影响平台生命周期。

## 产品身份、签名与服务安装

| 项目 | 值 |
| --- | --- |
| 主应用名称与 bundle ID | `Egrio`、`com.xinvexo.egrio` |
| 服务 launchd 标签 | `com.xinvexo.egrio.service` |
| 服务可执行文件 | `Egrio.app/Contents/MacOS/egrio-service`，随应用签名 |
| launchd 属性列表 | `Egrio.app/Contents/Library/LaunchDaemons/com.xinvexo.egrio.service.plist`（`desktop/egrio/macos/`） |
| 控制 socket | `/var/run/com.xinvexo.egrio.service.sock` |
| 签名身份与团队 | 默认 `Developer ID Application`，`--identity` 可指定本地证书；团队取自签名信息 |
| 最低系统 | macOS 13（SMAppService 需要 13 以上） |
| Info.plist | `desktop/egrio/macos/Info.plist`，含受保护文件夹的用途说明 |
| 许可证文本 | 根目录 `LICENSE` 原样复制到 `Egrio.app/Contents/Resources/LICENSE` |

应用包由 `cargo xtask package` 生成（`xtask/src/macos.rs`）：以 `MACOSX_DEPLOYMENT_TARGET=13.0` 编出应用与
服务，按上表组装 `Egrio.app`（可执行文件 `Contents/MacOS/egrio`，Info.plist 取自
`desktop/egrio/macos/Info.plist` 并填入版本，`LSMinimumSystemVersion` 为 13.0，`LSUIElement` 让应用启动时
不进 Dock、开窗口时才进；图标 `Contents/Resources/icon.icns`）；许可证在签名前随应用组装，DMG 通过应用包携带它。
先签服务、再签应用，都带 hardened runtime 与
安全时间戳，默认身份是 Developer ID Application；随后检查签名（`codesign --verify --deep --strict`）、服务与应用
同一团队、属性列表可读、服务能运行，再把应用与指向“应用程序”的链接放进 UDZO 格式的 DMG 并签名、
`hdiutil verify`。指定公证的钥匙串配置（`xcrun notarytool store-credentials` 存下的）时，应用先经 zip 送交公证、
只有 Accepted 才继续，钉上票据后再做 DMG，DMG 同样公证并钉上票据，最后以 `spctl --assess` 检查（Apple
“Customizing the notarization workflow”：公证服务为送交的文件及其中每一项生成票据，zip 不能钉，应用与磁盘
映像能钉）。应用不带任何 entitlement，因而不需要描述文件。属性列表以 `BundleProgram` 指向包内的服务、以
`run-macos-service` 启动，`RunAtLoad` 与 `KeepAlive` 让 launchd 在加载时启动并在退出后重启（
`ThrottleInterval` 2 秒），`AssociatedBundleIdentifiers` 让“登录项”把它记在 Egrio 名下，标准错误写入
`/var/log/egrio-service.log`。属性列表的标签、程序与命令和 Rust 常量（`service_layout.rs`）一致，由
`cargo xtask check` 的合约检查（`xtask/src/contracts.rs`）检查；签名包里服务与应用同一 Team ID 由打包时的检查保证。为另一架构
打包（Apple 芯片上 `cargo xtask package --target x86_64-apple-darwin`，先 `rustup target add x86_64-apple-darwin`）时，
应用与服务以同一目标交叉编译；打包时运行一次服务做检查，Intel 的服务在 Apple 芯片上经 Rosetta 运行（没装时
`softwareupdate --install-rosetta --agree-to-license`）。发布的两个 DMG 都在 GitHub 的 Apple 芯片机器上构建（见
[发布](../runbooks/release.md)）。[更新](../architecture/desktop.md#更新)
下载的 DMG 经 `NSWorkspace` 的 `openURL:` 交给 Finder 挂载，用户把新版拖进“应用程序”替换旧版。

配置可以指向用户放在“文稿”“桌面”“下载”里的文件（OpenVPN 节点的 `.ovpn`）。应用第一次读这些文件夹里的
文件时，系统先弹窗征求用户同意并记住回答；弹窗里的用途说明取自 Info.plist 的
`NSDocumentsFolderUsageDescription`、`NSDesktopFolderUsageDescription` 与 `NSDownloadsFolderUsageDescription`
（Apple Bundle Resources 的 Information Property List 文档，macOS 10.15 起）。用户回答前读取的 `open(2)` 一直阻塞，
锁屏时则等到解锁，所以这类读取不在启动或界面投影路径上，只在建立 OpenVPN 会话时进行（见
[Core 架构](../architecture/core.md) 的 `protocols/openvpn/`）。用户拒绝后读取得到 `EPERM`，可在“系统设置 >
隐私与安全性 > 文件与文件夹”中改回；`tccutil reset SystemPolicyDocumentsFolder com.xinvexo.egrio` 清除记住的
回答，桌面与下载对应 `SystemPolicyDesktopFolder`、`SystemPolicyDownloadsFolder`。

开启 TUN 前桌面检查环境（`desktop/egrio-desktop/src/tun_environment.rs`）：服务以本应用的协议完成握手即就绪，不论
它怎样启动；否则经 SMAppService 注册（ServiceManagement `SMAppService.h`，
`daemonServiceWithPlistName:`、`registerAndReturnError:`），状态已是 enabled 也再注册一次。注册后系统要求用户在
“系统设置 > 通用 > 登录项与扩展”中允许，桌面打开该页（`openSystemSettingsLoginItems`），消息里记一条“TUN 模式需要
批准”，允许后再次开启 TUN。注册状态不保证服务已经响应，环境检查仍以协议握手为准；服务不可达时再次注册。头文件说已注册的服务再注册返回 `kSMErrorAlreadyRegistered`，
注册报错而状态不是未登记时都当作已登记，照常等服务应答。
应用更新替换了包，launchd 却仍运行着旧服务：它在下一个连接到来时发现自己的可执行文件已被
替换（文件标识不同于启动时），没有会话持有隧道就退出，launchd 随即从更新后的包里启动新服务，桌面在
8 秒内重试握手。应用可执行文件以 `EGRIO_MACOS_SERVICE=status|register|unregister`
运行时只执行这项注册操作并打印 JSON。

服务只接受两类对端：root（它本可以自己做这些改动），以及与服务同一团队签名的 Egrio 应用。内核在
`connect(2)` 时记下对端的审计令牌（`sys/un.h` `LOCAL_PEERTOKEN`），服务据此找到对端此刻运行的代码
（Security `SecCodeCopyGuestWithAttributes`、`kSecGuestAttributeAudit`）并检查代码要求
`anchor apple generic and identifier "com.xinvexo.egrio" and certificate leaf[subject.OU] = "<服务自己签名的团队>"`
（`SecCodeCheckValidity`；团队取自服务自身的签名信息 `SecCodeCopySigningInformation`）。服务未经团队签名时
只接受 root。

## 网络设置与捕获范围

接口地址、虚拟 resolver 与 MTU 只由 Rust `tun/mod.rs` 定义（`MACOS_TUN_*`），服务、Core 的捕获配置
（`macos_tun_core_capture_config()`）与 fake-IP 预留地址（`macos_tun_reserved_addresses()`）引用同一组常量：

- utun 是点对点接口：IPv4 `10.255.255.1`、对端 `10.255.255.2`（`/30`），IPv6 `fd00:6572:6769:6f00::2/64`，
  网络服务的 IPv6 路由器是 `::1`；地址、MTU 与 up 经 ifconfig(8) 设置；
- MTU 65535。服务自己创建的 utun 不开 netif 通道（`UTUN_OPT_ENABLE_NETIF` 对第三方返回 EINVAL），XNU
  `if_utun.c` 的 `SIOCSIFMTU` 只在有通道时按槽位大小限制，所以接受到 65535；内核把 20 KB 的报文整个交给读取方。
  TCP 两端协商出 MSS 65495，数据成块到达的流（如 TLS 记录）经隧道的段因此更大、包更少（见[验证状态](#验证状态)）；
- socket 的收发缓冲各 4 MiB：系统送进隧道的报文在接收缓冲里等 Core 读取，放不下的被内核丢弃（XNU
  `kern_control.c` `ctl_enqueuembuf`），超过发送缓冲的写入直接被拒；
- 内核至多在 socket 上为 Core 排 16 个待读的报文（`UTUN_OPT_MAX_PENDING_PACKETS`）。默认只有 1 个：`utun_start`
  在有一个待读时就停止从接口的发送队列取包，每个进入隧道的报文都要等 Core 读完上一个，经隧道的小包上传因此
  受限（见[验证状态](#验证状态)）；排得更深反而更慢，1024 个（接收缓冲 8 MiB）时上传减半；
- 虚拟 DNS `198.18.0.1`。

服务为每个地址族加 8 条进 utun 的接口路由，覆盖首个 /8 以外的全部地址（`1.0.0.0/8`、`2.0.0.0/7`
直到 `128.0.0.0/1`，`100::/8` 直到 `8000::/1`）。它们比物理默认路由具体、比其他任何路由宽泛：物理网络服务仍是
主服务，它的默认路由、IPv4 组播路由（`224.0.0/4`）、广播与网段内路由都留在物理接口，链路本地目的地与 IPv6
组播按接口限定作用域，都不进隧道。不用 `0.0.0.0/1` 与 `::/1`：XNU 把覆盖全零地址的最具体路由当作默认路由
（`bsd/net/route.c` 的 `node_lookup_default` 以全零地址不带掩码查找，`SA_DEFAULT` 只看地址），限定作用域的选路
最后退回默认路由时拿到隧道的这条、接口不符，于是绑定物理接口（`IP_BOUND_IF`）的 Core socket 全部
`ENETUNREACH`；留在外面的 `0.0.0.0/8` 是“本网络”，`::/8` 是未指定、回环与其他保留地址，都不是要中继的
目的地。隧道只安装捕获路由，不发布成主网络服务，物理网络服务继续提供默认出口与上行信息。

服务在一个带会话键的动态存储会话中（SCDynamicStore.h `kSCDynamicStoreUseSessionKeys`）写入
`State:/Network/Service/com.xinvexo.egrio.tun/DNS`：`ServerAddresses` 只有虚拟 DNS，`SupplementalMatchDomains`
只有一个空字符串（SCSchemaDefinitions.h `kSCPropNetDNSSupplementalMatchDomains`）。configd 由空的补充匹配域
生成一个不带域名的解析器、排在主服务的之前，并把首个不带域名的解析器导出为默认解析器（configd
`Plugins/IPMonitor/dns-configuration.c` 的 `add_supplemental_resolvers` 与 `dns_configuration_set`），
`scutil --dns` 的首个解析器因此是虚拟 DNS。没有这个 ID 的网络服务，也不发布别的实体，系统代理仍是主服务的
（见[系统代理](#系统代理)）。会话键随会话消失，服务进程即使崩溃，系统也会把解析器交回物理网络服务；正常
关闭时先删除这个键，再删除路由。

`PacketCaptureSettings.excluded_prefixes` 从进 utun 的路由中减去：含排除网段的那条逐级对半拆分到排除网段为止、
保留不含它的一半，被排除覆盖的整条不装，与 Windows 是同一种拆分（`egrio-runtime` 的 `capture_prefixes`，每个
地址族至多 4096 条，超出时开启 TUN 失败）。排除的目的地于是不匹配任何进 utun 的路由，沿用系统原有的路由：
主服务的物理默认路由、直连网段，或其他 VPN 更具体的路由，并随它们变化，服务不跟踪上行与路由器。不为排除
网段另加经物理路由器的路由：那条路由比覆盖它的其他 VPN 的更宽的路由（Tailscale 的 `100.64.0.0/10`）更具体，
会把发往那个 VPN 的流量送到物理路由器。拆出的路由可能比其他 VPN 的路由更具体，见
[TUN 排除的目的地](../architecture/profile-store.md#tun-排除的目的地)。排除集合变化时先装新路由、再删多余的，
仍被捕获的目的地任何时刻都有进 utun 的路由。路由经路由套接字（route(4)）照 route(8) 的报文写入，不为每条路由
起一个进程：`rt_msghdr` 后依次是目的地址、网关与掩码，各补齐到 4 字节，掩码截到最后一个非零字节；接口路由
不带 `RTF_GATEWAY`、以该接口的链路地址（getifaddrs(3)）为网关。每条路由在加之前记入
`/var/run/egrio-tun-routes.json`（开机清空）、删除后
从中去掉，服务启动时先删除上一个进程留下的路由。macOS 的隧道总是安装这些路由与解析器，服务拒绝不这样
要求的捕获；没有物理上行时开启 TUN 失败。

排除集合可以在隧道运行中改变（切换分流模式或 Profile 时）：Runtime reload 只改变 capture 的排除时调用
`PacketCapture::update_excluded_prefixes`，桌面以 `UpdateExcludedPrefixes` 请求把新的完整集合发给服务，隧道不重开，
路由先加后删；后续能力失败时 Runtime 再发原排除补偿。macOS 没有 kill switch，排除不需要防火墙
放行。

隧道外到 fake IP 的连接当即失败：桌面在没有 Firewall 能力时把配置的 fake-IP 池及其 IPv6 投影放进
`PacketCaptureSettings.fake_ip_prefixes`，服务在每个物理接口上为它们各加一条作用域拒绝路由（route(8) 的
`-reject -ifscope`）：`rt_msghdr` 带 `RTF_REJECT` 与 `RTF_IFSCOPE`，`rtm_index` 是接口索引，XNU `bsd/net/rtsock.c`
的 `route_output` 以它作为加删的作用域。只有限定到该接口的选路，即以 `IP_BOUND_IF` / `IPV6_BOUND_IF` 绑定它的
socket，找得到这条路由，连接随即失败（macOS 上测试 IPv4 时为 `ENOMEM`，ARP 层把以太网的接口路由设成克隆路由，
`route -n get` 显示 `REJECT`、`CLONING`；IPv6 是 `ENETUNREACH`）；未绑定的 socket 仍匹配 utun 里更具体的路由。物理接口指开着的广播链路
（Wi-Fi、以太网、网桥），不含回环与点对点接口（utun 等隧道），且每个地址族只取有链路外地址的：内核拒绝在没有该族
地址的接口上加作用域路由（`ENETUNREACH`）。会话期间服务以一个路由套接字跟随接口的开关与地址增删（route(4) 的
`RTM_IFINFO`、`RTM_NEWADDR`、`RTM_DELADDR`），按当时的接口增删这些拒绝路由；接口换了地址而路由还在时，绑定它的
连接同样立即失败（`EADDRNOTAVAIL`）。拒绝路由与进 utun 的路由记入同一个状态文件、随会话撤销；加不上时只记日志，
那个接口上的连接仍要等到超时，隧道照常运行。

Host 通过 `CoreStartInputs.capture` 显式传递 Core 的 DNS 捕获配置。macOS 选择
`UdpPortWithVirtualTcpTargets`：捕获发往任意目标 UDP/53 的 DNS，并仅在虚拟 resolver
`198.18.0.1:53` 终结 TCP DNS；其他 TCP/53 保持普通路由连接。`PacketCaptureSettings.mtu` 同时进入 Core 与服务，
服务只接受 1280..=65535。共享源分片契约见[Core 源分片](../architecture/core.md#源分片)。配置档案 `ipv6` 是
Core 的 DNS 解析策略，不改变隧道的双栈捕获范围。

TUN 运行时的防泄漏与 Windows、Linux 是同一个模型（只拦泄漏、不当 kill switch、Egrio 不在时网络回到原样），macOS
不需要防火墙层就满足：默认解析器是虚拟 DNS、任意 UDP/53 在隧道里被劫持，IPv6 与 IPv4 一样全部进 utun，浏览器的
WebRTC 只在默认路由的接口（utun）收集候选，隧道外到 fake IP 的连接由上述拒绝路由当即拒绝；其他软件特意从隧道外
发出的（绑定 `en0` 连真实地址的 socket、其他 VPN 的路由）照常通行。Tailscale 的控制连接绑定物理接口，从系统解析器
拿到 fake IP 时被拒，随即改用自己的解析途径上线（见[验证状态](#验证状态)）。会话结束时路由与解析器随之撤销
（见[恢复](#恢复)）。

## 系统代理

`MacosSystemProxyAdapter` 以 `networksetup` 逐 Network Service 写入 HTTP/HTTPS/SOCKS 与 bypass。
checkpoint schema 2 保存基线与本次 Core listener；restore 逐 Network Service、逐
HTTP/HTTPS/SOCKS/bypass 项只恢复仍由 Egrio listener 持有的设置，外部接管的项和 checkpoint 之后新增的
service 保持不动。同进程 apply 半途失败时 `apply_incomplete` 允许清理基线与期望值混合的状态，进程
重启恢复仍要求精确的期望值。最终验证条件是没有 Egrio 持有的残留，而不是把整包系统代理强制写回；
其他 schema 的检查点在触碰系统设置前被拒绝。隧道运行时物理网络服务仍是主服务，这些代理照常生效，两层可以
任意组合。

## 服务协议与 utun 交接

桌面经控制 socket 与服务通信（`egrio-service` 的 `unix` 传输与协议，Linux 助手同用）：每个连接是一个桌面
会话，按[产品身份、签名与服务安装](#产品身份签名与服务安装)授权。macOS 会话只提供 PacketCapture：
`Prepare` 返回 checkpoint，`OpenPacketCapture` 打开隧道，`Observe`、`Restore`，以及打开期间的
`UpdateExcludedPrefixes`。隧道是整机的（一组路由、一个默认解析器），同一时刻只有一个会话
持有；会话的连接结束即关闭它。只做存活检查的连接（连上即断，还来不及读对端身份）被安静地忽略。

`OpenPacketCapture` 的应答是 `PacketChannel::Utun`（接口名、索引与 MTU），utun socket 的一个描述符以
SCM_RIGHTS 附在该应答帧的头几个字节上（unix(4)）；桌面的读取方收下描述符，`open` 取走它交给
`MacosTunDevice`。服务保留自己的描述符直到会话结束，utun 在两端的描述符都关闭后消失。每次读写一个报文，前缀为网络字节序的
协议族（服务不设 `UTUN_FLAGS_ENABLE_PROC_UUID`，设备仍会识别 16 字节 UUID 头）；写入因内核没有空间被拒
（ENOSPC、ENOBUFS）时 Core 不丢弃报文，1 ms 后重写，期间 TCP 引擎的发送被挡住。

## 出口环路隔离

`MacosEgressInterfaceBinder` 跟随物理接口与其默认路由，并作为 Core 的
`EgressSocketGuard` 注入 TCP、UDP、DNS 和代理传输。Core 跨越多个 TUN 会话：只在隧道打开期间绑定，仅系统
代理时不绑定，避免绕过用户的其他 VPN。桌面在请求服务打开隧道之前激活 `MacosTunEgress`（连同捕获前的系统
resolver 快照），因此绑定先于隧道的路由生效；打开失败或恢复后撤销。XNU 按目的地址为未绑定 socket 选路，下一条
隧道会回捕它们，因此绑定器记录隧道关闭时未绑定的非回环拨号（`take_unbound`）；TUN 在运行中的 Core 上打开时，
有此类拨号宿主才切断全部 Core 连接，listener、DNS 与 fake-IP 池保留。IPv4 使用 `IP_BOUND_IF`，IPv6 使用
`IPV6_BOUND_IF`；回环连接保留回环语义。

出口接口按系统的偏好顺序选择，也就是网络服务顺序。Network.framework 的路径监视器
（`native/path_monitor.c`；SDK 头文件 `Network/path_monitor.h`，`nw_path_enumerate_interfaces` 按偏好
顺序列出接口）在启动时和每次路径变化时给出 Wi-Fi、有线与蜂窝接口的顺序，utun（本隧道或其他 VPN）
等虚拟接口与回环不在其中；每个地址族取顺序中第一个有 `route -n get -ifscope` 物理默认路由的接口。
隧道进 utun 的路由比物理默认路由具体，未限定作用域的选路会进 utun，所以只读限定作用域的默认路由。这一结果只在路径变化时重新推导，
拨号只读取它；某族没有路由的拨号最多每秒重新推导一次（链路宣告后路由可能稍后才装好），仍没有时拒绝
该拨号，不退回未绑定 socket，也不保留旧选择（被移除接口的索引可能被复用）。该机制绕开自身 TUN，不依赖
来源应用签名或其他 VPN 的豁免前缀。服务开启 TUN 时也用它确认有物理默认路由。

同一次推导用 getifaddrs 读取这些接口的非链路本地地址，连同各族上行作为 `EgressNetwork` 发给 Core；
网络变化时 Core 结束被搁浅的连接，Hysteria2 的载体迁到当前上行，见
[Core 模块布局](../architecture/core.md#模块布局)的 `egress/network.rs`。系统代理模式下 socket 不绑定，
本地地址消失的连接同样结束。

绑定器替 Core 发 ICMP echo（`EgressSocketGuard::echo`）：从 ping socket（ICMP 数据报 socket，任何用户可开）
发出，与其他出口 socket 一样先绑定物理上行；IPv4 的应答连 IP 头一起交上来。实现在共享的
`egrio_platform::ping_socket_echo`。

TUN 激活时，Core 出口 DNS 取 `scutil --dns` 的系统 resolver 快照；运行中网络变化时改取新上行接口的
scoped resolver（隧道运行时系统的全局 resolver 是隧道自己的），它们没有时退回快照的选择，读取失败时
保留原来的解析器。两者都过滤虚拟 DNS 与回环 stub，不在捕获后的系统 DNS 上重新解析代理服务器导致
递归。没有活动 Core 时的独立节点探测由 `MacosPhysicalEgress::capture` 产生同样的快照与一个始终绑定的物理
socket guard。平台只提供物理输入，TCP 探测与代次取消契约由 [Core 数据面](../architecture/core.md#模块布局)维护。

## 恢复

捕获 `prepare` 由服务返回 PacketCapture checkpoint，`open` 打开隧道，Runtime 再驱动 device；正常停止先取消并
join packet pump，包泵结束前把经隧道的 TCP 连接向本机程序复位（见[捕获 TCP](../architecture/core.md#捕获-tcp)），
程序随即改走物理网络，再以 `Restore` 关闭隧道（撤销解析器、删除路由）。桌面进程崩溃时连接结束，服务关闭
该会话的隧道；utun 随最后一个描述符关闭而消失，内核随之删除经它的路由。服务崩溃或被强杀时会话键随进程
消失，系统把解析器交回物理网络服务；桌面在会话丢失后关闭自己的 utun 描述符，经 utun 的路由随接口消失，
其余路由由下一个服务进程启动时删除。桌面这一侧连接中断，Runtime 记为平台会话丢失；
桌面按[会话丢失恢复](../architecture/runtime.md#捕获层切换)通知中断，并重新打开隧道恢复 TUN（launchd 在 2 秒内
重启服务），系统代理与 Core 保持服务。早于当前服务进程的 checkpoint 恢复时无事可做。隧道不在时流量按物理
路由直连，macOS 没有 kill switch。应用崩溃后网络服务上的系统代理仍指向已停止的 listener，直到下一次启动
恢复。验收步骤见[macOS TUN 验收](../runbooks/macos-tun.md)。

## SDK 与验证依据

utun 依据 SDK 的 `net/if_utun.h`（`UTUN_CONTROL_NAME`、`UTUN_OPT_IFNAME`、`UTUN_OPT_FLAGS`、
`UTUN_OPT_ENABLE_NETIF`、`UTUN_OPT_MAX_PENDING_PACKETS`）、`sys/kern_control.h`（`CTLIOCGINFO`、`sockaddr_ctl`）与 `sys/sys_domain.h`
（`SYSPROTO_CONTROL`），报文头依据 Apple 开源 XNU `bsd/net/if_utun.c` 的 `UTUN_HEADER_SIZE`，MTU 上限依据同一
文件的 `SIOCSIFMTU`，待读报文数的默认值与发送队列的停顿依据同一文件的 `utun_ctl_bind`、`utun_start` 与
`utun_ctl_rcvd`，接收缓冲满时丢弃依据 `bsd/kern/kern_control.c` 的 `ctl_enqueuembuf`。默认解析器依据
SystemConfiguration 的 `SCDynamicStore.h`（`SCDynamicStoreCreateWithOptions`、`kSCDynamicStoreUseSessionKeys`、
`SCDynamicStoreSetMultiple`）、`SCSchemaDefinitions.h`（`ServerAddresses`、`SupplementalMatchDomains`）与 Apple
开源 configd 的 `Plugins/IPMonitor/dns-configuration.c`，结果以 `scutil --dns` 实测；路由报文依据 SDK 的
`net/route.h`、`net/if_dl.h` 与 Apple 开源 network_cmds 的 `route.tproj/route.c`（`rtmsg`、`ROUNDUP`、`mask_addr`、
`getaddr`），以 `route -n get` 与 `netstat -rn` 实测；作用域拒绝路由另依据 XNU `bsd/net/rtsock.c` 的
`route_output`（带 `RTF_IFSCOPE` 时以 `rtm_index` 为作用域），接口变化依据 route(4) 的 `RTM_IFINFO`、`RTM_NEWADDR`
与 `RTM_DELADDR`，拒绝的效果以绑定接口的 connect 实测。服务注册依据 ServiceManagement 的 `SMAppService.h`，
对端校验依据 `sys/un.h`（`LOCAL_PEERTOKEN`、`LOCAL_PEERPID`）、getpeereid(3) 与 Security 的 `SecCode.h`、
`SecRequirement.h`，描述符传递依据 unix(4) 与 `sys/socket.h`（`SCM_RIGHTS`）。路由与 resolver 的只读探测
以系统 `route(8)`、`ifconfig(8)`、`getifaddrs(3)` 和 `scutil(8)` 为依据，接口的偏好顺序与变化通知以
SDK 的 `Network/path_monitor.h`、`Network/path.h` 与 `Network/interface.h` 为依据，socket 绑定选项依据
`netinet/in.h` / `netinet6/in6.h`。

桌面应用的界面（见[桌面宿主](../architecture/desktop.md)）经 `objc2-app-kit` 调用 AppKit，依据 AppKit 文档与 SDK
头文件：主窗口是 `NSSplitViewController` 的两个普通分栏项（侧栏与页面）。侧栏项的
`minimumThickness` 与 `maximumThickness` 都是 180 pt；分栏控制器是 egrio 的子类，先调用父类（`NSSplitViewController.h`
标为 `NS_REQUIRES_SUPER`）再让 `splitView:effectiveRect:forDrawnRect:ofDividerAtIndex:` 与
`splitView:additionalEffectiveRectOfDividerAtIndex:` 返回空矩形：`NSSplitView.h` 说前者是点按开始拖动分隔线的区域，
分隔线因此不能拖动。整个窗口一层
半透明背景：每栏是 `underWindowBackground` 材质、`BehindWindow` 混合、始终 `Active` 的 `NSVisualEffectView`，上面
铺一层浅色（浅色外观 rgba(250,250,253,0.48)，深色 rgba(28,28,30,0.56)）；分栏视图的 `dividerThickness` 为 0，
标题栏透明（`titlebarAppearsTransparent`）、无分隔线（`NSTitlebarSeparatorStyleNone`），背景一直铺到工具栏下面。
工具栏是紧凑样式（`NSWindowToolbarStyleUnifiedCompact`），控件用小尺寸，依次是流量模式、系统代理与 TUN 模式；
窗口标题隐藏，没有页面标题（窗口标题仍随页面改，窗口菜单与调度中心显示它）。`setContentViewController:` 按视图
重算窗口尺寸，之后才设默认尺寸并恢复自动保存的框架；页面项的 `minimumThickness` 是界面层给出的页面最小宽度。
页面内容距页面栏的上、下边缘 10 pt，左边 20 pt；右边取工具栏最后一项（TUN 模式）离窗口右边的距离，在窗口显示前
布局一次后量出（AppKit 自己摆工具栏项，macOS 26 起每项下面的玻璃底板就是项的框），两者的右边因此对齐，量不出时
用 10 pt。消息胶囊是标题栏视图（关闭按钮的 `superview`）里的子视图，左边与页面对齐（页面栏左边 20 pt）、在标题栏
留出的那一条里垂直居中，不放进工具栏：macOS 26 起相邻的自定义工具栏项共用一层玻璃背景，没有 API 把它们分开，
胶囊放进工具栏就和开关连成一片。胶囊最宽到工具栏第一项（流量模式）前 16 pt，窗口改变大小时（`windowDidResize:`）
重算；悬停用跟踪区域；
它自己接住按下、`mouseDownCanMoveWindow` 返回 NO，否则标题栏把按下当作拖动窗口的开始而收走松开，
`acceptsFirstMouse:` 让非活动窗口的第一次点按也打开面板。铃铛是 SF Symbols 的 `bell` 模板图，由图像视图的
`contentTintColor` 着色，颜色随外观变化。胶囊的底面就是消息面板：它在窗口的内容视图里、分栏视图之上、透明的
标题栏下面，胶囊的内容从标题栏视图画在它上面；不放在页面栏里，分栏项的包装视图会把它裁在页面栏里，阴影到页面栏
左边就断了。底面是 `Popover` 材质的 `NSVisualEffectView`，经 `maskImage` 做圆角；材质之上、消息之下
有两层着色，平时那层在浅色外观里是 7% 的黑、深色外观里是 14% 的白（`colorWithName:dynamicProvider:` 按外观
取值，深色的 Popover 材质比窗口暗），有未读时那层是级别色的 14%。阴影画在底面后面一个同形状的 `NSBox` 上，只随
它的透明度出现。底面与胶囊同顶、同左、同宽，高度平时等于胶囊，打开后等于消息视图；两者之间的变化由一个常量
高度约束承担，常量经约束的 `animator` 变化，窗口逐帧重新布局，底面、材质、遮罩、着色与消息每一帧都一致。切换
约束后在 `allowsImplicitAnimation` 下 `layoutSubtreeIfNeeded` 的隐式帧动画不行：视效视图的子层与盒子的内容不跟随
动画中的边界。消息视图始终按打开时的宽度排版、贴着底面的顶，底面经 `clipsToBounds` 裁去它，打开前量到的就是
最终高度。宽度、高度、着色、阴影与消息的透明度在同一个 `NSAnimationContext` 组里变化，0.25 秒，缓出
（`kCAMediaTimingFunctionEaseOut`）。消息视图的高度只有上限（480 pt 与离页面栏底边 10 pt）：滚动区以低于栈视图
收紧的优先级（290）让自己的高度等于文档视图的高度，面板因此和消息一样高，到上限后滚动。
页面由 `NSStackView` 排布；表格是视图型 `NSTableView`，经 `tableView:viewForTableColumn:row:` 只为可见行
建视图，单元格视图按形状设标识，经 `makeViewWithIdentifier:owner:` 复用滚出视野的视图。带标记的单元格（规则的
内容与它的条目数、no-resolve）是横向的栈视图，铺满这一列，内容在前导重力区、标记在尾随重力区
（`addView:inGravity:`），标记因此排在列的右边，内容放不下时省略。原生行视图按显示位置复用：数据源先换成
新快照，行数变化时用 `noteNumberOfRowsChanged` 从末尾增减位置；经 `enumerateAvailableRowViewsUsingBlock:`
枚举列表持有的行，用 `viewAtColumn:row:makeIfNecessary:` 原地更新新旧位置上不同的单元格，形状变了的才用
`reloadDataForRowIndexes:columnIndexes:` 重载。选择随后按行键对回，排序、插入与移除都不让选择跟着位置变成别的行。
依据 SDK 的 `NSTableView.h`：行数通知只从末尾增减行，枚举包含可见及列表额外持有的行；`NSAnimationContext.h`
的零时长上下文使这次更新立即完成。文字折行的
表格（日志页）由 `tableView:heightOfRow:` 给出行高：按列宽用一个离屏文本框的 `cellSizeForBounds:` 量出每行最长
文字的高度并按行缓存；这个回调里不能向表格取几何信息，列宽在 `tableViewColumnDidResize:` 时取，随后
`noteHeightOfRowsWithIndexesChanged:` 让表格重新取所有行高。节点页的磁贴栅格是 `NSCollectionView`，布局是
`NSCollectionViewGridLayout`：`minimumItemSize` 是磁贴的最小宽度与高度，`maximumItemSize` 只限高度，一行放得下
几块就放几块，再均分行宽（文档只说两者是尺寸的上下限，均分为实测）。磁贴项的类经
`registerClass:forItemWithIdentifier:` 登记，`makeItemWithIdentifier:forIndexPath:` 复用滚出视野的项或以 `init`
新建，项在 `loadView` 里用代码建视图（`NSCollectionViewItem` 文档的做法）；变化的磁贴经 `itemAtIndexPath:` 取集合
视图持有的项原地更新，没有项时它返回 nil，那块出现时由数据源填写，磁贴增删时 `reloadData`。磁贴视图的
`hitTest:` 把内部的点击都交给自己，在 `mouseDown:`、`mouseDragged:` 与 `mouseUp:` 里按按钮的方式判断按下与
松开；悬停用 `NSTrackingAreaInVisibleRect` 的跟踪区域，SDK 头文件里它的 `owner` 是 weak，不与视图成环；辅助功能
角色是按钮，`accessibilityPerformPress` 与点按相同。可测的磁贴把延迟放进一个子视图做的测速按钮：磁贴的
`hitTest:` 把落在它里面的点击交给它，它有自己的悬停与按下高亮和提示，辅助功能角色也是按钮；选中的磁贴边框
用强调色、宽 2 pt，栅格要对勾时标题后有 `checkmark` 符号。控件的提示不用 `toolTip`：AppKit 的提示在指针停下约两秒后
才出现第一个，延迟没有 API。带提示的控件加一个跟踪区域（`NSTrackingMouseEnteredAndExited`、
`NSTrackingActiveInActiveApp`、`NSTrackingInVisibleRect`），区域的 owner 作为控件的关联对象
（`objc_setAssociatedObject`，`objc/runtime.h`）随控件存亡；指针停 0.5 秒后，提示在指针下方的一个无边框、
不激活、忽略鼠标的 `NSPanel` 里出现（`NSPopUpMenuWindowLevel`；材质 `NSVisualEffectMaterialToolTip`，macOS 10.14
起；字体 `toolTipsFontOfSize:`），从一个提示移到下一个控件时立即出现。指针离开、点击、按键、滚动（本地事件监视器）、
控件不在指针下或应用不再活跃时收起。圆角材质放在普通的内容视图里：内容视图自己的 `maskImage` 会成为窗口的
圆角遮罩，macOS 13.6 上这个面板因此在 `_NSSetWindowCornerMask` 断言失败。提示文字同时是控件的
`accessibilityHelp`，VoiceOver 照常读出；截断文字的展开提示（`allowsExpansionToolTips`）仍由系统显示。
规则表的行可以拖动重排：数据源的 `tableView:pasteboardWriterForRow:` 给每行一个带键的
`NSPasteboardItem`（返回 nil 的行不能拖），`tableView:draggingSession:willBeginAtPoint:forRowIndexes:` 记下拖动
的行，`tableView:validateDrop:proposedRow:proposedDropOperation:` 只接受同一表格的拖动，并经
`setDropRow:dropOperation:` 把落点改到两行之间（`NSTableViewDropAbove`），`tableView:acceptDrop:row:dropOperation:`
把行与落点交给界面；表格经 `registerForDraggedTypes:` 登记行的类型，落点显示为空隙
（`NSTableViewDraggingDestinationFeedbackStyleGap`），本应用内的拖动只做移动
（`setDraggingSourceOperationMask:forLocal:`）。弹出面板是 `NSPopover`：行为是 `NSPopoverBehaviorTransient`（用户在
面板外操作或按 Esc 时由系统关闭），内容是一个视图控制器的视图，打开时与内容变化后按内容的 `fittingSize` 设
`contentSize`，打开后第一个可编辑的文本框成为第一响应者。忙碌的按钮保持尺寸：图标换成同一符号经
`configurationWithPaletteColors:`（macOS 12 起）画成透明的版本，进度环转在 `imageRectForBounds:` 的位置；没有
图标的按钮把标题画成透明，进度环在中间。滚动区的
文档视图翻转（`isFlipped`），内容不足一屏时停在顶部。流量曲线在 `drawRect:` 里先 `NSBezierPath clipRect:`，因为 macOS 14 起视图默认
不裁剪子绘制。消息面板打开期间有两个本地事件监视器（`addLocalMonitorForEventsMatchingMask:handler:`）：一个接住
主窗口里的 Esc（`kVK_Escape`，HIToolbox 的 `Events.h`）并收起面板，第一响应者是 `NSTextView` 时不拦截，Esc 留给
文本与输入法；另一个看主窗口里左键与右键的按下，落在窗口的 `contentLayoutRect`（标题栏与工具栏以外的内容区）
里、面板以外时收起面板，事件照常送达；胶囊在标题栏里，它的点按由它自己开关面板。面板打开时第一响应者若在页面
里，窗口经 `makeFirstResponder:`（nil）收回键盘：页面的控件不在面板下接收按键，AppKit 也不把它的焦点环画在
面板上。
文本框是可编辑的 `NSTextField`：`controlTextDidChange:` 报告每次修改，界面状态与上次报告的值相同
时不写回，输入法的标记文本因此不被替换。搜索框是 `NSSearchField`，编辑同样经 `controlTextDidChange:` 报告；
清除按钮与 Esc 清空字段时不经编辑，由字段的动作报告（`sendsWholeSearchString` 为 NO 时每次修改都发送动作，
重复的值不再报告）。搜索框平时 240 pt 宽，所在的行放不下时最窄缩到 140 pt。原地改名的文字是无边框的可编辑 `NSTextField`，
`control:textView:doCommandBySelector:` 把 `insertNewline:` 当作提交、把 `cancelOperation:` 当作放弃，
`controlTextDidEndEditing:` 时提交改动。对话框是 `beginSheet:completionHandler:` 挂在主窗口上的 sheet，内容是
组件树；默认按钮的 `keyEquivalent` 是回车，取消按钮是 Esc。选文件用 `NSOpenPanel` 的
`beginSheetModalForWindow:completionHandler:`，类型按扩展名经 UniformTypeIdentifiers 的
`typeWithFilenameExtension:` 设到 `allowedContentTypes`。开关是 `NSSwitch`（macOS 10.15 起），单选是
`NSButtonTypeRadio` 的按钮，下拉选择是 `NSPopUpButton`；设置的分组是卡片上竖排的行，行间
是 `NSBox` 的分隔线，组里第一行不画。每次用户事件处理并重绘之后，后端把开关、分段选择与下拉选择的状态
（以及单选按钮的）重新设成界面给的值。托盘菜单的测速项与成员是自定义视图的菜单项，依据 Apple 的
[Views in Menu Items](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MenuList/Articles/ViewsInMenuItems.html)：
一行是一个视图，自己画勾选、标题（放不下时以省略号结尾）与延迟三段文字和高亮（指针下或 `enclosingMenuItem` 的
`isHighlighted` 时填强调色、文字用 `selectedMenuItemTextColor`，键盘移动高亮时文字同样变色），鼠标事件照常
收到；选成员时对所在的菜单调 `cancelTracking` 关闭菜单，测速项不调，菜单保持展开。策略组的行只在它的子菜单
显示期间存在：子菜单的委托在 `menuNeedsUpdate:` 里做出这些行——AppKit 在菜单将要显示时调用它，委托可以在其中
增删菜单项（[NSMenuDelegate](https://developer.apple.com/documentation/appkit/nsmenudelegate) 的
`menuNeedsUpdate(_:)`）——并在 `menuDidClose:` 返回之后放掉（`NSMenu.h`：这两个回调里不得改动菜单的结构与菜单项）；
子菜单开着时来的更新原地改这些行。按需建立并及时释放成员行，避免大型配置在打开顶层菜单时构造全部子菜单。
菜单关掉自动启用（`autoenablesItems` 为 NO），启用状态由界面给。菜单栏的雪花按 22 pt 显示，使用两倍像素的
`tray-macos-on.png` 与 `tray-macos-off.png`；两者都是黑色模板图（`NSImage.setTemplate(true)`），由 AppKit 按菜单栏的
外观着色，未捕获时那张是同一雪花的 42% 不透明度，图稿见[图标](../../design/icons/README.md)。图标只在捕获层
开关状态变化时换一次，关窗后没有周期重绘：按钮换图时，AppKit 也更新其余显示器菜单栏的状态项副本。
图像与按钮的依据为 SDK 的 `NSImage.h`（`template` 属性）与
`NSStatusItem.h`（`button`）。主题经 `NSApplication` 的 `appearance` 设为 `NSAppearanceNameAqua`、
`NSAppearanceNameDarkAqua` 或跟随系统（`nil`）；菜单栏的菜单按界面文本重建，切换语言时随之更新。退出时应用
委托的 `applicationShouldTerminate:` 先答 `NSTerminateLater`，退出清理完成后
`replyToApplicationShouldTerminate:`；主窗口或编辑器窗口存在时激活策略为 Regular，两者都关闭后为 Accessory。
实测（macOS 27.2 与 13.6）任何窗口挂着 sheet 时 `terminate:` 什么也不做，也不调用
`applicationShouldTerminate:`，⌘Q 与托盘的退出都一样，所以编辑器窗口不用 sheet 锁主窗口；托盘的退出在清理
完成后先结束打开的对话框再 `terminate:`，对话框开着时 ⌘Q 不起作用，同其他应用的 sheet。

编辑器窗口是独立的 `NSWindow`：`setFrameUsingName:` 取回上次的尺寸后居中在主窗口上，并限制在主窗口所在屏幕的
`visibleFrame` 里，关闭时清掉自动保存名，留给下一个编辑器窗口；`setDocumentEdited:` 在关闭按钮上标记未保存，
`windowShouldClose:` 只把关闭请求交给界面。文件菜单的保存（⌘S）与还原是标准的 `saveDocument:` 与
`revertDocumentToSaved:`，经响应链到达编辑器窗口的委托，由它的 `validateMenuItem:` 按界面的状态启用；关闭
（⌘W）也在文件菜单。纯文本框是 `scrollableTextView` 里的 `NSTextView`：不是富文本，关掉智能引号与破折号、
文本替换、拼写纠正、拼写与语法检查、链接与数据检测、智能插入删除和自动补全，开着查找栏与撤销；
`textDidChange:` 报告每次修改，界面的文本与上次报告的不同时才 `setString:`，同时清空撤销记录。“定位”用
`setSelectedRange:`、`scrollRangeToVisible:` 与 `showFindIndicatorForRange:`。输入法：在编辑器与搜索框里组字
（经 `setMarkedText:selectedRange:replacementRange:`）时修改照常报告，重绘不写回，标记文本保留。

## 代码结构

`egrio-platform-macos`：

- `tun/` — TUN。服务一侧：`interface.rs` 创建 utun 并配置地址与 MTU，`routes.rs` 维护进 utun 的路由（减去
  排除网段，`route_socket.rs` 经路由套接字写入），
  `resolver.rs` 发布默认解析器，`session.rs` 的 `MacosTunSession` 把三者组成一个会话；桌面一侧：
  `device.rs` 的 `MacosTunDevice` 与 `utun_io.rs` 在交来的 utun 上读写报文；`mod.rs` 是地址、MTU 与 Core 捕获
  配置的常量；
- `service_layout.rs` — 服务的 launchd 标签、属性列表、包内程序、控制 socket 与应用标识；
- `egress_binding.rs`、`egress.rs`、`dns_snapshot.rs` — 物理上行与 Core socket 的双栈接口绑定、发给
  Core 的物理网络、捕获前与随上行变化的 resolver 选择，以及 Core 出口 DNS 配置；
- `network_monitor.rs` 与 `native/path_monitor.c` — Network.framework 路径监视器，按系统偏好顺序报告物理
  接口并在路径变化时回调；
- `runtime_system_proxy.rs`、`system_proxy.rs` — `networksetup` 系统代理能力；
- `process_attribution/` — libproc 与用户态连接扫描（`native/`），实现 `MacosFlowScanner`；
- `app_identity.rs` — 经 Foundation/AppKit 解析显示名称与图标，结果按身份/路径对缓存（256 项，解析成功
  5 分钟、未解析 30 秒）；
- `background_activity.rs` — 平衡的 `NSProcessInfo beginActivityWithOptions:reason:`
  （`NSActivityUserInitiatedAllowingIdleSystemSleep`）：捕获启动前取得、完整停止成功后释放，Degraded 状态
  保留供恢复；不等于登录项或禁止系统休眠。

`egrio-service` 的 `macos/`：`host.rs` 是 launchd 运行的服务进程，`identity.rs` 的 `SignedPeers` 校验对端签名，
`capabilities.rs` 的 `MacosServiceHandler` 处理会话请求，`channel.rs` 是桌面一侧的绑定与 utun 交接；
`unix/` 是与 Linux 共用的 socket 传输与描述符传递。`egrio-sdk` 的 `macos_service` 把它们装进 Runtime，
`egrio-daemon` 的 `privileged_service/macos.rs` 负责 SMAppService 注册。

`desktop/egrio` 的 `macos/`（桌面应用的界面）：`mod.rs` 把界面运行时放在主线程并投递事件，`app.rs` 是应用
委托与菜单栏，`window.rs` 是主窗口外壳（侧栏、工具栏），`messages.rs` 是标题栏里的消息胶囊与由它
长成的消息面板，`editor.rs` 是编辑器窗口，`panels.rs` 是对话框与
打开面板，`widgets.rs` 把组件树实现为视图并执行补丁，`text.rs` 与 `text_editor.rs` 是文本框与纯文本框，
`button.rs` 与 `popover.rs` 是按钮与弹出面板，`tray.rs` 是菜单栏图标与托盘菜单，`table.rs`、`tiles.rs` 与 `chart.rs` 是表格、磁贴栅格与流量曲线，`style.rs` 把文本样式、色调与图标映射到
系统字体、语义颜色与 SF Symbols，`test_control.rs` 是只在 `test-control` feature 构建里的控制口。

## 验证状态

验收覆盖 macOS 13.6（arm64 虚拟环境）与 macOS 27.2（arm64），使用签名的 `test-control` 验收包、独立数据目录的
调试或 release 构建。以下验证状态截至 2026-11-14，不代表所有平台组合均已验收。

- 捕获层：macOS 13.6 的[捕获层验收](../runbooks/capture-layers.md)覆盖四种层组合、负载下切换、进程规则、失败补偿、
  服务丢失恢复、退出与桌面崩溃后的检查点恢复。经 listener 的连接在切换 TUN 时保持，关 TUN 时经 TUN 的连接结束。
  清理后接口、路由、DNS 与系统代理回到基线。
- 数据面：TCP、UDP、fake IP、IPv6 投影与 DNS 劫持可用；排除随模式切换原地更新，物理接口拒绝 fake IP 的路由可阻止
  绑定接口的流量误发。已核对上游与本机 fake-IP 池同段、数值地址 DoH 的情形，经节点与 DIRECT 的请求均成功；
  该情形只核对可用性，尚未建立失败样本的回归对照。
- 路由与共存：macOS 27.2 覆盖有线与 Wi-Fi 换上行、Tailscale 重启、MagicDNS、严格全局模式的 DNS 与 WebRTC 泄漏检查，
  以及经移动网络的远程桌面会话。物理接口抓包中的业务流量符合配置的出口；睡眠唤醒后请求恢复。
- 产品界面：消息胶囊与面板动画、捕获和模式控件、节点选择与测速、规则编辑、输入法组字、独立编辑器、单实例、
  主窗口关闭与重开已核对。macOS 27.2 的托盘按需建立并释放成员行，选中、延迟与键盘高亮正确；关窗后静止托盘图标的行为已核对。
- 打包与更新：arm64 应用与 DMG 通过签名、公证与 Gatekeeper；x86_64 包通过交叉编译、
  签名与 Rosetta 服务握手，并已在 Intel Mac 上完成安装验证。更新流程用本地发布描述覆盖下载、SHA-256 校验、
  Finder 挂载、退出与校验失败。
- 登录项：macOS 13.6 的应用包覆盖登录项启停、重启后登录启动与静默托盘启动。实体环境已验证登录后启动，
  静默启动时不显示主窗口。

未覆盖：Intel 硬件上的 TUN、macOS 27.2 的完整捕获层矩阵、macOS 13.6 托盘子菜单的按需生成时机，
以及消息胶囊的真实指针悬停。macOS 13.6 验收环境的 IPv6 字面量 UDP 在基线下也无应答，不能据此判定
捕获结果。其余未完成范围见[待办](../backlog.md)。

### 大文件下载与并发

软件包下载的对照验证覆盖 TUN、混合代理与绑定物理接口的旁路连接。固定资源、CDN 地址、地址族、HTTP 版本与
Range 后，部分慢速和停顿在旁路中同样存在；另一次单流慢速伴随节点发送端的拥塞窗口和发送节奏收缩、重传增加，
接收窗口保持打开。该样本定位到节点至客户端的 TCP 传输，没有显示捕获引擎读取上游不及时导致窗口闭合。

并发公开资源下载与 Core 的进程内多流基准均可完成，所测范围未发现固定限速或并发准入阻断。这些结果不代表实际
系统更新、所有 CDN 或后台下载优先级都已验证，未完成范围见[待办](../backlog.md#macos-软件包下载的间歇性慢速)。

复现时先取得实际任务使用的公开资源与请求方式，交替比较三条路径；单流从首个正文块开始计时，记录逐秒字节数与
最长停顿。旁路用 SDK `netinet/in.h` 的 `IP_BOUND_IF` 绑定物理接口，避免改变正在运行的捕获配置。用 `nettop` 核对
上游接口与速率；具备节点访问权限时，以 `ss -tinm` 比较拥塞窗口、重传、接收窗口限制与发送缓冲限制。客户端可用
`libproc.h` 的 `proc_pidinfo(PROC_PIDLISTFDS)` 与 `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` 采样 socket 队列，字段取自
`sys/proc_info.h` 的 `socket_fdinfo` 与 `sockbuf_info`。缓冲容量不等于剩余接收窗口；未复现慢速时的空队列样本不能
代替慢速现场，单次快慢差异也不足以归因于 CDN、HTTP 版本或捕获路径。原始输出按[文档规则](../README.md#设计待办与验证)
保存在系统临时目录。
