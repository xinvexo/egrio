# Core 数据面

`egrio-core` 是纯代理内核：运行时配置档案模型、规则引擎、DNS 引擎、流/会话状态、入站/出站
处理与原生 Core 运行时。它从调用方接收结构化的配置并执行，不持有产品输入格式或仓库：Clash YAML
导入、本地配置档案存储、应用数据目录、已保存的 GUI 选择、平台设置、恢复检查点
以及面向用户的网络探测，均属于宿主后端。Core 的生命周期由 [Runtime](runtime.md) 持有。

## 职责边界

`CoreRuntime`/`CoreSessionManager` 持有：

- 已编译的配置档案/运行时配置；
- 规则运行时和出站选择；
- DNS 引擎、DNS 缓存行为、fake-IP 分配和 DNS 劫持处理；
- TCP 流/会话状态，UDP 关联/会话状态和待处理响应队列；
- 数据包 TCP 协议栈等 packet 状态；
- 代理运行时所需的出站连接/socket 状态；
- 流、数据包、DNS、状态、事件和关闭入口点。

它不得持有：

- Wintun 适配器句柄、WFP 对象、utun 与系统网络服务、Linux TUN/nftables/ip-rule/路由表
  生命周期；
- 系统 DNS/接口设置、恢复快照或防火墙/kill-switch 检查点；
- 配置档案存储、应用数据路径或产品设置仓库；
- 桌面窗口、托盘或界面状态；
- fd rlimit 等进程级 OS 资源限制（由宿主入口点持有）；
- 服务安装、OS 权限、提权或 SCM/systemd/launchd 状态。

`lib.rs` 中 crate 根的重导出表面就是 crate API；该 crate 只依赖外部 crate，绝不依赖 workspace 中
的平台、daemon 或 GUI crate。

输入格式的边界划在规则词汇处：Clash 规则行语法（`DOMAIN-SUFFIX,example.com`、规则集载荷条目、
`behavior` 名称）属于规则引擎领域词汇，在 Core 内解析；包装这些规则行的 YAML 文档、
规则提供程序获取、缓存和刷新状态留在宿主后端，宿主通过 `RuntimeProfile.rule_sets` 交给 Core
已解除包装的条目行。Clash YAML 规范化在 `desktop/egrio-desktop/src/profile_source.rs`。

两个工具模块位于 feature 之后，不属于出货 API：`validation`
（`validation-tools`）持有 SOCKS5 验证代理示例的配置解析，`bench_internals`（`bench-internals`）
把内部热路径包装给 criterion 基准。`server` feature 选择服务端角色装配。基准与门禁见
[Core 基准](../../crates/egrio-core/bench/README.md)。

## 模块布局

- `profile.rs` — 运行时配置档案输入模型，包括宿主注入的规则集内容（`rule_sets`）与 GEODATA 条目
  （`geodata`）。一个规则集的条目是一块共享的只读存储（`profile/entries.rs` 的 `RuleSetEntries`：
  全部条目文本连续存放，另记每条的结束位置），克隆只共享、不复制，宿主保留的配置与 Core 的匹配表
  用同一份文本；序列化为字符串数组。配置自己的规则列表同样是一块（`profile/rules.rs` 的 `RouteRules`：
  各条 payload 的文本连续存放，每条另记类型、payload 的结束位置与 `no-resolve`，出站名每个只存一次、
  规则里记它的序号），读出来的一条是借用这块文本的 `RouteRule`，建一块也是逐条给 `RouteRule`；
  宿主解析来源得到的规则、它组合给 Core 的配置、Core 的规则引擎用的是同一块，序列化为规则对象的
  数组。规则没有 id：它在列表里的位置就是它的序号；
- `geodata.rs` — 解码 V2Ray 定义的 `geoip.dat` / `geosite.dat`：protobuf `GeoIPList` / `GeoSiteList`，
  字段依据 v2ray-core 的 `app/router/routercommon/common.proto`。宿主保存文件并把字节交给 Core，Core
  只取出规则用到的代码：GEOIP 的国家/地区码，GEOSITE 的类别及其 `@属性` 筛选（只留带有全部所列属性
  的域名）；整份文件只扫描一次，不整体载入内存。取出的条目由宿主写入 `RuntimeProfile.geodata`：
  每个代码的网段、每个类别的名字各是一块 `RuleSetEntries`（名字按域名规则集的写法，完整域名直接写、
  域名及子域写作 `+.名字`），克隆只共享，Core 的匹配表直接索引这块文本；关键字与正则各是一个列表。
  共享存储避免宿主与匹配表为同一条目重复保留文本；
- `rule_engine.rs` — 路由规则编译/匹配引擎；每个 `RuntimeSnapshot` 只编译一次，转发与 DNS 通过
  `Arc<RuleEngine>` 共享不可变结果。配置更新整体替换快照，旧规则在最后一个快照或 DNS 持有者释放
  后回收，不使用跨代全局规则缓存。按配置顺序首条匹配胜出，都不匹配时走 DIRECT。配置自己的规则就地
  在它的那一块上匹配（`rule_engine/rule_index.rs`）：`DOMAIN` 与 `DOMAIN-SUFFIX` 各一张散列表，表项只是
  规则的序号，名字从块里读（后缀沿主机名的各级父域逐级查）；`DOMAIN-KEYWORD` 合成一个 Aho-Corasick
  自动机，主机名过一遍就得到它含有的全部关键字；`IP-CIDR`/`IP-CIDR6` 按（前缀长度，该长度下的网络地址）
  进散列表，网段之间不是包含就是不相交，所以一个地址只需在规则用到的每个前缀长度上各查一次。同一个
  名字、关键字或网段的规则只有第一条进表；其余规则连同这些后几条按顺序排成一列逐条试，每条带着自己的
  序号。表里找到的与逐条试的按序号归并，序号最小的胜出；没写 `no-resolve` 的网段规则在表里另记每个出口的
  第一条，只有域名的目标归并到它时就在这里先解析，与逐条试到它时一样。归并的结果由一个对照测试守着：
  随机生成的规则表与流量，逐条从头试到尾得到什么，表就必须得到什么（`rule_engine/index_tests.rs`）。
  payload 要先小写或去掉末尾的点才是名字的规则另存一份规范化的名字，决策与连接记录里仍是它写出来的样子。
  编译不了的规则（类型未实现、
  payload 无效、规则集或 GEODATA 没有内容）不参与匹配，引擎按它在配置里的序号记一条编译警告；其中不取决于
  宿主数据的那些（类型与 payload 本身的问题）宿主不必启动 Core 就能问到（`rule_support_issues`），桌面的
  规则页据此标出不生效的规则。取决于数据的那些（GEODATA 里没有这个代码、规则集有解析不了的条目）只有编译
  时才知道：Core 启动或换上新配置时把全部警告写进宿主的日志（`log` 的 `rules` 类别，前 20 条写规则原文与
  原因，其余只报条数），桌面的日志页因此看得到；只为预览而编译不写。规则模式下 UDP
  流（包括经规则选路的 UDP DNS 上游）跳过出口未开 UDP 的规则继续匹配，可能越过 MATCH 落到后面的
  规则或 DIRECT：未开 UDP 的出口不接 UDP，与其丢弃，不如交给后面的规则决定；策略组按此刻会选中的
  节点判断，REJECT 与解析不到连接器的出口照常命中。节点的 `udp` 开关见[支持的 Clash 字段](profile-store.md#支持的-clash-字段)。
  内置出口除 `DIRECT` 外有拒绝连接的 `REJECT`、`BLOCK` 与 `REJECT-DROP`，三者均立即拒绝连接。出口写 `PASS`
  的规则不决定任何流，交给后面的规则，也不为域名触发解析。拒绝连接的出口也可以是策略组的成员：转换订阅里
  常见的“广告拦截：`REJECT` 或 `DIRECT`”选择组此刻选中 `REJECT` 时，路由结果就是 `REJECT`，与规则直接写
  `REJECT` 一样记录为被拒绝的连接；只有成员（含嵌套组）里有拒绝出口的组才在路由时去看它此刻的选择。
  全局模式不看该开关，UDP 照样发往全局出口，只有协议本身不能承载 UDP 的出口（HTTP 代理）拒绝。
  GEOIP 用目标地址查该代码的网段，GEOSITE 匹配完整域名、域名及其子域、关键字与正则；GEOIP 的 `LAN`
  是内置的本地地址类别，不在 GEODATA 中；匹配两个地址族的私有、未指定、环回、组播与链路本地地址。每个代码在
  一次编译中只建一份匹配表，逻辑规则与 classical 规则集里的同一代码共用。网段表是排序合并的地址
  区间、按二分查找，IP-CIDR 规则集也用它。域名规则集与 GEOSITE 的完整域名、域名及子域按形状（完整、
  `+.`、`.`、`*.`）放进散列表，表项只是条目在共享块里的序号（`rule_engine/domain_index.rs`），只有需要
  小写化或去掉首尾空白的条目另存规范化副本；散列用 hashbrown 默认的 foldhash（每进程随机种子）：条目
  来自用户自己的规则集、主机名来自本机应用，查找速度比抵抗构造的碰撞更要紧。classical 规则集的条目
  之间是“任一条匹配即匹配”，所以其中的 `DOMAIN`、`DOMAIN-SUFFIX` 与 `IP-CIDR`/`IP-CIDR6`（真实列表里
  几乎全部是这三种）进同样的散列表与网段表，名字取条目文本里规则类型之后的那一段，不另存。规则集
  与 GEOSITE 里不是名字的匹配（`rule_engine/patterns.rs`）各合成一个自动机，主机名只过一遍：关键字
  用 Aho-Corasick，正则与中间带 `*` 的域名用一个 `RegexSet`（过大而建不成时对半拆开，编译不了的那
  一条单独跳过）。classical 规则集里只有其余条目（端口、进程、来源网段、逻辑
  规则、GEOIP/GEOSITE）逐条匹配。一次决策里主机名只规范化一次，各条规则共用。没有 GEODATA 或数据中
  没有该代码时，该规则以编译警告跳过。
  读目标地址的规则（IP-CIDR、GEOIP、含网段的规则集，以及含它们的逻辑规则）没写 `no-resolve` 时，
  只有域名的目标扫描到这条规则就先解析，再从这条规则起带着地址继续匹配：更早的规则看不到这个
  地址；`no-resolve` 的规则自己不触发解析，但在解析之后照样匹配得到的地址。解析走应用查询的同一
  DNS 路径，失败时这些规则不匹配，也不再重试。fake IP 不是目标的地址，路由时目标只有它代表的域名。
  TCP 分发器在路由准入之前解析；UDP 的新关联把数据报交给单独的任务，解析后再准入，准入本身不等
  DNS；包阶段不解析，需要地址的数据报交给 UDP 会话决定。裸 DNS 查询在这样的规则之前既不判定为
  DIRECT，也不拒绝，因为路由取决于这次应答给出的地址；
- `policy_group.rs` — 策略组运行时：已编译的组拓扑、持久的 selector/健康状态、拨号时解析和健康
  探测规划。一次解析在组状态的一把锁下走完整棵组树，并给出答案能维持到何时：到它绕开的最早一个驱逐
  到期（Fallback 只算排在选中成员前面的，UrlTest 与 LoadBalance 算候选里被排除的），驱逐到期本身不推进
  状态的版本。组的解析结果按组名留着，供之后路由到同一个组的流直接用：UrlTest 组的一次解析要看遍所有
  成员；而走一遍读到的东西没变时答案不会变——选择、粘滞选择、驱逐的设置与解除都推进版本，绕开的驱逐
  到期由期限管，测速结果不推进版本所以记下时直接丢掉留着的结果，换了快照的组按编译时得到的编号区分
  （每次编译一个，进程内不重复）；按目标分流的 LoadBalance 不留。UrlTest 的新测速结果由健康侧应用：每次探测
  记下结果后重新解析各 UrlTest
  组，选中的成员变了才推进版本。宿主读的“正在用的成员”（`CorePolicyState.automatic_members`，Select
  组的选择另记在 `selected_members`）由同一条解析路径按组回答，给出的是组里声明的成员，嵌套组就是
  组名：它不带目标，所以按目标分流的 LoadBalance 不报告（Relay 也不报告，它要走完所有成员），也不记下
  UrlTest 的粘滞选择、不推进版本——读一次不能改下一次拨号的选择，更不能把已经在走的流换到别的成员；
- `device/health.rs` — 主动健康探测调度：到期最早的节点先探，至多 8 路并发、每节点至多一路，探测
  结束一个周期后再次到期，黑洞节点因此只按并发数而不是逐个推迟健康节点。调度循环同时接收出口 guard
  发布的网络变化（见 `egress/network.rs`）：中止在途探测（其结果描述旧网络）并让所有节点立即
  重探；节点退出配置或设备关闭时中止其探测。每个节点的到期与每次探测结束都唤醒它，所以计划只在
  发布的快照换了时重新展开（按节点名索引），平时一次唤醒只扫一遍节点，不再按节点数的平方整理；
- 节点测速：测一个节点的延迟就是经它请求一次测速地址（节点的 `test-url`，任何类型的节点都可以写，
  否则 `DEFAULT_PROBE_TEST_URL`，即 `http://www.gstatic.com/generate_204`），建连、代理握手与请求一起计时，
  配置正在运行时由 `NativeCoreDevice::probe_outbound` 在当前代次上测，
  结果同时进入健康状态，配置切换或关闭取消未完成的测速；Runtime 只在稳定状态取得当前 Core 后释放操作锁
  再等待，过渡或恢复状态直接报错。没有运行这份配置时由 `probe_profile_node` 只编译配置的节点、策略组与
  DNS（不编译规则，大型配置的几十万条规则不该让一次测速付出编译代价），走宿主提供的物理出口，不创建
  Core。宿主只能测已存配置里的节点和它写明的地址，界面因此无法把测速指向别处；
- `outbound/probe.rs` — 主动探测的 URL、目标站 TLS 和 HTTP 应答校验。HTTP/HTTPS 都在 5 秒整段
  探测预算内完成目标请求；HTTPS 必须验证目标站证书，代理跳点的 `skip-cert-verify` 不影响该验证。
  探测目标同样先经 Core DNS 取得数值连接地址，但 HTTP Host、TLS SNI 和证书校验仍使用原始 URL 的
  目标身份。延迟从这次拨号拿到第一个可拨地址时算起（`egress::LookupClock`，`resolve_candidates` 的第一个
  地址，缓存与字面地址立即就有）：节点服务器名字的解析是解析器的时间，之后的连接都从缓存取，不是节点的延迟；
  到节点的连接、握手与经它的请求都计入。完整 HTTP 响应头的 2xx/3xx 才是成功，累计头部最多 16 KiB；接受 TCP/代理握手或收到
  任意一个字节不构成健康成功。使用既有 rustls 与 HTTP URI parser，协议依据为
  [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)；
- `dns/config.rs`、`dns/service.rs` — 类型化解析策略与唯一查询执行入口，区分业务目标、直连目标、
  代理节点和解析器 bootstrap；上游、传输协议与 DNS 连接路径各自有明确归属。经代理节点的 TCP
  连接把客户端给出的域名原样交给节点，由节点解析；显式代理收到的域名、平台流的原始域名和 fake-IP
  恢复的域名都是如此，只有 hosts 映射的域名交给它映射的地址（见 `dns/hosts.rs`）。连接目标的是节点，它解析出的地址才对应它的网络位置；本机的答复可能被污染、
  被阻断或很慢，fake IP 只在本机有意义。代理协议本就为此让目标携带域名：SOCKS5 的 DOMAINNAME
  地址类型（[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html)），HTTP CONNECT 的 `host:port`
  （[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) §9.3.6），Shadowsocks 与 Trojan 沿用
  SOCKS5 地址格式，Hysteria2 的 TCP 请求携带 `host:port`。DIRECT 由本机连接，其 TCP 目标由 Core 按
  DirectTarget 解析。UDP 目标经任何出站都先由 Core 解析为数值：一个关联向多个目标发包，回包只带对端
  地址，Core 知道地址对应哪个目标，才能把回包映射回客户端使用的地址。严格全局模式下（见下）这次解析
  经全局出口问配置的服务器；只有系统来源时没有能问的服务器，经代理的 UDP 才把域名交给节点：每个 fake IP
  各用一条传输、只发往一个域名，首个回包的来源就是节点解析出的地址，此后来自它的回包映射回 fake IP，
  其他来源（例如 STUN 服务器的备用地址）保持原样。代理节点使用 ProxyEndpoint，解析器自身使用 Bootstrap。
  全局出口不是确定的 DIRECT 时，全局模式是严格的：所有连接都经全局出口，业务域名也只在它之后解析，
  本机不为业务域名向任何解析器发问。应用的 A/AAAA 查询不论 DNS 是否开启、`enhanced-mode` 与
  `fake-ip-filter` 如何都得到 fake IP，fake-IP 池在全局模式下总是启用；其他类型的查询与 UDP 目标的解析
  去掉系统来源，其余来源一律经全局出口（`DnsRoute::Proxy`，此刻选中 DIRECT 时失败而不是直连），没有
  这样的来源时查询答空 NOERROR、UDP 的域名交给节点。节点与 DNS 服务器自身主机名的解析不是业务查询，
  照常按 ProxyEndpoint 与 Bootstrap 直连，只暴露这些基础设施，写成数值地址即可避免。全局模式可以在
  TUN 运行中进入，所以 fake-IP 池与 TUN 地址、路由排除的冲突校验不论 DNS 模式都进行。
  `dns/policy.rs` 的只读投影委托同一服务，不另存从业务 route 推断的 DNS 路径，也没有虚构上游或
  内置 STUN/NTP 域名特判。桌面输入与支持范围见
  [DNS 配置来源](profile-store.md#dns-配置来源)；未配置时沿用该处的系统来源默认，Core 不因入口或
  节点协议另选上游；桌面层只转换明确填写的来源，不内置服务商预设。来源严格按配置顺序执行，有效
  正答复、NXDOMAIN 和 NODATA 都结束查询；传输故障及 SERVFAIL/REFUSED/NOTIMP 才尝试后项。整次
  查询 5 秒，每项最多 2 秒，并为剩余来源均分剩余预算，避免前项长期占用全部时间。代理来源不可用
  不改变它的连接路径，只有用户配置的下一项可接续。节点引导不继承业务来源，默认使用系统直连。
  捕获层活动时（只有这时本机把 fake-IP 池路由进自己的隧道，macOS 还在物理接口上拒绝它），Core 自己的
  地址查询（DIRECT 目标、UDP 目标、节点端点、解析器自身，不论用途）得到的地址落在池或它的 IPv6 投影内时
  不算地址：路上另一个 fake-IP 解析器（路由器或宿主机上的代理）答的是它自己隧道里的替身，而本机把这个段
  路由进自己的隧道，那里没有这条映射。没有捕获层时这个段没人接管，上游给的地址照它的本意经那个代理可达，
  照常使用。这些地址被丢掉，问题改问
  配置写明的服务器——默认只有系统来源的用途（节点端点）改问业务来源，bootstrap 只问它自己的数值
  服务器——拿到的真实地址也更好，连接从本机出去而不是再经那个代理。配置没有别的服务器时解析失败，
  错误写明答复落在池内：上游这样答复时通常也劫持了所有 UDP/53（路由器或宿主机上的代理都这么做），
  这样的网络里只有不经 53 端口的来源（写成数值地址的 DoH/DoT）或者换一个不同段的池能拿到真实地址。
  只有 Core 自己的查询这样判断，给应用的应答照常从池里分配。
  DNS IPv6 只读取本代 `NativeCoreEgressConfig.ipv6_enabled`；只读 `DnsEngine` 投影也显式接收同一个
  egress 配置。该值只控制 AAAA 应答、fake IPv6 分配和域名解析候选：关闭时 AAAA 返回空 NOERROR，
  域名只选择 IPv4；开启时允许 A/AAAA，TCP 拨号先试 IPv6（见 `egress/dial.rs`），单地址 UDP 消费者
  仍取 IPv4。已有数值 IPv6 目标不重新解析，DIRECT、
  代理目标与节点端点继续按路由和 scope 约束连接，TCP/UDP socket 不因解析开关关闭而拒绝 IPv6。
  需要阻断的流量由拒绝规则处理；只有 AAAA 的域名在关闭时仍无可选地址。`localhost` 及其下的名字按
  [RFC 6761 §6.3](https://www.rfc-editor.org/rfc/rfc6761#section-6.3) 本地作答，不问任何来源、不分 fake IP：
  A 答 127.0.0.1、AAAA 答 ::1（IPv6 关闭时为空），其他类型答空 NOERROR；出站拨号解析这些名字时同样直接
  给回环地址，不依赖系统 hosts 文件。域名解析开关与数值地址连接分离，捕获范围与 Windows 的
  IPv6 posture 由平台文档维护。`PreparedApplicationQuery` 同时持有业务出站上下文、解析
  用途、来源计划与只读投影，wire 应答执行该计划。显式 TCP/UDP 解析把已经选定的实际出站传入
  `QueryContext`；直连专用列表优先于域名策略，域名策略优先于默认列表。应用发问的业务解析器连接按
  规则出站；为 DIRECT 目标、节点与 Bootstrap 的解析默认直连：DIRECT 连接从本机网络出去，解析器按发问者的
  位置作答（CDN 给离发问者最近的服务器），经代理问到的是代理那一侧的地址，也不比 DIRECT 连接本身多隐藏
  什么；Core 的显式 `DnsRoute` 仍可表达独立的连接路径。裸 DNS 查询
  没有未来连接的端口和最终目标 IP，因此只判断可确定的直连，不以虚构端口选择混合 LoadBalance
  成员；未知业务成员时保留已命中的组供 DNS 连接选择，不宣称预查询已经知道未来数据连接的具体
  节点。已有真实 IP 不根据 SNI 重新解析；
- `dns/transport.rs` — UDP/TCP/DoT、明文 HTTP DNS 与 DoH 传输，DNS UDP 截断后按同一上游与路径转
  TCP；UDP 查询 500 ms 没有回答就从同一 socket 再发一次，此后间隔加倍，直到这个服务器的期限（2 秒）：解析器
  几十毫秒内作答，重发只在查询或回答丢了时才有，不然一次丢包就耗尽整个期限，只有一个服务器时查询失败；
  DoT 与 DoH 使用独立 TLS 协议协商，证书按解析器身份校验。DoH 由 Hyper 处理 HTTP/2 与
  HTTP/1.1，HTTP Age 扣减 DNS TTL，不手写 HTTP framing。HTTP/1.1 使用 Host，HTTP/2 从绝对 URI
  生成唯一的 `:authority`，不重复发送 Host；传输错误保留 HTTP 阶段和底层错误链。HTTP/2 authority
  依据为 [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1)；
- `dns/connections.rs` — 到流式服务器的连接留给之后的查询：TCP 与 DoT 的查询独占一条连接，答案到手后放回，
  同一服务器、同一路由每样至多留 4 条（[RFC 7766 §6.2.1](https://www.rfc-editor.org/rfc/rfc7766.html#section-6.2.1)、
  [RFC 7858 §3.4](https://www.rfc-editor.org/rfc/rfc7858.html#section-3.4)）；DoH 服务器的 HTTP/2 连接同时承载发往
  它的所有查询（[RFC 8484 §5](https://www.rfc-editor.org/rfc/rfc8484.html#section-5)），同时到来的查询共用一次
  握手。空闲超过 10 秒的 TCP/DoT 连接不再复用（服务器几秒后会关闭空闲连接，用到已关的连接要等失败才能重发），
  复用的连接失败时换一条新连接重发一次（DNS 查询可以重发）。HTTP/2 连接由服务的一个任务驱动，服务退役（换配置）、
  网络变化或 10 分钟没有查询时关闭，是这里唯一比打开它的查询活得更久的东西；它等待时每 30 秒发一个 PING
  （[RFC 9113 §6.7](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.7)，hyper 的 `keep_alive_interval`、
  `keep_alive_while_idle`），10 秒得不到确认就关闭，所以服务器或路径不再应答时，下一个查询会新开连接，不会发到
  死连接上等失败。PING 也维持路径上 NAT 的状态。fake-IP 模式下 `nameserver` 只在新名字遇到 IP 规则时才被问，
  两次之间可能相隔较久，保留活跃的 HTTP/2 连接可避免重复握手。服务器不接受
  HTTP/2 时，DoH 每个查询一条 HTTP/1.1 连接，并记住 10 分钟，其间同时到来的查询各自握手，不在这个服务器处排队；
- `dns/wire.rs`、`dns/cache.rs` — Hickory Message 编解码与有界、请求拥有的共享查询缓存，保留完整
  记录及返回码。TTL 按真实剩余时间递减，主机睡眠前缓存的应答在唤醒后作废（见 `suspension.rs`），零
  TTL 与无有效 TTL 的应答不持久缓存。带 SOA 的负应答（NXDOMAIN 与 NODATA，含 CNAME 链末端没有所问类型的）
  按 [RFC 2308 §5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5) 缓存 SOA 的 TTL 与 MINIMUM 中较小者，不超过
  链上 CNAME 的 TTL，至多 15 分钟；没有 SOA 的负应答与其他错误不缓存。同时等待的查询可共享一次
  结果，取消拥有者后等待者可接续，不残留脱离请求的查询任务；
- `dns/answers.rs` — Core 自己的地址查询（DIRECT 目标、UDP 目标、节点端点）在 wire 缓存之前的已解码
  应答：按名字、地址族、用途与业务出站保存地址，有效期与 wire 缓存相同（TTL 到期、主机睡过、网络变化时
  随服务一起清空），并记下规划时策略组状态的版本，组的选择变了就不再使用；嵌套查询（解析 DNS 服务器
  自己的名字）不经它，保留循环检查。命中时省掉上游规划、查询的构造与编码、缓存键与应答解码，每条新的
  DIRECT 连接或 UDP 流复用已解码结果。过了 TTL 一分钟内的应答仍先拿来连接，同时由一次后台查询刷新
  （同一应答只刷新一次，失败后下次再试；同时至多 32 次，随服务结束，网络变化后的结果作废）；
- `dns/pattern.rs` — DNS 过滤、策略与 hosts 的域名模式（`DnsDomainPattern`）和按模式找值的标签树
  （`PatternTrie`）。模式按点分的标签匹配：`*` 代表恰好一个标签，前缀 `+.` 是该域名及其下所有域名，`.` 只是
  其下的域名；单独的 `*` 表示所有域名。模式以这段文本读入与序列化。树从域名的最后一个标签往前走，每一级先走写明的标签、再走
  `*`、最后才取已到达节点上的 `+.`/`.`，走不通就退回上一级，所以一次查找只看域名的标签数，与模式多少
  无关。`hosts` 与 `fake-ip-filter` 各建一棵树；`nameserver-policy` 按声明顺序逐条比较，不分配；
- `dns/hosts.rs` — 映射到固定地址的域名：配置的 `hosts` 先于系统的 hosts 文件。配置里最具体的模式生效
  （`dns/pattern.rs` 的顺序：精确域名含 `+.` 模式的域名本身、`*.` 单级子域、最长的 `+.` 后缀、`*`），
  同一模式写两次取第一项；配置没有映射的名字在 `use_system_hosts` 时查系统文件（hosts(5)：一个地址后跟它的名字，
  `#` 起注释；Unix 是 `/etc/hosts`，Windows 是 `%SystemRoot%\System32\drivers\etc\hosts`），只有精确名字，
  同名多行的地址都保留，IPv4 映射的 IPv6 地址按 IPv4，带区域的地址那一行跳过；文件至多每 5 秒看一次，修改
  时间或长度变了才重读，读不到时不映射，单元测试不读。`DnsService::resolve_family` 先查映射：被映射的名字
  只得到映射里该族的地址，不向任何来源发问，所以 DIRECT 目标、需要解析的 IP 规则（`no-resolve` 的规则不为
  域名查地址，也就不看映射）、UDP 目标、节点端点与 DNS 服务器自身的名字都用映射；经代理的 TCP 连接交给节点
  映射的地址（先取 IPv4，`egress/resolver.rs` 的 `hosts_target`），严格全局模式下 UDP 也不把这样的名字交给
  节点。应用的查询在 `use_hosts` 时于 localhost、REJECT 与 IPv6 开关之后、fake IP
  之前判定（`DnsDecisionAction::Hosts`）：A/AAAA 答映射里该族的地址，TTL 10 秒，没有该族地址时答空；
  HTTPS 记录答空，它的地址提示会绕过映射；其他类型照常查上游。应用拿到映射地址后以数值地址进入 TUN 的
  连接按地址路由，不反查名字；
- `dns/resolver.rs` — 客户端 DNS 应答、fake-IP store 和劫持解析；非地址查询交给同一解析服务，不
  假答空 NOERROR，两种情况除外：严格全局模式没有可经代理的来源时；会拿到 fake IP 的名字的 HTTPS 与
  SVCB 查询（`DnsRecordType::Https`、`Svcb`）。这样的名字在应用那里只有 fake IP，上游记录里的地址提示是
  真实地址，会让连接绕过 fake IP，浏览器还要先等这次上游往返；
  `fake-ip-filter` 留给真实地址的名字照常查上游。上游 NXDOMAIN 等响应保留原码，传输/解析失败返回 SERVFAIL。未提供物理 DNS 快照
  且系统 API 不能查询的记录类型明确返回 NOTIMP。A/AAAA 共用一个地址映射，IPv4 按本代配置池分配，
  IPv6 在内部 ULA 前缀中嵌入同一 IPv4；反查与 stale-range 判断共用 session store。热换池保留已
  发布的映射，每个 Core 会话最多保留 131072 个映射；两张映射表共用每个域名的一份副本。应答提到映射、流去往它都算一次使用；当前池或映射
  上限满时，10 分钟内没用过的映射按最近使用从早到晚每次释放一批（1024 个），地址依次给之后的新域名
  （应答的 TTL 只有 1 秒，这段余量覆盖把应答多留一阵的客户端：浏览器约一分钟、Java 30 秒），释放后尚未
  重新分配的地址照 stale 目标拒绝。一次清扫只看池里 1024 个地址的一段，下次从上次停下处接着看，所以
  清扫成本有界。新域名找空地址的探测同样封顶（自哈希起点起 256 个）；池里没有空地址时，直到有地址被释放才
  再查一遍。换池后旧池的空闲映射在下一次清扫时一次释放（新池的
  偏移永远走不到它们），还在用的留到下次换池。全都在 10 分钟内用过时新域名返回 SERVFAIL，走完池里一圈
  仍没有一个空闲才一秒内不再寻找。按分配
  顺序回收会拿走正被频繁使用的域名的地址，把刚拿到应答的客户端导向别的域名。宿主在 `CoreStartInputs.fake_ip_mappings` 指定文件时映射跨 Core 保持
  （`device/fake_ip_keeper.rs`，格式见 `dns/fake_ip_file.rs`）：新一代 Core 或重启后的 Core 在应答任何查询前
  读回映射，当前池里的地址回到原域名并算作刚用过，已有映射的地址与域名不动；Core 关闭时写出，运行中有新映射
  时每 10 分钟写一次，崩溃时留下最近一次的内容。这样越过 TTL 拿着旧 fake IP 的客户端仍到达它问过的域名，
  不会因重启后分配顺序不同被导向别的域名；不指定文件时映射只在一个 Core 内保持。IPv6 未启用时 AAAA 返回空
  NOERROR；
- `inbound/acceptor.rs` — `InboundAcceptor` 契约（`OutboundConnector` 的对偶）：一个线路协议的
  服务器半部向共享分派器生成 `InboundSession`（带 `Metadata{user}` + 回复计划字节的流，或已认证的
  多流数据报接口）。没有拒绝回复的入站可附带 reset：分派器在准入拒绝、REJECT、出站不可用与拨号失败时先
  调用它再丢弃流，TUN 流以此用 RST 结束，与真实服务器拒绝连接相同，而不是一个空的应答；Core 自己结束的
  relay（被取消，例如出口随网络变化消失，或预算用尽）也复位，客户端不会把中断当成数据的结尾，上游自己关闭
  或出错时照常发完已写数据再 FIN；
- `inbound/dispatch.rs` — 对任意双工流通用且不感知协议的唯一 TCP 分派管线（扩充 → 路由 → 拨号 →
  中继）；listener acceptor 与 TUN 的 TCP 引擎均先构造 owned `AcceptedStream` 再进入
  `dispatch_accepted_stream`，`supports_tcp()`、进程元数据、路由账本、拨号和 `EGRIO_RELAY_TRACE`
  没有设备层副本。该模块还包含混合首字节明文握手（`accept_mixed_session`）和共享的
  `dispatch_session` 尾部；数据报接口泵（`dispatch_accepted_datagrams`）由无需等待的发送循环和按
  用户限定、针对 UDP 会话 actor 的后台排空组成，一个停滞目标不会造成连接中其他流的队首阻塞。
  排空同时按 flow 前缀限定：一个监听器可以同时运行 Shadowsocks 与 Hysteria2/Trojan 入站，两者
  用户表相互独立，同名用户可以在两边各存在一份，只按 user 限定会让一个入站取走另一个入站的响应
  并用自己的密钥封装后发往错误的客户端。face 结束时按自己独占的 flow 前缀关闭本 face 的 UDP 会话
  （`close_flows_with_prefix`，drop 时执行，取消路径同样回收）：flow id 内嵌单调递增的 face id，
  后续连接永远排空不到已死 face 的会话；
- `inbound/listener/` — `CoreSessionManager` 本地监听器会话（`mod.rs`，公开 API 与启动）；`compose.rs`
  在绑定任何 socket 之前由 `CoreSessionStartConfig` 上公开的 `CoreInbound` 入站选择器（`Mixed` /
  `Shadowsocks{cipher,users}` / `Trojan{cert,key,users}`，后两者终止于主监听器）组合出接受循环的
  `InboundStrategy`，以及同一配置上可选且公开的 `Hysteria2Inbound`（在主监听器旁提供服务的独立
  QUIC 端点，位于 `server` feature 后）；`accept.rs` 是接受循环与应用于每个 acceptor 的监听器级
  握手超时，`dns.rs` 是 DNS 监听，`scope.rs` 是本地混合监听器的地址范围，`state.rs` 是代次状态及其
  转换。监听 socket 上的错误不结束监听：`accept` 报的都是正要到来的那条连接或进程一时缺的东西，socket 本身
  仍然有效。客户端在排队时复位或中止的连接（POSIX 的 `ECONNABORTED`，Winsock `accept` 的 `WSAECONNRESET`）
  直接接下一条；其余错误——描述符或缓冲用尽（`EMFILE`、`ENFILE`、`ENOBUFS`、`ENOMEM`），以及 Linux 从 `accept`
  返回的新连接上挂起的网络错误（accept(2) 要求按 `EAGAIN` 重试）——记入状态的 `last_error`，停 10 毫秒后再接，
  连续失败时逐次加倍到 1 秒，接到一条连接即复原，其间照常回收结束的会话（描述符由此交还）。遇到这些就结束
  会让整个监听代次随之关停：桌面上系统代理此后指向一个已关闭的端口，公网端口上任何能建立连接的人都能让服务
  停止接入。一个 UDP socket 服务所有对端的循环（DNS 监听、Shadowsocks 的两个 UDP 服务）同样不因一次接收
  错误结束（`outbound/datagram.rs` 的 `after_receive_error`）：只关乎一个数据报或其路径的错误立即继续——
  Windows 上未连接的 socket 发出的数据报遇到关闭的端口后，下一次 `recvfrom` 以 `WSAECONNRESET` 失败
  （[recvfrom](https://learn.microsoft.com/windows/win32/api/winsock/nf-winsock-recvfrom)），否则一个提前关掉端口
  的客户端就结束了所有客户端的服务——其余错误停 50 毫秒再收。`start_on_device` 可让被占用或被保留的混合端口由它之上最近的空闲端口替代，状态的
  `listener_fallback` 记下请求地址与原因；绑定失败的消息写明地址、原因并提示换端口。控制面读取器为 `inbound_auth_failures()`（加密的流式入站，Shadowsocks 或 Trojan）、
  `hysteria2_auth_failures()` 与 `hysteria2_listen_addr()`；每次启动在绑定前预约唯一代次，stop 可使尚未提交的启动失效，
  TCP/DNS/UDP/QUIC 任务持有本代 shutdown receiver，且所有后台状态回写都按代次 fencing，旧任务不能
  关闭或改写重启后的监听器；`Stopped` 是该代次的资源释放屏障：顶层监听任务、TCP 会话、DNS 查询
  以及 Shadowsocks UDP / Hysteria2 的后台连接与流任务全部退出并释放 socket 后，再次关闭该会话自有
  的 Core device（清除 shutdown 竞态中的迟到 UDP actor），最后才发布 `Stopped` 或 `Failed` 终态；
  排空期间统一保持 `Stopping`；入站 dispatch 保留类型化结束事实直到 listener 记账，完成与失败分别
  累计；取消、客户端关闭和策略拒绝只结束活动会话，不计成完成/故障，也不覆盖 `last_error`。真实
  握手、拨号、上游传输及数据报 responder 错误保留诊断；HTTP 代理/SOCKS5 的 `InboundReplyPlan`
  引用静态响应字节，每条连接无需为成功及各类失败响应分别分配缓冲；
- `protocols/<name>/{codec,connector,acceptor}` — 每种线路协议的对偶半部：`http/`、`socks5/` 和
  `shadowsocks/` 均基于共享 codec 持有 connector（客户端半部，`OutboundConnector`）和 acceptor
  （服务器半部，`InboundAcceptor`）；Shadowsocks 的共享 codec 包括 AEAD 帧、地址和密钥调度，以及
  两个半部进行中继时共用的基于 poll 的明文双工流。帧在待发的密文缓冲里原地封装，明文只复制一次、不另分配，
  一帧可取自分散写的多块，避免先合并再加密。传统 AEAD 支持 `aes-128-gcm`、`aes-256-gcm`、
  `chacha20-ietf-poly1305`；`shadowsocks/aead2022/` 为 TCP/UDP 两端提供
  `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 和 `2022-blake3-chacha20-poly1305`。该模块
  只调用官方 `shadowsocks` crate 的 `ProxyClientStream::from_stream`、`ProxyServerStream` 和 UDP
  纯编解码接口，socket、DNS、出口绑定和路由仍归 Egrio；不启用该依赖的 DNS resolver feature。
  SS2022 的 `password` 是 Base64 编码的固定长度 PSK（AES-128 为 16 字节，其余为 32 字节），配置时
  校验，不能通过旧版的口令派生函数处理。AES 出站支持 `iPSK:…:uPSK` 身份密钥链；入站使用每个用户
  一个独立 PSK 的静态用户表，不提供 SIP023 身份处理器，带身份链的入站凭据会在绑定前拒绝。TCP 由
  官方 codec 校验时间戳、请求 salt 防重放及响应对请求 salt 的绑定；无首批数据也立即发送带 padding
  的请求，以支持服务端先发数据的协议。两种 acceptor 握手失败（读不够、解不开或头部校验不过）后都不立即
  关闭，而是读取并丢弃到对端关闭为止（在监听器 30 秒的握手预算内）：带着未读字节关闭会发 RST，逐字节
  试探的探测者据此得知服务器读了多少，SIP022 §3.1.4 要求不暴露这一点；门禁测试以不同长度的探测确认
  连接都保持到探测者关闭、随后以 FIN 结束。UDP 使用独立的客户端/服务端 session ID、单调 packet ID、
  每会话 1024 位滑动窗口及 120 秒空闲保留；先验证完整报文及客户端 session 绑定，再更新窗口。出站
  每条 UDP transport 最多保留 128 个服务端会话，入站每监听器最多 1024 个客户端会话，达到上限时
  拒绝新会话，不驱逐尚有效的窗口。入站按用户和 session ID 隔离 flow，以最新已认证客户端地址回复，
  换源端口仍复用原 Core flow；回复携带 flow ID 以免同源会话串流。协议依据为
  [SIP022](https://shadowsocks.org/doc/sip022.html)、[SIP023](https://shadowsocks.org/doc/sip023.html)
  与[官方 Rust codec](https://github.com/shadowsocks/shadowsocks-rust/tree/v1.25.0/crates/shadowsocks/src/relay)。
  `hysteria2/` 持有 connector、作为其线路词汇唯一归属的 `codec`（QUIC varint、填充、TCP 帧常量，
  以及两个半部通用的 UDP 数据报帧；始终编译），并在 `server` feature 后持有 QUIC/H3 服务器
  acceptor。后者是连接级 QUIC 服务器而非 `InboundAcceptor`，因为一个 QUIC 连接会多路复用多条代理
  流：它通过 HTTP/3 对静态用户表认证一次（成功应答以 `Hysteria-CC-RX: 0` 声明不限接收速率，客户端
  按自己配置的上传速率发送；服务器自己的发送不读取客户端报出的速率，沿用 quinn 默认拥塞控制），为每条
  接受的双向流驱动一次分派，并为连接的 QUIC 数据报泵送 UDP 数据报接口。`trojan/` 是经 TLS 隧道传输的对偶半部：其 acceptor（位于 `server` feature
  后）在接受的传输上终止 TLS，随后读取 Trojan 前导，并通过一次 map 查询对静态用户表认证
  `hex(SHA224(password))` 哈希（未命中时操作有界且会计数；连接直接丢弃，不设回退站点）；其
  connector 经共享载体（`outbound/carrier.rs`）发起 TLS，同一节点的连接共享客户端配置及 TLS
  会话缓存；普通 Trojan CONNECT 每条代理连接使用独立 TCP/TLS 连接，协议没有跨目标的流多路
  复用帧。CONNECT 产出流面，UDP associate 在同一 TLS 隧道上产出数据报面（每帧各自携带目标，一条
  associate 即一个 EIM 会话）。connector 的 associate 请求按协议写明期望的目的地址，即关联的首个目标：
  有的服务器按请求地址建立 UDP 会话、只在那里解析域名，请求写占位地址时它丢弃
  只在数据报帧里出现的域名目标；acceptor 只按每帧的目标转发。开了头的 UDP 帧要在 30 秒内收完，载荷按
  8 KiB 一段随到随长：帧是按长度分帧的，写了一个字节就停下的对端既无法重新对齐也不能一直等，否则这个
  面的任务要陪它到连接结束，还按它声称的长度先占住内存；而等待一帧开始本身不设期限——安静的 associate
  只要客户端还留着就一直留着。其 codec 单写认证哈希、请求帧和两个半部通用的 UDP associate 帧
  （始终编译；SOCKS 地址编码通过 `target.rs` 与 Shadowsocks、SOCKS5 出站共享）。Shadowsocks UDP associate
  服务器接口由直接驱动的 UDP 服务器（`protocols/shadowsocks/udp.rs`）与 SS TCP 共享监听端口：
  它不是 `InboundAcceptor`，因为一个 socket 携带多个用户各自使用独立密钥的数据包；它针对用户表
  尝试解密每个数据包，通过 UDP 会话表中继，并按用户排空响应。混合监听器的 HTTP 代理/SOCKS5 握手
  即这些 acceptor 半部。混合端口的 SOCKS5 只接受 CONNECT，UDP ASSOCIATE 以“命令不支持”（`0x07`）
  拒绝：本机 UDP 由 TUN 接管，混合端口不提供 SOCKS5 UDP 中继。两个 HTTP 半部按块读取头部（上限 8 KiB），读过头部的字节（请求正文、隧道
  的首批字节）经 `prefixed.rs` 回放给流的下一个读者；SS2022 acceptor 回放已认证的固定头也用它。
  HTTP 代理 acceptor 接受 `CONNECT` 隧道与 absolute-form 明文请求（系统代理
  把 `http://` 交给 HTTP 代理时的形式，RFC 9112 §3.2.2）：明文请求改写为 origin-form，`Host` 取自
  请求目标，去掉逐跳与代理字段（RFC 9110 §7.6.1，消息分帧字段保留），改写后的请求头先于正文重放
  给源站，入站标签为 `http-forward`。一条客户端连接只承载一个请求、一个源站：转发的请求携带
  `Connection: close`，客户端流在该请求的消息分帧处结束（无正文、`Content-Length` 或 chunked，
  RFC 9112 §6.3/§7.1；两者并存、非 chunked 结尾或长度冲突一律拒绝）。客户端若仍复用连接（流水线
  发下一个请求），下一个请求不会送达该源站：上行方向在这条消息的分帧处结束——这是客户端发完请求
  就安静下来的同一个结束，源站收到半关闭后照常把应答发完，客户端在新连接上重试第二个请求。以
  错误结束会同时掐掉两个方向，把第一个请求本来已经能拿到的应答一起丢掉。只有 WebSocket 升级不设
  边界，因此明文 HTTP 不复用 keep-alive。Shadowsocks 与 Trojan acceptor 由监听器的 `CoreInbound` 分支现场组合，
  Hysteria2 acceptor 由监听器的 `Hysteria2Inbound`（其自有 QUIC 端点）组合；各自都将 loopback
  门禁作为常设门禁。Hysteria2 的流不经监听器那层 30 秒的握手包装（它有自己的端点），所以每条代理
  流的 TCP 请求帧自己带上同一预算：否则一个已认证客户端在每条双向流上写半个 varint 就停下，就能
  按每条连接的并发流上限（1024，覆盖一个被捕获客户端能同时持有的流数）停住那么多任务，而它们在
  请求解析完之前都不进会话登记表。同一端点同时服务的连接数有上限（256）：一条连接是一个客户端而
  不是一条流（客户端把要代理的流全放在一条连接上），所以这个数就是接收窗口、数据报缓冲与流额度
  各有几份。满额时新来的尝试被拒（CONNECTION_REFUSED，[RFC 9000
  §20.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1)），在用的连接一条也不关。额度
  不分未认证与已认证两份：每条连接要位子时都还没认证，留一份只会缩小新用户能拿到的，而已在服务
  的连接不会再要位子。被放进来的尝试要在 10 秒内握完 QUIC，否则位子收回——一次拨号到达时不止一个
  Initial 包，无状态地拒掉第一个之后端点对其余的没有状态，同一次拨号的下一个包就成了一个自己的
  尝试，正好有位子空出来时它会被放进来，而客户端已经不在了。认证之前一条连接只拿到一小份接收
  窗口（256 KiB）：quinn 不管应用有没有接走都会缓存对端发来的流字节，而认证之前没有谁去接——HTTP/3
  那层只被问一次请求，凭据被拒的连接为了伪装还要留到空闲超时——所以挡在这样一个对端与主机内存之间的
  只有窗口。凭据一对上就换成隧道要用的 20 MiB（由 MAX_DATA 告知对端，在放行任何代理流之前发出），它要
  盖住这个客户端经这一条连接代理的全部流量的带宽时延积。QUIC 数据报的两个队列（两半都是）各按 128 个
  数据报收口：发送队列满了是挤掉最老的（quinn 的 `send_datagram`），所以它的深度不是丢包上限而是队头
  数据报出去时能有多旧——1024 个是 1.2 MB，约等于客户端在 10 Mbit/s 份额上的一秒，而 UDP 中继排一秒
  正是 Core 在别处都拒绝的缓冲膨胀（回包队列宁可停住读的一方，让丢包落在源头、让对端自己的拥塞控制看见）；
  接收队列排过一次突发同样没有意义，在服务端一侧还是未认证连接能占住的内存。
  `InboundAcceptor` 和协议 acceptor 保持 crate 私有，仅 `CoreInbound` 枚举和 `Hysteria2Inbound`
  配置公开。配置档案词汇还列出了更多协议（VMess/VLESS），但尚无对应
  connector；此类代理编译后不会产生出站表条目；
- `certificate.rs` — 服务端角色的证书加载，位于 `server` feature 后：将运维人员提供的 PEM 证书链
  和密钥解析为由 aws-lc-rs 支撑的 rustls `ServerConfig`，供加密 acceptor 使用（无 ACME，不自行签名）。
  客户端构建从不链接它；
- `tls.rs` — 共享的客户端 TLS：节点的 TLS 选项（`sni`/`servername`、`skip-cert-verify` 及其别名、
  `alpn`）只在此读取；固定使用 aws-lc-rs 的 rustls `ClientConfig` 构建器（webpki 根证书，或配置档案
  选择的 `skip-cert-verify` 免验证 verifier）使安全敏感的 verifier 只实现一次（Shadowsocks 的加密本来就链接
  aws-lc）。密钥交换优先 X25519MLKEM768 混合，与当前的浏览器一样：它的密钥份额让 ClientHello 超出一个 QUIC
  Initial 数据报，两个数据报让服务器在验证客户端地址之前能发出三倍于此的首轮应答（[RFC 9000 §8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1)），
  较大的证书链因此有机会在首轮应答中发完，减少等待客户端确认的往返。
  固定一个加密后端避免重复链接；`TlsClient` 持有每个节点
  只构建一次的配置（同一节点的连接共享 TLS 会话缓存）与校验过的服务器名。它握手出的流（`ClientTlsStream`）
  把节点不发 close_notify 就关闭 TCP 读作流的结束：多数代理服务端在目标关闭后这样结束隧道（它们所用的 Go
  crypto/tls 把它读作 EOF），rustls 报 `UnexpectedEof`，经这类节点的连接在数据到齐后都会记成失败；只有下层传输
  的正常关闭算数，下层自己的错误（例如前一跳截断的帧）照常让读取失败。任何跳点都未实现的信任
  选项（`fingerprint`、`certificate`、`private-key`、`ech-opts`）在此统一列出，带有它们的节点以配置
  错误失败，不以较弱的校验去连。Hysteria2 的 QUIC 栈、Trojan 和 `tls: true` 的 HTTP/SOCKS5 跳点都
  使用它；
- `outbound/` — `OutboundConnector` 契约和 DIRECT connector；线路协议 connector 位于 `protocols/`
  下（Hysteria2 持有其 QUIC/HTTP-3 握手、每条代理 TCP 连接一条 QUIC 流，以及原始数据报 UDP 中继）。
  `outbound/carrier.rs` 是流式协议成帧之下的载体：本机经出口拨号到节点的 TCP 连接，或节点写了
  `dialer-proxy` 时经那个出站到节点的流，节点要求时外包 TLS。Trojan、HTTP 与 SOCKS5 connector 都在
  它返回的流上成帧（Shadowsocks 直接在其下的连接上加密），所以以后加入的 WebSocket、gRPC 等
  传输对这些协议同时生效；HTTP/SOCKS5 节点的 `tls: true` 即 HTTPS 代理与 TLS 上的 SOCKS5（UDP
  中继仍是明文 UDP）。载体可能缓冲写入，因此每条握手消息与拨号阶段写出的 `early_data` 都在等待
  应答前 flush。`outbound/warm.rs` 为反复使用的节点预先拨好载体：新连接要先完成与节点的 TCP 与 TLS
  握手才能发出请求。节点在上一次拨号后 25 秒内再被拨号即算反复使用，此后每次取用或新拨都补拨到有两条载体在等；
  一条载体最多等 25 秒，交出前必须仍不可读（节点关闭、
  TLS 告警或任何未经请求的数据都说明它已不能承载请求），睡眠后全部作废，网络变化时连同正在拨的一起作废。
  载体在触发它的连接所在的执行器上拨号，可以交给另一个执行器上的连接（多队列捕获），这时它的 socket 改到
  接手方的 I/O 驱动上登记，连接的就绪事件不跨线程。节点进入反复使用后，在它最后一次拨号后的 10 分钟内一直留
  一条载体在等，每条在寿命的最后五分之一里由下一条接替：浏览一阵一阵，中间隔着阅读的停顿，停顿后的第一条连接
  因此不必再付两次握手。Trojan 经它拨号；写了 `dialer-proxy` 的节点不预拨，每条连接各自经链拨号。
  `outbound/hop.rs` 是链式代理（Clash 的 `dialer-proxy`，只用于出站）：节点经它指向的出站（节点或
  策略组）连到自己的服务器，向那个出站要一条到服务器的流，自己的协议原样跑在上面。名字在拨号时才
  解析，与路由出站一样经策略组及其状态，组的选择与健康决定每条新连接经哪一跳；解析为 DIRECT 就是
  本机直连。快照持有出站表、策略组与组状态，出口只持其弱引用（连接器会在自己起的任务里留出口的
  副本），并记着本次拨号已经过几跳：一次拨号最多经 8 跳，策略组只在解析时才可能构成的环因此在打开
  任何 socket 之前结束。上一跳的失败记作本节点的节点连接（目标解析失败记作节点地址解析）失败，配置与
  本机失败保持原阶段；只由节点组成的链在宿主列出节点时整体检查：指向不存在的名字、成环或经过 Core 不能
  连接的节点都标为不可用。节点的 UDP 经上一跳的数据报（`outbound/hop/datagrams.rs`）：节点照常封好
  每个数据报（Shadowsocks 的 AEAD 与 2022 包、SOCKS5 的 RFC 1928 §7 报头），由上一跳发往自己的服务器，
  服务器发回的包回到本节点解开；上一跳不承载 UDP 时这次拨号以配置阶段失败。SOCKS5 的关联只解析一次
  上一跳，控制连接与中继数据报走同一跳（负载均衡组解析两次可能各得一跳，代理会看到两个来源）；
  `BND.ADDR` 为通配地址时中继发往节点名字所指的主机，由上一跳解析。Trojan 的 UDP 走它的 TLS 连接。
  经上一跳的 Hysteria2 载体只拨一条 QUIC 连接（`protocols/hysteria2/hop_socket.rs`）：上一跳的数据报
  代替本机的 UDP socket，quinn 的包排队交给上一跳、上一跳的包排队给 quinn 读，每个包都记作来自拨号时的
  那个远端，quinn 不会把它们当成迁移了的路径；上一跳要再封装一次，socket 因此报告包可能分片，quinn 不做
  路径 MTU 探测，留在 QUIC 的初始包长；服务器的名字只由上一跳解析。这样的载体不竞速路径、不检查路径、
  网络变化时不迁移（都是上一跳的事），拨号时的上一跳一直用到它关闭；上一跳的数据报一断，quinn 的下一次
  读取失败，载体随即关闭，不等空闲超时。`outbound/hop/udp_tests.rs` 以本地服务器覆盖 Shadowsocks、
  SOCKS5、Hysteria2 节点经 Shadowsocks、Trojan、Hysteria2 上一跳的全部组合，并核对上一跳的服务器
  确实中继了这些数据报。`outbound/options.rs` 是按 Clash 别名读取节点协议选项的唯一实现。
  业务 TCP 目标由 `runtime/target.rs` 准备：经代理节点时原样提交一次，域名由节点解析，Core 不竞速、
  不换地址重放请求；DIRECT 由 Core 解析并在数值候选间竞速，只有赢家可以发送嗅探阶段已经读取的
  `early_data`，客户端前缀不能发送到多个候选。物理代理节点的连接竞速与业务目标是两层职责；DIRECT
  与物理拨号复用 `egress/dial.rs` 的候选调度，每个候选最多占用 8 秒，单次最多 4 个并发，整段受调用方
  总预算约束。DIRECT 的解析失败和本地策略拒绝不计入任何节点的健康。

  connector 在观察到失败的位置给出带阶段的结果（`OutboundStage`）：节点配置、本机、节点地址解析、
  节点连接（含 TLS/QUIC 握手与载体读写）、节点认证、节点协议、目标地址解析、目标。阶段本身决定证据
  归属，不解析错误文案：HTTP CONNECT 的 407 是节点认证，403 与 502–504 是节点对目标的答复；SOCKS5
  的 1–6 号应答是目标（许多服务器把目标连接失败报为 1 号），7、8 号是节点协议；Hysteria2 服务器拒绝
  TCP 请求是目标，认证状态非 233 是节点认证。egress 拨号只报告本机、解析或连接失败，候选调度报告各
  尝试的失败（区分出错与超时）、发起数、DNS 错误与是否耗尽预算，由调用方判断归属。被动健康据此计证：
  节点阶段计入节点失败，节点报告的目标失败记为节点成功，本机拒绝不作证据，连接预算超时仍计入节点。
  Hysteria2 服务器地址的竞速只因认证或配置失败结束。UDP 拨号失败按同一阶段记入传输诊断，节点阶段
  同样计入节点健康，未作答的拨号超时不计。连接结束原因以 `outbound` 原因携带阶段，界面按阶段显示。

  同一 Hysteria2 connector 的 TCP 流和 UDP 会话共用已认证的 QUIC 连接。该连接同样经
  `egress/dial.rs` 的候选调度在服务器的全部解析地址间建立，共用 10 秒预算；绑定 UDP socket 不代表
  服务器可达，尝试只在 HTTP/3 认证成功后才算成功，输家随其 endpoint 关闭，连接只记录赢家 socket 的
  出口绑定。每个地址的尝试同时从 3 个各自绑定的 socket 发起 QUIC 握手，先完成握手的一个去认证，其余
  随即关闭：网络按流的端口把流分到不同路径时，每个 socket 各得一条路径，载体就此留在最快的一条上，其上
  所有的流都按它的往返时间走。三条都慢、
  或之后路由变了的载体由路径检查换到快路径（`protocols/hysteria2/paths.rs`）：载体建立 5 秒后及此后每 5 分钟，
  从 3 个新 socket 各向服务器发一个它不支持的 QUIC 版本的包，服务器以版本协商包应答（[RFC 9000 §6](https://www.rfc-editor.org/rfc/rfc9000.html#section-6)，
  不需握手）；最先应答的路径往返不到载体的三分之二、且至少短 25 ms 时，载体迁到那个 socket，其上的流不断
  （迁移见下文 `egress/network.rs`）。底层连接断开后重建 socket/endpoint，仍复用该 connector 惰性构建的客户端配置及 TLS 会话/
  QUIC token 缓存。服务端是否接受会话恢复取决于票据及服务端策略；缓存不跨已编译 connector 或配置
  代次共享。

  一条 QUIC 连接上的代理 TCP 流轮流使用连接的发送空间（`protocols/hysteria2/turns.rs`，客户端与服务器
  两个半部都用）。quinn 只在连接级发送空间（对端的 `MAX_DATA` 与本端的发送窗口）有余量时接受写入；
  quinn-proto 0.11 把被拒的流压进一个栈，空间一释放就弹出全部并唤醒（`StreamsState::poll`），先运行的流
  拿走空间、其余重新排队，谁输取决于调度。Core 跑在一个工作线程上时最后被唤醒的任务先运行（Tokio 的 LIFO 槽），
  同一条流一再赢。现在被拒
  的流按先后排队，quinn 的唤醒只把流标记为已释放，最早排队的两条已释放流去写，每条写完或被拒后唤醒
  下一条（同时放两条，下一条的唤醒与上一条的写入重叠，一次释放出大片空间时不必逐个任务地填）；被拒的
  流保留位置，写成的流再写时排到队尾。quinn 只在流自身的流控额度未用完时报告可写，所以已释放的流仍被拒
  说明连接空间已经用完，它后面的流不再尝试，等下一次释放；只等自身 `MAX_STREAM_DATA` 的流不挡别人。
  每次释放只唤醒轮到的流，而不是唤醒全部等待的流。

  每条客户端连接独占自己的 endpoint 与 socket，只与一个服务器通信（`socket.rs`）。平台没有 UDP 分段卸载时
  每次发送就是一个报文，未连接的 socket 每发一个报文内核都要重新选源地址并检查路由（XNU `udp_output`），
  所以 socket 连接到服务器、发送不带地址，避免逐包重复选路。平台
  能分段卸载（quinn-udp 报告的分段数大于 1，如 Linux GSO、Windows USO）时沿用 quinn 自己的 socket。发送
  失败与 quinn-udp 一样只丢这一个报文：除了让 quinn 等待可写的 `WouldBlock`，其他错误（重负载上传时接口队列
  满的 ENOBUFS、已连接 socket 在下一次收发报出的 ICMP 错误 ECONNREFUSED）都交给 QUIC 当作丢包恢复，
  不结束连接或 endpoint。

  UDP 中继每个数据报一条 QUIC 数据报，放不下时切成带同一 Packet ID 的若干片，收方等齐各片才处理，缺片的
  数据报整个丢弃（[Hysteria 2 协议](https://github.com/apernet/hysteria/blob/master/PROTOCOL.md#fragmentation)）。
  收方只重组最近一个分片的数据报，另一个分片的数据报开始、或 Packet ID 前进 256 后仍缺片的即算丢失（发送方
  连续发出一个数据报的各片）；不然它会留到 16 位的 Packet ID 回绕，与重用这个 ID 的数据报的分片拼成错误的数据报。

  发送速率按 [Hysteria 2 协议](https://github.com/apernet/hysteria/blob/master/PROTOCOL.md#congestion-control)
  在认证时商定（`protocols/hysteria2/congestion.rs`）：客户端以 `Hysteria-CC-RX` 报出 `down`，服务器
  应答自己的接收速率。配置了 `up` 且应答不是 `auto` 时，连接在认证后以 `up` 与服务器速率中较小者固定
  速率发送（应答 0、缺省或无法解析都表示服务器不限速），否则保持 BBR；握手和认证总在 BBR 下进行。
  有的服务器在客户端没报 `down` 时一律应答 `auto`，所以只配 `up` 时上传仍可能是 BBR。BBR 下连接识别路径上
  的令牌桶限速器（`policer.rs`，依据 Linux 的 `net/ipv4/tcp_bbr.c` 的 long-term 带宽采样）：quinn 按拥塞窗口
  定节奏，每个往返放出 1.25 个窗口，BBR 的窗口是两倍带宽时延积；在排队的瓶颈前窗口会满、速率随之受限，限速器
  却把超出的部分丢掉而不排队，丢掉的包让出窗口，连接以估计带宽的约 2.5 倍发送。第一次丢包后开始采样，区间至少 4 个、至多 16 个往返，在丢包时结束；丢失超过送达的约五分之一、
  且连续两个区间的送达速率相差不过八分之一（或 4 kbit/s）时认定被限速，以两区间的平均送达速率发送 48 个往返，
  之后重新探测；应用没有数据可发时重新采样。固定速率按最近 5 秒丢失字节的比例上调以补发丢失的数据，最多
  1.25 倍，样本不足 50 个报文时不补偿。固定速率与限速器的速率都由连接独占的
  socket 上的令牌桶执行（`pacer.rs`，桶内最多存 4 ms 的发送量），而不是由拥塞窗口执行：quinn 每次唤醒
  只按窗口放出约 2 ms 的数据，按速率定窗口时，唤醒间隔一长发送就跟不上速率。窗口取速率在途数据的两倍，
  在途时间按数据从发出到确认或判丢实测，留出的余量给晚确认或尚未判丢的数据，不让它们挡住令牌桶；
- `protocols/openvpn/` — OpenVPN 客户端出站（只有客户端半部），OpenVPN 2.6 协议的现代子集，依据官方源码
  `release/2.6` 的 `src/openvpn`（`ssl.c`、`ssl_pkt.c`、`tls_crypt.c`、`crypto.c`、`reliable.c`、`push.c`）与线路
  协议草案（[openvpn-rfc](https://github.com/OpenVPN/openvpn-rfc) 的 `openvpn-wire-protocol.xml`）。节点的 `config`
  是 `.ovpn` 文件的路径（绝对路径，或 `~/` 开头即主目录下，同一份配置可用于各自在主目录下放同一位置的机器）。节点
  可用与否只按选项判断，不碰文件；文件在每次建立会话时于 Core 所在的应用进程里以用户权限读取，改了文件下一个会话
  生效。读取在阻塞线程池里进行：打开文件可能要等用户（macOS 上文件在“文稿”等受保护文件夹里时，`open` 等用户在
  系统弹窗里应允，见 [macOS](../platforms/macos.md#产品身份签名与服务安装)）。`config.rs` 只读这个子集：证书与密钥必须内联在文件里；只影响本机网卡、
  路由与脚本的指令跳过；线路行为不同的指令（压缩、tls-auth、tls-crypt-v2、静态密钥、TAP、fragment、OpenVPN
  自带的代理设置）使会话无法建立。文件读不到或不受支持时，经该节点的连接在配置阶段失败并给出原因。控制通道：tls-crypt（AES-256-CTR 加 HMAC-SHA256，标签兼作 IV，`crypt.rs`）包裹每个控制包，`reliable.rs`
  按编号确认、退避重传（起始为 `tls-timeout` 的 2 秒，至多 64 倍）并按序交付；其上是 TLS（rustls）：服务器证书只按
  `<ca>` 校验链、不比对主机名，再按 `remote-cert-tls server` 要求密钥用途与 TLS Web Server Authentication，按
  `verify-x509-name` 比对通用名；不发 SNI；Core 的 rustls 只编入 TLS 1.3，服务器需 OpenSSL 1.1.1 以上（OpenVPN 2.6
  的发行版都是）。TLS 之上先交换 key method 2（带用户名密码），首个密钥状态随后发推送请求、按 `push-continuation`
  收齐推送配置（地址、peer-id、数据加密算法、`tls-ekm`、ping、DNS 等，`exchange.rs`）。数据通道（`data.rs`）只用
  AEAD（AES-128/256-GCM、ChaCha20-Poly1305）：`P_DATA_V2` 带 peer-id，nonce 为包 ID 加密钥材料里的 8 字节隐式 IV，
  附加数据含操作码、peer-id 与包 ID，64 个包的重放窗口；数据密钥只由 TLS 导出器（`EXPORTER-OpenVPN-datakeys`）
  派生，服务器需 OpenVPN 2.6 以上（推送 `tls-ekm`），2.5 及更早所用的 TLS 1.0 PRF 派生不实现。服务器发起或到了
  `reneg-sec` 时重新协商：新密钥状态完整握手后换用新密钥，旧密钥再解密 60 秒。

  会话（`tunnel.rs`）由一个任务驱动：链路（`link.rs`：本机 UDP 或 TCP，或经 `dialer-proxy` 的上一跳的数据报或流，
  TCP 每个包带 16 位长度）、控制通道、数据密钥和隧道地址后的协议栈。链路的读前队列有 1024 个位子，另按字节
  封顶 2 MiB：包长按 16 位组帧，只数位子的话一千个位子会是 64 MiB，而这条链路承载的 1400 字节隧道用不到两兆；
  预算用尽时读的一方等隧道任务取走已排好的包，这是对服务器的回压而不是丢包。按推送的 `ping` 在空闲时发保活，
  `ping-restart` 内什么都没收到即结束，服务器的 `RESTART`、`HALT`、`EXIT` 也结束会话；同一节点的拨号共用一个会话
  （`connector.rs`），连续 5 分钟没有连接与关联时会话结束，下次拨号再建。会话（连同读文件）在自己的任务里建立，
  同一节点同一时刻只建一个，等着的拨号都等它；放弃等待的拨号把它留给下一个，而不是让下一个再建一个：没有
  `duplicate-cn` 的服务器在同一客户端的新会话连上时断开旧会话（OpenVPN 手册 `--duplicate-cn`），两个同时建立的
  会话会互相顶掉。没人等着的未建成会话、没有任何句柄的已建成会话都立即结束。结束时服务器接受就经控制通道发
  `EXIT`，否则按 `explicit-exit-notify` 发 OCC 退出消息，服务器随即释放地址。隧道地址后（`stack.rs`）TCP 由 Core
  自己的 TCP 引擎主动打开（见[捕获 TCP](#捕获-tcp)的主动打开；引擎 MTU 1400，加上数据通道与 UDP/IPv4 的头仍在
  1500 字节的路径内），UDP 每个关联一个本地端口、在本模块组帧，没有监听：VPN 一侧主动发来的 SYN 都得到 RST。
  任务每轮从链路取至多 48 个包，引擎每轮为每条收到数据的流确认一次，一个 ACK 因此至多约 64 KiB，与 Linux
  接收端的 GRO 聚合相当，减少确认包与用户态处理次数。经 TUN 捕获、路由到这个节点的 TCP 流同样由捕获引擎终结、
  在这里重新打开，本机这一跳的
  下行因此走 64 KiB 的段（上行是客户端按通告的 MSS 发的，至多 16 KiB）；把应用自己的包直接转进隧道时，应用
  的 TCP 只能用隧道的 1360 字节的段，会增加捕获设备上的包数与处理次数；utun 与 Wintun 没有分段卸载（XNU `bsd/net/if_utun.c` 与 Wintun `driver/wintun.c` 都不设卸载），上传也
  是这样。节点的流都经过它的会话：会话报告驱动它的运行时（`carrier_runtime`），捕获的流交给与会话同一执行器
  的队列（见[捕获 TCP](#捕获-tcp)）。
  目标是域名时经推送的 DNS 服务器在隧道里解析，与 VPN 自己的客户端一样；没有推送时按代理节点地址解析。凭据
  被拒记作节点认证失败，其余建立失败记作节点连接失败。OpenVPN 2.6 以上的真实服务器，以及 OpenVPN 2.7 的 UDP
  与 TCP 链路已验证握手、HTTP、推送 DNS、下载、重新协商与退出。`live.rs` 提供手动检查入口；`tests.rs` 以进程内服务器（rustls、tls-crypt、推送、数据通道，地址后是 Core 自己的
  TCP 引擎）在每次提交中端到端覆盖会话、TCP 与 UDP、名字解析、凭据被拒、`ping-restart`、放弃等待的拨号不另建
  会话，以及链式代理的两个方向：经 VPN 到达其后网络里的 HTTP 代理节点，和 VPN 自己的 TCP 链路经 HTTP 代理、
  UDP 链路经 Trojan 的 UDP 关联；
- `relay.rs` — 已建立连接阶段的中继步骤（私有模块）：将实时字节总数流式写入会话账本的计数复制，
  以及按会话设置的首个上游字节和空闲预算，用于清理可证实已停滞的中继（基于活动，不作为会话
  生存期）。TCP 双向复制（`relay/copy.rs`）沿用 Tokio `copy_bidirectional` 的状态机，每方向的
  64 KiB 缓冲只在字节在途时从 `buffer_pool.rs` 的共享池借用：读端挂起且已写空即归还，空闲连接不
  持有复制缓冲，池最多留 16 个待复用；DIRECT 和代理出站共用；复制缓冲不等同于内核 TCP 窗口；
- `tcp_flow.rs` — TCP 失败的类型化边界。`NativeTcpFlowError` 保留阶段、Core session ID、原始
  目标、恢复的域名、实际拨号目标、策略组/最终节点、规则及成功传输字节数；IO 原因保留客户端/
  上游、读/写/flush/shutdown、原始 `io::Error` 和系统错误码。`relay.rs` 的复制沿用 Tokio 双向
  复制的半关闭和背压处理，观测包装只在异常时记录出错端，不在每次成功 IO 上加锁。取消、策略
  拒绝和可确定的客户端 BrokenPipe/ConnectionReset 可作为预期结束；上游错误、预算超时、TLS 截断
  与未知原因报告故障。协议 connector 的失败带 `OutboundStage`（见 `outbound/`），连同全文在
  Dial 阶段保留，不从文本猜测出错端。失败回复写入出错
  不能覆盖原始拨号或路由故障。宿主在最终展示/日志边界才转成文本，不能匹配文案判断取消；出口目标
  限制由 `egress.rs` 的 `EgressPolicyRejection` 类型表达，TCP 拨号、主动探测和 UDP 每个目的地共用
  同一校验。该类拒绝在 connector 与节点健康计数前返回，不作为节点故障；
- `connection_termination.rs` — 连接结束事实。统一 TCP dispatcher 在得到真实结果时记录完成、
  取消、客户端关闭、路由/出口策略拒绝或实际失败，保留失败阶段与结构化原因；诊断文本限制为
  1 KiB。`SessionGuard` 退出只负责将该事实放入有界历史，不依据最后阶段或上传/下载字节猜测成功与
  失败。未报告结果时，已确认的取消记为取消，否则保持结果未知。完成/失败统计由明确终态累计，不能
  用准入拒绝数量代替连接失败数。遥测层将终态投影成连接状态，宿主历史收到迟到的真实结果时覆盖
  先前的未知结果；快照消失和代次替换本身不证明成功。连接详情展示该结束原因，不反向解析日志；
- `packet/` — 数据包管线：帧解析、[捕获 TCP](#捕获-tcp) 引擎（`packet/tcp/`）、非 TCP 执行器
  （UDP/DNS/ICMP）、[分片重组](#ip-分片重组)、[源分片](#源分片)与 `PacketDevice` 设备契约；泵本身在
  `device/pump.rs`，见[包设备与包泵](#包设备与包泵)。ICMP（`packet/icmp.rs`）只处理 echo：规则把目标
  （fake IP 按其域名）送往 DIRECT 时，由出口 guard 经物理上行发出（`EgressSocketGuard::echo`，各平台的
  实现见平台文档，Core 在阻塞线程上调用），4 秒内的应答按被 ping 的地址回给客户端，与上游 DNS 应答经
  同一个有界应答队列回到泵；guard 发不了 echo 时不中继。其余发往 fake IP 的 echo 在本地应答（后面没有
  主机，echo 也走不了代理），发往真实地址而经代理的 echo 与其他 ICMP 丢弃并计数；
- `udp.rs` 与 `udp/` — UDP 流会话表和中继。根模块是限额常量与会话、数据报的词汇；`udp/table.rs` 是会话表及其
  关闭、清扫与计数，`udp/entry.rs` 是一个会话的目标身份与它们共用或独占的传输，`udp/socket.rs` 是一条传输的
  发送邮箱与回包队列，`udp/send.rs` 是一个数据报的准入、路由与入会（`udp/preparation.rs` 是 fake IP 入会前的
  解析任务），`udp/reclaim.rs` 是满额时的让位，`udp/ready.rs` 与 `udp/drain.rs` 是就绪表与各路排空，
  `udp/pump.rs` 是包泵自己发送的已建立的流；`udp/actor.rs` 独占每个 transport 的建连、收发和终止。会话表最多
  1024 项、空闲 120 秒回收（[RFC 4787](https://www.rfc-editor.org/rfc/rfc4787) REQ-5：映射空闲不到两分钟不得
  过期）；空闲清扫由发送与各路排空触发（包泵的、以及认证 face 自己的——
  face 的排空与它的连接同寿，所以没有捕获、只服务 face 的主机也在扫），每秒至多一次。会话表满额或全 Core 的关联配额用尽时，已结束的交换让位：
  没有 socket 还在收发、也没有名字在解析的会话，只有名字在往传输路上走、什么回包也没有过、而这份准备已经超过
  10 秒的会话（一个可用的名字在 DNS 预算内就解析完、一个可达的节点远不到一秒就答复拨号；让新来者被拒才是突发
  新流时稳定的做法，所以这一让位要等过可能还会成功的准备），或者流量在开始后 2 秒内结束、最后发出的数据报
  已有回包或已等了 2 秒的会话，按
  最近活动从早到晚一次回收一批（256 个，仍满就继续），被回收的关联当即关闭并交还配额，它们的 actor 由会话表锁外的
  独立任务中止并释放（中止任务要调度它，释放会话会关掉 actor 的邮箱，都不必占着多个队列的包泵共用的会话表锁）；流量持续超过 2 秒的流与有回包
  待交付的会话保留到空闲回收，没有可回收的会话时拒绝新会话。会话记下最近一次回包时已发出的数据报数，此后再发
  的数据报要等到自己的回包：客户端在同一源端口上开始新的交换（新 socket 复用了刚关闭的端口）时，旧交换的回包
  不会让会话在新回包到达前被回收。准入平时只整理本会话已结束的 socket，满额时才扫描全表。一次没找到可回收
  会话的全表扫描会沿用 50 毫秒，期间会话数与空闲关联配额都没变则直接拒绝、不再扫：这把扫描从每个数据报一次
  降到每秒至多二十次，而被拒的数据报本来就是丢的、UDP 客户端会重试。两个计数都没变也要受这 50 毫秒的限，因为
  一个 socket 结束后要等扫描去剪才交还配额，这两个计数都看不出来。一次性交换可及时交还表项与 socket。actor 把回包放进自己的队列后，把 socket 登记到会话表的就绪表（已登记则不重复），
  结束或被替换时也登记一次以便释放；排空只访问就绪表里属于自己的 socket，每个 socket 每轮取一个，
  使繁忙的流轮流交付，因此一次排空的代价随待交付的回包而不随打开的会话数增长。被捕获的数据报带着读到它的
  捕获队列（`UdpDatagram::pump_queue`），它打开的会话登记到该队列包泵自己的就绪表，只由这个包泵排空，同一会话
  之后的数据报从哪个队列进来都一样；队列数比上一次捕获少时，留在已经没有包泵的下标上的会话由第一个队列的
  包泵接手（那些就绪表不丢弃：套接字自己持着它，从表里拿掉只会让之后的登记没人看），否则客户端照旧发包却
  再也收不到回包，直到会话空闲；认证用户的会话登记到这个用户自己的就绪表，一条回包因此只唤醒这个
  用户的排空、也只被它自己的流走一遍，而不是每条回包唤醒节点上所有连接的排空、各自再把整张表重扫一遍；
  没有用户的会话（本机捕获、环回的 SOCKS5 关联）留在会话表自己的就绪表上。各自的消费者按 flow 前缀
  排空，过滤发生在取出 actor 响应之前，不会先消费别人的响应再丢弃。通用 flow 的排空、owned endpoint 的 owner 队列与认证
  datagram face 的用户/前缀消费边界分别保留。一次读取里被平台黏在一起的
  数据报（Linux 的 GRO）按输出队列为一个数据报留的帧数切成若干列车，而不是一列：队列按帧记账，装不下的
  列车只能整个丢掉，而一次读取里有多少个数据报是平台定的。排空上限按"即使每个都最大分片也装得下的数据报
  数"算，一趟返回的数据报可以多于它（一次读取就是一列车），仍然装得下：一列车至多带那么多个，而一批在
  第一个越过上限的回包处停下。改成按帧给上限（一趟就能把队列填满）反而更慢——排空每轮每个 socket 只取
  一个回包，上限越大轮数和 await 越多。会被丢满的两个队列——每条会话的发送邮箱（64 个数据报）与一份
  准备期间待发的数据报（同样 64 个）——同时按字节封顶（各 512 KiB）：一个被捕获的数据报经分片重组后可达
  65 535 字节，只按个数封顶时，一千个关联对着一个停滞的传输就能让这些队列到 GB 量级。回包队列不在此列，它
  满时停住接收半边，让上游 socket 的缓冲填满、内核在源头丢包，这才是 UDP 对端该看到的。发送上丢掉的
  数据报都记进同一个计数（`udp_send_drops`）：套接字缓冲没地方、邮箱没地方、一列车传输只收了一部分
  （剩下的按个数计）、以及等一个最终没解析出来的名字时排着的那些。

  被捕获流的关联在传输建立后，凡是包泵能驱动的传输（`PumpDatagrams`：发送不等待、
  回包可读时唤醒它；DIRECT 的 socket、Shadowsocks 与 SOCKS5 的 UDP socket、Hysteria2 的 UDP 会话）都交给包泵，actor 只发包泵转来的
  数据报：每个数据报原本要在 actor 与包泵之间交接两次（下行收包后交给包泵，上行由包泵交给
  actor），每次都要唤醒另一个任务，码率低时攒不成批，唤醒的成本全落在单个包上。包泵记下已建立的
  流（客户端端点与目的地址到身份所在传输的映射，最多 4096 条），之后的数据报不再路由、不经 actor 和邮箱，
  直接交给传输发出（发往身份绑定的数值地址；交给节点解析的名字照样按名字发）。包设备把客户端
  socket 一次发出的一串数据报整串交来时（`ReceivedPacket::udp_segment`，Linux TUN 的 `GSO_UDP_L4`），记下的流
  整串交给传输（`PumpDatagrams::try_send_train`）：DIRECT 在平台的出口守卫能分段发送时一次发出
  （`EgressSocketGuard::send_segmented`，Linux 的 `UDP_SEGMENT`），否则与其他传输一样逐个发出；没记下的流的
  列车，以及同一条流此前的包还在等归因、或在同一批里排在前面时，切回各个数据报排在那些包后面走完整路径。传输有回包时它的就绪唤醒把会话登记到就绪表，包泵排空时在每个会话上一次读至多
  32 个数据报，按回复身份换成客户端看到的源地址后直接组成发往客户端的包。平台的出口守卫能合并接收
  （`EgressSocketGuard::coalesce_datagrams`，Linux 的 `UDP_GRO`）时，同一来源一起到达的数据报一次读出；
  包设备接受 UDP 列车（`PacketDevice::sends_udp_trains`，Linux TUN 的 `GSO_UDP_L4`）且每个数据报连同头部
  不超过 MTU 时，整批写成一帧，由操作系统切开，否则逐个组包。经策略组的路由，包泵记下流时组解析到的
  出站必须仍是该传输的出站；组状态的版本（选择、UrlTest 改选、驱逐与解除都会推进它）变了，或者到了
  那次解析答案的期限（见 `policy_group.rs`），这条流就回到完整路径重新解析，这样切换节点后流会改走新节点；
  选择不变时流不再解析，此前每条经策略组的流每秒都要回完整路径解析两次。
  会话关闭、退役、actor 结束或出口策略取消（配置切换都会经过其中之一）后，包泵记下的流失效，下一个
  数据报回到完整路径，建立新的关联。记下的流至多 4096 条，满时按最近使用情况忘掉最旧的 512 条——
  一次扫描摊到一批新流上，而不是每条新流一次。整表忘掉会让一个疯狂建流的客户端（BitTorrent 的
  对端扫描每几秒就填满一次）连带毁掉机器上其他应用的快路径，每条被忘掉的流的下一个数据报都要
  重新查归属、重走路由、再走一遍会话表。SOCKS5 的关联只与它的控制连接同在（RFC 1928 §7），包泵驱动它时 actor 仍守着
  控制连接（`OutboundDatagramReceiver::ended`），代理关闭控制连接即结束会话。包泵自己发出的数据报计数在会话上，读会话统计和判断空闲时并入。
  包泵记下的流的数据报不查进程归因，路由读取进程时也是：路由已经固定，归属在流建立时已记下。此前路由读取
  进程时每个数据报都要查一次，而归属的缓存只留 250 ms，间隔更久的数据报（每秒一次的 STUN、保活、DHT）每个都
  触发一次进程扫描并被扣住到扫描结束，列车也被拆开逐个发出。
  DIRECT 的 actor 与包泵都直接以非阻塞 `sendto` 发出数据报，只在缓冲区满时才等 socket 可写：新 socket
  在反应器里的就绪状态起初为空，经反应器的发送会让关联的第一个数据报等到反应器下一轮，包泵在那之前
  接手的数据报则会被当作缓冲区满丢掉。DIRECT 不给流配连接的 socket（连接后每次发送约省三到六成）：要保持
  端点无关映射，它得与未连接的 socket 共用端口，两者都要设 `SO_REUSEPORT`，而 XNU 的 `in_pcbbind`
  （`bsd/netinet/in_pcb.c`）对都绑通配地址的这类 socket 不比较 uid、绑具体地址时只拒绝其他 uid，
  `in_pcblookup_hash_locked` 又把单播数据报先交给绑了具体本地地址的 socket，同一用户的任何进程都能借此接走
  经 TUN 的 DIRECT UDP 回包；Linux 的 `SO_REUSEPORT` 同样接纳有效 uid 相同的进程
  （[socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)）。包泵也不把逐个发送的客户端在一轮里连着
  读到的等长数据报合成一次分段发送：低速时难以成批，高速突发则可能挤占设备接收队列。

  TCP/UDP 共用出站建立的 30 秒总预算，UDP 每次本地 transport 写入
  最多等待 10 秒。sender 明确声明发送取消语义：原子报文超时只丢当前包并保留映射，可能半写的载体
  帧超时才结束该子 transport，避免复用已经损坏的帧边界；两种情况都不重发数据。UDP 保持允许丢包和
  乱序的语义，不增加确认、重传、保序或补包；接收端不设置等待回包的故障超时，空闲会话回收也不代表
  对端故障。关闭或策略取消不记故障，真实错误以阶段、原因及最多 16 条近期记录通过
  `CoreStateAudit.udp_transport` 暴露，单条诊断最多 1 KiB；只有拨号失败在节点阶段时才计入节点
  健康（见 `outbound/`），发送与接收错误不计；
- `udp/association.rs` — UDP 回复身份。Egrio 只保证不成为打洞的阻碍：同一客户端 socket 经同一出站的远端共用
  一个映射（EIM，[RFC 4787](https://www.rfc-editor.org/rfc/rfc4787) REQ-1 的 MUST），任意远端的回复都送达（EIF，
  REQ-8 为透明性推荐的过滤）；不检测 NAT 类型，不实现 STUN/ICE，打洞能否成功取决于上游的 NAT 与节点。packet
  入口将客户端原始数值目的地址交给 UDP 核心；UDP 核心
  在路由/DNS 富化前保存该地址，再分别保留逻辑域名和客户端可见的 fake IP，回包使用原 fake IP 作为
  源地址。一个客户端的目标分成身份：全部真实地址是一个，每个 fake IP 连同它代表的域名是一个（同域名
  不同端口复用）。每个身份各自路由，路由在它存续期间固定；经同一出站的身份共用一条传输（DIRECT 的
  socket、节点的一个 associate），所以经名字问 STUN 与按地址连对端的数据报出自同一个映射（EIM）。
  fake IP 的身份先按出站的 Core DNS 策略把域名解析成确定的数值地址，再加入传输，在传输的回复表
  （`ReplyTable`）里认领这个地址；解析在独立任务里进行并占一个关联配额，其间它的数据报按序在身份里
  等候（至多 64 个），准入从不等 DNS。只有来自被认领地址或明确域名的回包换成 fake IP，始终保留真实
  源端口，未知对端原样送达。认领不重叠：解析到的地址已被同一传输上的另一个身份认领时，这个身份另开
  一条传输，每个回包仍回到发往它的身份；真实目标恰是被认领的地址时，它的回包按 fake IP 送达。身份
  被取走时它的认领也从回复表里取走（传输留给其他身份时也一样）：留下的死认领会一直占着那个地址，
  同一域名之后解析到那里就不能再共用这条传输，于是另开一条私有的，客户端的映射不再是端点无关的。严格
  全局模式下名字经全局出口向配置的服务器解析，照样加入共用的传输；只有系统来源时名字交给节点解析
  （数据报帧里的名字不可靠：有的服务器只解析 associate 请求里的名字，见上文 `trojan/`），每个 fake IP
  的身份各开一条传输、由首个回包认领地址，不与真实地址共用映射。已建立的身份固定其数值目标；
  DNS TTL 约束后续新身份的解析缓存，不自动迁移活动 UDP 映射。客户端流与子传输分别拥有生命周期，单个
  传输或解析失败不结束其他身份，后续新报文可重新准入失效身份但不重放旧包；每个客户端最多 64 个身份，
  全 Core 最多 1024 个关联配额（每条传输与每个解析中的身份各占一个），而 1024 个会话项里有 256 个只留给本机
  捕获：认证数据报 face 的客户端自己决定帧里写哪个来源，face 又给每个自称的来源一个独立的 flow id，于是一个
  用户的帧各自成一项会话，按会话键算的"每客户端 64 个身份"永远聚合不到它们——没有这份保留时，一个已认证
  用户就能占满会话表，本机每个应用的 UDP、包括经隧道的 DNS 全被拒。这份保留只隔开本机与入站，不隔开
  入站的用户彼此，所以每个已认证用户另有 64 项会话的绝对上限（按用户持有量除出来的份额做不到：它只在
  一个用户已经占完余量之后才生效，而那时新来的用户已经被拒了）。这个计数随会话的增减维护——每条删除
  路径本来就要走一遍全表，计数跟着它走；准入时现算会在洪水的每个数据报上扫一遍全表。
身份还不存在、而路由停在 IP 规则的
  数据报不能等在准入里（发送路径从不等 DNS），它在自己的任务里攥着载荷等名字解析完，所以这类等待的数据报
  全 Core 最多 256 个，超出即丢并计数：否则一个向 fake IP 以每秒一万个数据报推流的客户端，在 5 秒的 DNS
  预算里能有五万个数据报同时活着，而解析完它们一起涌向只装 64 个的邮箱，结果照样是丢。关闭客户端时取消并等待全部子
  任务及内存许可释放。配额由 transport task 与传输对象共同持有，包含已经结束但仍有有效回复待排空的
  对象；满额时只回收会话表认定已结束的交换（见 `udp.rs`），不清掉未交付的回复或仍在进行的流。`outbound/datagram.rs` 保留原生 UDP
  socket、载体及协议错误的不同来源；原生单报文发送失败（包括报文过大）不撤销映射，TLS/QUIC 载体
  错误不套用这一规则，错误后让出调度而不重发数据。DIRECT 每地址族最多一只未连接 socket，先注册
  接收通知再读取 socket 槽，以保持 EIM/EIF 并避免惰性创建另一族时漏唤醒；
- `udp/target.rs` — 数据报的业务目标准备。显式域名在发送前查询同一 Core DNS 缓存，遵循实际 TTL；
  连接器与首包共用首次解析，零 TTL 不会触发首包双查。后续域名报文可以取得新的地址，同时保留端点
  独立映射和真实回复来源。DNS 失败只丢弃当前报文，不将尚未写入载体的解析失败视为半帧写入；真实
  IP 不查 DNS，代理携带的 IPv6 目标不受本机 IPv6 出口开关误伤。解析器弱引用 DNS 代次，空闲关联
  不延长旧规则生命周期；
- `target.rs` — 入站目标解析（私有模块）。IP 与 zone 使用同一解析定义；带作用域的 IPv6 保持 IP
  分类、方括号和 zone，不能降格成域名。进入本机拨号前，平台/调用方须将接口名解析为数值 scope；
  Core 不将未规范化 zone 交给 DNS。zone 属于本节点，远端代理协议没有其表达能力，因此带 zone 的
  目的地只能在用户路由选择 DIRECT 后本地处理；不会自动改写用户路由或静默丢弃 zone。依据为
  [RFC 4007 §11.2](https://www.rfc-editor.org/rfc/rfc4007.html#section-11.2) 与
  [SOCKS5 地址格式](https://www.rfc-editor.org/rfc/rfc1928.html#section-5)；
- `sniff.rs` — 首轮数据域名嗅探，端口门控且受预算限制（私有模块）。普通真实 IP 仅在规则需要域名
  时嗅探，TLS SNI/HTTP Host 只补充路由上下文，不改写已有数值拨号目标。浏览器独立 DoH 或旧 DNS
  缓存产生的真实 IP 已在进入 Core 前确定，Core DNS 配置不能事后重写这些地址，也不承诺纠正未配置
  上游时已有的错误解析结果。缺少当前映射的 fake-range TCP 目标不论分流模式均尝试读取 TLS SNI/HTTP
  Host，并将成功恢复的域名用于路由和实际拨号。无法识别域名时拒绝该虚拟目标，不拨号到假 IP，也不
  保留旧配置或连接；
- `session_registry.rs` — 实时 TCP 中继会话账本：准入上限、取消树、按出站终止，以及用户切换时用
  已记录的路由输入重新匹配。结束的会话留在最近 512 条的记录环里，宿主按序号游标取走新增的
  （`traffic_telemetry_since`）。会话账本与 UDP 会话表携带已认证的 `user`，`PerUserTraffic` 按用户折叠
  两者的实时只读视图（`CoreSessionManager::per_user_traffic`），表示当前用量而非累计账单，累计由
  宿主负责；
- `watchdog.rs` — 事件循环停滞 watchdog；是否生成由宿主决定；
- `device/` — `NativeCoreDevice` 生命周期所有者，方法按职责分文件：`mod.rs` 是状态、报告、生命周期
  （`start`、`close`、`status`）与会话钉住的策略快照，`compile.rs` 把配置、出口与捕获编译成设备，
  `config.rs` 替换运行中设备的配置并切换旧连接，`flows.rs` 是一个包、一条 TCP 流、一个 UDP 数据报进入的入口，
  `captured_tcp.rs` 是各捕获队列的 TCP 引擎、它接受的流与隧道解析器地址上的 TCP DNS，`pump.rs` 是包泵，
  `health.rs` 是健康探测，`policy.rs` 是局部策略更新，`telemetry.rs` 是只读投影。`close()` 是终态：`SessionRegistry::close` latch
  住 `closed` 并取消一次性 root token，没有 reopen，所以重启会得到一个半活设备（放行 UDP 并向上游
  拨号，同时拒绝每条 TCP 会话，发出的 token 出生即取消）。需要在 close 后继续工作的调用方应编译
  新设备，Runtime 的逐代次 Core 即如此。`evaluate_route` 复用当前路由快照及策略组选择/健康状态，
  返回命中规则和最终节点；局部策略通过 `device/policy.rs` 的 prepare/apply 和精确旧 epoch
  retirement ticket 更新，不能以 `close()` 代替策略切换；`preview_route` 只编译保存的配置，不启动
  设备或后台探测；
- `runtime.rs` — 已编译的 `NativeCoreRuntime` 状态、分派助手和 `CoreRuntime` 门面；
- `egress.rs` — 物理出站 socket/绑定/DNS 服务器策略，以及每个物理出站 socket 都会连同其地址族/
  远端上下文经过的 `EgressSocketGuard` 连接前 hook；各平台以接口绑定、socket mark 或
  `VpnService.protect()` 实现，见平台文档。guard 在配置档案热应用期间随设备持久存在。桌面 Core
  跨越多个 TUN 会话，guard 因此按其平台 TUN 层当前是否活动来保护，并经 `capture_overlay()` 报告
  只在 TUN 活动期间成立的 `CaptureEgressOverlay`：捕获前的物理解析器与 TUN 的 IPv6 姿态。出口解析
  与拨号每次读取：活动时用 overlay 的解析器，且 IPv6 取启动配置与 overlay 的交集；未活动时回到
  启动配置，空解析器列表即系统解析器。原生 UDP 用完整报文大小（64 KiB）的接收缓冲，DIRECT、
  Shadowsocks 与 SOCKS5 的关联在 socket 可读后才从共享池借一个、读完即还（池最多留 8 个），等待
  回包的关联不持有缓冲。所有出站 UDP socket（含
  Hysteria2 的 QUIC socket）以及服务端 Hysteria2 与 Shadowsocks 的 UDP socket 都把内核收发缓冲
  请求到 8 MiB：取走报文的任务没在运行时，到达的报文在接收缓冲里等待，放不下的部分被内核丢弃，
  QUIC 把这种丢包当成拥塞而降速。Windows 给 UDP socket 的默认值是 64 KiB，只装得下高速 QUIC
  下载不到 1 ms 的流量，而 Wi-Fi 成批交付帧；8 MiB 在 1 Gbit/s 下约容纳 60 ms。被宿主拒绝的值
  逐次减半到 1 MiB；Linux 把请求静默封顶于 `net.core.rmem_max`/`wmem_max`，macOS 封顶于
  `kern.ipc.maxsockbuf`；宿主已有的更大值保留，发送缓冲至少 65536 字节。宿主接受过的大小记在进程里，
  之后的 socket 直接设置它，只在被拒时重新逐级减半；发送缓冲能容纳最大数据报这一点也只核对一次，所以
  每只新 socket 复用已有的缓冲设置结果。只设置当前 socket，不改
  系统参数。多目标 socket 的 guard 使用 `multi_destination(family)`，不继承首个 loopback 目的地
  的豁免。依据为 [Winsock SO_RCVBUF/SO_SNDBUF](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options)、
  [Linux socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)、
  [Apple XNU `sbreserve`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket2.c)、
  [socket2 缓冲 API](https://docs.rs/socket2/latest/socket2/struct.Socket.html#method.set_recv_buffer_size)、
  [Apple XNU UDP socket reservation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/udp_usrreq.c)
  和 [Tokio UDP 发送取消保证](https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html#method.send_to)。
  出站 TCP socket 在连接之前比较宿主的固定缓冲上限与自动调节上限：前者更大时使用固定缓冲、最多 32 MiB，
  否则交给宿主调节，避免用较小的固定值关闭自动调节。两个上限从宿主读取一次，不修改系统参数。macOS 读取
  `net.inet.tcp.autorcvbufmax` 与 `kern.ipc.maxsockbuf`；固定缓冲会清除 `SB_AUTOSIZE`（`sosetoptlock`），
  `sbreserve` 把请求限制在 `sb_max` 内，连接时由 `tcp_get_max_rwinscale` 确定窗口缩放。自动调节的增长依据
  `tcp_sbrcv_grow`，丢包后的速率下降可能让缓冲停在较小的尺寸。Linux 从 `tcp_rmem`、`tcp_moderate_rcvbuf` 与
  `net.core.rmem_max` 读取限制，按相同规则选择；固定接收缓冲受 `net.core.rmem_max` 约束并锁住自动调节
  （`sk_setsockopt`、`__sock_set_rcvbuf`）。Windows 未读取这两个上限，沿用系统调节。发送缓冲保持
  宿主行为，固定接收缓冲不能代替发送方的拥塞控制。依据为
  XNU 的 [`uipc_socket.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c)、
  [`tcp_subr.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_subr.c) 与
  [`tcp_input.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_input.c)，Linux 的
  [`tcp.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c)、
  [`tcp_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c) 与
  [`sock.c`](https://github.com/torvalds/linux/blob/master/net/core/sock.c)，以及
  [Windows 的接收窗口调节](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-tuning-nics#tcp-receive-window-autotuning)。
  所有出站 TCP 连接关闭 Nagle 并开启 keepalive：空闲 60 秒后探测，之后每 15 秒一次，直到对端应答或系统放弃
  （次数取系统默认）。被捕获客户端自己的 keepalive 探测终止于 TUN 的 TCP 引擎、由引擎应答，到不了上游，空闲的
  上游连接因此一个包也不发；运营商 NAT 远早于 [RFC 5382](https://www.rfc-editor.org/rfc/rfc5382.html) REQ-5
  要求的 2 小时 4 分钟就丢弃空闲映射；此后服务器推送的数据石沉大海，客户端却仍以为连接在。依据
  [socket2 `TcpKeepalive`](https://docs.rs/socket2/latest/socket2/struct.TcpKeepalive.html)。
  入站接下的连接按同样的参数设这两项。出站的 keepalive 只能证明**上游**还活着：客户端不发 FIN 就消失、
  上游又安静时（SSH、空闲的 IMAP），两个套接字都不报错，会话会在 Established 里坐满中继那一小时的空闲
  预算，占着一个登记位、一个监听器许可和两个套接字，账本也不标它（下行有过字节）。
  TCP 拨号仅在配置了 guard 时创建独立绑定记录器；无 guard 时直接借用运行时的出站配置及 DNS 缓存，
  避免逐连接克隆配置和分配空记录器。`egress/resolver.rs` 是物理解析与按用途选择 DNS 的适配入口，
  复用 `dns/wire.rs` 与 `dns/cache.rs`。查询在 5 秒预算内按 250 ms 错峰，最多四路并发、单服务器
  最多 2 秒。A/AAAA 请求仅查询自己的记录族，AAAA 先发。`egress/dial.rs` 将逐族解析结果直接送入
  TCP 调度，后到的地址族仍可参与：A 先到而 AAAA 未到时，首次尝试最多再等 50 ms，其间到达的 AAAA
  排在未尝试的 IPv4 之前，系统解析器一次给出的两族地址保持系统的顺序。这样两族都有应答时先试
  IPv6，与不经 Egrio 时操作系统的选择一致；IPv6 不通时最多多等一次 250 ms 的间隔，立即失败时只多
  10 ms。候选交错发起，最多四路并发、间隔 250 ms，硬失败将下一项等待缩至至少
  10 ms，解析和拨号共用 16 秒总预算，单地址最多 8 秒；另一族解析未结束时预留一个并发位置。到代理
  节点的拨号对每个地址还会补发一次：同一出口策略下到该地址最快一次握手的 1.5 倍（至少多 25 ms）过后仍未
  连上，就从另一个 socket 再连一次，先连上的留下、另一条丢弃；还没见过握手的地址一开始就同时连两次（本机、
  链路本地与私有地址只有一条路径，只连一次），最快的一次 10 分钟后可被更慢的取代。另一个源端口在按流分路径的网络里另有一条路径，而 TCP 连接的路径在握手时定下、沿用到
  连接结束。SYN
  丢失时也只多等到补发点，不必等重传超时。为以后的连接预先拨的载体（`outbound/warm.rs`）没有连接在等，
  握手超过补发点的（两次尝试都落在慢路径上）丢弃重拨，至多两次。
  Trojan 的 UDP 关联在会话存续期间一直用同一条连接，路径比片刻的等待要紧，没有预先拨好的载体时也这样拨。
  DIRECT 目标地址繁多、少有重复，不补发。通用
  地址集合查询收齐结果或到达查询预算后保持 IPv4 优先，单地址 UDP/QUIC 消费者不会因 DNS 抵达顺序
  改变地址族选择。赢家独占物理绑定记录，取消或成功立即丢弃其余请求拥有的 future/socket，不留下
  后台拨号。查询顺序、50 ms 的 Resolution Delay、错峰与地址族交错依据
  [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html) §3–5，IPv6 在前依据它引用的
  [RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.html)（§6 规则 6 比较 §2.1 默认策略表的
  优先级，IPv6 为 40、IPv4 为 35），不宣称实现其完整地址排序与历史延迟策略；DNS 依据为 [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html)
  与 [RFC 2181 §8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8)。`egress.rs` 还持有
  服务端组合的开放代理安全底线（`refuse_private_destinations`）：宿主启用后，两处拨号漏斗会在解析
  后拒绝 loopback/private/link-local/unique-local/unspecified/multicast 目标（默认关闭，客户端
  通常可以拨号私有目标）；
- `egress/network.rs` — 网络变化搁浅了什么。guard 经 `network()` 发布它观察到的物理网络
  （`EgressNetwork`：各地址族新拨号绑定的上行接口，以及各物理接口的地址），调度循环把前后两次的差异
  交给 `NativeCoreDevice::apply_network_change`。只收不发的连接没有要重传的数据，发现不了本地地址已经
  消失，只能等客户端放弃；所以本地地址不再存在、或所绑接口已没有该地址族地址的连接（TCP 会话与 UDP
  关联，出口记录在拨号时连同本地地址一起盖章）立即结束，客户端随即经现有网络重连，其余连接照常（插上
  网线时 Wi-Fi 上的连接不断）。Hysteria2 的载体（QUIC 连接）则随网络迁移（[RFC 9000 §9](https://www.rfc-editor.org/rfc/rfc9000.html#section-9)）：
  变化搁浅了它的 socket、或它所绑的接口不再是该地址族新拨号的上行时，载体换到经 guard 在当前上行上新绑定
  的 socket（quinn `Endpoint::rebind_abstract`），服务器验证新路径后把新地址当作客户端地址，其上的流与
  UDP 会话不断。新 socket 的路径同样是抽签，所以服务器应答过路径探测时，载体在 3 个新 socket 中取最先应答的
  一个；服务器从不应答时不探测，免得每次迁移都等满探测的时限。连接到服务器的 socket 保留连接时得到的源地址，所以载体的出口记下这个地址，地址消失即算
  搁浅；未连接的 socket（有分段卸载时）每个报文由内核选源地址，同一接口换地址时自己跟上。流与 UDP 会话的
  出口只记载体的接口、不记本地地址，不随变化结束。无上行可迁时载体暂停、不给新拨号，下一次带来上行的变化
  再迁，等不到就由 QUIC 空闲超时（30 秒）关闭。缓存的 DNS 应答随之清空：新网络的解析器可能给出不同的
  地址；变化之前发出、之后才收到应答的查询只回给等它的调用方，不进缓存。之后清空旧网络上得到的健康记录并
  重探全部节点，用户的选择保留。guard 没有 `network()` 时没有这些
  处理；
- `suspension.rs` — 察觉主机睡过。`Instant` 与 Tokio 的定时器在 Apple 平台（`CLOCK_UPTIME_RAW`）与
  Linux（`CLOCK_MONOTONIC`）上不计睡眠时间，墙上时钟照走，两者之差因此增加睡眠的长度（阈值 10 秒，
  大于醒着时校时的跳变）。睡眠期间该到期的东西在唤醒后还要再拖那么久：服务器早已丢弃的 Hysteria2
  载体要等醒着的空闲超时才关闭，DNS 应答超过 TTL 一整夜。所以睡眠之前建立的载体不再复用、之前缓存的
  DNS 应答作废，调度循环醒来时察觉睡过就按一次网络变化处理（不搁浅任何连接）。睡眠计入单调时钟的平台
  上这些定时器照常到期，这里不会触发；
- `capture.rs` — 捕获时契约：MTU、DNS 劫持捕获配置与 Fake-IP 地址冲突校验；
- `attribution/` — 本机连接的进程归因，见[进程归因](#进程归因)；
- `status.rs` — `NativeCoreState`/`NativeCoreStatus` 与替代端口记录 `ListenerFallback`；
- `self_test.rs` — 测试与服务端互操作使用的协议客户端/回显助手，以及仅测试编译的端到端场景；
- `telemetry.rs` — 流量遥测快照。连接行包含入站面（`tun`、`http-connect`、`http-forward`、
  `socks5-connect`、`udp-associate` 及加密协议入站）、进程、匹配规则、选定出站、出口接口、字节计数
  与状态；被 REJECT 的连接同样记录进程、规则与 REJECT 出站。匹配规则记的是配置里写的那一行
  （`RouteRule::text`，如 `DOMAIN-SUFFIX,example.com,Proxy`），路由决策的 `matched_rule` 同此：一条规则说的
  是什么不随它周围的列表变化，而宿主给它的 id 往往只是它在某一版列表里的位置；出口是这行的一部分，因为只在
  出口上不同的规则是不同的规则（一条承载不了的流会走到下一条）。行里的文字是共享的（`Arc<str>`）：实时 TCP
  会话的行拿的就是会话账本自己的字符串，读一次连接表不复制它们，留着行的宿主（历史、显示历史的表）也
  只是多拿一个指针。`TrafficVolume` 是 Core 自启动以来的
  上下行字节总量：TCP relay 与 UDP 会话在计入各自字节的同一处累加，只增不减，速率是它对时间的差分；
  快照的 `upload_bytes`/`download_bytes` 即此值，新的 Core 代次从零开始；
- `packet/probe.rs` — 进程内确定性探针：UDP 端点独立映射与过滤（RFC 4787 EIM/EIF，含经名字（fake IP）与经地址的远端共用映射、未联系过的
  远端回包）以及任意 UDP/53 的 DNS 劫持与 Fake-IP 反查，不依赖宿主网络状态。

## 包设备与包泵

平台设备实现 `egrio_core::PacketDevice`：`try_recv` 交来一个完整 IP 包或客户端一次发出的一串 UDP 数据报
（`ReceivedPacket`，见 [UDP](#模块布局) 的 `udp.rs`），`try_send` 只搬运完整 IP 包，两者从不阻塞，
`try_send` 满时返回 `Full`；`try_send_parts` 把 TCP 引擎一个段的头部与若干载荷片作为一个包发出，Linux 与
macOS 以 `writev` 写 fd，Windows 把各片直接复制进共享环的槽位，默认实现拼成一块再发。引擎写出的段头里
TCP 校验和只含伪首部和；设备报告 `completes_tcp_checksums` 时由其 OS 补全（Linux TUN 的 virtio-net 头，见
[Linux 平台](../platforms/linux.md)），否则泵在段进入输出队列时补全。`ready(interest)` 是
唯一等待点，由各平台以官方就绪机制实现（Unix fd 使用 Tokio `AsyncFd`，Windows 共享环使用服务端
事件）。泵在无事可做时停驻在设备就绪、TCP 引擎的唤醒与最早定时器、UDP 回包通知、DNS 应答、归因
完成、重组过期和取消上，不轮询也不忙等。一轮有进展后，只有这一轮给别的任务交了活（向 relay 交付客户端
字节或唤醒等待的 relay 任务、把数据报交给 UDP 会话、把 DNS 查询交给上游），或已连续 8 轮有进展时才让出，让这些任务
在同一线程上先运行（每个执行器只有一个工作线程，见 [Runtime](runtime.md#core-与启动输入)）；下载时的轮次只发 relay 的
字节、收确认，做完直接进入下一轮：让出的任务要等工作线程以零超时轮询一次 I/O 驱动（多一次系统调用）后才再运行，
因此不在每个有进展的轮次都让出。引擎最早定时器的等待常驻注册，期限变了才重设：每次等待都新注册一个早于时间驱动下次唤醒的
定时器，会写一次驱动的唤醒 fd。一轮的输出在下一轮开头写出。输出队列是硬上限
256 包，所有输出路径共同遵守：每轮读取的入站包数不超过空闲槽位（一个入站包至多产生一个直接
应答，如 ICMP echo），同时每轮读入的数据报不超过 512 个：平台黏在一起的一次读取带多少数据报就是多少
（Linux 的 GRO 读小数据报时是几十个），每个都要走一遍路由、会话与发送，只按读取数算的话一轮能把这份
工作做上千遍，而 TCP 引擎和输出都在后面等着；这个上限松到普通包的一轮永远碰不到、而列车的一轮仍能读
好几次。TCP 段每次占一槽，Core UDP（DNS 应答、会话回包）只在最大数据报按 MTU
分片后仍放得下时才取，且整报准入；UDP 列车对设备是一帧、对链路是若干数据报，所以按它携带的数据报
数占槽——只算一槽时队列按帧有界而按字节无界（256 个最大列车是 16 MiB，而 1500 字节链路的 256 槽
本意是 384 KiB）；回包大多只占一槽，所以一轮内只要还放得下最大数据报就继续取。
TCP 引擎的可用槽位在扣掉最大数据报之外，还扣掉 8 个留给读取路径的应答：引擎能占满整个队列时，
一次下载会让泵一个包也读不进来——客户端的 ACK（正是这次下载继续所依赖的）和其他流的上传一起停。
只保留必要的应答余量，避免过量压缩 TCP 输出空间。队列满时同时停止读取与取输出，只等设备可写，把设备
速率反压给所有生产者。被捕获的 DNS 查询先在泵内按 DNS 决策作答：拦截、Fake-IP、空应答与回环名都当场组成回复写回，
不起任务；只有要问上游的查询交给受跟踪的有界任务（至多 256 个并发），慢上游不阻塞其他包。

一个捕获可以有多个队列（Linux 的多队列 TUN，见 [Linux 平台](../platforms/linux.md)），内核按流的哈希把每条流
留在一个队列上。`NativeCoreDevice::run_packet_queues` 给每个队列一个包泵，跑在与队列配对的执行器上（SDK 的
执行器各有一个工作线程，见 [Runtime](runtime.md#core-与启动输入)），包泵派生的任务——到达该队列的 TCP 流的 relay、
它打开的 UDP 会话、它交给上游的 DNS 查询——也在那里运行，一条流的数据不在线程之间
交接，多条流又能用上多个核。每个队列有自己的 TCP 引擎、重组、归因闸门、输出队列与记下的 UDP 流；规则、DNS、
fake IP 池、会话登记与 UDP 会话表由所有队列共用。一个客户端 socket 的数据报发往不同远端时可能落在不同队列，
但它们属于同一个会话，经同一出站的共用一条传输（见 `udp/association.rs`），回包由打开传输的队列写出。一个队列的设备出错时其余队列一起
停下，各队列的报告逐项相加。只有一个队列的捕获（Wintun 的环，utun 的 fd）只有一个包泵。

多播、受限广播和捕获接口自身网段内的目的地址不中继：经出口 socket 发出，它们会从物理上行离开，
多播的回声还会被重新捕获成风暴。各平台的 capture 配置给出接口网段（`interface_networks`，Windows
由 Wintun 地址与掩码得出，Linux 与 macOS 为各自 TUN 前缀），网段内 UDP（包括 Windows 发往
定向广播的 NetBIOS 名称查询）计数后丢弃，TCP 在 accept 时以 RST 结束；发往网段内虚拟解析器的 DNS
先被劫持应答。

捕获接口上的包来自本机程序或网关捕获转发来的设备，不可信：解析器、重组器、分类与 TCP 引擎对任何字节都只丢弃
或以 RST 回应，不能 panic。单元测试以 TCP、UDP、DNS、ICMP、两族分片与 UDP 串的合法包为种子，偏向长度与首部
字段随机变异 4 万个包，逐个走这些路径。

## 捕获 TCP

TUN 捕获的 TCP 流由 Core 在本机终结：客户端的协议栈经捕获设备与 `packet/tcp/` 的引擎握手，字节交给
relay 走普通会话流水线，因此连接表、kill switch、路由重新验证和计费与监听器入站共用一个账本。捕获里引擎只做
被动打开（客户端发 SYN），对端是本机协议栈或经热点转发来的设备；隧道出站（OpenVPN）里同一个引擎主动打开
连接（见下文的主动打开）。引擎不做路由与通用 socket API。一条连接的状态机在 `packet/tcp/connection.rs`
（状态、建立与 relay 事件）及其下的 `connection/receive.rs`（到达的段、确认与丢包恢复、载荷与 FIN）、
`connection/timers.rs`（各定时器）与 `connection/transmit.rs`（一轮发送）；`engine.rs` 是每个捕获队列的连接表与
调度，`budget.rs` 是流共用的接收窗口与发送缓冲预算，`stream.rs` 是 relay 看到的流。

**驱动。** 每代 Core 设备的每个捕获队列一个引擎，放在设备的引擎表里，引擎的 accept 循环与它的流的 relay
跑在该队列的执行器上。引擎只在设备未进入 `Closing`/`Closed` 时创建：检查与创建都在表锁下，`close()` 发布
`Closing` 后在同一把锁下清空表，所以不会在关闭后再创建出无人清理的引擎与 accept 任务。整份配置的同代热更新与
`close()` 取下全部引擎后关闭它们的流，热更新后各队列的下一个 TCP 包创建新引擎；队列数不同的捕获开始时，上一个
捕获的引擎连同它们的流一并结束。只改策略（选择节点、流量模式、全局出口、IPv6 解析）不动引擎：引擎的 accept 循环
与引擎同寿，每条被接受的流在到达时固定当时的快照，捕获的流因此和别的会话一样按新策略逐条判断（见
[Runtime 的桌面配置操作](runtime.md#桌面配置操作与生效状态)）。包泵逐轮取本队列的当前引擎并在写出前核对身份，旧引擎不能向新策略写回。多个队列时，
各引擎把持有的流记在一张共用的持有表里（四元组到队列，连同每个队列持有几条）。新流的 SYN 不论落在哪个队列，都由
持有流最少的队列接受（并列时留在原队列）：内核把一条流留在最近一次写出这个哈希的包的队列上（`drivers/net/tun.c`
的 `tun_flow_update` 与 `tun_automq_select_queue`），接受它的引擎在自己的队列上写出 SYN|ACK，此后这条流就到这个
队列。新流只交给引擎已建起的队列：包泵启动时建起
本队列的引擎，整份配置热更新后则要等这个队列的下一个 TCP 包，交给没有引擎的队列的 SYN 会丢，客户端的重传按持有表仍去
那里。例外是流经过一条所有流共用的连接（Hysteria2 的载体、OpenVPN 节点的会话，
`OutboundConnector::carrier_runtime` 报告驱动它的运行时）时：包泵在 SYN 到达时用已知的目的地、fake IP 的名字与
已找到的进程预先路由，这样的流交给包泵与载体在同一执行器上的队列，流、它的 relay 与载体在一个线程上，减少跨执行器
交接。经这种连接的 UDP 会话同样交给那个队列的包泵。落到别的队列上的段（握手的最后一个 ACK 可能
早于内核记下这条流；记录 3 秒不用即过期，此后的第一个包按哈希选队列；两条流的哈希相撞时其中一条会被带到另一条
的队列）交给持有它的引擎并唤醒那个包泵，而不是被不认识它的引擎以 RST 回应。持有表只在建立与结束连接、以及没有
本地连接的段到达时查，已知连接的段不碰它；一个队列时没有持有表。包泵独占驱动引擎：一轮读到的 TCP 包在一次加锁
内按四元组从哈希表找到连接、就地处理；随后处理 relay 的唤醒与到期定时器，把有段要发的连接按轮转（每次
至多 16 段）放进泵的输出队列，引擎的最早定时器参与泵的等待：定时器堆没有删除，报出最早期限前先清掉没人等的项（流已走、或被更早的项取代）、把被推后的项按它现在要的期限重排，泵不为陈旧的期限醒来。没有分片任务与注入、发射通道，跨任务交接只
在引擎与各条流的 relay 之间。捕获流上限 1024 条，按设备级计数在新旧引擎间共享，超出时以 RST 回应 SYN；
引擎关停时按自身的流逐条递减计数。TIME-WAIT 不计入：连接发出对客户端 FIN 的确认、进入 TIME-WAIT 后，引擎
释放连接，只留一条精简记录（两个方向的下一序号、通告过的右边沿与窗口、到期时间），每个引擎至多 16384 条，
再多时最早的提前结束：客户端重传 FIN 在自己的几个重传超时之内，最早的记录最不可能还用得上，没有记录的
FIN 得到 RST，客户端的 LAST-ACK 一样结束。TIME-WAIT 计入上限时，服务端先关闭的短连接各占一个名额 2 秒，
连接风暴每秒只放行约 500 条，其余被 RST 拒绝。

**主动打开。** `TcpEngine::opening` 是只拨出的引擎，由 OpenVPN 会话的任务独占驱动（`protocols/openvpn/stack.rs`），
隧道地址收到的 SYN 一律以 RST 回应：VPN 另一侧不能连进本机。`connect` 选一个空闲的临时端口（49152–65535），连接
从 SYN-SENT 开始，SYN 带 MSS（由引擎的 MTU 定）、窗口缩放与 SACK 许可；对端的 SYN|ACK 按
[RFC 9293 §3.10.7.3](https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3) 处理：确认号不在 (ISS, SND.NXT] 内时回
RST，可接受的 RST 即拒绝，双方都提出时才用窗口缩放与 SACK，发送 MSS 取对端与自己的较小者，随后进入
ESTABLISHED 并通知流（`CapturedTcpStream::established`），拨号方在这之前拿不到流。SYN 与被动打开的 SYN|ACK 一样
按 RTO 退避重传 5 次后放弃；ICMP 或 ICMPv6 目的不可达引用的打开中的连接立即结束，不等超时。不做同时打开（只有
SYN 没有 ACK），也不收 SYN|ACK 带的数据（只有 TCP Fast Open 会发）。建立之后的窗口、SACK、拥塞控制、丢包恢复与
RFC 5961 检查与捕获连接相同；`packet/tcp/tests/opening.rs` 让主动打开的引擎与接受的引擎在丢包、重复、乱序的链路上双向传输
并逐字节校验。

**交接。** 每条流与它的 relay 共享 `FlowShared`（relay 一侧是 `CapturedTcpStream`）：上传与下载各一个块
队列、关闭与复位标志和两个唤醒槽。上传块是捕获包缓冲的 `Bytes` 切片，不复制；不超过 1 KiB 的载荷复制进
16 KiB 的合并缓冲，免得大量小块的开销超出窗口所限的内存。下载时 relay 把读到的缓冲整块交给引擎；段的
载荷引用这些块（每段至多 8 片），头部单独生成，块在确认后释放。待发与未确认的字节有上限（发送缓冲，`packet/tcp/budget.rs`），
引擎按客户端窗口与拥塞窗口中较小者的两倍设定，在 1 MiB 与一条流的上限之间（捕获 4 MiB，
隧道 32 MiB，见下文的接收窗口），再取与"32 MiB 的发送预算减去其余流已获发放"的较小值：下一个窗口的字节在当前窗口被确认时已经排好，客户端停读、窗口收拢后回到 1 MiB。手上没有
relay 字节（都已确认）的流没有发送缓冲、不占预算：它的 relay 仍可写一块（手上一块都没有的流都可以），引擎拿到
这块时按上面的规则重新定上限，下一块因此不必等确认。这与 Linux 相同：发送缓冲按拥塞窗口的两倍自调
（`net/ipv4/tcp_input.c` 的 `tcp_sndbuf_expand`），只按占着的内存
计，内存用满时手上什么都没排着的 socket 仍可先排一点以免卡死（`net/ipv4/tcp.c` 的 `tcp_wmem_schedule` 与
`sk_forced_mem_schedule`）。重传记分板的记录跟着这个上限：在途为空时把上限之外的空间交回去——1500 字节的段、
4 MiB 的发送缓冲下，一个窗口的记录约 0.26 MB，爆发过一次的流不交回就会一直留着它，空闲的流因此全部交回。接收
窗口的预算是捕获设备的队列、是硬限制，这份是引擎自己的内存；没有它时每条流各自定上限，一千个客户端停读就是
一 GB，每个隧道的引擎还各自再来一份。32 MiB 下同时有字节在手的流不到 32 条时，每条本来就只拿下限；预算发满
后来的流上限为零，而 relay 手上一块都没有时仍可写一块，所以是逐块推进而不是卡死。空闲的流也占着 1 MiB 下限
时，开着 32 条安静的连接就把预算占满，之后每条流写一块都要等客户端确认完才能写下一块；对单个段延迟确认的
客户端每次确认只走一块。relay 一次读取上游当下所有的字节再整块
交出。一次连续接收（相邻读取相隔不超过 10 ms）交出 1 MiB 之后，单次读到不足 8 KiB 时，连同已读到的字节最多再等
1 ms，攒到 32 KiB 或到时再交出：QUIC 这类每次读到一两个包的上游否则每个包都成为经捕获设备的一段，设备一次写入，
客户端协议栈一次接收和一次确认；本机客户端对每段立即确认，所以只在有未确认字节时等待的 Nagle 算法从不等待。只有按
这次连续接收的平均速率，缺的字节能在一次等待实际可能持续的 2 ms 内到齐时才等（约 16 MB/s 以上）：更慢的下载每次都
会等满却凑不满，只增加延迟。更大的
读取（TLS 记录、套接字的积压）从不等待：它们的段本来就大，每次读取都等会拖住高速的单流。1 MiB 以内的传输从不
等待，更大的传输最后的字节至多晚约 2 ms（1 ms 的计时器按毫秒粒度向上取整）；读取之间的停顿短于 10 ms 不算中断，
否则 QUIC 流控等造成的停顿会让连续接收频繁重新计数。上游安静 1 秒后交还读缓冲；没有读缓冲时（还没收到过数据的新流
也是）先读进栈上 4 KiB 的探读，读到字节才申请 64 KiB 的缓冲，否则上传时每次写入唤醒的任务都要为一次空读申请、
释放一次。空闲连接不长期持有读缓冲。上游不支持
分散写时（QUIC 流、SS2022 的分帧），relay 把攒下的块先合并成一块再写；传统 AEAD 的流接受分散写，一帧直接从这些块
  封出。唤醒只在边沿
发生：引擎在队列由空变非空、由满变出空位时唤醒 relay；relay 写入、消费的字节足以重新打开窗口、关闭或
复位时把流登记进待处理列表（已登记的不重复）并唤醒泵。`relay/captured.rs` 认出 TUN 流后走块接口：上传
方向把至多 16 块、64 KiB 以 vectored write 交给上游，下载方向读进 64 KiB 的缓冲后整块交出；半关闭、错误与
预算的语义与通用复制循环一致。嗅探与虚拟 DNS 经 `AsyncRead`/`AsyncWrite` 读写同一条流。段经设备的
`try_send_parts` 分散写出（见[包设备与包泵](#包设备与包泵)）。

**协议行为。**

- 握手（[RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293#section-3.5)）：SYN 到达即建立连接并交给
  accept 侧。SYN|ACK 通告的 MSS 是 MTU 减去 IP 与 TCP 头，至多 16 KiB：捕获设备的 MTU 远大于链路（macOS
  utun 为 65 535，一个段就是 64 KiB），而接收的流共用一份预算，把设备的段整个通告出去会让忙碌的流只剩一两
  个段深的窗口，SWS 规避随即把窗口更新压到窗口腾出一半才发，窗口收拢过的流因此被饿住。发送段不受这个上
  限约束，仍取设备的段与客户端 MSS 的较小值（§3.7.1，客户端未给 MSS 时 IPv4 按 536、IPv6 按 1220），下载因
  此保持设备的段。客户端提供窗口缩放时以缩放 5 回应，1 MiB 窗口是 32 768 个单位；隧道的
  引擎主动打开时提出缩放 10，32 MiB 是 32 768 个单位
  （[RFC 7323 §2](https://www.rfc-editor.org/rfc/rfc7323#section-2)）；提供 SACK 时回应 SACK-permitted
  （[RFC 2018](https://www.rfc-editor.org/rfc/rfc2018)）；不回应时间戳，连接因此不使用时间戳（RFC 7323
  §3.2）。SYN|ACK 的窗口不缩放（§2.2），一条流的起始窗口放得进这个字段，握手完成时不再另发一次。初始序号
  随机；重复的 SYN 重发 SYN|ACK，未获确认时按重传超时至多重发 5 次。客户端换了初始序号的 SYN 让未完成的
  握手让位。
- 接收：段按历次通告的最远右边沿判断是否在窗口内（RFC 7323 §2.4），超出的部分截掉；通告的右边沿不后退
  （RFC 9293 §3.8.6），缩放后的窗口向上取整。乱序段保留在窗口内，以 SACK 块报告，第一块含最近
  到达的段（RFC 2018 §4）；捕获的引擎每条流至多保留 256 段，隧道的引擎至多一个 32 MiB 窗口的段（约 24 700
  段）：长路径上丢一个包后，窗口里其余的数据都乱序到达，只留 256 段时接收方丢掉其余部分，发送方只能再发一遍。
  确认按批：泵处理完一批包后，每条收到
  数据的流发一个 ACK，与待发数据同段时搭载。窗口更新遵守接收端 SWS 规避（§3.8.6.2.2）：右边沿至少前进
  min(MSS, 上限的一半) 才通告，
  窗口不到一半时，relay 读到队列只剩不超过某个水位时才唤醒引擎；水位在队列锁内比较，与读取并发也不会错过。
- 接收窗口（`packet/tcp/budget.rs`）：一条流通告的窗口是它的上限减去已排队的字节；上限取三者中最小的一个：它
  在接收中的流里平分到的那一份（4 MiB 平分，每条至多 1 MiB）、它挣到的窗口、预算减去其余接收中的流已通告而客户
  端还没用掉的窗口，但其余流的承诺至多把它压到下限——起始窗口，且不超过它的那一份——从不压到零。窗口属于
  每条流、随它的用量长大，不占用的流不计入，共享资源吃紧时把流压到一个下限。
  Linux 在中度内存压力下仍保证每个 socket 的 `tcp_rmem[0]`，压力下把窗口夹到四个段（`include/net/tcp.h` 的
  `tcp_adjust_rcv_ssthresh`），到硬上限时宁可丢段也不通告零窗口（`net/ipv4/tcp_input.c` 的 `tcp_prune_queue`）。
  捕获设备的容量需要单独约束：Linux 上本机发送方由
  自己的排队规则顶住，utun 与 Wintun 则丢掉队列装不下的包，所以接收中的流通告出去的窗口要按设备的队列做预算。
  - 挣到的窗口从 16 KiB（一个通告的段）起，客户端在这条流的一个半往返内、且至少 50 ms 内发满一整个窗口就翻一番，
    发得比这慢的流保持原窗口。更大的窗口只对被窗口卡住的发送方有用，它每个往返发满一次。
    捕获使用近端客户端的往返时间，隧道的对端在网络另一头，必须同时考虑路径时延，避免远端流无法增长窗口。
    Linux 按读取方每个往返取走的字节定接收缓冲（`tcp_rcv_space_adjust`），判断依据相同。只数累计字节时，持续发小请求的
    长连接同样会长大（200 个 4 KiB 的请求
    长到 512 KiB）；不按是否到达旧右边沿判断：引擎会在接收过程中用新的确认推进右边沿。窗口要挣，是因为一条流在
    需要之前就拿到整份份额时，后开的流要等它把这份承诺用掉或安静下来。
  - 通告过的右边沿不能后退（RFC 9293 §3.8.6），先打开的流在接收中的流还少时拿到的大窗口会一直挂着，所以预算
    按未兑现的承诺发放，而不是只按人头平分：只按人头平分、又在流需要之前就给足时，64 条流逐个打开再一起发，
    承诺之和可能超过捕获设备的容量，导致丢包与后开的流停顿。
  - 只有接收中的流计入：它最近 1 秒打开或收到过数据，或者手上还攥着 relay 未取走的字节。被 relay 顶住的流并没有
    停止接收，它已通告的窗口仍会把字节带到捕获设备；把它排除在外时，计数内的流各自分到整份预算的一份，而它还
    另外攥着字节，窗口之和同样越过设备装得下的量。客户端安静下来的流不再往设备里送字节，它的承诺退出总和，再
    收到数据时回来；安静的流也计入时，上传过的长连接开着就一直占着整份预算。
  - 下限与份额一样，每种流数下加起来都装得进预算，都停在下限的流不会让设备溢出；超出预算的只可能是安静的流
    再开口时还挂着的承诺，设备装不下的包由客户端重传。压到零的代价大得多：新连接的 SYN|ACK 通告零窗口时，客户
    端的第一批字节（TLS ClientHello）要等零窗口探测，macOS 最早 5 秒才探、之后退避到至多 60 秒（XNU
    `bsd/netinet/tcp_timer.h` 的 `TCPTV_PERSMIN` 与 `TCPTV_PERSMAX`）。监听器入站不经这个引擎。
  - 上传在途的字节排在捕获适配器的环与设备队列里。多条流同时发出较大的初始窗口可能装满 Wintun 的环，
    通告的 MSS 与窗口上限需要一起受捕获预算约束。客户端不提供窗口缩放时窗口至多 65 535 字节（RFC 7323 §2.2），上限随之封顶。上限变小时，窗口已收拢的
    流按新上限重新登记唤醒水位，否则读完队列也不会再通告窗口。
  - 隧道的引擎（主动打开）的流在途的字节在网络里，窗口与发送缓冲要盖住路径的带宽时延积：接收中的流平分
    32 MiB，一条流可以拿满，发送缓冲同样至多 32 MiB，在发送预算里分；同时收发的流平分预算，引擎的内存因此不变。从 8 MiB
    起（服务器以十个段起步），按上面的规则挣到更大的窗口。
- 发送：遵守对端窗口与发送端 SWS 规避（§3.8.6.2.1）：小于 MSS、小于待发数据且小于对端最大窗口一半的段先
  不发，200 ms 后仍无更多窗口才发出；到时输出队列满着，这个段就等输出有空位，计时器不再留在堆里，否则包泵
  会在设备可写前反复醒来空转。新数据的段不超过对端通告过的最大窗口的一半（窗口不超过 536 字节时不拆）：接收方
  每两个满长段立即确认一次、单独一个段要等延迟确认计时器（[RFC 1122 §4.2.3.2](https://www.rfc-editor.org/rfc/rfc1122#section-4.2.3.2)），
  一个段占满整个窗口时，每个窗口都要等一次这个计时器，拆成两个段可避免依赖延迟确认。判为丢失的段先于新数据
  重发（[RFC 6675](https://www.rfc-editor.org/rfc/rfc6675) 的 NextSeg 规则 1、2），在途量低于拥塞窗口才发，
  数据段都按下文的 pacing 放出。PSH 只置在让该流无字节可发的段上。到本机客户端的段不经线路，丢失只来自设备
  丢弃；到热点设备的段在捕获接口之后还要过一段真实链路，隧道的段走真实网络，丢失意味着那里拥塞。
- 拥塞控制（`cubic.rs`）是 [CUBIC](https://www.rfc-editor.org/rfc/rfc9438)。初始窗口按
  [RFC 6928](https://www.rfc-editor.org/rfc/rfc6928)：十个段（MSS 大于 1460 字节时为 14 600 字节，至少两个段），
  十个段以内的请求在第一个往返就发完；握手重发过 SYN 或 SYN|ACK 时只有一个段（§2）。空闲超过一个重传超时后回到
  重启窗口（[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681) §4.1）。拥塞事件
  把 ssthresh 设为窗口的 0.7 倍（β，至少两个 MSS），记下 W_max 并做快速收敛（§4.7）；此后窗口按 C = 0.4 的三次
  曲线在 K 秒后回到 W_max、再越过它探测，曲线低于同样确认量下 Reno 会有的窗口（W_est）时取后者（§4.3）。窗口
  限制了发送、或慢启动中在途量达到窗口一半时才算用满；没用满时，那时发出的数据被确认前窗口不增长，三次曲线的
  时间也不走（§5.8），应用自己发得慢的流不会攒出一个从没用过的大窗口。第一次慢启动用
  [HyStart++](https://www.rfc-editor.org/rfc/rfc9406)：一轮有了 8 个 RTT 样本后，本轮最小 RTT 比上一轮高出
  clamp(上一轮的 1/8, 4 ms, 16 ms) 就转入保守慢启动（按确认量的四分之一增长），其间最小 RTT 回落则回到慢启动，
  5 轮后进入拥塞避免；发送有 pacing，每个 ACK 的增长不设上限（L 为无穷）。本轮最小 RTT 反映的是上一轮开始时的
  队列，慢启动因此可能比瓶颈容量多冲一些，由一次快速恢复收回。重传超时之后的
  慢启动按 RFC 5681 §3.1，每个 ACK 至多增长两个 MSS（[RFC 3465 §2.2](https://www.rfc-editor.org/rfc/rfc3465#section-2.2)）。
  拥塞窗口以 2^30 为上限，即 TCP 能通告的最大窗口：无丢包时慢启动不会结束，超过序号空间一半的窗口会让序号运算
  回绕。
- 丢包恢复（`scoreboard.rs`、`rack.rs`）：记分板按段记下最近一次发出的时间，以及是否被 SACK、判为丢失、丢失后
  已重发；在途量是未确认的字节减去 SACK 的与判为丢失的，加上丢失后重发的（RFC 6675）。丢失按时间判断
  （[RACK-TLP](https://www.rfc-editor.org/rfc/rfc8985)）：比某段晚发出的段已送达，且该段发出后已过最近的 RTT 加
  重排窗口，它就算丢失；还没到时间的由重排计时器到时再判。一次送达（重发的段的送达也算）就能判出之前发出的所有
  丢失，重发的段再丢也一样，不必每个往返只补一处。重排窗口是最小 RTT 的四分之一：最小 RTT 取 300 秒内的最小样本，
  以握手的 RTT 打底（握手的段比任何数据段都小，短的重发不会快过它而被当成迟到的原段）；没见过乱序时，在恢复中或
  已 SACK 3 段以上为 0；带 DSACK 的往返每次把它加宽四分之一个最小 RTT，16 次恢复后复原，不超过 SRTT。从没重发过
  的段在更高的段之后送达、或重发的段在短于最小 RTT 的时间里被确认（原段只是迟到），都算见过乱序。判出新的丢失时
  开始快速恢复，直到这时发出的数据都被确认；期间窗口按 [PRR](https://www.rfc-editor.org/rfc/rfc6937)：在途量高于
  ssthresh 时按送达量乘 ssthresh 与恢复开始时在途量之比放出，不高于时按慢启动的速度补回 ssthresh，判出新丢失的
  ACK 至少放出一个段；恢复结束时窗口取 ssthresh。不发 SACK 块的对端按 3 个重复 ACK（RFC 5681 §3.2）与恢复中的
  部分确认（[RFC 6582](https://www.rfc-editor.org/rfc/rfc6582)）判第一个未确认的段丢失。
- 尾丢探测（RFC 8985 §7）：有 SACK、不在恢复中、没有 SACK 过的段且重排计时器未开时，新数据发出或累计确认前进
  后设探测计时：2 SRTT 加 2 ms（包泵的计时器与对端的 ACK 要一两毫秒，亚毫秒的路径上只等两个往返会在 ACK 回来
  之前探测），只有一个段在途时改加 200 ms 的延迟确认余量，没有 SRTT 时 1 秒，都不晚于重传超时。到时发一个探测：
  对端窗口容得下就发新数据，不受拥塞窗口与 pacing 限制，否则重发最后一个段；探测引出的 SACK 让 RACK 判出前面
  丢的段，尾部丢包与短请求不必等重传超时。下一次探测要等到新的 RTT 样本；重发的探测补上了唯一的丢失（确认越过
  它，且没有 DSACK 说两份都到了）时，窗口照快速恢复降一次（§7.4.2）。
- Pacing：数据段（包括重发的）按 cwnd/SRTT 的速率放出，慢启动时乘 2、拥塞避免时乘 1.2，与 Linux 的
  `tcp_pacing_ss_ratio`、`tcp_pacing_ca_ratio` 默认值相同
  （[ip-sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html)）：慢启动的窗口每个往返加倍，
  要留出余量；拥塞避免中留一点，免得 pacing 拖住窗口。窗口因此不再成批涌进瓶颈的队列，缓冲只有四分之一带宽时延积
  的路径也能用满。流可以领先 pacing 1 ms（包泵的计时器约为毫秒粒度），且至少能连发 10 个段
  （[RFC 6928](https://www.rfc-editor.org/rfc/rfc6928) 的初始窗口，路径接得住这么多连发的段）：慢的流一次只放
  一两个段时，每放一次都要唤醒包泵一次。空闲的时间不攒额度。
- 重传超时按 [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298) 计算，初值 1 秒、下限 200 ms、上限 60 秒，
  指数退避，重传过的段不取 RTT 样本（Karn）。超时时丢掉 SACK 信息（对端可能扔掉了 SACK 过的数据，RFC 2018 §8），
  第一个段与发出后已过 RTT 加重排窗口的段判为丢失（RFC 8985 §6.3）；窗口回到一个 MSS，一次超时连串里的第一次把
  ssthresh 设为窗口的 0.7 倍（RFC 9438 §4.8）；到那时发出的数据被确认前不进入快速恢复（RFC 6675 §5.1）。
- 零窗口：对端通告零窗口而仍有数据或 FIN 待发时，按退避的间隔发送序号为 SND.UNA−1 的探测段取得对端当前
  窗口（RFC 9293 §3.8.6.1）；对端仍应答就不放弃。
- 健壮性（[RFC 5961](https://www.rfc-editor.org/rfc/rfc5961)）：只有序号恰为 RCV.NXT 的 RST 结束连接，窗口内
  其他位置的 RST 与同步状态下的 SYN 得到挑战 ACK（§3.2、§4.2）；确认号超出已发送范围、或早于对端最大窗口
  之前的 ACK 被丢弃并应答（§5.2）。无连接的段按 RFC 9293 §3.10.7.1 以 RST 回应。
- 保活与超时：空闲 28 秒后每 28 秒发送一次保活探测，最后一次收到客户端的段 88 秒后中止；有未确认的
  数据时，60 秒没有新的确认即中止。保活的到期时间向上取整到 4 秒的网格，相近时间转入空闲的流在一次唤醒里
  一起探测，而不是各醒一次。
- 关闭：relay 结束时先发完已写数据再发 FIN；被拒与拨号失败的流在任何握手阶段都以 RST 结束，Core 取消或
  回收的流也以 RST 结束；客户端的
  RST 让 relay 读写失败；relay 放弃流之后再到达的客户端数据以 RST 回应（RFC 1122 §4.2.2.13）。主动关闭的一方经
  TIME-WAIT，持续 2 秒，由精简记录照连接的规则应答（RFC 9293 §3.10.7.4）：重传的 FIN 再得到 ACK 并重新
  计时，序号超过旧连接终点的 SYN 开启新连接，恰在 RCV.NXT 的 RST 结束记录。
- 捕获结束（关 TUN、Runtime 停下包泵）时，包泵在设备关闭前把本队列引擎里的每条流向客户端复位并结束它的
  relay：RST|ACK 的序号取 SND.UNA，与 SND.NXT 不同时再发一个 SND.NXT 的。客户端协议栈只在一个序号上接受
  复位，别处只换来挑战 ACK：XNU 是它最后发出的确认号（`bsd/netinet/tcp_input.c` 的 `last_ack_sent`），在这里
  收到它的确认后即 SND.UNA；Linux 是 RCV.NXT（`net/ipv4/tcp_input.c` 的 `tcp_validate_incoming`），发出的段
  到达后即 SND.NXT，客户端还压着延迟确认时两者不同。设备 200 ms 内写不下的复位放弃。不复位时，留在已消失
  隧道地址上的 socket 要等自己的重传失败。整份配置热更新与 `close()` 取下的引擎不发复位，本机 socket 下次发送时由新引擎以 RST 回应；只改策略时引擎留着，
被改道的流由它的 relay 结束，客户端当即收到复位。
- 校验和：段头写入 IPv4 校验和与 TCP 伪首部和，TCP 校验和的其余部分由设备的 OS 或泵补全（见
  [包设备与包泵](#包设备与包泵)）；求和按本机字节序的 32 位字累加到 64 位累加器再折叠（RFC 1071 §2(B)：
  反码和与字节序无关）。捕获的包由本机协议栈生成，不校验。

**测试。** 单元测试按上面的规则以脚本化的段覆盖握手、两个方向的数据、乱序与 SACK、窗口边沿、重传与快速
恢复、零窗口探测、复位与挑战 ACK、保活、TIME-WAIT 与流上限。随机化测试以 smoltcp 作客户端（开发依赖），在
内存链路上注入丢包、乱序、重复与延迟，比对两个方向的字节、检查有序关闭，并在无损链路上要求最长停顿不超过
100 ms。`packet/tcp/tests/congestion.rs` 在虚拟时间里量发送端：主动打开的引擎经一个瓶颈把数据发给接受的引擎，
瓶颈是固定速率与 drop-tail 队列，两侧是固定的单程时延，ACK 原路返回；接收端按隧道的引擎设窗口，像网络另一头的
服务器那样收得下一整个窗口。每个场景量瓶颈的利用率、数据包排队时延的 p50 与 p95、重发与重复到达的字节、短传输的
完成时间与多流的 Jain 公平指数，覆盖带宽时延积、浅缓冲、随机丢包、尾部丢包与多流竞争，并检查速率利用、
重传和排队时延是否满足测试定义的边界。另以随机的段（任意序号、确认号、标志、窗口、选项与长度，一半落在客户端下一步会发的
位置）与 relay 的
写、读、关闭、复位及时间推进交替，要求引擎不 panic、发出的段都合法、流计数准确。`e2e_packet_throughput` 与 `idle_flow_memory` 示例作吞吐与内存基准。

## IP 分片重组

入站 IP 分片先经过 `packet/reassembly.rs` 的有界重组，再进入 TCP/UDP 分类与同一 Core。重组器由
每次 packet pump run 独占，stop、移除 packet capability 或新代启动都会释放未完成缓存，不将残片
保存在长期 Core 中。限制为 128 组（含重叠拒绝墓碑）、4 MiB 已计费缓存、每组 256 片和从首片起
固定 60 秒期限；泵只在有未完成的组时按最早的期限设定时器，到期回收，没有残片时不为重组醒来。重叠或冲突丢弃整组，IPv6 atomic fragment 独立归一化，
不影响同 ID 的普通片；CE/Not-ECT 按 RFC 3168 合并/拒绝。无状态 packet parser 仍要求完整报文，
不把孤立片当作完整 transport header。依据为 [RFC 791](https://www.rfc-editor.org/rfc/rfc791)、
[RFC 8200 §4.5](https://www.rfc-editor.org/rfc/rfc8200#section-4.5)、
[RFC 5722 §4](https://www.rfc-editor.org/rfc/rfc5722#section-4)、
[RFC 815](https://www.rfc-editor.org/rfc/rfc815) 和
[RFC 3168 §5.3](https://www.rfc-editor.org/rfc/rfc3168#section-5.3)。

## 源分片

Core 本地产生的 UDP/DNS 回包在 pump 唯一写入口经 `packet/source_fragment/` 按 MTU 源分片；这不是
IPv6 路由器分片能力，不接收任意转发报文。源包只有普通 IP 头和 UDP，已有分片、IP options/
extension chain、非法长度、超大元数据或 DF 禁止分片都明确拒绝。IPv4 小包置 DF 成为 atomic
datagram，避免消耗非 atomic 的 16 位 ID；IPv6 小包不加 Fragment header。超 MTU 源包的每片均不
超过 MTU，首片含完整 UDP 头，transport checksum 保留，IPv4 每片重算 header checksum。IPv6 合法
逻辑包可以达到 65575 字节，但分片后才进入 macOS/Windows 的 65535 字节 IPC，不提高传输上限。TCP
段由引擎按同一 MTU 生成，其他来源的意外超限包会报告错误，不通过清 DF 或通用 IPv6 分片掩盖
传输层问题。

源分片 ID 由进程范围的固定 8192 桶/地址族计数器加上按地址对秘密散列出的偏移构成（RFC 7739
§5.3 的结构），计数器随机播种，跨 pump 和 Core generation 保持，进程重启换新种子；同一地址对的
IPv4 ID 走完全部 65536 个值才重复。计数器直接回绕，不为最大报文生存期（MDL）扣留 ID。RFC 6864
§4.3 要求同一地址对在一个 MDL 内不重复 ID，§5.2 据此要求非 atomic 报文的源限速；按常见的 120 秒
MDL，一个地址对每秒只能发约 546 个分片报文，持续收大报文的流（例如在 TUN 里运行、外层报文超过
1472 字节的 UDP 隧道）会在第 65536 个报文后中断两分钟，RFC 4963 §2 也指出这一上限在高速率下普遍
不被遵守。回绕的代价是 RFC 4963 §2–3 所述的误组装：接收端丢掉某个报文的部分分片后，残片留在它的
重组队列里，ID 回绕后会与新报文的分片拼接。Core 把整个报文一次放入输出队列并按序写出，自身不制造
残片；接收端丢片引起的误组装绝大多数被 UDP 校验和丢弃，其余由上层完整性校验承担（RFC 6864
§5.2），持续发送大报文的隧道与 QUIC 都带 AEAD 校验。偶发误组装远轻于整条流中断，所以这里有意
不按 §5.2 限速。IPv6 Fragment header 的 ID 有 32 位，回绕需要 2^32 个报文，远超接收端 60 秒的
重组期限（RFC 8200 §4.5）。单报文最多 64 片，元数据上限 16 KiB，ID 状态固定为 64 KiB。依据为
[RFC 6864 §4–5](https://www.rfc-editor.org/rfc/rfc6864#section-4)、
[RFC 4963 §2–3](https://www.rfc-editor.org/rfc/rfc4963#section-2)、
[RFC 8200 §4.5](https://www.rfc-editor.org/rfc/rfc8200#section-4.5)、
[RFC 7112 §5](https://www.rfc-editor.org/rfc/rfc7112#section-5) 和
[RFC 7739 §5.3](https://www.rfc-editor.org/rfc/rfc7739#section-5.3)。

## 进程归因

进程归因属于 Core 而不属于某一捕获层。平台只实现 `FlowScanner`：批量把客户端 socket 的五元组映射
到进程名/路径，按方向匹配（源是该 socket 的本地端点）。宿主的 `CoreConfigSource` 在
`CoreStartInputs.flow_scanner` 中提供平台扫描器，每代 Core 设备只有一个归因 worker 与有界缓存：
缓存 4096 项、待查 1024 项、一次扫描答复全部待查、100 ms 扫描预算，正结果保留 250 ms、负结果 50 ms，命中即
顺延（持续收发的流不会到期重扫），新连接强制重查。每个查询有自己的答复，等它的查询只在它被回答时醒来，
worker 停止时把未扫的查询答复为未知；批次完成另经 watch 唤醒首包门控。过期项只在缓存满时清理。

扫描要遍历全部进程的 socket（Linux 读 `/proc`，macOS 用 libproc），其开销取决于进程与连接数量，等待扫描会延长建连
与 DNS 查询。所以只有路由可能取决于进程时才等：规则模式下，`MATCH` 之前可达
的规则（含逻辑规则与规则集里的条目）有 `PROCESS-NAME`/`PROCESS-PATH`。否则流立即继续，归因照常在后台
进行，连接记录在结果返回后补上进程（最多再等 2 秒）。一次扫描的成本几乎与它回答的流数无关，所以没人等结果
的查询先攒 200 ms 或攒满 1024 条再一起扫；有人等结果的查询（路由读取进程时）立即开扫并带上已攒的，等待中
的查询被等待时也会立即开扫。代价是存活不到约 200 ms 的连接可能记不上进程。两个入口共用它：

- TUN 泵内门控只为流的开端查询：TCP 只有初始 SYN 查询，归属随 SYN 建立的引擎连接确定，
  之后的报文不查询直接放行（仍排在同一流被扣的 SYN 之后）；UDP 报文查缓存，已有关联沿用建立时的
  路由。路由读取进程时，新流首包在重组之后、分类之前最多等待 150 ms，至多 256 包/512 KiB、每条流至多
  16 包，过载或到期以未知身份放行原包，同一流不乱序；超出自己那一份的流放行它自己最旧的那个包，队列
  被别的流占满时放行刚到的这个包——先到先得、过载时放行等得最久的那个（不论它属于谁）会让一条有包
  可挤的流在另一个应用那条孤零零的 SYN 即将拿到答案时把它挤出去，那条连接就错过自己的 `PROCESS-NAME`
  规则、走了别的出站，错的是路由而不只是晚了；否则 SYN 带着发起的查询交给引擎、由连接记录等待，UDP 报文带上
  缓存里已有的归属（未命中时查询在后台进行，后续报文带上结果，未知不覆盖已知），发往隧道自身 DNS 的
  查询不做归因；
- listener 接受回环客户端时，以客户端视角的四元组（客户端地址 → 它拨号的 listener 地址）发起
  查询；路由读取进程时与代理握手并行、自接受起最多等待 150 ms，否则不等待。未知时按无进程路由，与
  TUN 一致。远端客户端不查询，客户端请求头也不能声明进程身份。

因此仅开系统代理时进程规则与连接表同样有效，开关 TUN 不改变归因。结果是 socket 快照而非认证
身份，不能把进程规则当作安全边界。各平台扫描器的数据源与限制见平台文档。
