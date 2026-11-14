# 配置档案存储

桌面配置由产品后端 `egrio-desktop` 拥有。配置文件（Profile）就是它的来源 YAML，加上使用中做出的
选择（模式、节点选择、全局出口）和 provider 缓存引用。应用改动的配置（规则页的规则、设置页
的 IPv6 与局域网开关）直接写入 YAML，没有覆盖层，YAML 是配置内容的唯一事实。从 URL 或文件
导入都只是取得来源的方式：导入后是一份本地副本，不保留链接，不自动或手动刷新，需要新内容时
重新导入。`configuration.rs` 把来源与选择组合成最终值，`profile_store.rs` 管理持久数据，
配置服务与宿主操作连接既有 Runtime 控制面。Core、SDK 与可复用 Runtime 不读取这些产品数据。

## 持久布局

默认根目录由 `ProjectDirs::from("com", "xinvexo", "Egrio")` 按平台约定确定，使用产品命名空间。
`EGRIO_DATA_DIR` 可显式覆盖根目录；以下路径均相对于该目录。

- `configuration/manifest.json`：schema 2，保存活动 Profile ID、各 Profile 聚合、宿主偏好
  与恢复状态。
- `configuration/sources/<sha256>.yaml`：按内容寻址的不可变文件版本。编辑器保存、规则页
  编辑和设置页开关都写入新版本并切换指针；模式与节点选择只写 manifest。
- `configuration/provider-cache/<descriptor-hash>/<content-hash>`：绑定 provider 名称、URL
  和 behavior 的派生缓存，同名定义改变后旧正文不再有效。

## 取值规则与作用域

| 项目 | 规则 |
| --- | --- |
| System Proxy / TUN | 本地生命周期意图与 Runtime 实际状态；来源不能自动启用 OS 接管 |
| 日志级别、UI 与宿主偏好 | App 独立保存；日志缺省 info，来源 log-level 不覆盖 |
| 监听端口、绑定地址、DNS | 来源明确值，缺省时使用程序默认；在编辑器中修改 |
| IPv6、allow-lan | 来源明确值，缺省时使用程序默认；设置页开关把值写入来源 |
| 节点、策略组、rule-providers 定义 | 由当前配置文件决定，在编辑器中修改 |
| TUN 排除的目的地 | 来源 `tun.route-exclude-address`，在编辑器中修改；全局模式下不排除 |
| 规则 | 来源的 `rules` 列表；规则页的编辑写入来源 |
| mode | 当前 Profile 选择的模式 > 来源值 > 程序默认；来源写入另一个 `mode` 时清除所选模式 |
| 节点选择、全局出口 | 归属当前 Profile，不复制到另一份配置 |

默认值、表单显示值和运行态观察值不写回来源。应用对来源的编辑（`profile_source/edit.rs`）
只改写目标行，保留其余内容的注释、顺序与格式：设置改写或补上一个顶层键并保留行尾注释，规则
上方的注释随规则移动，流式列表 `rules: [...]` 改写为块列表。改写结果重新解析，与原文档只在
目标键上不同才保存；重复的键、被其他键别名引用的列表等改写不安全的结构直接拒绝，提示在编辑器
中修改。

修改来源的请求携带 source revision（来源内容 hash），陈旧请求拒绝；规则 id 是规则在该
版本中的位置，与 revision 一同失效，所以只用来指明要编辑哪一条——连接命中了哪条规则、每条规则命中多少次，
都按规则的原文记（见[桌面架构](desktop.md#产品后端)）。模式与节点选择不改变来源，不使规则页与设置页持有的
revision 失效。Profile 的整体 revision 随来源与选择变化推进。

新导入的 Profile 没有选择。切换只读取目标配置及其自己的选择；切回时恢复该配置自己的
状态。编辑器保存保留本 Profile 的选择。

## 支持的 Clash 字段

来源是 Clash 配置格式的一个子集，只读取下表的顶层键，由 `profile_source.rs` 一次解码：

| 键 | 读取内容 |
| --- | --- |
| `mixed-port`、`bind-address`、`allow-lan`、`ipv6` | 见[监听字段](#监听字段) |
| `mode` | `rule`、`global`、`direct`，不分大小写（订阅转换的模板写 `Rule`）；界面选择的模式优先 |
| `dns` | 见 [DNS 配置来源](#dns-配置来源) |
| `hosts` | 域名到固定地址的映射，见 [hosts](#hosts) |
| `proxies` | `name`、`type`、`server`、`port`；其余键原样交给 Core 出站按协议解释。可连接的类型为 `ss`、`trojan`、`hysteria2`、`http`、`socks5`、`openvpn`。`openvpn` 节点的 `config` 是 `.ovpn` 文件的路径，绝对路径或 `~/` 开头（主目录下），每次建立会话时读取（节点照常列出，文件读不到或不受支持时经它的连接失败并给出原因）；服务器、端口与传输协议取自文件里的 `remote` 与 `proto`，不写 `server`/`port`（支持的子集见 [Core 架构](core.md) 的 `protocols/openvpn/`）；文件含 `auth-user-pass` 时写 `username`、`password`；隧道承载 IP，`udp` 缺省为开。`ss`、`trojan`、`socks5` 的 `udp` 缺省为关：服务器是否中继 UDP 无法预先知道，不中继时数据报会无声丢失，所以只有配置写明 `udp: true` 才经该节点发 UDP；`hysteria2` 总是承载 UDP，`http` 不承载；`trojan` 未写 `alpn` 时提供浏览器同样提供的 `h2`、`http/1.1`（Trojan 要像普通 HTTPS，不带 ALPN 的握手反而显眼），写了则原样使用，空列表即不发 ALPN。任何类型的节点都可写 `hidden: true`（节点页的节点列表不显示、不测速，策略组和托盘照常列出它）、`test-url`（测速与未写 `url` 的策略组的健康探测经它请求的地址，未写时为 `http://www.gstatic.com/generate_204`）与 `dialer-proxy`（节点经这个节点或策略组连到自己的服务器，即链式代理，见 [Core 架构](core.md) 的 `outbound/hop.rs`；节点的 UDP 经上一跳的数据报，上一跳须承载 UDP） |
| `proxy-groups` | `name`、`type`（`select`、`url-test`、`fallback`、`load-balance`）、`proxies`、`interval`、`url` |
| `rules` | 规则行，语法属于 Core 规则引擎；GEOIP 与 GEOSITE 规则读取应用共用的 [GEODATA](desktop.md#产品后端)，不在配置中；`GEOIP,LAN` 是本地地址，不读数据 |
| `rule-providers` | `url`、`behavior`，供 `RULE-SET` 规则引用；条目损坏时只跳过该条 |
| `tun` | 只读 `route-exclude-address`，见 [TUN 排除的目的地](#tun-排除的目的地)；TUN 模式的开关、栈与路由选项由应用管理 |

节点与策略组允许有限的类型转换：该是文本的地方写了数字就取它的数字文本，
所以不加引号的纯数字名字、组成员和密码（`password: 123456`）照常可用；`interval` 写成带引号的数字也照常
读取。顶层的 `mixed-port`、`ipv6` 等要求使用字段定义的类型。

其他键一律忽略：日志级别、监听等由应用自己管理，`proxy-providers`、
`sniffer` 与策略组的 `use`、`filter` 等尚未支持。来源文件原样保存，以后支持某个键只需扩展
解码，已保存的配置无需重新导入即可生效。解码前展开 YAML 锚点与合并键（`<<: *anchor`）；
只写键名不写值（如 `proxies:`）视为空列表。`vmess`、`vless`、`tuic` 等其他节点类型与 `relay`
组照常保存和列出，但没有出站、不能连接，也不使整份配置失效。可连接类型的未实现变体同样照常列出，
使用时以配置错误失败、不以错误的协议去连：Trojan 的 `network`（WebSocket、gRPC 等）与 REALITY、
Shadowsocks 的 `plugin`、Hysteria2 的 `obfs`，以及任一 TLS 跳点的证书固定（`fingerprint`）、客户端证书
与 `ech-opts`。原因由 Core 的 `proxy_support_issue` 给出，
随节点清单交给界面：节点页与托盘把这些节点标为不支持并显示原因，不可选择、不测速。配置编辑器的补全与悬停说明
只提供上表的键，并按所在位置给出：节点只给它的 `type` 读取的键（尚未写 `type` 时给出全部），已写的键不再提供；
`dialer-proxy` 的值补全配置里的策略组名与节点名，策略组的成员与规则的出站另加 `DIRECT`、`REJECT`。其他顶层
键标为不生效。

## 来源解析与生效

来源一次解码并验证：监听、IPv6、模式与 DNS 在解码时转换，只有文件省略的键使用程序
默认，任一无效值都拒绝整份来源。组合只加上 Profile 的身份与选择。所有监听、Core profile、IPv6 解析与 Provider 物化输入来自一次固定快照；启动过程中
不各自重读 YAML。快照中的来源 hash/revision 只留在 GUI，运行世代仍由 Runtime 管理。

来源文件不可变，解析结果按内容 hash 复用：进程内保留最近使用的四份，组合与校验都从同一份
解析结果出发，不逐次重读 YAML。规则行解析进 Core 的共享规则块（`RouteRules`），组合出的配置与
运行中的 Core 用的就是解析结果里的这一块，不再各存一份。规则页读到的规则列表也是这一块，另带两张按规则位置记
的稀疏表：Core 不认识的类型在来源里的写法，和 Core 不会用的规则各自的原因；规则的 id 由位置算出，不存。
配置摘要只取来源的几个数（节点、策略组、规则的条数和文件写的
模式），这几个数每份来源解析时记下一次，另外留着：配置列表要每个配置的摘要，若它也经过那四份，
超过缓存容量时，反复列出会挤掉正在使用的解析结果。为摘要而解析
的来源只放进空着的位置，不挤掉用过的。节点选择只依赖来源中的策略组，校验与保存都不组合规则列表。
节点与策略组清单（节点页、托盘、选择校验共用）直接读解析结果、不含规则，规则列表连同
编辑要提交的 source revision 单独查询，节点切换的开销因此与规则数量无关。

首次启动时，缓存齐全就以完整配置启动；缺少正文时，固定的 Runtime 先准备同一个 Core 的节点与
出站，通过当前选择的出口获取实际引用的缺失 provider。全部正文就绪后，在同一 Core 上装入完整配置，
再开放普通监听与请求的捕获层；生命周期见 [Core 与启动输入](runtime.md#core-与启动输入)。下载期间
固定节点与模式选择，失败后允许调整选择、手动重试或停止，已取得的有效缓存保留，不自动重试。

运行中的完整重启先经当前 Core 的内部出站补齐正文，已有会话保持运行，成功后才停止并替换。
设置/编辑查询不要求加载外部规则正文。规则集正文逐条写入 Core 的共享条目块（`RuleSetEntries`），
解析时不为每条留下字符串或 YAML 值；Core 的匹配表直接读这一份条目。完整配置交给 Core 后，GUI
只保留该代次的来源身份与网络元数据，不继续持有整份正文。

规则集刷新由同一 Profile 的单次操作拥有下载客户端、连接池和缓存提交；批量、单项和
启动依赖准备共享刷新准入，同 Profile 不允许重叠下载覆盖。批量在各 HTTP 请求之间复用
同一 Client，不按 provider 反复创建和销毁连接池。启动准备在同一操作内部获取缺失内容，
不会递归获取自己的准入。缓存已齐全时，准备入口只读返回，不获取刷新准入或构建 Client；
只有真正缺失才互斥下载并在准入后重新检查。准入在下载/缓存阶段结束时释放，随后才进入
既有 Runtime 配置协调，避免配置重启的依赖准备发生自锁。

每项刷新区分内容改变与检查成功但未变化：相同 descriptor/content hash 只更新检查时间和
条目元数据，不推进 Profile revision，也不重启 Runtime；内容改变才触发既有活动 Profile
传播。批量在整个下载阶段结束后最多传播一次，全部失败或零变化不传播。缓存写入成功
但 Runtime 生效失败返回明确阶段错误，不能报告应用成功。下载失败保留旧缓存，不能把
旧缓存计入本次成功。批量结果由 GUI 汇总为单条全部成功、部分成功、全部失败或未变化
通知，不同时逐项弹绿色成功和红色失败。报错时也刷新缓存查询，区分已保存与已生效。

设置查询区分来源值、来源版本与实际运行值；保存不等于生效。IPv6 开关写入来源后复用现有
策略更新，allow-lan 写入来源后使用监听作用域重载，二者都不重启；模式与节点选择同样走策略
更新。规则编辑、编辑器保存（含 DNS 与监听端点变化）通过完整 Runtime 替换应用。停止态只保存，不因保存配置而开启网络。失败阶段与清理责任见
[桌面配置操作](runtime.md#桌面配置操作与生效状态)。

### 监听字段

| 字段 | 缺省值 | 约束 |
| --- | --- | --- |
| mixed-port | 7890 | 范围 1..65535；0 不代表随机端口，明确拒绝 |
| allow-lan | false | 设置页开关写入来源；关闭时监听 127.0.0.1。导入的文件写着 `true` 时保存的副本改为 `false`，见下 |
| bind-address | * | 开启 LAN 时使用；接受 IPv4/IPv6 字面地址，IPv6 可带方括号 |
| ipv6 | false | Core IPv6 解析开关，不改变监听地址族或禁止已有 IPv6 目标 |

从 URL 或文件导入的配置不能替用户打开局域网访问：来源写着 `allow-lan: true` 时，保存下来的副本把这一个键
改写成 `false`（注释与其余内容不动；改写不了的写法，如整份文档是一个流式映射，导入失败并说明原因）。
监听一旦对局域网开放，同一网络里的任何设备不需要密码就能使用本机的代理：既能用配置里的节点，也能经
DIRECT 访问只有本机到得了的服务。
所以它由使用这台机器的人决定：在设置页打开开关，或者在编辑器里自己写（新建的空白配置与编辑器保存照写的生效）。

端口或绑定地址不合法时拒绝候选，不借用前一配置的值、不回退随机端口。端口合法却无法监听时，桌面
改用它之上最近的空闲端口并提示，配置文件不变：被其他程序占用，或落在系统保留的端口里（Windows 的
排除端口范围由 Hyper-V、WSL 等成段保留，`netsh interface ipv4 show excludedportrange protocol=tcp`
可以查看）。机制与提示见 [Runtime 监听端点](runtime.md#core-与启动输入)和
[桌面界面](desktop.md#界面)。

### TUN 排除的目的地

`tun.route-exclude-address` 是 Clash 配置格式的 TUN 排除列表，列出 TUN 模式下不进入隧道的目的地：
它们沿用系统原有的路由（物理接口或其他 VPN 的更具体路由），不经 Core，适合远程桌面的对端、内网
网段或其他 VPN 的地址。与其他 VPN 共用就靠这份列表，产品不为各家 VPN 单独适配或验证。排除在进入隧道的
路由上挖洞：含排除网段的那条捕获路由被对半拆分，拆出的路由更长，可能比其他 VPN 覆盖它们的路由更具体，
所以要把一个 VPN 的网段整个留给它，就排除它的整段（Tailscale 是 `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`），
只排除其中一部分时其余地址仍进隧道。每项是 IPv4 或 IPv6 的 CIDR，或单个地址（即一个主机）；主机位清零，重复项
只保留第一次出现，至多 256 项，任一项无效都拒绝整份来源。

```yaml
tun:
  route-exclude-address:
    - 192.168.0.0/16
    - 100.64.0.0/10
    - fd7a:115c:a1e0::/48
```

规则与直连模式下排除生效；全局模式下所有连接都经 Core，排除不生效。TUN 运行中切换模式时原地
更新，不重建 TUN（顺序见 [桌面配置操作](runtime.md#桌面配置操作与生效状态)）。排除覆盖 TUN 自身
地址或 fake-IP 池时，开启 TUN 失败：路由到隧道外的 fake 地址到不了回答它的 Core。各平台如何把
排除落到路由与防泄漏规则上见平台文档。

## DNS 配置来源

DNS 只来自来源的 `dns` 段，在编辑器中修改；省略整段时 DNS 策略关闭。DNS 的类型转换由
`profile_source/dns.rs` 完成。

当前只支持以下 DNS 字段，地址和过滤规则均为示例：

```yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - https://dns.alidns.com/dns-query
  direct-nameserver:
    - system
  proxy-server-nameserver:
    - https://doh.pub/dns-query
  nameserver-policy: {}
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
```

| 字段 | 作用与缺省 |
| --- | --- |
| `enable` | 是否启用本段 DNS 策略，默认 `false`。未启用时使用系统解析与真实地址。 |
| `enhanced-mode` | `redir-host` 返回真实地址（默认），`normal` 同它；`fake-ip` 为未命中过滤的地址查询分配虚拟地址。不分大小写。 |
| `nameserver` | 默认业务 DNS，省略时使用 `system`。 |
| `direct-nameserver` | 明确为 DIRECT 的目标最终解析使用的 DNS；显式配置时优先于域名策略，省略时按策略与默认列表解析，都经直连查询。 |
| `proxy-server-nameserver` | 解析代理节点自身域名，固定直连；省略时独立使用 `system`，不继承业务 DNS。 |
| `nameserver-policy` | 按域名选择 DNS，未命中时使用 `nameserver`；默认无策略。 |
| `default-nameserver` | Bootstrap：解析 DNS 服务自身的域名，固定直连；省略时使用 `system`。 |
| `fake-ip-range` | IPv4 虚拟地址池，默认 `198.18.0.0/16`；只定义地址池，不改变 `enable` 或模式。 |
| `fake-ip-filter` | 使用真实地址而不分配 Fake IP 的域名，默认空列表。 |
| `use-hosts` | 应用查询 [hosts](#hosts) 映射的域名时直接答映射的地址，先于 Fake IP，默认 `true`；为 `false` 时应用照常得到 Fake IP 或上游答复，Egrio 自己解析时仍用映射。 |
| `use-system-hosts` | 也用系统的 hosts 文件映射配置没有映射的域名，默认 `true`。 |

其他 DNS 字段（如 `listen`、`fallback`、`fallback-filter`、`prefer-h3`）与顶层未识别的键
一样被忽略、原样保留在来源文件里，编辑器把它们标为不生效；`dns.ipv6` 同样不读取，AAAA 解析由顶层
`ipv6` 决定。配置依赖 `fallback` 防污染时，解析只按上面的字段进行。

DNS 地址支持 `system`、IP（UDP 53）、IP:端口，以及 `udp://`、`tcp://`、`tls://`、
`http://`、`https://` URL。HTTP/HTTPS 必须是返回 DNS wire message 的服务，
不是普通网页；HTTPS/DoT 验证服务端证书。`system` 固定直连，捕获场景使用平台接管前
取得的 DNS 快照。`default-nameserver` 只接受 `system` 或数值 IP 服务地址，防止自解析。
不提供隐含服务商的 `proxy` 简写，也不支持 URL 的 `#DIRECT`、`#RULES`、`#组名` 后缀。

各服务器列表严格按配置顺序尝试：有效正答复、NODATA 和 NXDOMAIN 都结束查询，
传输故障或 SERVFAIL/REFUSED/NOTIMP 才尝试下一项。显式空服务器列表报错，省略字段
才使用该字段的缺省行为；`nameserver-policy: {}` 与 `fake-ip-filter: []` 合法。
不会自动判断有效答复是否受污染，也不会把示例中的服务商设为默认值。

应用发问的业务 DNS 的 IP/URL 连接按解析器自身地址、端口、传输协议匹配当前规则和模式；
DIRECT 目标的解析、节点解析与 Bootstrap 固定直连：DIRECT 连接从本机网络出去，要的是本机网络
的解析器给的地址（CDN 按发问者的位置作答），节点与 Bootstrap 不能为了建立代理又依赖该代理。`respect-rules` 和
`direct-nameserver-follow-policy` 不是配置项，职责与优先级固定，不增加第二套开关。

DNS 应答与显式域名连接共用业务解析计划。裸 DNS 查询只判断可确定的 DIRECT，
不会凭空假定未来连接端口或负载均衡成员；显式 TCP/UDP 连接使用已选定的实际出站。
经代理节点的 TCP 连接把域名交给节点解析，不查询本机 DNS；UDP 目标则由本机解析。
最终为 DIRECT 的域名（含 Fake IP 恢复的域名）通过 `direct-nameserver` 解析，真实数值
目标不会因为 SNI 或域名嗅探被改写。

全局模式（全局出口不是 DIRECT）下业务域名只经代理解析，本机不为它们发出 DNS 查询：
所有地址查询都得到 Fake IP，`enable`、`enhanced-mode` 与 `fake-ip-filter` 不起作用。
其他类型的查询与 UDP 目标的解析跳过 `system`，其余服务器一律经全局出口；只配置了
`system` 时查询答空，UDP 的域名交给节点。打洞要求经名字与经地址的 UDP 远端共用一个
映射，这只在 UDP 的域名经全局出口解析成地址时成立，交给节点时每个域名另有映射，所以
用全局模式打洞的配置要在 `nameserver` 里写 `system` 以外的服务器。`proxy-server-nameserver`
与 `default-nameserver` 照常直连，只暴露节点与 DNS 服务器自身的主机名。规则与直连模式不受影响，
细节见 [Core DNS](core.md#模块布局)。

`nameserver-policy`、`fake-ip-filter` 与 [hosts](#hosts) 的域名采用按标签匹配的模式：点分的标签，
其中 `*` 代表恰好一个标签，可以在任何位置（`*.lan`、`time.*.com`、`stun.*.*`、`*.*.xboxlive.com`）；
前缀 `+.` 表示该域名与它之下的所有域名（`+.example.com`、`+.stun.*.*`），前缀 `.` 只表示它之下的
域名；单独的 `*` 是所有域名。标签只能由字母、数字、`-` 与 `_` 组成。`geosite:`、`rule-set:` 引用与
其他不是域名的写法都使配置报错：悄悄略过的过滤项或策略会让解析与配置所写的不同。
域名策略多项匹配时按声明顺序使用第一项；策略值可为单个服务器或服务器列表，一个键可以用逗号写几个域名
（`'+.a.example,+.b.example'`），各自得到这个键的服务器。
例如 `nameserver-policy: {'+.internal.example': [system]}`。

`fake-ip-range` 接受有效 IPv4 单播 CIDR，输入中的主机位会规范化，例如
`198.18.0.1/16` 对应 `198.18.0.0/16`。网络地址、首个主机地址和广播地址不参与分配。
不允许包含非单播地址的范围，或没有可分配地址的 `/31`、`/32`。地址池应避开真实业务网段。
热换池保留本次会话已发布的地址映射，不把已发给客户端的地址重新绑定给另一域名；
容量耗尽明确失败。IPv6 的内部映射与 IPv4 对应，不另提供 `fake-ip-range6` 配置。

IPv6 解析只由来源顶层 `ipv6` 控制；关闭 DNS 后其附属配置不参与执行。
完整 YAML 保存/替换仍触发原有整体 Runtime 配置替换；具体执行职责见
[Core DNS](core.md#模块布局)。

### hosts

顶层 `hosts` 把域名映射到固定地址，值是一个 IP 或 IP 列表，键的写法与 `fake-ip-filter` 相同（例如
`'+.dev.example': [127.0.0.1, '::1']`）。几项都匹配时最具体的生效：从域名的最后一个标签往前，每一级
先看写明的标签，再看 `*`，最后才是已走到的域名上的 `+.` 或 `.`。所以精确域名（含 `+.` 的域名本身）
先于 `*.` 单级子域，后者先于最长的 `+.` 后缀，单独的 `*` 最后；同一模式写两次用第一项。配置没有映射的
域名在 `dns.use-system-hosts` 时再查系统的 hosts 文件（只有精确域名），文件改了几秒内生效。映射不随
`dns.enable`：DNS 未启用时同样生效，`use-hosts` 与 `use-system-hosts` 取缺省值。

被映射的域名在 Egrio 自己解析的地方都用映射的地址，不向任何 DNS 服务器查询：DIRECT 连接、需要解析的
IP 规则（`no-resolve` 的规则不为域名查地址）、UDP 目标、节点与 DNS 服务器自身的域名；经代理节点的连接交给
节点映射的地址（有 IPv4 时取 IPv4）而不是域名。应用的地址查询在 `dns.use-hosts` 时直接
得到映射的地址（TTL 10 秒），先于 Fake IP，映射里没有所问族的地址时答空；同名的 HTTPS 记录查询答空，
其中的地址提示会绕过映射，其他类型照常查询上游。值写成另一个域名、`lan` 或空列表时
配置报错。

## 提交与删除

产品后端是单一写入者。来源 blob 先写入，再原子替换 manifest；校验或发布前失败保留旧
来源与选择。Unix 写入使用受限权限，文件及目录项同步；其他平台的断电持久性不能由 macOS 的
验证结果代替。文件发布后目录同步失败返回专门的不确定性错误，要求重新读取。

删除配置一次移除选择与缓存引用，再清理无引用文件。清理失败
不复活对象。准备/读取与 GC 使用同一存储边界，已返回的有效配置拥有解码后的内容，不依赖
继续打开旧 blob。共享 hash 文件按全部现存引用回收。

运行中的活动配置必须走“停止并删除”：用户切换锁跨越 Runtime 停止、OS 恢复及 manifest
删除，清理失败保留对象和恢复责任；成功后清空活动 ID，不自动选择别的配置。已停止的
配置可直接删除，后续导入本身不会启动网络。

## 规则编辑和选择

选择按 Profile 的组与候选校验。新配置没有保存选择时使用已验证的初始化规则；旧选择
失效时报告冲突，不偷偷选另一个出口。

规则页的新增、修改、删除与排序直接改写来源的 `rules` 列表。新增规则放在列表最前，避免
落在 MATCH 后面；规则类型按 Clash 惯例写成大写。Core 不认识的规则类型（`IP-ASN`、`IN-PORT`
等）在 Core 的规则块里都是“未知类型”，来源写的是什么由解析结果在块之外按规则位置另记：规则按
这个类型列出，修改它时写回的也是这个类型。应用写入的规则必须指向配置中存在的出口
和 rule-provider；手写规则由作者负责，出口缺失在连接命中该规则时由 Core 报告。provider
定义来自来源，本地只更新缓存。规则清单和 source revision 来自同一快照，编辑器提交的 CAS
不拼接另一次查询的版本；来源变化后，界面清除按旧位置做的多选。
