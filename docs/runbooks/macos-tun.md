# macOS TUN 验收

实现边界、网络设置与 SDK 依据统一见
[macOS 平台](../platforms/macos.md)；两层组合的通用矩阵见
[捕获层验收](capture-layers.md)。本手册定义可重复操作，
不代表当前机器已经通过系统验收。

## 网络影响与准备

注册或替换 Egrio 服务会改变 launchd 与“登录项”状态；开启 TUN 会新增 utun、把每个地址族除首个 /8 外的地址空间
路由进它（减去排除的网段）、在物理接口上为 fake-IP 池加作用域拒绝路由、把默认解析器换成虚拟 resolver；切换或
停止会中断相应连接并恢复这些设置。执行前说明这些影响，记录用户约定的最终模式与节点；已有网络状态变更授权继续
适用，不额外引入重复审批。

先保存系统代理、活动配置、模式、节点、IPv6 设置、`scutil --nwi`、`scutil --dns`、`scutil --proxy`、
`route -n get default`、`route -n get -inet6 default`、`netstat -rn` 和接口清单。确认 recovery
checkpoint 可从本地读取；清理不得依赖公网服务或测试连接继续存活。本机若有其他 VPN，单独记录它的
预期状态与出口，不把它的变化混进本次结果。

## 构建与安装输入

1. 执行 `cargo xtask check` 和 `cargo xtask package`（验收应用加 `--test-control`），记录命令、退出状态、commit/工作区
   版本和生成物。
2. 核对签名应用的 `Contents/MacOS/egrio-service` 与应用同一 Team ID，
   `Contents/Library/LaunchDaemons/com.xinvexo.egrio.service.plist` 与 Rust 常量一致（打包时已检查）。
3. 从 `/Applications` 启动应用并开启 TUN：首次注册后系统要求批准，在“系统设置 > 通用 > 登录项与扩展”
   中允许 Egrio 后再次开启；旧版以另一类证书签名时，先按 [macOS 平台](../platforms/macos.md#产品身份签名与服务安装)
   注销再注册。用 `EGRIO_MACOS_SERVICE=status` 运行应用可执行文件读取注册状态；独立核对
   `launchctl print system/com.xinvexo.egrio.service` 中运行的可执行文件是本次构建。

本地构建/契约/签名检查不修改路由、DNS 或代理；注册、批准和捕获运行属于上节所述网络变更。

## 数据面验证

分别运行 TUN、SystemProxy 和组合 topology，检查每次都只有一个 Runtime Core。
TUN 流量应显示为 packet 入口；SystemProxy listener 与 TUN 共享 Fake-IP/DNS/规则状态，
不能把显式 HTTP/SOCKS 请求成功等同于原生 TUN 成功。

| 范围 | 需要保存的独立证据 |
| --- | --- |
| 路由与解析器 | `scutil --nwi` 首位仍是物理接口，公网目的地（`route -n get`）双栈都经本隧道的 utun，组播与网段内目的地经物理接口，`scutil --dns` 首个解析器是虚拟 resolver，系统解析器（`getaddrinfo`）为 fake-IP 域名给出 fake IP |
| IPv4、IPv6 TCP | 不依赖系统代理的原生 socket 请求；同一 Core 遥测和实际远端/出口结果 |
| UDP、QUIC | 原生 UDP 往返与实际 QUIC 请求，分别记录协议、端点和双向 payload |
| DNS/Fake-IP | 系统 DNS 进入虚拟 resolver、Core 查询/映射和后续 TCP/UDP 反向映射；出口 DNS 不递归回 TUN |
| DIRECT、代理出口 | 分别核对物理接口绑定、真实出口与不存在自身捕获回环；不以模式名称代替路径证据 |
| 排除与组播 | 排除网段与 `224.0.0.251` 的 `route -n get` 指向物理上行；切换上行后跟随新上行；切换模式时 utun 不变、路由先加后删（`route -n monitor`） |
| 隧道外的 fake IP | `netstat -rn` 中物理接口上有 fake-IP 池与其 IPv6 投影的拒绝路由；绑定物理接口（`IP_BOUND_IF`、`IPV6_BOUND_IF`）连 fake IP 立即失败，未绑定的经 utun 连上，绑定物理接口连真实地址照常；其他 VPN（Tailscale）开着 TUN 冷启动上线 |
| 系统代理 | 两层同开时 `scutil --proxy` 是指向 listener 的 HTTP/HTTPS；只开 TUN 时为空 |
| MTU、分片与大数据 | 记录请求大小、实际完成字节数、丢包/错误和响应；不同 packet 大小独立验证 |
| 程序元数据缺失 | 未获得进程身份时仍可完成捕获、规则与遥测；不伪造程序名或图标 |

测试使用受控服务或端点，记录时间戳和真实返回；隐藏自动重连、缓存与重试会使结论无效。

## 接管前连接

路由切换不保证所有既有连接具有相同的切换行为，因此逐项观察：

1. 关闭捕获后，分别建立原生 BSD socket 和 Network.framework `NWConnection` 的 IPv4/
   IPv6 TLS keep-alive 连接；记录 PID、FD/connection identity、本地端口、真实远端和出口 IP。
2. 保留主动发送与空闲旧连接，开启 TUN，记录 `capture-change-requested`/`capture-change-finished`；
   探针禁止自动重连。
3. 在原对象上重复请求并记录实际读写结果。ESTABLISHED、页面缓存或应用自行重建 socket
   不足以证明原连接继续传输。
4. 明确创建新连接，核对它进入本次 packet Core 和预期出口。旧连接失效还需排除服务器
   空闲超时，不能仅按时间邻近推断原因。
5. 重复关闭/开启与双栈场景；UDP/QUIC 单独记录。

捕获切换的时间取自应用日志 `~/Library/Logs/com.xinvexo.egrio/egrio.log`，服务的打开与关闭取自
`/var/log/egrio-service.log`。记录只留本地，不得保存配置正文或凭据。

## 失败、恢复与长时间运行

依次验证启动失败、服务被强杀或重启、桌面进程崩溃、应用退出和进程重启 recovery：强杀服务后解析器随会话
消失、路由随 utun 回到物理接口，桌面报告 TUN 中断并原地恢复；桌面崩溃后服务结束该会话的隧道；重启后的
服务先移除上一进程留下的路由。当前 macOS 未提供独立 OS kill-switch，测试必须记录失败窗口的真实
网络行为，不能默认其必定 fail-closed。

网络中断后本地仍能完成停止与恢复。切换物理网络、睡眠/唤醒和锁屏，验证出口接口重新探测、排除路由
跟随、DNS 不递归、旧连接结束与新连接恢复；无可用物理出口时开启 TUN 明确失败。进行持续 TCP/UDP/DNS
混合运行，记录时间长度、包/连接计数、内存、fd、队列背压与错误。

最后独立重读系统代理、接口、路由与 DNS，核对约定基线和外部 VPN/代理未被覆盖；恢复用户约定的最终
模式与节点。结果按[捕获层验收](capture-layers.md#记录)的方式写回平台文档的验证状态与待办，原始输出
只留在系统临时目录，不写进项目目录，凭据不得入库。
