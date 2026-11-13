# 架构总览

Egrio 是一个可复用的 Rust 代理栈加一个桌面客户端：`egrio-core` 是代理数据面，`egrio-runtime` 与
`egrio-sdk` 负责生命周期与装配，平台 crate 实现系统代理与 TUN 捕获，产品后端 `egrio-desktop`、
界面 `egrio-ui` 与应用 `egrio`（各平台的原生界面）组成桌面应用。可复用栈必须能脱离桌面应用，被其他 CLI、守护进程或
GUI 宿主嵌入。

产品统一命名为 Egrio：Rust 包和命令行二进制使用 `egrio` / `egrio-*`，公开 SDK 类型使用
`EgrioSdk` / `EgrioSdkBuilder`，环境变量使用 `EGRIO_*`，桌面应用标识为 `com.xinvexo.egrio`。
Clash YAML 指 Clash 系客户端的配置格式，其格式名与导入 API 保留该语义。

## 原则

- **Rust API 是主要集成面。** 官方宿主与第三方使用同一套 SDK/Runtime 公共 API；桌面应用、CLI 与
  特权服务都是可替换的宿主或适配器。桌面产品（`desktop/`）是可复用栈的提取边界，产品概念（配置档案
  存储、Clash YAML、HTTP 获取、应用数据目录）不进入其下的 crate。
- **角色是组合而不是模式。** 客户端、服务端与中继是同一条 Core 流水线按配置组合的入站与出站，
  协议的客户端/服务端两端共享同一个 codec；Core 不公开客户端/服务端标志。`capture` 与 `server`
  cargo feature 只是打包选择，可以构建仅客户端、仅服务端或两者兼有的二进制。产品只交付桌面客户端
  （桌面产品启用 `capture`，从不启用 `server`），服务端以无头方式运行（`egrio-server`）。
- **Runtime 是唯一的生命周期边界。** 一个 Runtime 拥有一套独立的入站、出站、路由、DNS、会话、
  平台资源、健康状态、遥测和取消；一个进程可以创建多个相互隔离的 Runtime。系统代理、默认路由、
  系统 DNS 与防泄漏防火墙等宿主全局资源由 SDK 发放排他租约，冲突在修改 OS 之前失败。
- **OS 接管是可替换的适配器。** 平台能力以小契约接入 Runtime，具体 OS 代码留在平台 crate；特权
  服务只是远程适配器，不定义领域模型。远程适配器与进程内适配器运行同一套契约测试。
- **数据面不感知平台与产品。** Core 不依赖界面、GUI 状态或具体 OS 适配器，配置文件格式不是
  Runtime 模型：Clash YAML 与节点链接是桌面后端的输入，结构化的 `RuntimeProfile` 才是 Core 的交接
  格式。界面不持有长期网络状态。
- **行为基准是全流量控制。** 进程可见性、DNS 一致性、TCP/UDP 覆盖、防泄漏行为与干净的系统
  恢复共同构成全流量控制的验收范围；配置格式与 Clash 兼容，执行以原生 Core 为先。协议以其规范为准，平台 API
  以官方文档和 SDK 为准。
- **安装系统组件需要用户授权。** 特权服务等永久组件只在用户授权后安装或运行（Windows UAC、
  Linux polkit、macOS 在“登录项”中允许）；开启 TUN 不会静默安装任何组件。

## 分层

```text
egrio（应用：AppKit / WinUI 3 / GTK 4 后端）
  -> egrio-ui：组件、比对、窗口与托盘的描述
  -> egrio-desktop：配置档案、设置、连接历史与宿主操作
  -> DesktopRuntime：每个桌面平台一个固定 Runtime
       -> egrio-runtime：Core generation、能力事务、租约、检查点、packet 任务
            -> egrio-core：规则、DNS/Fake-IP、TCP/UDP、协议、出站
            -> 平台能力：系统代理（进程内）与 TUN（PacketCapture/Route/DNS/Firewall）
                 -> egrio-service 特权服务（远程能力端口；macOS 由 launchd 运行）

egrio-node（egrio-daemon）：经 SDK 装配 Runtime 的诊断与运行 CLI
egrio-server（egrio-daemon，server feature）：只含 Core 的无头服务端
  -> 入站：SOCKS5/HTTP · Shadowsocks · Trojan · Hysteria2 -> DIRECT / 上游出站
```

## Crate 职责

| 位置 | 职责 | 文档 |
| --- | --- | --- |
| `crates/egrio-core` | 代理数据面：配置档案模型、规则、DNS/Fake-IP、TCP/UDP 会话、协议、包处理、进程归因门控、遥测 | [Core 数据面](core.md) |
| `crates/egrio-runtime` | Core 与平台能力的生命周期事务、reload、回滚、检查点、恢复与 packet 任务 | [Runtime 与 SDK](runtime.md) |
| `crates/egrio-sdk` | Runtime 装配、平台能力注入、进程内租约协调、持久检查点存储与启动恢复 | [Runtime 与 SDK](runtime.md) |
| `crates/egrio-platform` | 平台共享契约：捕获层模型（`CaptureLayers`、`CaptureSupport`、`capture_support_for_os`）、进程显示 DTO（`ProcessDisplayQuery`、`ProcessDisplayIdentity`）、系统代理 DTO 与 `system_proxy_config_from_listen_addr` | 本节 |
| `crates/egrio-platform-{windows,macos,linux}` | 桌面平台的 TUN、路由/DNS/防火墙、系统代理、出口保护与进程扫描器 | [平台文档](#平台) |
| `crates/egrio-service` | Windows 服务、Linux root 助手与 macOS launchd 服务：远程能力端口、控制协议与包通道 | [特权服务](runtime.md#特权服务) |
| `crates/egrio-daemon` | `egrio-node` CLI、`egrio-server` 服务端与桌面侧特权服务生命周期 | [非 GUI 宿主](runtime.md#非-gui-宿主) |
| `desktop/egrio-desktop` | 桌面产品后端与 Runtime 宿主 | [桌面宿主](desktop.md)、[配置档案存储](profile-store.md) |
| `desktop/egrio-ui` | 界面：组件与比对、窗口与托盘的描述、文本与流量曲线几何，不链接界面工具包 | [桌面宿主](desktop.md#界面层) |
| `desktop/egrio` | 桌面应用：进程入口与 macOS、Windows、Linux 的平台后端 | [桌面宿主](desktop.md)与各平台文档 |
| `xtask` | 仓库任务：检查门禁、文档与依赖检查、macOS 应用包、图标、Windows 构建旁的 DLL | 本节 |

`egrio-platform` 只保存真正平台中立的契约，使用 `control_command` 等宿主中立命名，不把桌面外壳
指定为控制平面所有者，也不提供就绪报告、预检、诊断快照或计划描述这类旁路探测。

## 依赖规则

允许的 workspace 依赖边由 `scripts/workspace-dependency-policy.json` 唯一定义，并由
`cargo xtask check` 中的依赖检查（`xtask/src/dependencies.rs`）强制。方向是：

```text
egrio-core
  <- egrio-runtime
       <- egrio-platform-{windows,macos,linux}（另依赖 egrio-platform）
       <- egrio-service
       <- egrio-sdk（按 platform-* feature 选择平台 crate 与 egrio-service）
            <- egrio-daemon、egrio-desktop
                 <- egrio-ui
                      <- egrio（另依赖 egrio-daemon）
```

无论如何都必须成立：

- Core 绝不依赖界面、GUI 状态、具体 OS 适配器或任何 workspace crate；
- 平台适配器 crate 绝不相互依赖，只经 `egrio-core`、`egrio-platform` 与 `egrio-runtime` 契约相遇，
  也绝不依赖 `egrio-daemon` 或宿主；
- 以 `--no-default-features --features server` 构建的 `egrio-daemon` 不链接 Runtime 或任何具体
  平台 crate；
- 宿主绝不重导出 workspace crate API；
- 可复用的数据包、路由、DNS、协议或平台适配器 API 不得只存在于桌面产品 crate；
- 产品配置档案存储留在产品后端，不进入 `egrio-core` 或 `egrio-daemon`；
- 只读诊断不得成为生产环境的路由、DNS、防火墙或捕获所有权路径；
- Core 不执行进程级 OS 变更（rlimit、信号、提权），由宿主持有其进程环境；
- 不为重命名的内部 API 提供兼容性别名。

## 捕获模型

捕获只有**系统代理**与 **TUN 模式**两个独立开关，可单独或同时开启，没有第三种模式。同时开启时，
遵循系统代理的应用经本机监听进入 Core，其余流量由 TUN 接管。macOS、Linux、Windows 三个平台都支持两层，
实现之外的系统两层都不支持（要求哪一层都会被拒，而不是当作什么都没做）。切换一层不重启 Core，失败回到切换前的层，不连带关闭另一层；实现见
[捕获层切换](runtime.md#捕获层切换)。流量策略与捕获层相互独立：`rule`、`global` 与 `direct` 在
平台支持的每种层组合下都必须工作。

桌面 TUN 统一使用 IP 层设备，数据包进入同一 Runtime/Core 管线；平台只负责设备、网络设置、出口
环路隔离和恢复：

```text
OS TUN / packet flow
  -> platform PacketDevice（非阻塞 + 就绪）
  -> Runtime-owned NativeCorePacketDataPlane
  -> 同一 NativeCoreDevice
       -> IP parser / TCP engine
       -> TCP / UDP / DNS / Fake-IP
       -> rules / outbound
```

每个 Runtime generation 只有一个 Core；显式 HTTP/SOCKS listener 与 TUN 入口共享规则、DNS/Fake-IP
状态、UDP actor、进程归因和连接遥测。平台不实现 TCP/UDP flow relay，也不另建 Core。系统代理是
可选的应用代理设置能力，可与 TUN 组合，不形成第二套全局捕获数据面。进程名、签名标识和程序图标
是可选增强，无法提供时如实报告缺失，不阻塞捕获，也不凭空推断。

## 平台

| 平台 | 捕获设备 | 网络控制 | 文档 |
| --- | --- | --- | --- |
| Windows | Wintun | 特权服务持有适配器、路由、DNS 与 WFP；桌面 Runtime 持有 Core 与 packet pump | [Windows](../platforms/windows.md) |
| macOS | utun | launchd 服务建立 utun、进 utun 的路由、排除路由与默认解析器，交出 utun 的描述符；Core 出站 socket 绑定物理接口 | [macOS](../platforms/macos.md) |
| Linux | `/dev/net/tun` | root 助手建立设备、专用策略路由、DNS 与 nftables；Core socket 由助手打出口标记 | [Linux](../platforms/linux.md) |

每个平台文档记录机制、官方依据、代码结构与验证状态；本地契约测试不能代替真实系统验证。
