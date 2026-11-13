# Egrio 文档

本页是文档地图和文档规则。文档只描述项目现在的样子；过去的设计、计划与验证过程留在 Git 历史中。

## 文档地图

| 文档 | 内容 |
| --- | --- |
| [架构总览](architecture/overview.md) | 原则、分层、crate 职责、依赖规则、捕获模型与平台总表 |
| [Runtime 与 SDK](architecture/runtime.md) | 生命周期事务、包数据面、捕获层切换、配置操作、平台装配、特权服务与非 GUI 宿主 |
| [Core 数据面](architecture/core.md) | `egrio-core` 的职责边界、模块、包泵、分片与进程归因 |
| [桌面宿主](architecture/desktop.md) | 产品后端、界面层、页面与消息、托盘、编辑器窗口、启动、退出、日志与测试控制口 |
| [配置档案存储](architecture/profile-store.md) | 配置来源、选择与取值规则、来源改写、DNS 配置、提交与删除 |
| [Windows 平台](platforms/windows.md) | Wintun、特权服务、WFP、出口绑定、DNS、进程归因、桌面应用与验证状态 |
| [macOS 平台](platforms/macos.md) | utun 与 launchd 服务、签名与服务安装、网络设置、出口绑定、归因、桌面应用与验证状态 |
| [Linux 平台](platforms/linux.md) | `/dev/net/tun`、root 助手、策略路由、DNS、nftables、出口标记、桌面应用与验证状态 |
| [捕获层验收](runbooks/capture-layers.md) | 三个桌面平台的系统代理与 TUN 验收矩阵 |
| [macOS TUN 验收](runbooks/macos-tun.md) | macOS 服务安装、数据面、旧连接、失败恢复与长时间运行的验收步骤 |
| [发布](runbooks/release.md) | GitHub 发布工作流、发布的文件、所需的密钥与发布步骤 |
| [待办与已知问题](backlog.md) | 未完成的工作、已知缺陷与未验证范围 |
| [捕获数据面设计](designs/capture-data-plane.md) | UDP、ICMP 与其他协议面向实时语音（Wi-Fi Calling）的行为、热点设备与实施步骤 |

代码旁的 README 只说明所在目录的构建、测试与使用：[Core 基准](../crates/egrio-core/bench/README.md)、
[验证脚本](../scripts/validation/README.md)与[应用图标](../design/icons/README.md)。

漏洞报告方式见[安全说明](../SECURITY.md)。

## 工程检查

[`CI` 工作流](../.github/workflows/ci.yml)在推送 `main`、提交 Pull Request 或手动触发时运行。
`Check (macOS)`、`Check (Windows)` 与 `Check (Linux)` 分别在三个平台执行 `cargo xtask check --full`。
Windows 先运行 `cargo xtask windows-deps`，Linux 安装 GTK 4 与 libadwaita 开发依赖。
自动门禁覆盖构建与测试；修改系统捕获状态的验收另按[捕获层验收](runbooks/capture-layers.md)执行。

## 文档规则

### 只写现在

- 架构与平台文档描述当前代码与产品行为，与代码在同一提交中更新。文档与代码不一致是缺陷：先确认哪边
  错了，再修正。
- 不写历史：不叙述代码或设计如何演变（“原先如何”“某物已删除”“迁移后”），不写阶段编号、日期化进展或
  “本批”，不保留划掉的条目。设计理由写成当前的约束与取舍；被替换的方案与过程只留在提交信息和 Git
  历史中。
- 理由用本项目自己的约束与取舍说明，协议行为以协议规范为依据，不以“与某实现一致”作依据；Clash 配置键
  直接写明其语义。
- 没有归档。完成、放弃或过时的文档直接删除，不留占位文件或旧路径别名。

### 一类事实一个位置

| 事实 | 位置 |
| --- | --- |
| 原则、crate 职责、依赖规则、捕获模型 | `architecture/overview.md` |
| Runtime/SDK 生命周期、捕获层切换、配置操作、特权服务协议 | `architecture/runtime.md` |
| Core 数据面行为、限额与协议依据 | `architecture/core.md` |
| 桌面宿主模块与界面行为 | `architecture/desktop.md` |
| 桌面配置的存储与取值 | `architecture/profile-store.md` |
| 平台机制、官方 API 依据、平台代码结构与验证状态 | `platforms/<平台>.md` |
| 可重复的验收步骤与发布步骤 | `runbooks/` |
| 未完成工作、已知缺陷、未验证范围 | `backlog.md` |
| 允许的 crate 依赖边 | `scripts/workspace-dependency-policy.json` |

其他文档链接到该位置，不复述。

### 设计、待办与验证

- 需要先达成一致的大改动在 `designs/<主题>.md` 写设计与实施步骤，并加入本页地图。实施完成时，把仍然
  成立的事实写进架构或平台文档，在同一提交删除设计；放弃时直接删除。
- `backlog.md` 是唯一的待办清单。每项写清问题、影响与完成标准；完成即删除该项，不标注“已完成”。
- 验证结果不单独成文。系统验收后替换对应平台文档的“验证状态”：日期、环境、构建、已覆盖与未覆盖
  范围；未修复的发现写入 `backlog.md`；原始输出只留在系统临时目录，不写进项目目录，凭据不进入仓库。
- 公开文档只保留复现所需的系统版本、构建和条件。实机名称、个人用户名与目录、私有网络拓扑、节点地址、订阅及
  签名人的身份不进入仓库；本地跑分、线路测速和调试流水账不写入当前文档，验收只保留可复用的结论与缺口。
  地址示例使用文档保留地址，秘密通过环境变量或本地配置传入。

### 格式

- 正文与标题使用中文，文件名使用不带日期的英文 `kebab-case`。
- 不使用前置元数据；第一行是文档唯一的一级标题，标题在全部文档中唯一。
- 项目内链接使用相对路径，锚点必须指向存在的标题。
- 一份文档只承担一类职责；混入其他职责或明显过长时按职责拆分。
- 平台行为注明官方文档、SDK 头文件或厂商参考作为依据。
- 新增、删除或重命名文档时在同一提交更新本页地图。`cargo xtask docs` 检查地图完整、链接与锚点有效、
  标题唯一，并拒绝前置元数据和删除线。
