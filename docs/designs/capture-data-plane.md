# 捕获数据面设计

TUN 捕获的包按协议分四路：TCP 由 Core 的引擎终结后交给 relay（见[捕获 TCP](../architecture/core.md#捕获-tcp)），
UDP 按流中继，ICMP 本地应答或转发，其他 IP 协议按平台直连或丢弃。本设计补齐 UDP、ICMP 与其他协议面向
实时语音（Wi-Fi Calling）的行为。完成后本页的事实写进 [Core 数据面](../architecture/core.md)与各平台文档，
本页删除。

## 动机

Wi-Fi Calling 是手机经 IKEv2/IPsec 连到运营商的 ePDG（3GPP TS 24.302；ePDG 的域名形如
`epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org`，TS 23.003）。它的包经 Core 的 UDP 中继离开时源地址被改写，
IKE 的 NAT 检测必然命中（RFC 7296 §2.23），ESP 于是封装在 UDP 4500 里（RFC 3948），所以它对数据面的要求
落在 UDP 上：映射稳定、会话不过早回收、大报文能重组、语音的 DSCP 标记不丢、延迟稳定。它经两种路径到达
Egrio 节点：手机上的 Egrio 捕获后经节点协议转发；或手机连接电脑开启的热点，电脑把热点设备转发来的流量
送进 TUN，由电脑上的 Egrio 经节点转发。

## UDP

UDP 按客户端 socket 建会话，同一客户端 socket 发往任何目的地都经同一个出口 socket（端点无关映射，
RFC 4787 REQ-1），回包按来源地址回到客户端。会话空闲 120 秒才回收，长于 IPsec NAT-T 保活的常见间隔
（RFC 3948 §4）。补充两点：

- DSCP：客户端包的 DS 字段（RFC 2474）随报文带到出口 socket（`IP_TOS`/`IPV6_TCLASS`，按会话或逐报文设置），
  回包的 DS 字段带回客户端；Wi-Fi 上 WMM 按它把语音放进优先队列。代理出站无法逐报文标记时只标记到代理
  服务器的外层连接。
- 大报文：分片的报文先重组再中继（已有），出口由操作系统按路径 MTU 分片。

### 经节点承载语音

- 每一跳的会话：Core 的 UDP 会话与节点出口的会话都保持端点无关映射，空闲回收时间都长于 NAT-T 保活间隔。
- 承载协议：Hysteria2 与 Shadowsocks 原生转发 UDP，丢包只影响该报文；Trojan 把 UDP 放在 TCP 上，丢包时
  后续报文要等重传，语音抖动更大。超过 QUIC 数据报上限的 IKE 报文按 Hysteria2 协议分片承载。
- DSCP：经代理时只能标记我们发出的那一跳（客户端到节点的连接、节点到 ePDG 的出口），节点协议不携带
  内层的 DS 字段。

### 热点设备

电脑开启热点时，热点设备的包由电脑转发进 TUN，源地址是热点网段而不是本机。数据面对它们与本机流量一视同仁
（TCP 按四元组终结，UDP 按客户端 socket 建会话），另有两点：

- 链路 MTU：TUN 的 MTU 可达 65535，热点链路通常是 1500。TCP 按客户端 SYN 的 MSS 分段，不受影响；Core 发回
  的 UDP 超过 1500（IPv4）或 1280（IPv6，RFC 8200 §5 的最小链路 MTU）时在源头分片，IPv4 分片不置 DF，
  电脑转发到更小 MTU 的链路时还能再分片。带证书的 IKE_AUTH 应答因此能到达手机，不依赖 IKEv2 分片
  （RFC 7383）是否协商成功。
- 平台接入：热点的转发与地址转换（Windows 移动热点的 ICS、macOS 的互联网共享、Linux NetworkManager 的共享
  连接）与 TUN 的路由、kill switch 和 DNS 如何配合，按各平台的官方文档另行设计与验证。

## ICMP

- 回显：发往 Fake-IP 目标的请求本地应答（已有）；发往真实目标的请求按路由 DIRECT 时经各平台无需特权的
  ICMP 接口转发并把应答写回客户端（Linux 与 macOS 的 `SOCK_DGRAM` ICMP socket，Windows 的
  `IcmpSendEcho2`），经代理的目标仍本地应答。
- 差错：出口 socket 收到的差错（端口不可达、需要分片、Packet Too Big）按 RFC 1812 §4.3.2.3 与 RFC 4443 的
  格式合成回客户端，引用客户端发出的原始包头，让客户端的应用快速失败、让路径 MTU 发现正常工作。

## 其他 IP 协议

裸 ESP、GRE、SCTP 等无法经用户态中继代理，只能直连。Linux 以按协议的策略路由（`ip rule ... ipproto`）只把
TCP、UDP 与 ICMP 引入 TUN，其余由内核按主路由表直接转发，kill switch 对它们的放行与否随配置；macOS 与
Windows 的系统 VPN 接口把所有协议交进隧道，这些包计数后丢弃。

## 验证

以 strongSwan 作 IKEv2/IPsec 客户端与服务端，分别经 TUN 的 DIRECT、经节点、经电脑热点再经节点三种路径建
隧道，检查 NAT-T 生效、保活下各跳会话不被回收、大于链路 MTU 的 IKE 报文到达、DSCP 带到可控的一跳、持续
小包流的延迟与抖动。

## 实施步骤

1. UDP：各跳会话的映射与回收、按链路 MTU 的源分片、DSCP 传递，ICMP 回显转发与差错合成，三种路径的语音
   验证。
2. Linux 按协议引流与其他协议的直连；各平台热点接入。更新平台文档，删除本页。
