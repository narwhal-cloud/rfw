# rfw

Rust Firewall - 基于 eBPF/XDP 的高性能防火墙，支持 GeoIP 过滤和协议深度检测

[![Release](https://github.com/narwhal-cloud/rfw/actions/workflows/build.yml/badge.svg)](https://github.com/narwhal-cloud/rfw/actions/workflows/build.yml)

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [技术实现](#技术实现)
- [编译和安装](#编译和安装)
- [License](#license)

## 功能特性

### 灵活的 GeoIP 过滤

- **多国家支持** - 支持指定任意国家代码（CN、RU、KP、US 等）
- **灵活的过滤模式**:
  - **黑名单模式** - 阻止指定国家的流量
  - **白名单模式** - 只允许指定国家的流量
  - **无 GeoIP 模式** - 直接基于协议规则过滤所有流量
- **自动下载 GeoIP 数据** - 运行时自动下载指定国家的最新 IP 段

### 支持的过滤规则

1. **屏蔽 Email** - 阻止邮件（SMTP: 25/587/465/2525）相关端口流量
2. **屏蔽 HTTP 入站** - 使用协议深度检测识别 HTTP 流量，配合 GeoIP 或全局过滤
3. **屏蔽 SOCKS5 入站** - 使用协议深度检测识别 SOCKS5 流量，配合 GeoIP 或全局过滤
4. **屏蔽全加密流量入站** - 使用 FET 算法识别 Shadowsocks、V2Ray 等加密代理
5. **屏蔽 WireGuard VPN 入站** - 精准识别 WireGuard VPN 协议
6. **屏蔽 QUIC 入站** - 精准识别 QUIC 协议（HTTP/3）
7. **屏蔽所有入站流量** - 阻止所有入站连接（配合 GeoIP 或全局）

### 协议深度检测 (DPI)

与传统的基于端口号的防火墙不同，rfw 使用**协议深度检测**（Deep Packet Inspection, DPI）：

- **HTTP 检测**：识别 HTTP 请求方法（GET, POST 等）
- **SOCKS5 检测**：识别 SOCKS5 握手协议特征
- **全加密流量检测**：使用统计算法识别 Shadowsocks、V2Ray 等加密代理
- **WireGuard 检测**：精准识别 WireGuard VPN 协议
- **QUIC 检测**：识别 QUIC v1/v2 和 Google QUIC 协议（HTTP/3）
- **不依赖端口号**：即使服务运行在非标准端口也能识别

### 性能特性

- **XDP (eXpress Data Path)**：在网卡驱动层处理数据包，极低延迟
- **零拷贝**：直接在内核中处理，无需复制数据到用户空间
- **高吞吐**：可处理 10Gbps+ 的网络流量

### 协议支持

- **仅支持 IPv4**：目前不支持 IPv6 流量
- **GeoIP 自动更新**：每次运行时自动下载指定国家的最新 IP 数据
- **多数据源**：使用 [lyc8503/sing-box-rules](https://github.com/lyc8503/sing-box-rules) 提供的 GeoIP 数据

## 快速开始

### 编译

```bash
# Linux 环境
cargo build --release

# macOS 交叉编译到 Linux (x86_64)
CC=x86_64-linux-musl-gcc cargo build --package rfw --release \
  --target=x86_64-unknown-linux-musl \
  --config=target.x86_64-unknown-linux-musl.linker=\"x86_64-linux-musl-gcc\"

# macOS 交叉编译到 Linux (aarch64)
CC=aarch64-linux-musl-gcc cargo build --package rfw --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\"
```

### 基本使用

```bash
# 查看帮助
sudo ./target/release/rfw --help

# 阻止指定国家的 HTTP 和 SOCKS5 流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN,RU,KP \
  --block-http --block-socks5

# 阻止来自中国的所有流量（快捷方式）
sudo ./target/release/rfw --iface eth0 \
  --block-all-from CN

# 白名单模式：只允许来自美国、日本、韩国的流量
sudo ./target/release/rfw --iface eth0 \
  --allow-only-countries US,JP,KR \
  --block-http --block-socks5

# 不限国家，阻止所有 HTTP 流量
sudo ./target/release/rfw --iface eth0 \
  --block-http

# 启用详细日志
sudo RUST_LOG=info ./target/release/rfw --iface eth0 --countries CN --block-wireguard --block-quic
```

## 使用说明

### GeoIP 配置

#### 1. 黑名单模式（阻止指定国家）

```bash
# 阻止来自中国、俄罗斯、朝鲜的 HTTP 流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN,RU,KP \
  --block-http

# 阻止来自指定国家的所有流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN,RU \
  --block-all
```

#### 2. 白名单模式（只允许指定国家）

```bash
# 只允许来自美国、日本、韩国的访问
sudo ./target/release/rfw --iface eth0 \
  --allow-only-countries US,JP,KR \
  --block-http --block-socks5
```

#### 3. 快捷方式：阻止指定国家的所有流量

```bash
# 等价于 --countries CN --block-all
sudo ./target/release/rfw --iface eth0 \
  --block-all-from CN,RU,KP
```

#### 4. 不使用 GeoIP（全局协议过滤）

```bash
# 阻止所有来源的 HTTP 和 SOCKS5 流量
sudo ./target/release/rfw --iface eth0 \
  --block-http --block-socks5
```

### 协议规则详解

#### 1. 屏蔽发送 Email

```bash
sudo ./target/release/rfw --iface eth0 --block-email
```

此规则会**仅阻止发送邮件**的出站流量，**允许接收邮件**：

**阻止的 SMTP 端口（发送邮件）：**
- 端口 25 - 标准 SMTP（未加密）
- 端口 587 - SMTP Submission（STARTTLS）
- 端口 465 - SMTPS（SSL/TLS 加密）
- 端口 2525 - 备用 SMTP 端口

**允许的端口（接收邮件）：**
- ✅ 端口 110 - POP3（未加密）
- ✅ 端口 995 - POP3S（SSL/TLS 加密）
- ✅ 端口 143 - IMAP（未加密）
- ✅ 端口 993 - IMAPS（SSL/TLS 加密）

**效果说明：**
- ❌ 阻止使用邮件客户端（Outlook, Thunderbird, Apple Mail 等）**发送**邮件
- ❌ 阻止命令行邮件工具（sendmail, mutt 等）发送邮件
- ✅ **允许**使用邮件客户端**接收**邮件（POP3/IMAP）
- ✅ 不影响基于浏览器的网页邮箱（如 Gmail 网页版，使用 HTTP/HTTPS）

**使用场景：**
- 防止服务器被用作垃圾邮件发送源
- 防止恶意软件发送钓鱼邮件
- 允许用户正常接收邮件，但禁止发送

#### 2. 屏蔽 HTTP 入站

```bash
# 阻止指定国家的 HTTP 流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN,RU \
  --block-http

# 阻止所有来源的 HTTP 流量
sudo ./target/release/rfw --iface eth0 \
  --block-http
```

阻止 HTTP 入站连接（仅明文 HTTP，不包括 HTTPS）

#### 3. 屏蔽 SOCKS5 入站

```bash
# 阻止指定国家的 SOCKS5 流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN \
  --block-socks5

# 阻止所有来源的 SOCKS5 流量
sudo ./target/release/rfw --iface eth0 \
  --block-socks5
```

阻止 SOCKS5 代理入站连接

#### 4. 屏蔽全加密流量入站

```bash
# 严格模式：阻止指定国家的全加密流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN \
  --block-fet-strict

# 宽松模式
sudo ./target/release/rfw --iface eth0 \
  --countries CN \
  --block-fet-loose
```

阻止全加密代理流量（Shadowsocks、V2Ray 等）

**特点：**
- 使用统计算法识别加密代理特征
- 自动豁免合法的 TLS/HTTPS 流量
- 基于 GFW 研究论文实现

**注意：**
- 检测基于统计特征，可能有极少的误报

#### 5. 屏蔽 WireGuard VPN 入站

```bash
# 阻止指定国家的 WireGuard 流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN \
  --block-wireguard

# 阻止所有来源的 WireGuard 流量
sudo ./target/release/rfw --iface eth0 \
  --block-wireguard
```

阻止 WireGuard VPN 流量

**特点：**
- 基于 WireGuard 协议特征精准识别
- 误报率极低，性能开销小
- 不会影响其他 UDP 应用

#### 6. 屏蔽 QUIC 入站

```bash
# 阻止指定国家的 QUIC 流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN \
  --block-quic

# 阻止所有来源的 QUIC 流量
sudo ./target/release/rfw --iface eth0 \
  --block-quic
```

阻止 QUIC 协议流量（HTTP/3）

**特点：**
- 精准识别 QUIC v1（RFC 9000）和 QUIC v2（RFC 9369）
- 支持检测 Google QUIC 协议
- 识别长头部和短头部数据包
- 误报率极低，不影响其他 UDP 应用

**支持的 QUIC 版本：**
- QUIC v1（RFC 9000，版本号 0x00000001）
- QUIC v2（RFC 9369，版本号 0x6b3343cf）
- Google QUIC（Q0xx 系列）
- 版本协商包

**使用场景：**
- 阻止基于 HTTP/3 的服务被滥用
- 防止 QUIC 代理服务器被滥用
- 限制新一代加密传输协议的入站连接

#### 7. 屏蔽所有入站流量

```bash
# 阻止指定国家的所有流量
sudo ./target/release/rfw --iface eth0 \
  --countries CN,RU \
  --block-all

# 快捷方式
sudo ./target/release/rfw --iface eth0 \
  --block-all-from CN,RU

# 白名单模式：只允许指定国家
sudo ./target/release/rfw --iface eth0 \
  --allow-only-countries US,JP,KR \
  --block-all

# 阻止所有来源的流量（不使用 GeoIP）
sudo ./target/release/rfw --iface eth0 \
  --block-all
```

阻止**所有**入站流量（不限协议、不限端口）

**特点：**
- 配合 GeoIP 时，仅基于 GeoIP 检测，性能开销最小
- 最彻底的屏蔽方式
- 优先级最高，在协议检测之前执行

**使用场景：**
- 服务器只面向特定地区用户（使用白名单模式）
- 需要彻底阻止来自特定国家的访问

**注意：**
- 如果启用此规则，无需启用其他协议检测规则
- 只影响入站流量，不影响出站流量

### 组合使用多个规则

```bash
# 同时启用所有规则（针对指定国家）
sudo ./target/release/rfw --iface eth0 \
  --countries CN,RU,KP \
  --block-email \
  --block-http \
  --block-socks5 \
  --block-fet-strict \
  --block-wireguard \
  --block-quic

# 多国家分别配置（使用白名单）
sudo ./target/release/rfw --iface eth0 \
  --allow-only-countries US,JP,KR,SG \
  --block-http \
  --block-socks5

# 不使用 GeoIP,全局协议检测
sudo ./target/release/rfw --iface eth0 \
  --block-http \
  --block-socks5 \
  --block-wireguard \
  --block-quic

# 组合使用：邮件 + 特定国家的代理协议
sudo ./target/release/rfw --iface eth0 \
  --block-email \
  --countries CN \
  --block-http \
  --block-socks5

# 最激进模式：阻止指定国家的所有流量
sudo ./target/release/rfw --iface eth0 \
  --block-all-from CN,RU,KP
```

### 运行要求

1. **Linux 内核版本**: 需要支持 XDP 的内核（通常是 4.8+，推荐 5.x+）
2. **Root 权限**: 加载 eBPF 程序需要 root 权限
3. **网络接口**: 确保指定的网卡名称正确（使用 `ip link` 查看）
4. **协议支持**: 目前仅支持 IPv4，不支持 IPv6

### 日志

程序使用 `env_logger` 记录日志。可以通过设置 `RUST_LOG` 环境变量来控制日志级别：

```bash
# 显示详细日志
sudo RUST_LOG=info ./target/release/rfw --iface eth0 --block-email

# 显示调试日志
sudo RUST_LOG=debug ./target/release/rfw --iface eth0 --block-email
```

当数据包被阻止时，eBPF 程序会记录相关信息到内核日志中。

### 停止防火墙

按 `Ctrl+C` 即可停止防火墙程序。程序会自动卸载 eBPF 程序并清理资源。

## 技术实现

rfw 基于 **eBPF/XDP** 技术，使用 **Rust** 语言开发。

### 架构

- **rfw-ebpf**: 运行在内核的 eBPF 程序，负责数据包过滤
- **rfw**: 用户空间程序，负责加载配置和管理 eBPF 程序
- **rfw-common**: 共享的数据结构定义

### 工作原理

1. 在网卡驱动层拦截数据包（XDP）
2. 检查是否为 IPv4 数据包（**目前仅支持 IPv4**）
3. 根据启用的规则进行检测：
   - **GeoIP 检测**：使用 LpmTrie 高效匹配源 IP 是否在指定国家列表中
   - **白名单/黑名单模式**：支持阻止指定国家或只允许指定国家
   - **协议检测**：识别 HTTP、SOCKS5、WireGuard、QUIC 等协议特征
   - **端口检测**：识别 Email 发送端口
4. 返回判决：允许通过或丢弃

### GeoIP 数据管理

- **数据源**: [lyc8503/sing-box-rules](https://github.com/lyc8503/sing-box-rules)
- **存储方式**: 使用 LpmTrie (Longest Prefix Match Trie) 进行高效前缀匹配
- **容量**: 最多支持 65536 个 CIDR 前缀
- **性能**: O(1) 时间复杂度的 IP 查询
- **更新策略**: 每次程序启动时自动下载最新数据

### 性能优势

- 在内核驱动层处理，延迟极低
- 零拷贝，无需将数据传到用户空间
- 可处理 10Gbps+ 高速流量

## 编译和安装

### Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
4. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
5. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
6. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

### 编译

#### Linux 环境

```bash
cargo build --release
```

#### macOS 交叉编译

交叉编译适用于 Intel 和 Apple Silicon Mac：

```bash
# x86_64
CC=x86_64-linux-musl-gcc cargo build --package rfw --release \
  --target=x86_64-unknown-linux-musl \
  --config=target.x86_64-unknown-linux-musl.linker=\"x86_64-linux-musl-gcc\"

# aarch64
CC=aarch64-linux-musl-gcc cargo build --package rfw --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\"
```

交叉编译后的程序位于 `target/${ARCH}-unknown-linux-musl/release/rfw`，可以复制到 Linux 服务器或虚拟机上运行。

### 运行

```bash
# 基本运行
sudo ./target/release/rfw --iface eth0

# 启用规则
sudo ./target/release/rfw --iface eth0 --block-email --block-cn-http

# 查看日志
sudo RUST_LOG=info ./target/release/rfw --iface eth0 --block-cn-fet-strict
```

## 参考资料

- [eBPF 文档](https://ebpf.io/)
- [XDP 教程](https://github.com/xdp-project/xdp-tutorial)
- [Aya 框架](https://aya-rs.dev/)
- [OpenGFW 项目](https://github.com/apernet/OpenGFW)
- [FET 论文](https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf)

## License

With the exception of eBPF code, rfw is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
