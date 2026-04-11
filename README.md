# RFW 防火墙

基于 eBPF/XDP 的高性能全状态防火墙 - 支持实时 API 配置、应用协议识别 (DPI)、GeoIP 自动化过滤。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

## 🚀 核心特性

- ⚡ **实时 API 配置** - 所有规则修改通过内存中的 eBPF Maps 立即生效，无需重启。
- 🔍 **应用协议识别 (DPI)** - 深度包检测支持识别 **HTTP**, **SOCKS5**, **TLS** 以及 **FET** (全加密流量)。
- 🔄 **连接状态跟踪 (Action Caching)** - 仅在连接建立初期进行深度检测，识别后自动缓存动作 (BLOCK/PASS)，后续包极速转发。
- 🌍 **自动 GeoIP 下载** - 规则中指定国家代码，系统自动获取最新 IP 段并加载至内核 LPM Trie。
- 🚀 **极高性能** - 基于 eBPF/XDP (入站) 和 TC (出站) 技术，核心路径采用无循环设计与硬件加速指令。
- 🦀 **安全可靠** - 使用 Rust 编写用户态管理程序，确保内存安全。

---

## 🛠 快速开始

### 1. 构建

项目使用 `cargo` 进行管理，配套自动化构建脚本：

```bash
# 编译 release 版本
./build.sh
```

### 2. 运行

```bash
# 需要 root 权限以加载 eBPF 程序
sudo ./target/release/rfw --iface eth0 --api-addr 0.0.0.0:8080
```

| 参数           | 默认值          | 说明                          |
|--------------|--------------|-----------------------------|
| `--iface`    | eth0         | 要监听的网络接口                    |
| `--api-addr` | 0.0.0.0:8080 | REST API 服务地址               |
| `--xdp-mode` | auto         | XDP 模式 (auto, skb, drv, hw) |

---

## 📚 核心概念

### 支持的协议 (`protocol`)

| 协议            | 说明                                        |
|---------------|-------------------------------------------|
| `tcp` / `udp` | 基础 L4 协议过滤                                |
| `http`        | 识别常见的 HTTP 请求方法 (GET, POST, etc.)         |
| `socks5`      | 识别 SOCKS5 代理握手特征                          |
| `fet`         | Fully Encrypted Traffic (识别高熵、无明显特征的加密流量) |
| `all`         | 匹配所有协议                                    |

### 性能优化：连接跟踪与动作缓存

RFW 不仅仅是一个简单的过滤器，它还是一个高性能的状态防火墙：
1. **DPI 延迟执行**：仅在检测到第一个带有数据载荷 (Payload) 的包时运行深度识别逻辑。
2. **动作缓存**：一旦判定了连接的动作（封禁或放行），结果将存入内核 LRU Map。该连接后续的所有数据包将直接走 **Fast Path**，跳过所有规则检查。
3. **硬件加速**：FET 识别采用 64 位无循环采样，利用 CPU 原生 `POPCNT` 指令计算熵值。

---

## 📡 API 详解

### 1. 获取系统状态
`GET /api/status`

### 2. 创建规则
`POST /api/rules`

**请求体示例 (封禁来自海外的 FET 加密流量)：**
```json
{
  "priority": 100,
  "direction": "in",
  "protocol": "fet",
  "port_start": 0,
  "ip_type": "geoip",
  "countries": ["US", "JP", "SG"],
  "action": "block"
}
```

**请求体示例 (仅允许特定 IP 访问 80 端口的 HTTP 协议)：**
```json
{
  "priority": 200,
  "direction": "in",
  "protocol": "http",
  "port_start": 80,
  "ip_type": "cidr",
  "ip": "1.2.3.0/24",
  "action": "pass"
}
```

### 3. 列出规则
`GET /api/rules`

### 4. 删除规则
`DELETE /api/rules/{id}`

---

## 📈 性能参考

- **匹配速度**: 连接建立后，单包处理延迟低于 500 纳秒。
- **并发能力**: 默认支持 16,384 个并发连接跟踪（可调）。
- **规则限制**: 支持最多 64 条全局/精细化规则线性加速。

---

## 🛡 安全说明

- 运行此程序需要 **Root** 权限。
- 建议在 Linux 内核 5.15 或更高版本上运行以获得最佳兼容性（支持更长的指令路径和更先进的验证器分析）。

---

## 📝 许可证

RFW 采用 MIT 许可证。详见 [LICENSE-MIT](./LICENSE-MIT)。
