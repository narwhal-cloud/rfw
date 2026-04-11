# RFW 防火墙

基于 eBPF/XDP 的高性能防火墙 - 支持实时 API 配置、GeoIP 自动化过滤、CIDR 匹配。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

## 🚀 核心特性

- ⚡ **实时 API 配置** - 所有规则修改通过内存中的 eBPF Maps 立即生效，无需重启。
- 🌍 **自动 GeoIP 下载** - 规则中指定国家代码，系统自动从 GitHub 获取最新 CIDR 数据并加载至内核。
- 🔒 **灵活的匹配模式** - 支持 Any (全匹配)、CIDR (网段匹配) 和 GeoIP (地理位置匹配)。
- 🚀 **极高性能** - 基于 eBPF/XDP 技术，在内核协议栈最底层进行丢弃或放行处理，延迟极低。
- 🦀 **安全可靠** - 使用 Rust 编写用户态管理程序，基于 `aya` 框架构建。

---

## 🛠 快速开始

### 1. 构建

项目使用 `cargo` 进行管理，并配套有自动构建脚本：

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

### 匹配维度

| 维度            | 可选值                    | 说明                       |
|---------------|------------------------|--------------------------|
| **Direction** | `in`, `out`            | `in` 代表入站流量，`out` 代表出站流量 |
| **Protocol**  | `tcp`, `udp`, `all`    | 支持具体协议或全部匹配              |
| **Action**    | `block`, `pass`        | `block` 丢弃数据包，`pass` 放行  |
| **IP Type**   | `any`, `cidr`, `geoip` | 决定如何匹配对端 IP              |

### IP 匹配模式

1. **Any**: 匹配所有来源/目的 IP。
2. **CIDR**: 匹配指定的网段（如 `1.2.3.0/24`）。
3. **GeoIP**: 匹配指定国家的 IP 段。指定后系统将自动维护内核中的前缀匹配树 (LPM Trie)。

---

## 📡 API 详解

### 1. 获取系统状态
`GET /api/status`

**响应示例：**
```json
{
  "iface": "eth0",
  "api_version": "2.0",
  "rule_count": 5
}
```

### 2. 创建规则
`POST /api/rules`

**请求体格式：**
```json
{
  "priority": 100,
  "enabled": true,
  "direction": "in",
  "protocol": "tcp",
  "port_start": 80,
  "port_end": 80,
  "ip_type": "cidr",
  "ip": "1.2.3.4/32",
  "action": "block"
}
```

**示例 1：封禁来自中国的入站 TCP 80 端口**
```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "priority": 10,
    "direction": "in",
    "protocol": "tcp",
    "port_start": 80,
    "ip_type": "geoip",
    "countries": ["CN"],
    "action": "block"
  }'
```

**示例 2：仅允许特定网段访问 22 端口（白名单模式）**
```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "priority": 50,
    "direction": "in",
    "protocol": "tcp",
    "port_start": 22,
    "ip_type": "cidr",
    "ip": "192.168.1.0/24",
    "action": "pass"
  }'
```

### 3. 列出规则
`GET /api/rules`

返回当前内存中维护的所有规则列表，按优先级排序。

### 4. 删除规则
`DELETE /api/rules/{id}`

通过规则 ID（在创建或列表接口中获得）彻底删除规则。

---

## 🏗 项目结构

- **rfw/**: 用户态管理服务，负责 API 交互、GeoIP 数据获取、eBPF Maps 同步。
- **rfw-ebpf/**: 内核态 XDP/TC 程序，执行核心的数据包过滤逻辑。
- **rfw-common/**: 共享库，定义了跨内核和用户态的 `FirewallRule` 等核心结构体。

---

## 📈 性能说明

- **规则容量**: 内核默认支持 64 条规则线性遍历（`MAX_RULES` 可在 common 中调整）。
- **同步优化**: 用户态仅将 `enabled: true` 的规则同步至内核，最小化 eBPF 执行开销。
- **匹配速度**: CIDR 和 GeoIP 均采用位运算或 LPM Trie 实现，单次判定时间在纳秒级。

---

## 🛡 安全说明

- 运行此程序需要 **Root** 权限。
- 建议在 Linux 内核 5.15 或更高版本上运行以获得最佳兼容性。
- **注意**: XDP 仅处理入站流量，出站流量由 TC (Traffic Control) 挂钩处理。

---

## 📝 许可证

RFW 采用 MIT 许可证。详见 [LICENSE-MIT](./LICENSE-MIT)。
