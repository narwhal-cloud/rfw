# RFW 防火墙

基于 eBPF/XDP 的高性能防火墙 - 支持实时 API 配置、GeoIP 过滤、端口转发、协议检测

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

## 🚀 核心特性

- ⚡ **实时 API 配置** - 所有规则修改立即生效，无需重启
- 🌍 **自动 GeoIP 下载** - 在规则中指定国家，自动从 GitHub 下载最新 IP 段
- 🔒 **黑白名单模式** - 灵活的访问控制（阻止/允许）
- 🔧 **细粒度控制** - 端口、协议、方向、IP 段、域名多维度组合
- 🚀 **高性能** - 内核级 eBPF/XDP，线速处理，< 1μs 延迟
- 📊 **实时统计** - 端口访问日志和流量统计

## 📖 文档

- **[OpenAPI 规范](./RFW_OPENAPI.yaml)** - 标准 API 文档（Swagger/Postman）

---

## 🛠 快速开始

### 1. 构建

```bash
# 一键编译（自动检查和安装依赖）
./build.sh          # 编译 aarch64（默认）
./build.sh x86_64   # 编译 x86_64
```

### 2. 运行防火墙

```bash
# 在 Linux 上运行
sudo ./target/release/rfw \
  --iface eth0 \
  --api-addr 0.0.0.0:8080 \
  --xdp-mode auto
```

**参数说明：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--iface` | eth0 | 网络接口名称（如 eth0, ens33, wlan0） |
| `--api-addr` | 0.0.0.0:8080 | API 监听地址（例如 127.0.0.1:8080） |
| `--xdp-mode` | auto | XDP 附加模式（auto, skb, drv, hw） |

### 3. 验证防火墙运行

```bash
# 检查状态
curl http://localhost:8080/api/status

# 输出示例：
# {
#   "interface": "eth0",
#   "config_flags": 0,
#   "active_rules": 0
# }
```

---

## 📚 核心概念

### 规则类型

防火墙支持多种规则类型，通过 `protocol` 参数区分：

#### 传输层规则（Transport Layer）
- `tcp` - TCP 协议
- `udp` - UDP 协议  
- `any` - TCP 和 UDP 都阻止

#### 应用层规则（Application Layer）
- `socks5` - SOCKS5 代理检测
- `http` - HTTP 协议检测
- `tls` - TLS/HTTPS 检测（支持 SNI 域名过滤）
- `wireguard` - WireGuard VPN 检测
- `quic` - QUIC/HTTP3 检测
- `fet_strict` - 全加密流量（严格模式）
- `fet_loose` - 全加密流量（宽松模式）
- `email` - SMTP/邮件协议检测
- `all` - 所有协议

### 操作模式

#### 黑名单模式（Block）
```json
"action": "block"
```
- 阻止指定的协议或端口
- 其他流量正常通过
- 用于禁止特定服务

#### 白名单模式（Allow）
```json
"action": "allow"
```
- 仅允许指定的协议或端口
- 其他流量被阻止
- 用于严格的访问控制

### 流量方向

- `inbound` - 入站流量（源地址为外网）
- `outbound` - 出站流量（目标地址为外网）
- `both` - 双向（入站和出站都检查）

### 端口指定

支持多种格式的灵活指定：

| 格式 | 示例 | 说明 |
|------|------|------|
| 单个端口 | `"8080"` | 仅 8080 端口 |
| 端口范围 | `"8000-9000"` | 8000 到 9000 的所有端口 |
| 端口列表 | `"80,443,8080"` | 指定的几个端口 |
| 混合方式 | `"80-100,443,8080-8090"` | 范围和列表混合 |
| 所有端口 | `"0"` | 特殊值，表示全局规则 |

### GeoIP 过滤

GeoIP 过滤基于源 IP（入站）或目标 IP（出站）的地理位置：

**支持的国家代码示例：**
- `CN` - 中国
- `RU` - 俄罗斯
- `US` - 美国
- `GB` - 英国
- `DE` - 德国
- 等等（所有 ISO 3166-1 alpha-2 代码）

**工作流程：**
1. 用户在规则中指定 `geoip: ["CN"]`
2. 系统自动从 GitHub 下载 CN 的 IP 段数据
3. 将数据加载到 LpmTrie 结构（高效前缀匹配）
4. 立即对所有流量进行地理位置过滤

### 条件组合

单条规则可以组合多个条件，实现复杂的策略：

```json
{
  "ports": "1080",           // 特定端口
  "protocol": "socks5",      // 特定协议
  "direction": "inbound",    // 流量方向
  "action": "block",         // 操作模式
  "geoip": ["CN", "RU"],     // GeoIP 条件（可选）
  "ip_range": ["1.0.0.0/8"], // IP 段条件（可选）
  "domains": ["*.example.com"] // 域名条件（可选）
}
```

---

## 📡 API 详解

### 1. 端口规则管理

#### POST /api/rules/port
**创建或更新端口规则**

**请求体：**
```json
{
  "ports": "1080|0",
  "protocol": "socks5|tcp|udp|http|tls|...",
  "direction": "inbound|outbound|both",
  "action": "block|allow",
  "domains": ["example.com"],
  "geoip": ["CN", "RU"],
  "ip_range": ["1.0.0.0/8"]
}
```

**参数详解：**

| 参数 | 必需 | 说明 |
|------|------|------|
| ports | ✅ | 端口号或范围，"0" 表示全局 |
| protocol | ✅ | 协议类型（见核心概念） |
| direction | ❌ | 默认 "inbound" |
| action | ❌ | 默认 "block"（黑名单） |
| domains | ❌ | 仅用于 protocol=tls，指定要过滤的域名 |
| geoip | ❌ | 国家代码列表，自动下载对应国家的 IP 段 |
| ip_range | ❌ | CIDR 格式的 IP 段列表 |

**示例 1：禁止 port 1080 的 SOCKS5**
```bash
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "1080",
    "protocol": "socks5",
    "action": "block"
  }'
```

**示例 2：禁止来自中国的 HTTP 连接**
```bash
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "80,443",
    "protocol": "http",
    "direction": "inbound",
    "action": "block",
    "geoip": ["CN"]
  }'
```

**示例 3：仅允许特定 IP 段访问 8080**
```bash
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "8080",
    "protocol": "tcp",
    "action": "allow",
    "ip_range": ["192.168.1.0/24", "10.0.0.0/8"]
  }'
```

**响应：**
```
200 OK - 规则应用成功
400 Bad Request - 参数错误
500 Internal Server Error - 服务器错误
```

#### DELETE /api/rules/port/{port}
**删除指定端口的所有规则**

**示例：**
```bash
# 删除 port 1080 的所有规则
curl -X DELETE http://localhost:8080/api/rules/port/1080

# 删除全局规则（port=0）
curl -X DELETE http://localhost:8080/api/rules/port/0
```

---

### 2. 端口转发

#### POST /api/rules/forward
**配置端口转发规则**

**请求体：**
```json
{
  "dst_port": 8080,
  "protocol": "tcp|udp",
  "new_dst_ip": "127.0.0.1",
  "new_dst_port": 3000
}
```

**示例：** 转发 8080 到本地 3000
```bash
curl -X POST http://localhost:8080/api/rules/forward \
  -H "Content-Type: application/json" \
  -d '{
    "dst_port": 8080,
    "protocol": "tcp",
    "new_dst_ip": "127.0.0.1",
    "new_dst_port": 3000
  }'
```

#### DELETE /api/rules/forward/{port}/{protocol}
**删除端口转发规则**

**示例：**
```bash
curl -X DELETE http://localhost:8080/api/rules/forward/8080/tcp
```

---

### 3. 域名过滤

#### DELETE /api/rules/domain/{domain}
**删除域名黑名单**

**示例：**
```bash
curl -X DELETE http://localhost:8080/api/rules/domain/example.com
```

---

### 4. 日志配置

#### POST /api/rules/logging
**启用或禁用端口访问日志**

**请求体：**
```json
{
  "enabled": true|false
}
```

**示例：** 启用访问日志
```bash
curl -X POST http://localhost:8080/api/rules/logging \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

---

### 5. 全局配置

#### POST /api/config/flags
**直接设置防火墙配置标志**

**请求体：**
```json
{
  "flags": 12345
}
```

**说明：** 此接口用于高级用户，直接操作内核 eBPF CONFIG map。一般情况下无需使用。

---

### 6. 查询接口

#### GET /api/status
**获取防火墙状态**

**响应示例：**
```json
{
  "interface": "eth0",
  "config_flags": 0,
  "active_rules": 0
}
```

#### GET /api/stats
**获取端口访问统计**

**响应示例：**
```json
{
  "stats": [
    {
      "port": 1080,
      "protocol": 6,
      "src_ip": "192.168.1.100",
      "allowed": 10,
      "blocked": 5
    }
  ]
}
```

---

## 🎯 使用场景

### 场景 1：企业网关 - 禁止员工使用代理

**需求：** 阻止所有从外网进来的代理连接

```bash
# 禁止 SOCKS5（默认 1080）
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "1080,1081,1082",
    "protocol": "socks5",
    "direction": "inbound",
    "action": "block"
  }'

# 禁止 HTTP 代理（3128）
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "3128,8080,8888",
    "protocol": "http",
    "direction": "inbound",
    "action": "block"
  }'
```

### 场景 2：CDN/内容分发 - 地理位置限制

**需求：** 仅允许特定地区的用户访问服务

```bash
# 仅允许中国和新加坡的用户
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "0",
    "protocol": "all",
    "direction": "inbound",
    "action": "allow",
    "geoip": ["CN", "SG"]
  }'
```

### 场景 3：VPN 检测 - 禁止加密通道

**需求：** 阻止 VPN 和加密代理

```bash
# 禁止 WireGuard
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "0",
    "protocol": "wireguard",
    "direction": "inbound",
    "action": "block"
  }'

# 禁止 QUIC（HTTP/3）
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "443",
    "protocol": "quic",
    "action": "block"
  }'
```

### 场景 4：WAF 功能 - 只允许明确列出的 IP

**需求：** 白名单模式只允许特定 IP 段

```bash
# 只允许公司 IP 段和 CDN IP 访问
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "443",
    "protocol": "tcp",
    "action": "allow",
    "ip_range": ["203.0.113.0/24", "198.51.100.0/24"]
  }'
```

### 场景 5：域名过滤 - SNI 黑名单

**需求：** 禁止访问特定域名

```bash
# 阻止访问特定域名
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "443",
    "protocol": "tls",
    "action": "block",
    "domains": ["blocked-domain.com", "ads.example.com"]
  }'
```

### 场景 6：出站监控 - 禁止到特定国家的连接

**需求：** 防止员工访问特定地区的网站

```bash
# 禁止出站到中国和伊朗的所有流量
curl -X POST http://localhost:8080/api/rules/port \
  -H "Content-Type: application/json" \
  -d '{
    "ports": "0",
    "protocol": "all",
    "direction": "outbound",
    "action": "block",
    "geoip": ["CN", "IR"]
  }'
```

---

## ❓ 常见问题

### Q1: GeoIP 数据从哪里获取？

**A:** 系统使用 [Loyalsoldier 的 GeoIP 仓库](https://github.com/Loyalsoldier/geoip)，数据来自多个开源 GeoIP 数据库：
- IP2Location
- MaxMind
- APNIC
- RIPE NCC

数据每周更新一次。

### Q2: GeoIP 数据要下载多长时间？

**A:** 取决于网络速度，单个国家通常 5-30 秒。例如：
- 中国 (CN) - 约 650 条 CIDR 前缀
- 美国 (US) - 约 5000+ 条 CIDR 前缀

### Q3: 可以同时使用黑名单和白名单吗？

**A:** 可以。可以为不同的端口或协议设置不同的模式：
```bash
# 某个端口黑名单
curl -X POST .../api/rules/port -d '{"ports":"1080","protocol":"socks5","action":"block"}'

# 另一个端口白名单
curl -X POST .../api/rules/port -d '{"ports":"8080","protocol":"tcp","action":"allow","ip_range":["192.168.1.0/24"]}'
```

### Q4: 规则生效需要多长时间？

**A:** **立即生效**。所有规则修改直接操作 eBPF maps，无需重启防火墙。

### Q5: 如何查看当前应用的所有规则？

**A:** 使用 `GET /api/status` 和 `GET /api/stats` 查看活跃规则数和统计信息。完整规则查询需要读取 eBPF maps，可以使用 `bpftool` 工具：

```bash
# 查看 PORT_PROTO_FLAGS map
sudo bpftool map dump name PORT_PROTO_FLAGS

# 查看 BLOCK_PORTS map
sudo bpftool map dump name BLOCK_PORTS
```

### Q6: 如何记录日志？

**A:** 使用 `POST /api/rules/logging` 启用：

```bash
curl -X POST http://localhost:8080/api/rules/logging \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

启用后，日志会输出到标准输出和 `/sys/kernel/debug/tracing/trace_pipe`。

### Q7: 白名单模式如何工作？

**A:** 白名单模式 (`action: "allow"`) 只允许指定的流量通过，其他流量被阻止：

```json
{
  "ports": "443",
  "protocol": "tcp",
  "action": "allow",
  "ip_range": ["192.168.1.0/24"]
}
```
这条规则表示：**仅允许** 192.168.1.0/24 这个 IP 段访问 443 端口的 TCP 流量。

### Q8: 支持修改已有规则吗？

**A:** 支持。再次调用 `POST /api/rules/port` 相同的端口和协议组合，会覆盖原有规则。

### Q9: 如何完全清除防火墙规则？

**A:** 删除所有规则：

```bash
# 删除全局规则
curl -X DELETE http://localhost:8080/api/rules/port/0

# 删除其他端口规则（重复删除）
for port in 1080 8080 443 80; do
  curl -X DELETE http://localhost:8080/api/rules/port/$port
done
```

### Q10: XDP 模式选择有什么区别？

**A:** 
- `auto` - 自动选择（推荐）
- `skb` - SKB 模式，兼容性最好，性能最低
- `drv` - 驱动模式，需要网卡支持，性能好
- `hw` - 硬件卸载，需要网卡支持，性能最好

---

## 🏗 项目结构

```
rfw/
├── rfw/              # 用户空间程序（Rust）
│   └── src/main.rs   # API 服务器、规则管理
├── rfw-ebpf/         # eBPF 内核程序（Rust）
│   └── src/main.rs   # XDP/TC 数据包过滤逻辑
├── rfw-common/       # 共享结构体和常量
│   └── src/lib.rs    # eBPF 和用户空间共用定义
├── build.sh          # 自动化编译脚本
├── RFW_OPENAPI.yaml  # OpenAPI 3.0 规范
└── README.md         # 本文件
```

---

## 📈 性能参考

| 指标 | 值 |
|------|-----|
| 最大规则数 | ~10,000（受 eBPF maps 限制） |
| GeoIP 国家数 | 249 个 |
| 延迟 | < 1μs（内核级处理） |
| 吞吐量 | Mpps 级（线速） |

---

## 🔧 故障排除

### 问题：权限被拒绝

```
error: Permission denied
```

**解决：** 使用 `sudo` 运行防火墙
```bash
sudo ./target/release/rfw --iface eth0
```

### 问题：找不到网络接口

```
error: Interface not found: eth0
```

**解决：** 检查正确的接口名称
```bash
ip link show
```

### 问题：GeoIP 下载失败

```
error: Failed to fetch GeoIP data: ...
```

**解决：** 
- 检查网络连接
- 检查防火墙是否阻止了到 GitHub 的连接
- 使用科学上网或配置代理

### 问题：eBPF 程序加载失败

```
error: Failed to load eBPF program
```

**解决：**
- 确保内核版本 >= 4.15
- 检查 `CONFIG_BPF=y` 是否启用
- 检查 `/sys/kernel/debug/` 是否挂载

---

## 🛡 安全说明

- ⚠️ **需要 root 权限** - 加载 eBPF 程序需要 root
- ⚠️ **内核要求** - Linux 内核 4.15+ (推荐 5.x+)
- ⚠️ **仅 IPv4** - 目前不支持 IPv6

---

## 📝 许可证

RFW 代码采用 MIT 或 Apache 2.0 双许可（用户可选）。
eBPF 代码采用 GPL-2 或 MIT 双许可。

详见 [LICENSE-MIT](./LICENSE-MIT) 和 [LICENSE-GPL2](./LICENSE-GPL2)

---

## 🔗 相关资源

- [eBPF 官方文档](https://ebpf.io/)
- [XDP 教程](https://github.com/xdp-project/xdp-tutorial)
- [Aya 框架](https://aya-rs.dev/)
- [GeoIP 数据源](https://github.com/Loyalsoldier/geoip)

---

**需要帮助？** 查看 [RFW_OPENAPI.yaml](./RFW_OPENAPI.yaml)
