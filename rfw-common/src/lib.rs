#![no_std]

/// 最多支持的规则数量
pub const MAX_RULES: u32 = 64;

// 方向
pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;

// 协议
pub const PROTO_ALL: u8 = 0;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// 应用层协议（自定义编号）
pub const PROTO_HTTP: u8 = 80;
pub const PROTO_SOCKS5: u8 = 108;

// HTTP 方法特征值 (大端序 u32)
pub const HTTP_GET: u32 = 0x47455420;     // "GET "
pub const HTTP_POST: u32 = 0x504F5354;    // "POST"
pub const HTTP_HEAD: u32 = 0x48454144;    // "HEAD"
pub const HTTP_PUT: u32 = 0x50555420;     // "PUT "
pub const HTTP_DELETE: u32 = 0x44454C45;  // "DELE"
pub const HTTP_OPTIONS: u32 = 0x4F505449; // "OPTI"
pub const HTTP_PATCH: u32 = 0x50415443;   // "PATC"
pub const HTTP_CONNECT: u32 = 0x434F4E4E; // "CONN"

pub const SOCKS5_VERSION: u8 = 0x05;

// 动作
pub const ACTION_BLOCK: u8 = 0;
pub const ACTION_PASS: u8 = 1;

// IP 匹配类型
pub const IP_TYPE_ANY: u8 = 0;   // 匹配所有 IP
pub const IP_TYPE_CIDR: u8 = 1;  // 匹配指定 CIDR
pub const IP_TYPE_GEOIP: u8 = 2; // 匹配 GEOIP_MAP 中的 IP

/// 防火墙规则（存储在 eBPF Array 中）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FirewallRule {
    pub priority: u32,       // 优先级，越大越高
    pub enabled: u8,         // 0=禁用, 1=启用
    pub direction: u8,       // DIR_IN / DIR_OUT
    pub protocol: u8,        // PROTO_ALL / PROTO_TCP / PROTO_UDP
    pub action: u8,          // ACTION_BLOCK / ACTION_PASS
    pub port_start: u16,     // 端口范围起始，0 表示所有端口
    pub port_end: u16,       // 端口范围结束，与 port_start 相同则为单端口
    pub ip_type: u8,         // IP_TYPE_ANY / IP_TYPE_CIDR / IP_TYPE_GEOIP
    pub _padding: [u8; 3],
    pub src_ip: u32,         // 对端 IP（入站=源IP，出站=目标IP），网络字节序
    pub src_prefix_len: u32, // 前缀长度 (0-32)，ip_type=CIDR 时有效
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallRule {}

/// LpmTrie Key 结构 - 用于 GeoIP 前缀匹配
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LpmTrieKey {
    pub prefix_len: u32,
    pub data: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmTrieKey {}
