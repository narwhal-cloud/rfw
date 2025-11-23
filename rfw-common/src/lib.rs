#![no_std]

/// 防火墙规则配置的位标志
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FirewallConfig {
    pub flags: u32,
}

// 规则标志位
pub const RULE_BLOCK_EMAIL: u32 = 1 << 0; // 屏蔽发送 email
pub const RULE_BLOCK_HTTP: u32 = 1 << 1; // 屏蔽 HTTP 入站(配合 GeoIP 或全局)
pub const RULE_BLOCK_SOCKS5: u32 = 1 << 2; // 屏蔽 SOCKS5 入站(配合 GeoIP 或全局)
pub const RULE_BLOCK_FET_STRICT: u32 = 1 << 3; // 屏蔽全加密流量入站 (严格模式，默认阻止)
pub const RULE_BLOCK_WIREGUARD: u32 = 1 << 4; // 屏蔽 WireGuard 入站(配合 GeoIP 或全局)
pub const RULE_BLOCK_ALL: u32 = 1 << 5; // 屏蔽所有入站流量(配合 GeoIP 或全局)
pub const RULE_BLOCK_FET_LOOSE: u32 = 1 << 6; // 屏蔽全加密流量入站 (宽松模式，默认放过)
pub const RULE_BLOCK_QUIC: u32 = 1 << 7; // 屏蔽 QUIC 入站(配合 GeoIP 或全局)

// GeoIP 过滤模式
pub const RULE_GEOIP_ENABLED: u32 = 1 << 8; // 启用 GeoIP 国家过滤
pub const RULE_GEOIP_WHITELIST: u32 = 1 << 9; // GeoIP 白名单模式(只允许列表中的国家)

impl FirewallConfig {
    pub fn new() -> Self {
        Self { flags: 0 }
    }

    pub fn enable_rule(&mut self, rule: u32) {
        self.flags |= rule;
    }

    pub fn has_rule(&self, rule: u32) -> bool {
        (self.flags & rule) != 0
    }
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// GeoIP 条目 - IP 地址范围及国家代码
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GeoIpEntry {
    pub start_ip: u32,      // 起始 IP (网络字节序)
    pub end_ip: u32,        // 结束 IP (网络字节序)
    pub country_code: u16,  // 国家代码(两字母 ISO 3166-1 alpha-2,如 CN=0x434E, US=0x5553)
    pub _padding: u16,      // 对齐填充
}

// 为 GeoIpEntry 实现 Pod trait，使其可以在 eBPF map 中使用
#[cfg(feature = "user")]
unsafe impl aya::Pod for GeoIpEntry {}

/// LpmTrie Key 结构 - 用于 IP 前缀匹配
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LpmTrieKey {
    pub prefix_len: u32, // 前缀长度（位数）
    pub data: u32,       // IP 地址（网络字节序）
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmTrieKey {}
