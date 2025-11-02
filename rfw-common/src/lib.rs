#![no_std]

/// 防火墙规则配置的位标志
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FirewallConfig {
    pub flags: u32,
}

// 规则标志位
pub const RULE_BLOCK_EMAIL: u32 = 1 << 0; // 屏蔽发送 email
pub const RULE_BLOCK_CN_HTTP: u32 = 1 << 1; // 屏蔽中国 IP 的 HTTP 入站
pub const RULE_BLOCK_CN_SOCKS5: u32 = 1 << 2; // 屏蔽中国 IP 的 SOCKS5 入站
pub const RULE_BLOCK_CN_FET_STRICT: u32 = 1 << 3; // 屏蔽中国 IP 的全加密流量入站 (严格模式，默认阻止)
pub const RULE_BLOCK_CN_WIREGUARD: u32 = 1 << 4; // 屏蔽中国 IP 的 WireGuard 入站
pub const RULE_BLOCK_CN_ALL: u32 = 1 << 5; // 屏蔽中国 IP 的所有入站流量
pub const RULE_BLOCK_CN_FET_LOOSE: u32 = 1 << 6; // 屏蔽中国 IP 的全加密流量入站 (宽松模式，默认放过)

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

/// GeoIP 条目 - 中国 IP 地址范围
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GeoIpEntry {
    pub start_ip: u32, // 起始 IP (网络字节序)
    pub end_ip: u32,   // 结束 IP (网络字节序)
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
