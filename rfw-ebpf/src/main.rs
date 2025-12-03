#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LpmTrie, LruHashMap, lpm_trie::Key},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use core::mem::size_of;

// 防火墙配置 map
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

// GeoIP 数据 map - 国家 IP 段（使用 LpmTrie 进行高效前缀匹配）
// LpmTrie key: prefix_len (4 bytes) + IP address (4 bytes)
// value: u8 (1 = 匹配的IP)
#[map]
static GEOIP_MAP: LpmTrie<u32, u8> = LpmTrie::with_max_entries(65536, 0);

// TCP 连接跟踪 map - 记录已检测过的连接（五元组）
// 使用 LRU 策略自动淘汰旧连接
// 值：0 = 已检测且通过, 1 = 已检测且阻止
#[map]
static TCP_CONN_TRACKER: LruHashMap<ConnKey, u8> = LruHashMap::with_max_entries(65536, 0);

// 端口访问记录 map - 记录每个端口被哪些 IP 访问
// Key: (dst_port, src_ip)，Value: 访问统计信息
#[map]
static PORT_ACCESS_LOG: LruHashMap<PortAccessKey, PortAccessStats> =
    LruHashMap::with_max_entries(65536, 0);

// 连接状态常量
const CONN_STATE_ALLOWED: u8 = 0;
const CONN_STATE_BLOCKED: u8 = 1;

// 连接五元组 key
#[repr(C)]
#[derive(Clone, Copy)]
struct ConnKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _padding: [u8; 3], // 对齐到8字节
}

// 端口访问记录的 key
#[repr(C)]
#[derive(Clone, Copy)]
struct PortAccessKey {
    dst_port: u16,
    protocol: u8,
    _padding: u8,
    src_ip: u32,
}

// 端口访问统计信息
#[repr(C)]
#[derive(Clone, Copy)]
struct PortAccessStats {
    allowed_count: u64, // 允许通过的次数
    blocked_count: u64, // 被阻断的次数
    last_seen: u64,     // 最后访问时间（保留，暂时未使用）
}

// 以太网头部
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// IP 头部
#[repr(C)]
struct IpHdr {
    _bitfield: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

// TCP 头部
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    _bitfield: u16, // data offset (4 bits) + reserved (3 bits) + flags (9 bits)
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// TCP flags (in network byte order, lower byte of _bitfield)
const TCP_SYN: u8 = 0x02;

// HTTP 方法字符串（前4个字节）
const HTTP_GET: u32 = 0x47455420; // "GET "
const HTTP_POST: u32 = 0x504f5354; // "POST"
const HTTP_HEAD: u32 = 0x48454144; // "HEAD"
const HTTP_PUT: u32 = 0x50555420; // "PUT "
const HTTP_DELETE: u32 = 0x44454c45; // "DELE" (DELETE 的前4字节)
const HTTP_OPTIONS: u32 = 0x4f505449; // "OPTI" (OPTIONS 的前4字节)
const HTTP_PATCH: u32 = 0x50415443; // "PATC" (PATCH 的前4字节)
const HTTP_CONNECT: u32 = 0x434f4e4e; // "CONN" (CONNECT 的前4字节)

// SOCKS 版本号
const SOCKS5_VERSION: u8 = 0x05;

// UDP 头部
#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// 规则标志位
const RULE_BLOCK_EMAIL: u32 = 1 << 0;
const RULE_BLOCK_HTTP: u32 = 1 << 1;
const RULE_BLOCK_SOCKS5: u32 = 1 << 2;
const RULE_BLOCK_FET_STRICT: u32 = 1 << 3; // FET 严格模式（默认阻止）
const RULE_BLOCK_WIREGUARD: u32 = 1 << 4;
const RULE_BLOCK_ALL: u32 = 1 << 5;
const RULE_BLOCK_FET_LOOSE: u32 = 1 << 6; // FET 宽松模式（默认放过）
const RULE_BLOCK_QUIC: u32 = 1 << 7;
const RULE_GEOIP_ENABLED: u32 = 1 << 8; // 启用 GeoIP 国家过滤
const RULE_GEOIP_WHITELIST: u32 = 1 << 9; // GeoIP 白名单模式
const RULE_LOG_PORT_ACCESS: u32 = 1 << 10; // 记录端口访问日志

// WireGuard 协议常量
const WG_TYPE_HANDSHAKE_INIT: u8 = 1;
const WG_TYPE_HANDSHAKE_RESP: u8 = 2;
const WG_TYPE_COOKIE_REPLY: u8 = 3;
const WG_TYPE_DATA: u8 = 4;

const WG_SIZE_HANDSHAKE_INIT: usize = 148;
const WG_SIZE_HANDSHAKE_RESP: usize = 92;
const WG_SIZE_COOKIE_REPLY: usize = 64;
const WG_MIN_SIZE_DATA: usize = 32;

#[xdp]
pub fn rfw(ctx: XdpContext) -> u32 {
    match try_rfw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_rfw(ctx: XdpContext) -> Result<u32, ()> {
    // 读取配置
    let config_flags = CONFIG.get(0).ok_or(())?;

    // 解析以太网头（ptr_at 内部会做边界检查）
    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth_proto = u16::from_be(unsafe { (*eth_hdr).h_proto });
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // 解析 IP 头（ptr_at 内部会做边界检查）
    let ip_hdr = ptr_at::<IpHdr>(&ctx, size_of::<EthHdr>())?;
    let protocol = unsafe { (*ip_hdr).protocol };
    let src_ip = unsafe { (*ip_hdr).saddr };

    // IP 头长度（IHL 字段在第一个字节的低 4 位）
    let ihl = unsafe { (*ip_hdr)._bitfield & 0x0F };
    let ip_hdr_len = (ihl as usize) * 4;

    // 验证 IP 头长度合理性
    if ip_hdr_len < 20 || ip_hdr_len > 60 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 检查是否启用了 GeoIP 过滤 + 屏蔽所有流量规则
    if (*config_flags & RULE_BLOCK_ALL) != 0 {
        if (*config_flags & RULE_GEOIP_ENABLED) != 0 {
            let in_geoip_list = is_geoip_match(src_ip)?;
            let whitelist_mode = (*config_flags & RULE_GEOIP_WHITELIST) != 0;

            let should_block = if whitelist_mode {
                // 白名单模式: 不在列表中的阻止
                !in_geoip_list
            } else {
                // 黑名单模式: 在列表中的阻止
                in_geoip_list
            };

            if should_block {
                info!(
                    &ctx,
                    "BLOCKED: 所有入站流量来自受限 IP: {:i}",
                    u32::from_be(src_ip)
                );
                return Ok(xdp_action::XDP_DROP);
            }
        } else {
            // 未启用 GeoIP,阻止所有流量
            info!(
                &ctx,
                "BLOCKED: 所有入站流量被阻止 (全局规则): {:i}",
                u32::from_be(src_ip)
            );
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // 根据协议解析传输层头
    match protocol {
        IPPROTO_TCP => {
            let tcp_hdr = ptr_at::<TcpHdr>(&ctx, size_of::<EthHdr>() + ip_hdr_len)?;
            let dst_port = u16::from_be(unsafe { (*tcp_hdr).dest });
            let src_port = u16::from_be(unsafe { (*tcp_hdr).source });
            // 获取 TCP 头长度（data offset 字段在 _bitfield 的高4位，单位是4字节）
            let tcp_data_offset = (u16::from_be(unsafe { (*tcp_hdr)._bitfield }) >> 12) as usize;
            let tcp_hdr_len = tcp_data_offset * 4;

            // 验证 TCP 头长度最小为 20 字节
            if tcp_hdr_len < 20 {
                return Ok(xdp_action::XDP_PASS);
            }

            // TCP payload 的起始位置
            let payload_offset = size_of::<EthHdr>() + ip_hdr_len + tcp_hdr_len;

            // 检查 Email 屏蔽规则（阻止所有 SMTP 流量）
            if (*config_flags & RULE_BLOCK_EMAIL) != 0 {
                // 封禁所有 SMTP 相关端口，无论方向
                if dst_port == 25 || dst_port == 587 || dst_port == 465 || dst_port == 2525 {
                    if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                        log_port_access(src_ip, dst_port, IPPROTO_TCP, true);
                    }
                    info!(&ctx, "BLOCKED: SMTP 流量被阻止, 目标端口: {}", dst_port);
                    return Ok(xdp_action::XDP_DROP);
                }
                if src_port == 25 || src_port == 587 || src_port == 465 || src_port == 2525 {
                    if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                        log_port_access(src_ip, dst_port, IPPROTO_TCP, true);
                    }
                    info!(&ctx, "BLOCKED: SMTP 流量被阻止, 源端口: {}", src_port);
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // 协议深度检测（HTTP/SOCKS5/FET）- 使用连接跟踪避免误判
            // 检查是否启用了任何需要协议检测的规则
            let needs_protocol_detection = (*config_flags
                & (RULE_BLOCK_HTTP
                    | RULE_BLOCK_SOCKS5
                    | RULE_BLOCK_FET_STRICT
                    | RULE_BLOCK_FET_LOOSE))
                != 0;

            unsafe {
                if needs_protocol_detection {
                    // 优化：如果启用了 GeoIP 过滤，先检查 IP 是否匹配
                    if (*config_flags & RULE_GEOIP_ENABLED) != 0 {
                        let in_geoip_list = is_geoip_match(src_ip)?;
                        let whitelist_mode = (*config_flags & RULE_GEOIP_WHITELIST) != 0;

                        let should_check = if whitelist_mode {
                            // 白名单模式: 不在列表中的需要检测
                            !in_geoip_list
                        } else {
                            // 黑名单模式: 在列表中的需要检测
                            in_geoip_list
                        };

                        if !should_check {
                            // 不需要检测此IP,直接放行
                            return Ok(xdp_action::XDP_PASS);
                        }
                    }

                    // 继续进行协议检测
                    let dst_ip = (*ip_hdr).daddr;

                    // 提取TCP flags（_bitfield的低8位）
                    let tcp_flags = (u16::from_be((*tcp_hdr)._bitfield) & 0xFF) as u8;

                    // 跳过TCP握手包（SYN包，包括SYN和SYN-ACK）
                    // SYN包用于建立连接，不包含应用层数据
                    if (tcp_flags & TCP_SYN) != 0 {
                        return Ok(xdp_action::XDP_PASS);
                    }

                    // 检查是否有实际的TCP payload
                    let start = ctx.data();
                    let end = ctx.data_end();
                    let payload_size = end.saturating_sub(start + payload_offset);

                    // 没有payload，跳过检测（例如纯ACK包、FIN包等控制包）
                    if payload_size == 0 {
                        return Ok(xdp_action::XDP_PASS);
                    }

                    let conn_key = ConnKey {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol: IPPROTO_TCP,
                        _padding: [0; 3],
                    };

                    // 检查这个连接的状态
                    match TCP_CONN_TRACKER.get(&conn_key) {
                        Some(&state) => {
                            // 连接已被检测过
                            if state == CONN_STATE_BLOCKED {
                                if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                                    log_port_access(src_ip, dst_port, IPPROTO_TCP, true);
                                }
                                return Ok(xdp_action::XDP_DROP);
                            } else {
                                // 连接已允许，记录日志
                                if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                                    log_port_access(src_ip, dst_port, IPPROTO_TCP, false);
                                }
                            }
                        }
                        None => {
                            debug!(
                                &ctx,
                                "检测包含payload的TCP包: 源 {:i}:{} -> 目标端口 {}, flags=0x{:x}, payload={}字节, offset={}",
                                u32::from_be(src_ip),
                                src_port,
                                dst_port,
                                tcp_flags,
                                payload_size,
                                payload_offset
                            );

                            // 新连接，需要进行协议检测（已确保有payload）
                            let mut should_block = false;

                            // 检查 HTTP 入站屏蔽规则
                            if (*config_flags & RULE_BLOCK_HTTP) != 0 && payload_size >= 4 {
                                if is_http_request(&ctx, payload_offset)? {
                                    info!(
                                        &ctx,
                                        "BLOCKED: HTTP 入站流量, 源 {:i}:{} -> 目标端口 {}",
                                        u32::from_be(src_ip),
                                        src_port,
                                        dst_port
                                    );
                                    should_block = true;
                                }
                            }

                            // 检查 SOCKS5 入站屏蔽规则
                            if !should_block
                                && (*config_flags & RULE_BLOCK_SOCKS5) != 0
                                && payload_size >= 2
                            {
                                if is_socks5_request(&ctx, payload_offset)? {
                                    info!(
                                        &ctx,
                                        "BLOCKED: SOCKS5 入站流量, 源 {:i}:{} -> 目标端口 {}",
                                        u32::from_be(src_ip),
                                        src_port,
                                        dst_port
                                    );
                                    should_block = true;
                                }
                            }

                            // 检查 FET（全加密流量）入站屏蔽规则
                            // FET 检测需要至少 16 字节
                            if !should_block && payload_size >= 16 {
                                // 判断模式：严格或宽松
                                let strict_mode = (*config_flags & RULE_BLOCK_FET_STRICT) != 0;
                                let loose_mode = (*config_flags & RULE_BLOCK_FET_LOOSE) != 0;

                                if strict_mode || loose_mode {
                                    if is_fully_encrypted_traffic(
                                        &ctx,
                                        payload_offset,
                                        payload_size,
                                        strict_mode,
                                        src_ip,
                                        src_port,
                                        dst_port,
                                    )? {
                                        let mode_str =
                                            if strict_mode { "严格" } else { "宽松" };
                                        info!(
                                            &ctx,
                                            "BLOCKED: 全加密流量 (FET-{}) 入站, 源 {:i}:{} -> 目标端口 {}",
                                            mode_str,
                                            u32::from_be(src_ip),
                                            src_port,
                                            dst_port
                                        );
                                        should_block = true;
                                    }
                                }
                            }
                            // 放过小包等后续大包再检查
                            if payload_size <= 6 {
                                return Ok(xdp_action::XDP_PASS);
                            }
                            // 处理检测结果
                            if should_block {
                                // 标记这个连接为已阻止，后续包也会被DROP
                                let _ = TCP_CONN_TRACKER.insert(&conn_key, &CONN_STATE_BLOCKED, 0);
                                if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                                    log_port_access(src_ip, dst_port, IPPROTO_TCP, true);
                                }
                                return Ok(xdp_action::XDP_DROP);
                            } else {
                                // 标记这个连接为已通过，后续包直接放行
                                let _ = TCP_CONN_TRACKER.insert(&conn_key, &CONN_STATE_ALLOWED, 0);
                                if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                                    log_port_access(src_ip, dst_port, IPPROTO_TCP, false);
                                }
                            }
                        }
                    }
                }
            }
        }
        IPPROTO_UDP => {
            // 处理 UDP 协议
            let udp_hdr = ptr_at::<UdpHdr>(&ctx, size_of::<EthHdr>() + ip_hdr_len)?;

            // UDP payload 的起始位置
            let payload_offset = size_of::<EthHdr>() + ip_hdr_len + size_of::<UdpHdr>();

            // 检查 WireGuard 入站屏蔽规则
            if (*config_flags & RULE_BLOCK_WIREGUARD) != 0 {
                // 先检查 GeoIP 过滤（如果启用）
                let should_check_wg = if (*config_flags & RULE_GEOIP_ENABLED) != 0 {
                    let in_geoip_list = is_geoip_match(src_ip)?;
                    let whitelist_mode = (*config_flags & RULE_GEOIP_WHITELIST) != 0;
                    if whitelist_mode {
                        !in_geoip_list
                    } else {
                        in_geoip_list
                    }
                } else {
                    true // 未启用 GeoIP,检测所有流量
                };

                if should_check_wg && is_wireguard_packet(&ctx, payload_offset)? {
                    let src_port = u16::from_be(unsafe { (*udp_hdr).source });
                    let dst_port = u16::from_be(unsafe { (*udp_hdr).dest });
                    if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                        log_port_access(src_ip, dst_port, IPPROTO_UDP, true);
                    }
                    info!(
                        &ctx,
                        "BLOCKED: WireGuard VPN 入站流量, 源 {:i}:{} -> 目标端口 {}",
                        u32::from_be(src_ip),
                        src_port,
                        dst_port
                    );
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // 检查 QUIC 入站屏蔽规则
            if (*config_flags & RULE_BLOCK_QUIC) != 0 {
                // 先检查 GeoIP 过滤（如果启用）
                let should_check_quic = if (*config_flags & RULE_GEOIP_ENABLED) != 0 {
                    let in_geoip_list = is_geoip_match(src_ip)?;
                    let whitelist_mode = (*config_flags & RULE_GEOIP_WHITELIST) != 0;
                    if whitelist_mode {
                        !in_geoip_list
                    } else {
                        in_geoip_list
                    }
                } else {
                    true // 未启用 GeoIP,检测所有流量
                };

                if should_check_quic && is_quic_packet(&ctx, payload_offset)? {
                    let src_port = u16::from_be(unsafe { (*udp_hdr).source });
                    let dst_port = u16::from_be(unsafe { (*udp_hdr).dest });
                    if (*config_flags & RULE_LOG_PORT_ACCESS) != 0 {
                        log_port_access(src_ip, dst_port, IPPROTO_UDP, true);
                    }
                    info!(
                        &ctx,
                        "BLOCKED: QUIC 入站流量, 源 {:i}:{} -> 目标端口 {}",
                        u32::from_be(src_ip),
                        src_port,
                        dst_port
                    );
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

// 检测是否为 TLS 流量
// TLS 握手格式：[\x16-\x17]\x03[\x00-\x09]
#[inline(always)]
fn is_tls(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 读取前3个字节
    let bytes = match ptr_at::<[u8; 3]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return Ok(false),
    };

    // TLS: [\x16-\x17]\x03[\x00-\x09]
    if bytes[0] >= 0x16 && bytes[0] <= 0x17 && bytes[1] == 0x03 && bytes[2] <= 0x09 {
        return Ok(true);
    }

    Ok(false)
}

// 检测是否为 HTTP 请求
// 检查 TCP payload 开头是否包含 HTTP 方法
#[inline(always)]
fn is_http_request(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 尝试读取前4个字节来检测 HTTP 方法
    let method_bytes = match ptr_at::<[u8; 4]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => {
            return Ok(false);
        }
    };

    // 构造u32进行比较（大端）
    let method_u32 = ((method_bytes[0] as u32) << 24)
        | ((method_bytes[1] as u32) << 16)
        | ((method_bytes[2] as u32) << 8)
        | (method_bytes[3] as u32);

    // 检查是否匹配常见的 HTTP 方法
    if method_u32 == HTTP_GET
        || method_u32 == HTTP_POST
        || method_u32 == HTTP_HEAD
        || method_u32 == HTTP_PUT
        || method_u32 == HTTP_DELETE
        || method_u32 == HTTP_OPTIONS
        || method_u32 == HTTP_PATCH
        || method_u32 == HTTP_CONNECT
    {
        return Ok(true);
    }

    Ok(false)
}

// 检测是否为 SOCKS5 请求
// SOCKS5 握手格式：VER (1 byte) | NMETHODS (1 byte) | METHODS (1-255 bytes)
// VER = 0x05
fn is_socks5_request(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 尝试读取前2个字节
    let socks_header = match ptr_at::<[u8; 2]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return Ok(false), // payload 太小
    };

    // 检查版本号
    if socks_header[0] != SOCKS5_VERSION {
        return Ok(false);
    }

    // 检查方法数量是否合理（1-255）
    let nmethods = socks_header[1];
    if nmethods == 0 {
        return Ok(false);
    }

    // 进一步验证：确保至少有 nmethods 字节的数据可读
    // 如果能读到，说明这很可能是一个有效的 SOCKS5 握手
    let total_len = 2 + nmethods as usize;
    match ptr_at::<u8>(ctx, payload_offset + total_len - 1) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// 检查 IP 是否匹配 GeoIP 列表
// 使用 LpmTrie 进行高效的最长前缀匹配，时间复杂度 O(1)
#[inline(always)]
fn is_geoip_match(ip: u32) -> Result<bool, ()> {
    // 构造 LpmTrie Key: prefix_len=32 (查询完整IP地址)
    let key = Key::<u32>::new(32, ip);

    // 进行最长前缀匹配查询
    match GEOIP_MAP.get(&key) {
        Some(&1) => Ok(true), // 找到匹配的 IP 前缀
        _ => Ok(false),       // 未找到
    }
}

// FET (Fully Encrypted Traffic) 检测相关函数
// 基于论文: https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf
//
// eBPF 优化策略 - 不使用循环，直接展开检查固定字节：
// 1. 尝试检查前 32 字节，不足则检查更小尺寸（16/8 字节）
// 2. 先检查 TLS/HTTP（3-4字节，最快排除）
// 3. 检查前 6 字节可打印性（展开，无循环）
// 4. 根据实际读取的字节数计算 popcount（展开，无循环）

// 宏：计算单个字节的 popcount（内联展开）
macro_rules! byte_popcount {
    ($b:expr) => {{
        let mut count = 0u32;
        let mut byte = $b;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        byte >>= 1;
        count += (byte & 1) as u32;
        count
    }};
}

// FET (Fully Encrypted Traffic) 检测 - 栈优化版本
// 分批读取32字节以减少栈使用
//
// 检测逻辑：
// 1. TLS/HTTP 豁免（Ex5）- 复用公共方法
// 2. 前6字节可打印性豁免（Ex2）
// 3. 熵值检测（Ex1，通过 popcount）
// 4. 严格模式：默认阻止 | 宽松模式：默认放过
#[inline(always)]
fn is_fully_encrypted_traffic(
    ctx: &XdpContext,
    payload_offset: usize,
    payload_len: usize,
    strict_mode: bool,
    src_ip: u32,
    src_port: u16,
    dst_port: u16,
) -> Result<bool, ()> {
    // Ex5: TLS 豁免检测
    if is_tls(ctx, payload_offset)? {
        debug!(
            ctx,
            "FET豁免-TLS: 源 {:i}:{} -> 目标端口 {}, payload={}字节",
            u32::from_be(src_ip),
            src_port,
            dst_port,
            payload_len
        );
        return Ok(false);
    }

    // Ex5: HTTP 豁免检测（需要4字节）
    if payload_len >= 4 && is_http_request(ctx, payload_offset)? {
        debug!(
            ctx,
            "FET豁免-HTTP: 源 {:i}:{} -> 目标端口 {}, payload={}字节",
            u32::from_be(src_ip),
            src_port,
            dst_port,
            payload_len
        );
        return Ok(false);
    }

    // 分批读取以减少栈使用：先读取前16字节
    let bytes_first = match ptr_at::<[u8; 16]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => {
            debug!(
                ctx,
                "FET豁免-无法读取: 源 {:i}:{} -> 目标端口 {}, payload={}字节",
                u32::from_be(src_ip),
                src_port,
                dst_port,
                payload_len
            );
            return Ok(false);
        }
    };

    // Ex2: 检查前6字节是否都是可打印字符
    let all_printable = bytes_first[0] >= 0x20
        && bytes_first[0] <= 0x7e
        && bytes_first[1] >= 0x20
        && bytes_first[1] <= 0x7e
        && bytes_first[2] >= 0x20
        && bytes_first[2] <= 0x7e
        && bytes_first[3] >= 0x20
        && bytes_first[3] <= 0x7e
        && bytes_first[4] >= 0x20
        && bytes_first[4] <= 0x7e
        && bytes_first[5] >= 0x20
        && bytes_first[5] <= 0x7e;

    if all_printable {
        debug!(
            ctx,
            "FET豁免-可打印字符: 源 {:i}:{} -> 目标端口 {}, payload={}字节, 前6字节=[{:x},{:x},{:x},{:x},{:x},{:x}]",
            u32::from_be(src_ip),
            src_port,
            dst_port,
            payload_len,
            bytes_first[0],
            bytes_first[1],
            bytes_first[2],
            bytes_first[3],
            bytes_first[4],
            bytes_first[5]
        );
        return Ok(false); // 豁免：可能是文本协议
    }

    // 确定实际要检测的字节数（最多32）
    let check_len = if payload_len > 32 { 32 } else { payload_len };

    // Ex1: 计算前16字节的 popcount
    let mut total_popcount = 0u32;

    // 根据实际长度处理前16字节
    if check_len >= 16 {
        // 完整处理前16字节
        total_popcount = byte_popcount!(bytes_first[0])
            + byte_popcount!(bytes_first[1])
            + byte_popcount!(bytes_first[2])
            + byte_popcount!(bytes_first[3])
            + byte_popcount!(bytes_first[4])
            + byte_popcount!(bytes_first[5])
            + byte_popcount!(bytes_first[6])
            + byte_popcount!(bytes_first[7])
            + byte_popcount!(bytes_first[8])
            + byte_popcount!(bytes_first[9])
            + byte_popcount!(bytes_first[10])
            + byte_popcount!(bytes_first[11])
            + byte_popcount!(bytes_first[12])
            + byte_popcount!(bytes_first[13])
            + byte_popcount!(bytes_first[14])
            + byte_popcount!(bytes_first[15]);

        // 如果需要检测超过16字节，读取后16字节
        if check_len > 16 {
            let bytes_second = match ptr_at::<[u8; 16]>(ctx, payload_offset + 16) {
                Ok(ptr) => unsafe { *ptr },
                Err(_) => {
                    // 无法读取后16字节，使用前16字节的结果
                    let avg_popcount_x100 = (total_popcount * 100) / 16;
                    return Ok(strict_mode && (avg_popcount_x100 > 340 && avg_popcount_x100 < 460));
                }
            };

            // 计算需要的后半部分字节数
            let remaining = check_len - 16;

            // 累加后16字节（最多16字节）
            if remaining >= 1 {
                total_popcount += byte_popcount!(bytes_second[0]);
            }
            if remaining >= 2 {
                total_popcount += byte_popcount!(bytes_second[1]);
            }
            if remaining >= 3 {
                total_popcount += byte_popcount!(bytes_second[2]);
            }
            if remaining >= 4 {
                total_popcount += byte_popcount!(bytes_second[3]);
            }
            if remaining >= 5 {
                total_popcount += byte_popcount!(bytes_second[4]);
            }
            if remaining >= 6 {
                total_popcount += byte_popcount!(bytes_second[5]);
            }
            if remaining >= 7 {
                total_popcount += byte_popcount!(bytes_second[6]);
            }
            if remaining >= 8 {
                total_popcount += byte_popcount!(bytes_second[7]);
            }
            if remaining >= 9 {
                total_popcount += byte_popcount!(bytes_second[8]);
            }
            if remaining >= 10 {
                total_popcount += byte_popcount!(bytes_second[9]);
            }
            if remaining >= 11 {
                total_popcount += byte_popcount!(bytes_second[10]);
            }
            if remaining >= 12 {
                total_popcount += byte_popcount!(bytes_second[11]);
            }
            if remaining >= 13 {
                total_popcount += byte_popcount!(bytes_second[12]);
            }
            if remaining >= 14 {
                total_popcount += byte_popcount!(bytes_second[13]);
            }
            if remaining >= 15 {
                total_popcount += byte_popcount!(bytes_second[14]);
            }
            if remaining >= 16 {
                total_popcount += byte_popcount!(bytes_second[15]);
            }
        }
    } else {
        // 长度在6-15之间，只处理实际长度（展开以避免循环）
        if check_len >= 1 {
            total_popcount += byte_popcount!(bytes_first[0]);
        }
        if check_len >= 2 {
            total_popcount += byte_popcount!(bytes_first[1]);
        }
        if check_len >= 3 {
            total_popcount += byte_popcount!(bytes_first[2]);
        }
        if check_len >= 4 {
            total_popcount += byte_popcount!(bytes_first[3]);
        }
        if check_len >= 5 {
            total_popcount += byte_popcount!(bytes_first[4]);
        }
        if check_len >= 6 {
            total_popcount += byte_popcount!(bytes_first[5]);
        }
        if check_len >= 7 {
            total_popcount += byte_popcount!(bytes_first[6]);
        }
        if check_len >= 8 {
            total_popcount += byte_popcount!(bytes_first[7]);
        }
        if check_len >= 9 {
            total_popcount += byte_popcount!(bytes_first[8]);
        }
        if check_len >= 10 {
            total_popcount += byte_popcount!(bytes_first[9]);
        }
        if check_len >= 11 {
            total_popcount += byte_popcount!(bytes_first[10]);
        }
        if check_len >= 12 {
            total_popcount += byte_popcount!(bytes_first[11]);
        }
        if check_len >= 13 {
            total_popcount += byte_popcount!(bytes_first[12]);
        }
        if check_len >= 14 {
            total_popcount += byte_popcount!(bytes_first[13]);
        }
        if check_len >= 15 {
            total_popcount += byte_popcount!(bytes_first[14]);
        }
    }

    // 平均 popcount * 100（避免浮点运算）
    let avg_popcount_x100 = (total_popcount * 100) / (check_len as u32);

    // 熵值异常豁免：不在 3.4-4.6 范围内（340-460）
    if avg_popcount_x100 <= 340 || avg_popcount_x100 >= 460 {
        debug!(
            ctx,
            "FET豁免-熵值异常: 源 {:i}:{} -> 目标端口 {}, 熵值={}.{}, payload={}字节",
            u32::from_be(src_ip),
            src_port,
            dst_port,
            avg_popcount_x100 / 100,
            avg_popcount_x100 % 100,
            payload_len
        );
        return Ok(false); // 豁免：熵值异常
    }

    // 所有豁免条件都不满足
    // 严格模式：判定为全加密流量（阻止）
    // 宽松模式：默认放过
    if strict_mode {
        debug!(
            ctx,
            "FET检测-全加密流量: 源 {:i}:{} -> 目标端口 {}, 熵值={}.{}, payload={}字节, 检测长度={}",
            u32::from_be(src_ip),
            src_port,
            dst_port,
            avg_popcount_x100 / 100,
            avg_popcount_x100 % 100,
            payload_len,
            check_len
        );
    } else {
        debug!(
            ctx,
            "FET检测-疑似全加密(宽松放过): 源 {:i}:{} -> 目标端口 {}, 熵值={}.{}, payload={}字节, 检测长度={}",
            u32::from_be(src_ip),
            src_port,
            dst_port,
            avg_popcount_x100 / 100,
            avg_popcount_x100 % 100,
            payload_len,
            check_len
        );
    }
    Ok(strict_mode)
}

// 检测是否为 WireGuard VPN 数据包
// WireGuard 协议特征：
// - 字节 0: 消息类型 (1=握手初始, 2=握手响应, 3=Cookie应答, 4=数据)
// - 字节 1-3: 必须为 0（保留字段）
// - 固定的包大小（根据类型）
#[inline(always)]
fn is_wireguard_packet(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 使用安全的 ptr_at 函数读取前4个字节
    let header = match ptr_at::<[u8; 4]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return Ok(false),
    };

    let msg_type = header[0];
    let reserved1 = header[1];
    let reserved2 = header[2];
    let reserved3 = header[3];

    // WireGuard 保留字段必须为 0
    if reserved1 != 0 || reserved2 != 0 || reserved3 != 0 {
        return Ok(false);
    }

    // 计算实际数据包长度
    let start = ctx.data();
    let end = ctx.data_end();
    let packet_len = end.saturating_sub(start + payload_offset);

    // 根据消息类型检查包大小
    match msg_type {
        WG_TYPE_HANDSHAKE_INIT => {
            // 握手初始化包必须是 148 字节
            if packet_len == WG_SIZE_HANDSHAKE_INIT {
                return Ok(true);
            }
        }
        WG_TYPE_HANDSHAKE_RESP => {
            // 握手响应包必须是 92 字节
            if packet_len == WG_SIZE_HANDSHAKE_RESP {
                return Ok(true);
            }
        }
        WG_TYPE_COOKIE_REPLY => {
            // Cookie 应答包必须是 64 字节
            if packet_len == WG_SIZE_COOKIE_REPLY {
                return Ok(true);
            }
        }
        WG_TYPE_DATA => {
            // 数据包必须至少 32 字节，且长度是 16 的倍数（WireGuard 填充规则）
            if packet_len >= WG_MIN_SIZE_DATA && (packet_len % 16) == 0 {
                return Ok(true);
            }
        }
        _ => {
            // 未知的消息类型
            return Ok(false);
        }
    }

    Ok(false)
}

// 检测是否为 QUIC 协议数据包
// QUIC 协议特征：
// - 长头部包（Long Header）：首字节最高位为 1，包含版本号字段
//   - QUIC v1: 版本号 0x00000001
//   - QUIC v2: 版本号 0x6b3343cf
//   - 版本协商包: 版本号 0x00000000
// - 短头部包（Short Header）：首字节最高位为 0（已建立连接）
#[inline(always)]
fn is_quic_packet(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 读取前5个字节（首字节 + 4字节版本号）
    let header = match ptr_at::<[u8; 5]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return Ok(false),
    };

    let first_byte = header[0];

    // 检查长头部包（最高位为 1）
    if (first_byte & 0x80) == 0x80 {
        // 读取版本号（大端序）
        let version = ((header[1] as u32) << 24)
            | ((header[2] as u32) << 16)
            | ((header[3] as u32) << 8)
            | (header[4] as u32);

        // 检查常见的 QUIC 版本号
        // 0x00000000: 版本协商包
        // 0x00000001: QUIC v1 (RFC 9000)
        // 0x6b3343cf: QUIC v2 (RFC 9369)
        // 0x51303xxx: Google QUIC (Q0xx)
        if version == 0x00000000
            || version == 0x00000001
            || version == 0x6b3343cf
            || (version & 0xFFFF0000) == 0x51303000
        {
            return Ok(true);
        }

        // 其他小版本号也可能是 QUIC（允许未来版本）
        // 但为了减少误判，只识别已知版本
        if version != 0 && version < 0x0000000a {
            return Ok(true);
        }
    } else {
        // 短头部包（最高位为 0）
        // 这些是已建立连接的数据包，更难识别
        // 但如果首字节符合 QUIC 短头部格式，也认为是 QUIC
        // 短头部格式：0XXX XXXX (最高位为0)
        // 为了减少误判，我们只在有明确特征时才识别

        // 检查是否有 QUIC 连接 ID（通过数据包长度判断）
        let start = ctx.data();
        let end = ctx.data_end();
        let packet_len = end.saturating_sub(start + payload_offset);

        // QUIC 短头部包通常至少有 20 字节
        // 并且第一个字节的特定位模式
        if packet_len >= 20 {
            // 如果固定位（bit 6）为 1，这是 QUIC v1/v2 的要求
            if (first_byte & 0x40) == 0x40 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

// 记录端口访问
// 参数：源IP、目标端口、协议、是否被阻断
#[inline(always)]
fn log_port_access(src_ip: u32, dst_port: u16, protocol: u8, blocked: bool) {
    let key = PortAccessKey {
        dst_port,
        protocol,
        _padding: 0,
        src_ip,
    };

    // 尝试获取现有记录
    match unsafe { PORT_ACCESS_LOG.get(&key) } {
        Some(stats) => {
            // 更新统计
            let mut new_stats = *stats;
            if blocked {
                new_stats.blocked_count = new_stats.blocked_count.saturating_add(1);
            } else {
                new_stats.allowed_count = new_stats.allowed_count.saturating_add(1);
            }
            let _ = PORT_ACCESS_LOG.insert(&key, &new_stats, 0);
        }
        None => {
            // 创建新记录
            let new_stats = PortAccessStats {
                allowed_count: if blocked { 0 } else { 1 },
                blocked_count: if blocked { 1 } else { 0 },
                last_seen: 0,
            };
            let _ = PORT_ACCESS_LOG.insert(&key, &new_stats, 0);
        }
    }
}

// 辅助函数：从数据包中获取指定偏移的指针
// CRITICAL: 必须使用直接的指针比较，verifier 才能理解
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    // Verifier 要求这种形式：直接比较指针，不能先减法
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
