#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use core::mem::size_of;

// 防火墙配置 map
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

// GeoIP 数据 map - 中国 IP 段（使用 LpmTrie 进行高效前缀匹配）
// LpmTrie key: prefix_len (4 bytes) + IP address (4 bytes)
// value: u8 (1 = 中国IP)
#[map]
static GEOIP_CN: LpmTrie<u32, u8> = LpmTrie::with_max_entries(65536, 0);

// TCP 连接跟踪 map - 记录已检测过的连接（五元组）
// 使用 LRU 策略自动淘汰旧连接
// 值：0 = 已检测且通过, 1 = 已检测且阻止
#[map]
static TCP_CONN_TRACKER: LruHashMap<ConnKey, u8> = LruHashMap::with_max_entries(65536, 0);

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
const RULE_BLOCK_CN_HTTP: u32 = 1 << 1;
const RULE_BLOCK_CN_SOCKS5: u32 = 1 << 2;
const RULE_BLOCK_CN_FET: u32 = 1 << 3;
const RULE_BLOCK_CN_WIREGUARD: u32 = 1 << 4;
const RULE_BLOCK_CN_ALL: u32 = 1 << 5;

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

    // 检查是否启用了屏蔽中国所有入站流量规则
    if (*config_flags & RULE_BLOCK_CN_ALL) != 0 {
        if is_cn_ip(src_ip)? {
            info!(&ctx, "BLOCKED: 所有入站流量来自中国 IP: {:i}", src_ip);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // 根据协议解析传输层头
    match protocol {
        IPPROTO_TCP => {
            let tcp_hdr = ptr_at::<TcpHdr>(&ctx, size_of::<EthHdr>() + ip_hdr_len)?;
            let dst_port = u16::from_be(unsafe { (*tcp_hdr).dest });

            // 获取 TCP 头长度（data offset 字段在 _bitfield 的高4位，单位是4字节）
            let tcp_data_offset = (u16::from_be(unsafe { (*tcp_hdr)._bitfield }) >> 12) as usize;
            let tcp_hdr_len = tcp_data_offset * 4;

            // 验证 TCP 头长度最小为 20 字节
            if tcp_hdr_len < 20 {
                return Ok(xdp_action::XDP_PASS);
            }

            // TCP payload 的起始位置
            let payload_offset = size_of::<EthHdr>() + ip_hdr_len + tcp_hdr_len;

            // 检查 Email 屏蔽规则（仅阻止发送 SMTP，允许接收 POP3/IMAP）
            if (*config_flags & RULE_BLOCK_EMAIL) != 0 {
                // 仅阻止 SMTP 发送邮件端口：25, 587, 465, 2525
                // 允许 POP3（110, 995）和 IMAP（143, 993）接收邮件
                if dst_port == 25 || dst_port == 587 || dst_port == 465 || dst_port == 2525 {
                    info!(
                        &ctx,
                        "BLOCKED: Email (SMTP) 发送出站流量, 目标端口: {}", dst_port
                    );
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // 协议深度检测（HTTP/SOCKS5/FET）- 使用连接跟踪避免误判
            // 检查是否启用了任何需要协议检测的规则
            let needs_protocol_detection = (*config_flags
                & (RULE_BLOCK_CN_HTTP | RULE_BLOCK_CN_SOCKS5 | RULE_BLOCK_CN_FET))
                != 0;

            unsafe {
                if needs_protocol_detection {
                    // 构造连接五元组 key
                    let src_port = u16::from_be((*tcp_hdr).source);
                    let dst_ip = (*ip_hdr).daddr;

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
                                // 这个连接已被标记为阻止，直接DROP所有后续包
                                debug!(
                                    &ctx,
                                    "BLOCKED: 已阻止连接的后续包, 源IP: {:i}",
                                    src_ip
                                );
                                return Ok(xdp_action::XDP_DROP);
                            }
                            // state == CONN_STATE_ALLOWED, 直接放行
                        }
                        None => {
                            // 新连接，需要进行协议检测
                            // 检查是否有TCP payload
                            let start = ctx.data();
                            let end = ctx.data_end();
                            let payload_size = end.saturating_sub(start + payload_offset);

                            // 只有当有payload时才进行检测
                            if payload_size > 0 {
                                let mut should_block = false;

                                // 检查 HTTP 入站屏蔽规则
                                if (*config_flags & RULE_BLOCK_CN_HTTP) != 0 && payload_size >= 4 {
                                    if is_http_request(&ctx, payload_offset)? {
                                        if is_cn_ip(src_ip)? {
                                            info!(
                                                &ctx,
                                                "BLOCKED: HTTP 入站流量来自中国 IP: {:i}",
                                                src_ip
                                            );
                                            should_block = true;
                                        }
                                    }
                                }

                                // 检查 SOCKS5 入站屏蔽规则
                                if !should_block
                                    && (*config_flags & RULE_BLOCK_CN_SOCKS5) != 0
                                    && payload_size >= 2
                                {
                                    if is_socks5_request(&ctx, payload_offset)? {
                                        if is_cn_ip(src_ip)? {
                                            info!(
                                                &ctx,
                                                "BLOCKED: SOCKS5 入站流量来自中国 IP: {:i}",
                                                src_ip
                                            );
                                            should_block = true;
                                        }
                                    }
                                }

                                // 检查 FET（全加密流量）入站屏蔽规则
                                // FET 检测需要至少 16 字节
                                if !should_block
                                    && (*config_flags & RULE_BLOCK_CN_FET) != 0
                                    && payload_size >= 16
                                {
                                    if is_fully_encrypted_traffic(&ctx, payload_offset, payload_size)? {
                                        if is_cn_ip(src_ip)? {
                                            info!(
                                                &ctx,
                                                "BLOCKED: 全加密流量 (FET) 入站来自中国 IP: {:i}",
                                                src_ip
                                            );
                                            should_block = true;
                                        }
                                    }
                                }

                                // 处理检测结果
                                if should_block {
                                    // 标记这个连接为已阻止，后续包也会被DROP
                                    let _ =
                                        TCP_CONN_TRACKER.insert(&conn_key, &CONN_STATE_BLOCKED, 0);
                                    return Ok(xdp_action::XDP_DROP);
                                } else {
                                    // 标记这个连接为已通过，后续包直接放行
                                    let _ =
                                        TCP_CONN_TRACKER.insert(&conn_key, &CONN_STATE_ALLOWED, 0);
                                }
                            }
                            // 如果没有payload，不记录状态，等待有payload的包
                        }
                    }
                }
            }
        }
        IPPROTO_UDP => {
            // 处理 UDP 协议
            let _udp_hdr = ptr_at::<UdpHdr>(&ctx, size_of::<EthHdr>() + ip_hdr_len)?;

            // UDP payload 的起始位置
            let payload_offset = size_of::<EthHdr>() + ip_hdr_len + size_of::<UdpHdr>();

            // 检查 WireGuard 入站屏蔽规则（来自中国的入站）
            if (*config_flags & RULE_BLOCK_CN_WIREGUARD) != 0 {
                // 通过协议深度检测识别 WireGuard 流量
                if is_wireguard_packet(&ctx, payload_offset)? {
                    if is_cn_ip(src_ip)? {
                        info!(
                            &ctx,
                            "BLOCKED: WireGuard VPN 入站流量来自中国 IP: {:i}", src_ip
                        );
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

// 检测是否为 HTTP 请求
// 检查 TCP payload 开头是否包含 HTTP 方法
fn is_http_request(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 尝试读取前4个字节来检测 HTTP 方法
    let method_bytes = match ptr_at::<u32>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return Ok(false), // payload 太小，不是 HTTP
    };

    // 检查是否匹配常见的 HTTP 方法
    // 注意：这里的字节序是网络字节序（大端）
    let method_be = u32::from_be(method_bytes);

    if method_be == HTTP_GET
        || method_be == HTTP_POST
        || method_be == HTTP_HEAD
        || method_be == HTTP_PUT
        || method_be == HTTP_DELETE
        || method_be == HTTP_OPTIONS
        || method_be == HTTP_PATCH
        || method_be == HTTP_CONNECT
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

// 检查 IP 是否属于中国
// 使用 LpmTrie 进行高效的最长前缀匹配，时间复杂度 O(1)
#[inline(always)]
fn is_cn_ip(ip: u32) -> Result<bool, ()> {
    // 构造 LpmTrie Key: prefix_len=32 (查询完整IP地址)
    let key = Key::<u32>::new(32, ip);

    // 进行最长前缀匹配查询
    match GEOIP_CN.get(&key) {
        Some(&1) => Ok(true),  // 找到匹配的中国IP前缀
        _ => Ok(false),        // 未找到或不是中国IP
    }
}

// FET (Fully Encrypted Traffic) 检测相关函数
// 基于论文: https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf
//
// eBPF 优化策略 - 不使用循环，直接展开检查固定字节：
// 1. 只检查前 16 字节（足够判断，避免循环导致指令爆炸）
// 2. 先检查 TLS/HTTP（3字节，最快排除）
// 3. 检查前 6 字节可打印性（展开，无循环）
// 4. 检查 16 字节的 popcount（展开，无循环）

// 宏：计算单个字节的 popcount（内联展开）
macro_rules! byte_popcount {
    ($b:expr) => {{
        let mut count = 0u32;
        let mut byte = $b;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32; byte >>= 1;
        count += (byte & 1) as u32;
        count
    }};
}

// Ex2+Ex1 组合：检查前 16 字节的特征
// 返回 (前6字节是否都可打印, 平均popcount*100)
#[inline(always)]
fn check_first_16_bytes(ctx: &XdpContext, payload_offset: usize) -> Result<(bool, u32), ()> {
    // 尝试读取前 16 字节
    let bytes = match ptr_at::<[u8; 16]>(ctx, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return Ok((false, 0)),
    };

    // 检查前 6 字节是否都可打印（Ex2）
    let all_printable = bytes[0] >= 0x20 && bytes[0] <= 0x7e
        && bytes[1] >= 0x20 && bytes[1] <= 0x7e
        && bytes[2] >= 0x20 && bytes[2] <= 0x7e
        && bytes[3] >= 0x20 && bytes[3] <= 0x7e
        && bytes[4] >= 0x20 && bytes[4] <= 0x7e
        && bytes[5] >= 0x20 && bytes[5] <= 0x7e;

    // 计算 16 字节的总 popcount（Ex1）- 完全展开，无循环
    let total_popcount = byte_popcount!(bytes[0])
        + byte_popcount!(bytes[1])
        + byte_popcount!(bytes[2])
        + byte_popcount!(bytes[3])
        + byte_popcount!(bytes[4])
        + byte_popcount!(bytes[5])
        + byte_popcount!(bytes[6])
        + byte_popcount!(bytes[7])
        + byte_popcount!(bytes[8])
        + byte_popcount!(bytes[9])
        + byte_popcount!(bytes[10])
        + byte_popcount!(bytes[11])
        + byte_popcount!(bytes[12])
        + byte_popcount!(bytes[13])
        + byte_popcount!(bytes[14])
        + byte_popcount!(bytes[15]);

    // 平均 popcount * 100 / 16 字节 = total * 100 / 16
    let avg_popcount_x100 = (total_popcount * 100) / 16;

    Ok((all_printable, avg_popcount_x100))
}

// Ex5: 检查是否是 TLS 或 HTTP 流量
#[inline(always)]
fn is_tls_or_http(ctx: &XdpContext, payload_offset: usize) -> Result<bool, ()> {
    // 检查至少有3个字节
    match ptr_at::<[u8; 3]>(ctx, payload_offset) {
        Ok(ptr) => {
            let bytes = unsafe { *ptr };

            // TLS: [\x16-\x17]\x03[\x00-\x09]
            if bytes[0] >= 0x16 && bytes[0] <= 0x17
                && bytes[1] == 0x03
                && bytes[2] <= 0x09 {
                return Ok(true);
            }

            // HTTP 方法检测（复用已有的函数）
            if is_http_request(ctx, payload_offset)? {
                return Ok(true);
            }

            Ok(false)
        }
        Err(_) => Ok(false),
    }
}

// FET 检测主函数
// 如果返回 true，表示检测到全加密流量（应该阻止）
//
// 简化策略（避免循环导致指令爆炸）：
// - 只检查前 16 字节
// - Ex5: TLS/HTTP 检测（3字节）- 最快排除合法流量
// - Ex2: 前6字节可打印性（无循环）
// - Ex1: 平均 popcount（16字节，无循环）
#[inline(always)]
fn is_fully_encrypted_traffic(ctx: &XdpContext, payload_offset: usize, payload_len: usize) -> Result<bool, ()> {
    // 需要至少 16 个字节才能进行准确检测
    if payload_len < 16 {
        return Ok(false);
    }

    // Ex5: 优先检查是否是 TLS 或 HTTP（最快豁免）
    if is_tls_or_http(ctx, payload_offset)? {
        return Ok(false); // 豁免 TLS/HTTPS/HTTP
    }

    // Ex2 + Ex1: 检查前 16 字节的统计特征
    let (all_printable, avg_popcount_x100) = check_first_16_bytes(ctx, payload_offset)?;

    // Ex2: 如果前 6 字节都是可打印字符，豁免（可能是文本协议）
    if all_printable {
        return Ok(false);
    }

    // Ex1: 检查平均 popcount
    // 正常范围是 3.4 到 4.6，即 340 到 460（* 100后）
    // 全加密流量的 popcount 应该接近 4.0 (400)
    if avg_popcount_x100 <= 340 || avg_popcount_x100 >= 460 {
        return Ok(false); // 豁免
    }

    // 所有豁免条件都不满足，判定为全加密流量
    // - 不是 TLS/HTTP (Ex5)
    // - 平均 popcount 在 3.4-4.6 范围内 (Ex1) - 高熵值
    // - 前6字节不全是可打印字符 (Ex2) - 不是文本协议
    Ok(true)
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
