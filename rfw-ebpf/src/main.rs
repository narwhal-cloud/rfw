#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie},
    programs::{TcContext, XdpContext},
};
use core::mem::size_of;
use rfw_common::{
    FirewallRule, ACTION_BLOCK, ACTION_PASS, DIR_IN, DIR_OUT, HTTP_CONNECT, HTTP_DELETE, HTTP_GET,
    HTTP_HEAD, HTTP_OPTIONS, HTTP_PATCH, HTTP_POST, HTTP_PUT, IP_TYPE_ANY, IP_TYPE_CIDR,
    IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL, PROTO_HTTP, PROTO_SOCKS5, SOCKS5_VERSION,
};

// 防火墙规则数组（按优先级降序排列，index=0 为最高优先级）
#[map]
static RULES: Array<FirewallRule> = Array::with_max_entries(MAX_RULES, 0);

// GeoIP 前缀匹配表
#[map]
static GEOIP_MAP: LpmTrie<u32, u8> = LpmTrie::with_max_entries(65536, 0);

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

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

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    _bitfield: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

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
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_PIPE: i32 = 3;

#[xdp]
pub fn rfw(ctx: XdpContext) -> u32 {
    match try_rfw(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[classifier]
pub fn rfw_egress(ctx: TcContext) -> i32 {
    match try_rfw_egress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_rfw(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<IpHdr>(ctx, size_of::<EthHdr>())?;
    let protocol = unsafe { (*ip).protocol };
    let remote_ip = unsafe { (*ip).saddr }; // 入站：源IP为对端IP
    let ihl = (unsafe { (*ip)._bitfield } & 0x0F) as usize * 4;
    if ihl < 20 || ihl > 60 {
        return Ok(xdp_action::XDP_PASS);
    }

    let mut payload_offset = size_of::<EthHdr>() + ihl;
    let port = match protocol {
        IPPROTO_TCP => {
            let tcp = ptr_at::<TcpHdr>(ctx, payload_offset)?;
            payload_offset += (u16::from_be(unsafe { (*tcp)._bitfield }) >> 12) as usize * 4;
            u16::from_be(unsafe { (*tcp).dest })
        }
        IPPROTO_UDP => {
            let udp = ptr_at::<UdpHdr>(ctx, payload_offset)?;
            payload_offset += size_of::<UdpHdr>();
            u16::from_be(unsafe { (*udp).dest })
        }
        _ => 0,
    };

    let ctx_data = (ctx.data() as *const u8, ctx.data_end() as *const u8);
    if apply_rules(ctx_data, payload_offset, remote_ip, protocol, port, DIR_IN) == ACTION_BLOCK {
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

fn try_rfw_egress(ctx: &TcContext) -> Result<i32, ()> {
    let eth = ptr_at_tc::<EthHdr>(ctx, 0)?;
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let ip = ptr_at_tc::<IpHdr>(ctx, size_of::<EthHdr>())?;
    let protocol = unsafe { (*ip).protocol };
    let remote_ip = unsafe { (*ip).daddr }; // 出站：目标IP为对端IP
    let ihl = (unsafe { (*ip)._bitfield } & 0x0F) as usize * 4;
    if ihl < 20 || ihl > 60 {
        return Ok(TC_ACT_PIPE);
    }

    let mut payload_offset = size_of::<EthHdr>() + ihl;
    let port = match protocol {
        IPPROTO_TCP => {
            let tcp = ptr_at_tc::<TcpHdr>(ctx, payload_offset)?;
            payload_offset += (u16::from_be(unsafe { (*tcp)._bitfield }) >> 12) as usize * 4;
            u16::from_be(unsafe { (*tcp).dest })
        }
        IPPROTO_UDP => {
            let udp = ptr_at_tc::<UdpHdr>(ctx, payload_offset)?;
            payload_offset += size_of::<UdpHdr>();
            u16::from_be(unsafe { (*udp).dest })
        }
        _ => 0,
    };

    let ctx_data = (ctx.data() as *const u8, ctx.data_end() as *const u8);
    if apply_rules(ctx_data, payload_offset, remote_ip, protocol, port, DIR_OUT) == ACTION_BLOCK {
        Ok(TC_ACT_SHOT)
    } else {
        Ok(TC_ACT_PIPE)
    }
}

/// 遍历规则数组，返回第一条匹配规则的动作；无匹配则放行
#[inline(always)]
fn apply_rules(
    ctx_data: (*const u8, *const u8),
    payload_offset: usize,
    remote_ip: u32,
    protocol: u8,
    port: u16,
    direction: u8,
) -> u8 {
    for i in 0..MAX_RULES {
        let rule = match RULES.get(i) {
            Some(r) => r,
            None => continue,
        };

        if rule.enabled == 0 {
            continue;
        }
        if rule.direction != direction {
            continue;
        }

        // 协议匹配
        if rule.protocol != PROTO_ALL {
            if rule.protocol == PROTO_HTTP {
                if protocol != IPPROTO_TCP || !is_http_request(ctx_data, payload_offset) {
                    continue;
                }
            } else if rule.protocol == PROTO_SOCKS5 {
                if protocol != IPPROTO_TCP || !is_socks5_request(ctx_data, payload_offset) {
                    continue;
                }
            } else if rule.protocol != protocol {
                continue;
            }
        }

        // 端口匹配：port_start=0 且 port_end=0 表示所有端口
        if rule.port_start != 0 || rule.port_end != 0 {
            if port < rule.port_start || port > rule.port_end {
                continue;
            }
        }

        // IP 匹配
        let ip_ok = match rule.ip_type {
            IP_TYPE_ANY => true,
            IP_TYPE_CIDR => {
                let mask = if rule.src_prefix_len == 0 {
                    0u32
                } else if rule.src_prefix_len >= 32 {
                    0xFFFF_FFFFu32
                } else {
                    0xFFFF_FFFFu32.wrapping_shl(32 - rule.src_prefix_len)
                };
                (u32::from_be(remote_ip) & mask) == (u32::from_be(rule.src_ip) & mask)
            }
            IP_TYPE_GEOIP => {
                let key = Key::<u32>::new(32, remote_ip);
                match GEOIP_MAP.get(&key) {
                    Some(&1) => true,
                    _ => false,
                }
            }
            _ => false,
        };

        if !ip_ok {
            continue;
        }

        return rule.action;
    }

    ACTION_PASS // 默认放行
}

// 检测是否为 HTTP 请求
#[inline(always)]
fn is_http_request(ctx_data: (*const u8, *const u8), payload_offset: usize) -> bool {
    // 尝试读取前4个字节来检测 HTTP 方法
    let method_bytes = match ptr_at_raw::<[u8; 4]>(ctx_data, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return false,
    };

    // 构造 u32 进行比较 (大端)
    let method_u32 = ((method_bytes[0] as u32) << 24)
        | ((method_bytes[1] as u32) << 16)
        | ((method_bytes[2] as u32) << 8)
        | (method_bytes[3] as u32);

    // 检查是否匹配常见的 HTTP 方法
    method_u32 == HTTP_GET
        || method_u32 == HTTP_POST
        || method_u32 == HTTP_HEAD
        || method_u32 == HTTP_PUT
        || method_u32 == HTTP_DELETE
        || method_u32 == HTTP_OPTIONS
        || method_u32 == HTTP_PATCH
        || method_u32 == HTTP_CONNECT
}

// 检测是否为 SOCKS5 请求
#[inline(always)]
fn is_socks5_request(ctx_data: (*const u8, *const u8), payload_offset: usize) -> bool {
    // 尝试读取前2个字节
    let socks_header = match ptr_at_raw::<[u8; 2]>(ctx_data, payload_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(_) => return false,
    };

    // 检查版本号
    if socks_header[0] != SOCKS5_VERSION {
        return false;
    }

    // 检查方法数量是否合理 (1-255)
    let nmethods = socks_header[1];
    if nmethods == 0 {
        return false;
    }

    // 进一步验证：确保至少有 nmethods 字节的数据可读
    let total_len = 2 + nmethods as usize;
    ptr_at_raw::<u8>(ctx_data, payload_offset + total_len - 1).is_ok()
}

#[inline(always)]
fn ptr_at_raw<T>(ctx_data: (*const u8, *const u8), offset: usize) -> Result<*const T, ()> {
    let (start, end) = ctx_data;
    let len = size_of::<T>();
    if (start as usize) + offset + len > (end as usize) {
        return Err(());
    }
    Ok(((start as usize) + offset) as *const T)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    ptr_at_raw((ctx.data() as *const u8, ctx.data_end() as *const u8), offset)
}

#[inline(always)]
fn ptr_at_tc<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    ptr_at_raw((ctx.data() as *const u8, ctx.data_end() as *const u8), offset)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
