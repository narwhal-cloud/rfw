#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie, LruHashMap},
    programs::{TcContext, XdpContext},
};
use core::mem::size_of;
use rfw_common::{
    ConnKey, FirewallRule, ACTION_BLOCK, ACTION_PASS, DIR_IN, DIR_OUT, HTTP_CONNECT, HTTP_DELETE,
    HTTP_GET, HTTP_HEAD, HTTP_OPTIONS, HTTP_PATCH, HTTP_POST, HTTP_PUT, IP_TYPE_ANY, IP_TYPE_CIDR,
    IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL, PROTO_FET, PROTO_HTTP, PROTO_SOCKS5, PROTO_TLS,
    SOCKS5_VERSION,
};

#[map]
static RULES: Array<FirewallRule> = Array::with_max_entries(MAX_RULES, 0);

#[map]
static GEOIP_MAP: LpmTrie<u32, u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
static CONNTRACK: LruHashMap<ConnKey, u8> = LruHashMap::with_max_entries(16384, 0);

#[repr(C)]
struct EthHdr { h_dest: [u8; 6], h_source: [u8; 6], h_proto: u16 }
#[repr(C)]
struct IpHdr { _bitfield: u8, tos: u8, tot_len: u16, id: u16, frag_off: u16, ttl: u8, protocol: u8, check: u16, saddr: u32, daddr: u32 }
#[repr(C)]
struct TcpHdr { source: u16, dest: u16, seq: u32, ack_seq: u32, _bitfield: u16, window: u16, check: u16, urg_ptr: u16 }
#[repr(C)]
struct UdpHdr { source: u16, dest: u16, len: u16, check: u16 }

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_PIPE: i32 = 3;

#[xdp]
pub fn rfw(ctx: XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    match try_rfw(data, data_end) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[classifier]
pub fn rfw_egress(ctx: TcContext) -> i32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    try_rfw_egress(data, data_end).unwrap_or_else(|_| TC_ACT_PIPE)
}

fn try_rfw(data: *const u8, data_end: *const u8) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(data, data_end, 0)?;
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP { return Ok(xdp_action::XDP_PASS); }

    let ip = ptr_at::<IpHdr>(data, data_end, 14)?;
    let protocol = unsafe { (*ip).protocol };
    let (remote_ip, local_ip) = (unsafe { (*ip).saddr }, unsafe { (*ip).daddr });
    let ihl = (unsafe { (*ip)._bitfield } & 0x0F) as usize * 4;
    if ihl < 20 || ihl > 60 { return Ok(xdp_action::XDP_PASS); }

    let mut payload_offset = 14 + ihl;
    let (local_port, remote_port) = match protocol {
        IPPROTO_TCP => {
            let tcp = ptr_at::<TcpHdr>(data, data_end, payload_offset)?;
            let doff = ((u16::from_be(unsafe { (*tcp)._bitfield }) >> 12) & 0xF) as usize * 4;
            if doff < 20 || doff > 60 { return Err(()); }
            let res = (u16::from_be(unsafe { (*tcp).dest }), u16::from_be(unsafe { (*tcp).source }));
            payload_offset += doff;
            res
        }
        IPPROTO_UDP => {
            let udp = ptr_at::<UdpHdr>(data, data_end, payload_offset)?;
            let res = (u16::from_be(unsafe { (*udp).dest }), u16::from_be(unsafe { (*udp).source }));
            payload_offset += 8;
            res
        }
        _ => (0, 0),
    };

    let key = ConnKey { local_ip, remote_ip, local_port, remote_port, protocol, direction: DIR_IN, _padding: [0; 2] };
    if let Some(&action) = unsafe { CONNTRACK.get(&key) } {
        return Ok(if action == ACTION_BLOCK { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS });
    }

    let app_proto = detect_app_proto(data, data_end, protocol, payload_offset);
    let action = apply_rules(remote_ip, protocol, app_proto, local_port, DIR_IN);

    if action == ACTION_BLOCK || app_proto != 0 { let _ = CONNTRACK.insert(&key, &action, 0); }
    Ok(if action == ACTION_BLOCK { xdp_action::XDP_DROP } else { xdp_action::XDP_PASS })
}

fn try_rfw_egress(data: *const u8, data_end: *const u8) -> Result<i32, ()> {
    let eth = ptr_at::<EthHdr>(data, data_end, 0)?;
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP { return Ok(TC_ACT_PIPE); }

    let ip = ptr_at::<IpHdr>(data, data_end, 14)?;
    let protocol = unsafe { (*ip).protocol };
    let (local_ip, remote_ip) = (unsafe { (*ip).saddr }, unsafe { (*ip).daddr });
    let ihl = (unsafe { (*ip)._bitfield } & 0x0F) as usize * 4;
    if ihl < 20 || ihl > 60 { return Ok(TC_ACT_PIPE); }

    let payload_offset = 14 + ihl;
    let (local_port, remote_port) = match protocol {
        IPPROTO_TCP => {
            let tcp = ptr_at::<TcpHdr>(data, data_end, payload_offset)?;
            let doff = ((u16::from_be(unsafe { (*tcp)._bitfield }) >> 12) & 0xF) as usize * 4;
            if doff < 20 || doff > 60 { return Err(()); }
            (u16::from_be(unsafe { (*tcp).source }), u16::from_be(unsafe { (*tcp).dest }))
        }
        IPPROTO_UDP => {
            let udp = ptr_at::<UdpHdr>(data, data_end, payload_offset)?;
            (u16::from_be(unsafe { (*udp).source }), u16::from_be(unsafe { (*udp).dest }))
        }
        _ => (0, 0),
    };

    let key = ConnKey { local_ip, remote_ip, local_port, remote_port, protocol, direction: DIR_OUT, _padding: [0; 2] };
    if let Some(&action) = unsafe { CONNTRACK.get(&key) } {
        return Ok(if action == ACTION_BLOCK { TC_ACT_SHOT } else { TC_ACT_PIPE });
    }

    let app_proto = 0;
    let action = apply_rules(remote_ip, protocol, app_proto, remote_port, DIR_OUT);

    if action == ACTION_BLOCK || app_proto != 0 { let _ = CONNTRACK.insert(&key, &action, 0); }
    Ok(if action == ACTION_BLOCK { TC_ACT_SHOT } else { TC_ACT_PIPE })
}

#[inline(always)]
fn detect_app_proto(data: *const u8, data_end: *const u8, protocol: u8, payload_offset: usize) -> u8 {
    if protocol != IPPROTO_TCP { return 0; }
    if is_tls(data, data_end, payload_offset) { return PROTO_TLS; }
    if is_http_request(data, data_end, payload_offset) { return PROTO_HTTP; }
    if is_socks5_request(data, data_end, payload_offset) { return PROTO_SOCKS5; }
    // FET 判断在 plain_text 之前：高熵数据优先识别为加密流量
    if is_fet(data, data_end, payload_offset) { return PROTO_FET; }
    0
}

#[inline(always)]
fn apply_rules(remote_ip: u32, protocol: u8, app_proto: u8, port: u16, direction: u8) -> u8 {
    for i in 0..MAX_RULES {
        let rule = match RULES.get(i) { Some(r) => r, None => break };
        if rule.enabled == 0 { break; }
        if rule.direction != direction { continue; }
        // 匹配逻辑：如果规则是具体协议(HTTP/FET等)，则检查 app_proto；如果是基础协议(TCP/UDP)，则匹配 L4 协议
        if rule.protocol != PROTO_ALL {
            if rule.protocol != protocol && rule.protocol != app_proto { continue; }
        }
        if (rule.port_start != 0 || rule.port_end != 0) && (port < rule.port_start || port > rule.port_end) { continue; }
        let ip_ok = match rule.ip_type {
            IP_TYPE_ANY => true,
            IP_TYPE_CIDR => {
                let mask = if rule.src_prefix_len == 0 { 0 } else if rule.src_prefix_len >= 32 { 0xFFFFFFFF } else { 0xFFFF_FFFFu32.wrapping_shl(32 - rule.src_prefix_len) };
                (u32::from_be(remote_ip) & mask) == (u32::from_be(rule.src_ip) & mask)
            }
            IP_TYPE_GEOIP => {
                let key = Key::<u32>::new(32, remote_ip);
                match GEOIP_MAP.get(&key) { Some(&1) => true, _ => false }
            }
            _ => false,
        };
        if ip_ok { return rule.action; }
    }
    ACTION_PASS
}

#[inline(always)]
fn is_tls(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 3 > data_end as usize { return false; }
    let p = start as *const u8;
    unsafe { *p == 0x16 && *p.add(1) == 0x03 && *p.add(2) <= 0x03 }
}

#[inline(always)]
fn is_fet(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 16 > data_end as usize { return false; }
    let p = start as *const u8;
    let mut ones: u32 = 0;
    let mut i = 0;
    while i < 16 {
        ones += unsafe { (*p.add(i)).count_ones() };
        i += 1;
    }
    ones >= 54 && ones <= 74
}

#[inline(always)]
fn is_http_request(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 4 > data_end as usize { return false; }
    let p = start as *const u32;
    let m = u32::from_be(unsafe { *p });
    m == HTTP_GET || m == HTTP_POST || m == HTTP_HEAD || m == HTTP_PUT || m == HTTP_DELETE || m == HTTP_OPTIONS || m == HTTP_PATCH || m == HTTP_CONNECT
}

#[inline(always)]
fn is_socks5_request(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 3 > data_end as usize { return false; }
    let p = start as *const u8;
    unsafe {
        let methods = *p.add(1);
        // version=0x05, methods 在合理范围 1-8, 且包长度足以容纳 method list
        *p == SOCKS5_VERSION
            && methods >= 1
            && methods <= 8
            && start + 2 + methods as usize <= data_end as usize
    }
}

#[inline(always)]
fn ptr_at<T>(data: *const u8, data_end: *const u8, offset: usize) -> Result<*const T, ()> {
    let start = data as usize + offset;
    if start + size_of::<T>() > data_end as usize { return Err(()); }
    Ok(start as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { unsafe { core::hint::unreachable_unchecked() } }

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
