#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie, LruHashMap, RingBuf},
    programs::{TcContext, XdpContext},
};
use core::mem::size_of;
use rfw_common::{
    BlockEvent, ConnKey, FirewallRule, ACTION_BLOCK, ACTION_PASS, DIR_IN, DIR_OUT, HTTP_CONNECT,
    HTTP_DELETE, HTTP_GET, HTTP_HEAD, HTTP_OPTIONS, HTTP_PATCH, HTTP_POST, HTTP_PUT, IP_TYPE_ANY,
    IP_TYPE_CIDR, IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL, PROTO_FET, PROTO_HTTP, PROTO_OPENVPN,
    PROTO_QUIC, PROTO_SOCKS, PROTO_SSH, PROTO_TLS, PROTO_WIREGUARD, SOCKS4_VERSION,
    SOCKS5_VERSION, SSH_BANNER,
};

#[map]
static RULES: Array<FirewallRule> = Array::with_max_entries(MAX_RULES, 0);

#[map]
static GEOIP_MAP: LpmTrie<u32, u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
static CONNTRACK: LruHashMap<ConnKey, u8> = LruHashMap::with_max_entries(16384, 0);

#[map]
static BLOCK_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 16, 0);

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
    let (action, rule_idx) = apply_rules(remote_ip, protocol, app_proto, local_port, DIR_IN);

    // 有 payload 才缓存：SYN/ACK 等无 payload 的包不缓存，保证 HTTP/GeoIP 等应用层规则能正确命中首个数据包
    let has_payload = payload_offset < (data_end as usize - data as usize);
    // 识别到应用层协议或被阻断时发送事件（用于调试）
    if action == ACTION_BLOCK || app_proto != 0 {
        let _ = BLOCK_EVENTS.output::<BlockEvent>(&BlockEvent {
            src_ip: remote_ip, dst_ip: local_ip,
            src_port: remote_port, dst_port: local_port,
            protocol, app_proto, direction: DIR_IN,
            rule_idx: rule_idx as u8, action, _pad: 0,
        }, 0);
    }
    if action == ACTION_BLOCK || app_proto != 0 || has_payload {
        let _ = CONNTRACK.insert(&key, &action, 0);
    }
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

    let app_proto = 0u8;
    let (action, rule_idx) = apply_rules(remote_ip, protocol, app_proto, remote_port, DIR_OUT);

    if action == ACTION_BLOCK {
        let _ = BLOCK_EVENTS.output::<BlockEvent>(&BlockEvent {
            src_ip: local_ip, dst_ip: remote_ip,
            src_port: local_port, dst_port: remote_port,
            protocol, app_proto, direction: DIR_OUT,
            rule_idx: rule_idx as u8, action, _pad: 0,
        }, 0);
        let _ = CONNTRACK.insert(&key, &action, 0);
    }
    Ok(if action == ACTION_BLOCK { TC_ACT_SHOT } else { TC_ACT_PIPE })
}

#[inline(always)]
fn detect_app_proto(data: *const u8, data_end: *const u8, protocol: u8, payload_offset: usize) -> u8 {
    match protocol {
        IPPROTO_TCP => {
            if is_tls(data, data_end, payload_offset) { return PROTO_TLS; }
            if is_http_request(data, data_end, payload_offset) { return PROTO_HTTP; }
            // SSH banner 为明文，会被 is_fet 的可打印豁免放行，故在 FET 之前显式识别
            if is_ssh(data, data_end, payload_offset) { return PROTO_SSH; }
            if is_socks5_request(data, data_end, payload_offset)
                || is_socks4_request(data, data_end, payload_offset) { return PROTO_SOCKS; }
            if is_openvpn_tcp(data, data_end, payload_offset) { return PROTO_OPENVPN; }
            // is_fet 内部已做明文豁免：前6字节全为可打印ASCII则直接返回false，确保高熵数据才被识别为加密流量（FET）
            if is_fet(data, data_end, payload_offset) { return PROTO_FET; }
            0
        }
        IPPROTO_UDP => {
            if is_wireguard(data, data_end, payload_offset) { return PROTO_WIREGUARD; }
            if is_quic(data, data_end, payload_offset) { return PROTO_QUIC; }
            if is_openvpn_udp(data, data_end, payload_offset) { return PROTO_OPENVPN; }
            0
        }
        _ => 0,
    }
}

#[inline(always)]
fn apply_rules(remote_ip: u32, protocol: u8, app_proto: u8, port: u16, direction: u8) -> (u8, u32) {
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
        if ip_ok { return (rule.action, i); }
    }
    (ACTION_PASS, MAX_RULES)
}

#[inline(always)]
fn is_tls(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 3 > data_end as usize { return false; }
    let p = start as *const u8;
    unsafe { *p >= 0x16 && *p <= 0x17 && *p.add(1) == 0x03 && *p.add(2) <= 0x09 }
}

#[inline(always)]
fn is_fet(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 16 > data_end as usize { return false; }
    let p = start as *const u8;
    // Ex2: 前6字节全为可打印 ASCII 则豁免（覆盖 SSH、SMTP 等明文协议）
    let all_printable = unsafe {
        let b0 = *p;
        let b1 = *p.add(1);
        let b2 = *p.add(2);
        let b3 = *p.add(3);
        let b4 = *p.add(4);
        let b5 = *p.add(5);
        b0 >= 0x20 && b0 <= 0x7e
            && b1 >= 0x20 && b1 <= 0x7e
            && b2 >= 0x20 && b2 <= 0x7e
            && b3 >= 0x20 && b3 <= 0x7e
            && b4 >= 0x20 && b4 <= 0x7e
            && b5 >= 0x20 && b5 <= 0x7e
    };
    if all_printable { return false; }
    let mut ones: u32 = 0;
    let mut i = 0;
    while i < 16 {
        ones += unsafe { (*p.add(i)).count_ones() };
        i += 1;
    }
    // 尝试扩展到32字节以提高精度（与旧版行为一致）
    let check_len = if start + 32 <= data_end as usize {
        let mut j = 16;
        while j < 32 {
            ones += unsafe { (*p.add(j)).count_ones() };
            j += 1;
        }
        32u32
    } else {
        16u32
    };
    // 开区间 (3.4, 4.6) bits/byte，对应旧版 avg_x100 > 340 && avg_x100 < 460
    let avg_x100 = (ones * 100) / check_len;
    avg_x100 > 340 && avg_x100 < 460
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
fn is_ssh(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 4 > data_end as usize { return false; }
    // 客户端/服务端标识串均以 "SSH-" 开头 (RFC 4253)
    u32::from_be(unsafe { *(start as *const u32) }) == SSH_BANNER
}

#[inline(always)]
fn is_socks4_request(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    // VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(...) NULL → 最少 9 字节
    if start + 9 > data_end as usize { return false; }
    let p = start as *const u8;
    unsafe {
        let cd = *p.add(1);
        // version=0x04, command=CONNECT(1)/BIND(2)
        *p == SOCKS4_VERSION && (cd == 0x01 || cd == 0x02)
    }
}

#[inline(always)]
fn is_wireguard(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 4 > data_end as usize { return false; }
    let avail = data_end as usize - start;
    let p = start as *const u8;
    unsafe {
        // message_type(1) + reserved_zero(3)，握手包定长：发起=148 / 响应=92
        let reserved_zero = *p.add(1) == 0 && *p.add(2) == 0 && *p.add(3) == 0;
        if !reserved_zero { return false; }
        match *p {
            1 => avail == 148, // Handshake Initiation
            2 => avail == 92,  // Handshake Response
            _ => false,
        }
    }
}

#[inline(always)]
fn is_quic(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    if start + 5 > data_end as usize { return false; }
    let p = start as *const u8;
    // 长头部 + Fixed Bit：连接首包(Initial) 必为长头部
    if unsafe { *p } & 0xC0 != 0xC0 { return false; }
    let version = u32::from_be(unsafe { *(start.wrapping_add(1) as *const u32) });
    let v_hi = version >> 24;
    // v1(RFC9000)=1, v2(RFC9369)=0x6b3343cf, draft=0xff??????, Google QUIC=0x51('Q')??????
    version == 0x0000_0001 || version == 0x6b33_43cf || v_hi == 0xff || v_hi == 0x51
}

// OpenVPN 控制包 opcode 位于字节高 5 位；首包为 HARD_RESET_CLIENT (V1=1/V2=7/V3=10)
#[inline(always)]
fn is_openvpn_opcode(b: u8) -> bool {
    let opcode = b >> 3;
    opcode == 1 || opcode == 7 || opcode == 10
}

#[inline(always)]
fn is_openvpn_tcp(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    // TCP 模式每个包前置 2 字节大端长度，随后是 opcode 字节
    if start + 3 > data_end as usize { return false; }
    let p = start as *const u8;
    let plen = u16::from_be(unsafe { *(start as *const u16) }) as usize;
    let avail = data_end as usize - start;
    // 长度字段应与剩余载荷一致（首个握手包通常不粘包）
    avail >= 3 && plen == avail - 2 && is_openvpn_opcode(unsafe { *p.add(2) })
}

#[inline(always)]
fn is_openvpn_udp(data: *const u8, data_end: *const u8, payload_offset: usize) -> bool {
    let start = data as usize + payload_offset;
    // opcode(1) + session_id(8) + packet_id_array_len(1) + msg_packet_id(4) ≥ 14
    if start + 14 > data_end as usize { return false; }
    is_openvpn_opcode(unsafe { *(start as *const u8) })
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
