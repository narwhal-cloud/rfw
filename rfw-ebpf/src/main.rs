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
    FirewallRule, ACTION_BLOCK, ACTION_PASS, DIR_IN, DIR_OUT, IP_TYPE_ANY, IP_TYPE_CIDR,
    IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL,
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

    let port = match protocol {
        IPPROTO_TCP => {
            let tcp = ptr_at::<TcpHdr>(ctx, size_of::<EthHdr>() + ihl)?;
            u16::from_be(unsafe { (*tcp).dest })
        }
        IPPROTO_UDP => {
            let udp = ptr_at::<UdpHdr>(ctx, size_of::<EthHdr>() + ihl)?;
            u16::from_be(unsafe { (*udp).dest })
        }
        _ => 0,
    };

    if apply_rules(remote_ip, protocol, port, DIR_IN) == ACTION_BLOCK {
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

    let port = match protocol {
        IPPROTO_TCP => {
            let tcp = ptr_at_tc::<TcpHdr>(ctx, size_of::<EthHdr>() + ihl)?;
            u16::from_be(unsafe { (*tcp).dest })
        }
        IPPROTO_UDP => {
            let udp = ptr_at_tc::<UdpHdr>(ctx, size_of::<EthHdr>() + ihl)?;
            u16::from_be(unsafe { (*udp).dest })
        }
        _ => 0,
    };

    if apply_rules(remote_ip, protocol, port, DIR_OUT) == ACTION_BLOCK {
        Ok(TC_ACT_SHOT)
    } else {
        Ok(TC_ACT_PIPE)
    }
}

/// 遍历规则数组，返回第一条匹配规则的动作；无匹配则放行
#[inline(always)]
fn apply_rules(remote_ip: u32, protocol: u8, port: u16, direction: u8) -> u8 {
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

        // 协议匹配：PROTO_ALL 匹配任意协议
        if rule.protocol != PROTO_ALL && rule.protocol != protocol {
            continue;
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

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_tc<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
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
