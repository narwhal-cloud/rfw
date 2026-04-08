use anyhow::Context as _;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use aya::maps::{Array, HashMap as AyaHashMap, LpmTrie};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use rfw_common::{PortAccessKey, PortAccessStats};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

// 从 URL 下载并解析指定国家的 GeoIP 数据
async fn fetch_geoip_data(country_code: &str) -> anyhow::Result<Vec<String>> {
    const GEOIP_URL_TEMPLATE: &str = "https://raw.githubusercontent.com/Loyalsoldier/geoip/refs/heads/release/text/{}.txt";

    let url = GEOIP_URL_TEMPLATE.replace("{}", &country_code.to_lowercase());
    info!(
        "正在从 {} 下载 {} 的 GeoIP 数据...",
        url,
        country_code.to_uppercase()
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!(
            "下载 {} 的 GeoIP 数据失败: HTTP {}",
            country_code,
            response.status()
        );
    }

    let text = response.text().await?;
    let cidrs: Vec<String> = text
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    info!(
        "成功下载并解析 {} 的 {} 个 IP CIDR 前缀",
        country_code.to_uppercase(),
        cidrs.len()
    );

    Ok(cidrs)
}

// 批量下载多个国家的 GeoIP 数据
async fn fetch_multiple_geoip_data(
    country_codes: &[String],
) -> anyhow::Result<Vec<(String, Vec<String>)>> {
    let mut results = Vec::new();

    for code in country_codes {
        let code_upper = code.to_uppercase();
        match fetch_geoip_data(&code_upper).await {
            Ok(data) => {
                results.push((code_upper.clone(), data));
            }
            Err(e) => {
                warn!("获取 {} 的 GeoIP 数据失败: {}", code_upper, e);
            }
        }
    }

    if results.is_empty() {
        anyhow::bail!("所有国家的 GeoIP 数据下载均失败");
    }

    Ok(results)
}

// 解析 CIDR 格式（如 "1.0.1.0/24"）为 LpmTrie 的 (IP, prefix_len)
fn parse_cidr_to_lpm(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return None;
    }

    let ip: u32 = ip_parts
        .iter()
        .enumerate()
        .try_fold(0u32, |acc, (i, &part)| {
            part.parse::<u8>()
                .ok()
                .map(|byte| acc | ((byte as u32) << (24 - i * 8)))
        })?;

    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };

    let network_ip = ip & mask;
    Some((network_ip, prefix_len))
}

#[derive(Debug, Parser)]
#[clap(name = "rfw", version, about = "基于 eBPF/XDP 的高性能防火墙")]
struct Cli {
    /// 网络接口名称（如 eth0, ens33, wlan0）
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// API 监听地址（例如 0.0.0.0:8080 或 127.0.0.1:8080）
    /// 所有防火墙规则通过此 API 动态配置
    #[clap(long, default_value = "0.0.0.0:8080")]
    api_addr: String,

    /// XDP 附加模式 (auto|skb|drv|hw)
    #[clap(long, default_value = "auto")]
    xdp_mode: String,
}

#[derive(Clone)]
struct AppState {
    ebpf: Arc<Mutex<Ebpf>>,
    iface: String,
}

// ========== API Request/Response Types ==========

#[derive(serde::Serialize)]
struct StatusResponse {
    iface: String,
    api_version: &'static str,
}

#[derive(serde::Serialize)]
struct PortAccessStatsResponse {
    src_ip: String,
    protocol: String,
    dst_port: u16,
    allowed: u64,
    blocked: u64,
    total: u64,
}

#[derive(serde::Deserialize)]
struct ConfigUpdateRequest {
    flags: u32,
}


#[derive(serde::Deserialize)]
struct PortRuleRequest {
    ports: String,                         // "0"(所有) | "8000-9000" | "8080,8081,8082" | "80-100,443,8080-8090"
    protocol: String,                      // tcp|udp|any (传输层) | socks5|http|wireguard|quic|fet_strict|fet_loose|tls|all|email (应用层)
    direction: Option<String>,             // inbound|outbound|both (default: inbound)
    domains: Option<Vec<String>>,          // 仅用于 protocol="tls" 时，支持多个域名
    geoip: Option<Vec<String>>,            // 国家代码列表：CN|RU|KP 等（用于 inbound/outbound 限制）
    ip_range: Option<Vec<String>>,         // CIDR 范围列表：1.0.0.0/8（用于 inbound/outbound 限制）
    action: Option<String>,                // block (黑名单，默认) | allow (白名单)
}

#[derive(serde::Deserialize)]
struct PortForwardRequest {
    dst_port: u16,
    protocol: String,
    new_dst_ip: String,
    new_dst_port: u16,
}

#[derive(serde::Deserialize)]
struct LoggingConfigRequest {
    enabled: bool,
}

// ========== API Handlers ==========

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(StatusResponse {
        iface: state.iface.clone(),
        api_version: "1.0",
    })
}

async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ebpf = state.ebpf.lock().await;
    let port_access_map: AyaHashMap<_, PortAccessKey, PortAccessStats> =
        match ebpf.map("PORT_ACCESS_LOG") {
            Some(m) => m.try_into().unwrap(),
            None => return (StatusCode::NOT_FOUND, "Map not found").into_response(),
        };

    let mut records = Vec::new();
    for item in port_access_map.iter() {
        if let Ok((key, stats)) = item {
            let src_ip = Ipv4Addr::from(u32::from_be(key.src_ip));
            let protocol_name = if key.protocol == 6 {
                "TCP".to_string()
            } else {
                "UDP".to_string()
            };
            let total = stats.allowed_count + stats.blocked_count;

            records.push(PortAccessStatsResponse {
                src_ip: src_ip.to_string(),
                protocol: protocol_name,
                dst_port: key.dst_port,
                allowed: stats.allowed_count,
                blocked: stats.blocked_count,
                total,
            });
        }
    }

    Json(records).into_response()
}

async fn update_config_flags(
    State(state): State<AppState>,
    Json(req): Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    let mut ebpf = state.ebpf.lock().await;
    let mut config_map: Array<_, u32> = match ebpf.map_mut("CONFIG") {
        Some(m) => m.try_into().unwrap(),
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG map not found").into_response()
        }
    };

    match config_map.set(0, req.flags, 0) {
        Ok(_) => {
            info!("通过 API 更新防火墙配置: flags = 0x{:x}", req.flags);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            warn!("通过 API 更新配置失败: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

// 解析端口范围/列表字符串，如 "80", "8000-9000", "80,443,8080-8090"
fn parse_ports(ports_str: &str) -> Vec<u16> {
    let mut result = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        if let Some(dash_pos) = part.find('-') {
            // 端口范围
            if let (Ok(start), Ok(end)) = (
                part[..dash_pos].parse::<u16>(),
                part[dash_pos + 1..].parse::<u16>(),
            ) {
                for port in start..=end {
                    result.push(port);
                }
            }
        } else {
            // 单个端口
            if let Ok(port) = part.parse::<u16>() {
                result.push(port);
            }
        }
    }
    result
}

// 将协议字符串转换为相应的 flag 位
fn protocol_to_flag(protocol: &str) -> Option<u32> {
    match protocol.to_lowercase().as_str() {
        "socks5" => Some(rfw_common::RULE_BLOCK_SOCKS5),
        "http" => Some(rfw_common::RULE_BLOCK_HTTP),
        "wireguard" | "wg" => Some(rfw_common::RULE_BLOCK_WIREGUARD),
        "quic" => Some(rfw_common::RULE_BLOCK_QUIC),
        "fet_strict" | "fet-strict" => Some(rfw_common::RULE_BLOCK_FET_STRICT),
        "fet_loose" | "fet-loose" => Some(rfw_common::RULE_BLOCK_FET_LOOSE),
        "email" => Some(rfw_common::RULE_BLOCK_EMAIL),
        "tls" | "sni" => Some(rfw_common::RULE_BLOCK_SNI),
        "all" => Some(rfw_common::RULE_BLOCK_ALL),
        _ => None,
    }
}


// 设置端口规则 (ports="0" 表示所有端口)
async fn set_port_rule(
    State(state): State<AppState>,
    Json(mut req): Json<PortRuleRequest>,
) -> impl IntoResponse {
    // 解析端口列表
    let ports_list = parse_ports(&req.ports);

    if ports_list.is_empty() {
        return (StatusCode::BAD_REQUEST, "No valid ports specified").into_response();
    }

    let action = req.action.take().unwrap_or_else(|| "block".to_string()).to_lowercase();
    if !matches!(action.as_str(), "block" | "allow") {
        return (StatusCode::BAD_REQUEST, "action must be 'block' or 'allow'").into_response();
    }

    let is_allow = action == "allow";
    let action_desc = if is_allow { "白名单" } else { "黑名单" };

    let direction = match req.direction.take().unwrap_or_else(|| "inbound".to_string()).to_lowercase().as_str() {
        "inbound" | "in" => 0,
        "outbound" | "out" => 1,
        "both" => 2,
        _ => return (StatusCode::BAD_REQUEST, "Invalid direction").into_response(),
    };

    let mut ebpf = state.ebpf.lock().await;

    // 检查是否包含端口 0（表示所有端口）
    let has_port_zero = ports_list.contains(&0);

    if has_port_zero && ports_list.len() > 1 {
        return (StatusCode::BAD_REQUEST, "Port 0 cannot be mixed with other ports").into_response();
    }

    let protocol_lower = req.protocol.to_lowercase();

    // 判断是传输层协议还是应用层协议
    let is_transport_protocol = matches!(protocol_lower.as_str(), "tcp" | "udp" | "any");

    if is_transport_protocol {
        // 传输层协议：使用 BLOCK_PORTS map
        if has_port_zero {
            return (StatusCode::BAD_REQUEST, "Port 0 cannot be used with transport-level protocols (tcp/udp/any). Use application protocols instead").into_response();
        }

        let transport_list: Vec<u8> = match protocol_lower.as_str() {
            "tcp" => vec![6],
            "udp" => vec![17],
            "any" => vec![6, 17],
            _ => return (StatusCode::BAD_REQUEST, "Invalid transport protocol").into_response(),
        };

        let mut block_ports: AyaHashMap<_, rfw_common::PortBlockKey, u8> =
            match ebpf.map_mut("BLOCK_PORTS") {
                Some(m) => m.try_into().unwrap(),
                None => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "BLOCK_PORTS map not found")
                        .into_response()
                }
            };

        let mut success_count = 0;
        for port in &ports_list {
            for proto in &transport_list {
                let key = rfw_common::PortBlockKey {
                    port: *port,
                    protocol: *proto,
                    direction,
                };

                // 0 = block (blacklist), 1 = allow (whitelist)
                let action_value = if is_allow { 1 } else { 0 };
                if block_ports.insert(key, action_value, 0).is_ok() {
                    success_count += 1;
                }
            }
        }

        info!(
            "通过 API 设置 {} 个规则: 端口={} 协议={} 方向={}",
            success_count,
            ports_list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
            protocol_lower,
            direction
        );

        if success_count == (ports_list.len() * transport_list.len()) {
            StatusCode::OK.into_response()
        } else {
            (StatusCode::PARTIAL_CONTENT, format!("Partially applied to {}/{} rules", success_count, ports_list.len() * transport_list.len())).into_response()
        }
    } else {
        // 应用层协议：使用 PORT_PROTO_FLAGS map 或全局 CONFIG
        let flag = match protocol_to_flag(&req.protocol) {
            Some(f) => f,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Unknown protocol: {}. Valid protocols: tcp, udp, any, socks5, http, wireguard, quic, fet_strict, fet_loose, tls, email, all", req.protocol),
                )
                    .into_response()
            }
        };

        // 如果是 TLS 协议且提供了域名，添加到 DOMAIN_BLACKLIST
        if protocol_lower == "tls" || protocol_lower == "sni" {
            if let Some(domains) = &req.domains {
                if let Some(m) = ebpf.map_mut("DOMAIN_BLACKLIST") {
                    if let Ok(mut domain_blacklist) = <AyaHashMap<_, [u8; 64], u8>>::try_from(m) {
                        let mut domain_count = 0;
                        for domain in domains {
                            let mut domain_bytes = [0u8; 64];
                            let domain_len = domain.len().min(64);
                            domain_bytes[..domain_len].copy_from_slice(&domain.as_bytes()[..domain_len]);

                            if domain_blacklist.insert(domain_bytes, 1, 0).is_ok() {
                                domain_count += 1;
                            }
                        }
                        info!("通过 API 添加 {} 个 TLS 域名到黑名单", domain_count);
                    }
                }
            }
        }

        // GeoIP 条件：动态下载对应国家数据
        if let Some(geoip_countries) = &req.geoip {
            if !geoip_countries.is_empty() {
                match load_geoip_to_map(&mut ebpf, geoip_countries).await {
                    Ok(loaded_count) => {
                        // 启用 GeoIP 过滤
                        if let Some(m) = ebpf.map_mut("CONFIG") {
                            if let Ok(mut config_map) = <Array<_, u32>>::try_from(m) {
                                let current_flags = config_map.get(&0, 0).unwrap_or(0);
                                let new_flags = current_flags | rfw_common::RULE_GEOIP_ENABLED;
                                let _ = config_map.set(0, new_flags, 0);
                            }
                        }
                        info!(
                            "规则配置 {} GeoIP 条件: {} 方向={} 国家={:?} (加载{}条IP)",
                            action_desc,
                            ports_list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                            match direction {
                                0 => "入站",
                                1 => "出站",
                                _ => "双向",
                            },
                            geoip_countries,
                            loaded_count
                        );
                    }
                    Err(e) => {
                        warn!("加载 GeoIP 数据失败: {}", e);
                    }
                }
            }
        }

        // 记录 IP 范围条件（API 层支持）
        if let Some(ip_ranges) = &req.ip_range {
            info!(
                "规则配置 {} IP 范围条件: {} 方向={} 范围={:?}",
                action_desc,
                ports_list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                match direction {
                    0 => "入站",
                    1 => "出站",
                    _ => "双向",
                },
                ip_ranges
            );
        }

        if has_port_zero {
            // 端口 0 = 所有端口，更新全局 CONFIG map
            if let Some(m) = ebpf.map_mut("CONFIG") {
                if let Ok(mut config_map) = <Array<_, u32>>::try_from(m) {
                    let current_flags = config_map.get(&0, 0).ok().unwrap_or(0);
                    let new_flags = current_flags | flag;
                    if config_map.set(0, new_flags, 0).is_ok() {
                        info!("通过 API 设置全局规则: protocol={} direction={}", req.protocol, direction);
                        return StatusCode::OK.into_response();
                    }
                }
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG map not found").into_response();
        } else {
            // 特定端口，更新 PORT_PROTO_FLAGS（黑名单）或 PORT_PROTO_ALLOW_FLAGS（白名单）
            let map_name = if is_allow { "PORT_PROTO_ALLOW_FLAGS" } else { "PORT_PROTO_FLAGS" };
            let mut port_proto_flags: AyaHashMap<_, u16, u32> = match ebpf.map_mut(map_name) {
                Some(m) => m.try_into().unwrap(),
                None => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, format!("{} map not found", map_name))
                        .into_response()
                }
            };

            let mut success_count = 0;
            for port in &ports_list {
                let existing_flags = match port_proto_flags.get(port, 0) {
                    Ok(v) => v,
                    Err(_) => 0,
                };
                let new_flags = existing_flags | flag;

                if port_proto_flags.insert(*port, new_flags, 0).is_ok() {
                    success_count += 1;
                }
            }

            info!(
                "通过 API 设置 {} 个端口的规则 ({}): protocol={} direction={} 端口={}",
                success_count,
                action_desc,
                req.protocol,
                direction,
                ports_list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
            );

            if success_count == ports_list.len() {
                StatusCode::OK.into_response()
            } else {
                (StatusCode::PARTIAL_CONTENT, format!("Partially applied to {}/{} ports", success_count, ports_list.len())).into_response()
            }
        }
    }
}

// 删除端口规则 (ports="0" 删除所有端口的全局规则)
async fn delete_port_rule(
    State(state): State<AppState>,
    Path(ports_str): Path<String>,
) -> impl IntoResponse {
    let ports_list = parse_ports(&ports_str);
    if ports_list.is_empty() {
        return (StatusCode::BAD_REQUEST, "No valid ports specified").into_response();
    }

    let has_port_zero = ports_list.contains(&0);

    if has_port_zero && ports_list.len() > 1 {
        return (StatusCode::BAD_REQUEST, "Port 0 cannot be mixed with other ports").into_response();
    }

    let mut ebpf = state.ebpf.lock().await;
    if has_port_zero {
        // 删除全局规则（重置 CONFIG）
        if let Some(m) = ebpf.map_mut("CONFIG") {
            if let Ok(mut config_map) = <Array<_, u32>>::try_from(m) {
                if config_map.set(0, 0, 0).is_ok() {
                    info!("通过 API 删除全局规则");
                }
            }
        }
    } else {
        // 删除端口特定的黑名单协议规则
        let mut removed_count = 0;
        {
            if let Some(m) = ebpf.map_mut("PORT_PROTO_FLAGS") {
                if let Ok(mut port_proto_flags) = <AyaHashMap<_, u16, u32>>::try_from(m) {
                    for port in &ports_list {
                        if port_proto_flags.remove(port).is_ok() {
                            removed_count += 1;
                        }
                    }
                }
            }
        }

        // 删除端口特定的白名单协议规则
        {
            if let Some(m) = ebpf.map_mut("PORT_PROTO_ALLOW_FLAGS") {
                if let Ok(mut port_allow_flags) = <AyaHashMap<_, u16, u32>>::try_from(m) {
                    for port in &ports_list {
                        if port_allow_flags.remove(port).is_ok() {
                            removed_count += 1;
                        }
                    }
                }
            }
        }

        // 删除传输层阻止规则
        {
            if let Some(m) = ebpf.map_mut("BLOCK_PORTS") {
                if let Ok(mut block_ports) = <AyaHashMap<_, rfw_common::PortBlockKey, u8>>::try_from(m) {
                    for port in &ports_list {
                        for proto in &[6u8, 17u8] {
                            for direction in &[0u8, 1u8, 2u8] {
                                let key = rfw_common::PortBlockKey {
                                    port: *port,
                                    protocol: *proto,
                                    direction: *direction,
                                };
                                if block_ports.remove(&key).is_ok() {
                                    removed_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("通过 API 删除端口规则，移除 {} 条", removed_count);
    }

    StatusCode::OK.into_response()
}

// 辅助函数：下载并加载 GeoIP 数据到 eBPF map
async fn load_geoip_to_map(ebpf: &mut Ebpf, country_codes: &[String]) -> anyhow::Result<usize> {
    let geo_data_list = fetch_multiple_geoip_data(country_codes).await?;

    let mut geoip_map: LpmTrie<_, u32, u8> = match ebpf.map_mut("GEOIP_MAP") {
        Some(m) => m.try_into().unwrap(),
        None => anyhow::bail!("GEOIP_MAP not found"),
    };

    let mut loaded_count = 0;
    for (_country_code, cidrs) in geo_data_list {
        for cidr in &cidrs {
            if let Some((ip, prefix_len)) = parse_cidr_to_lpm(cidr) {
                let key = aya::maps::lpm_trie::Key::new(prefix_len, ip.to_be());
                if geoip_map.insert(&key, 1, 0).is_ok() {
                    loaded_count += 1;
                }
            }
        }
    }

    Ok(loaded_count)
}

// 端口转发
async fn add_forward(
    State(state): State<AppState>,
    Json(req): Json<PortForwardRequest>,
) -> impl IntoResponse {
    let mut ebpf = state.ebpf.lock().await;
    let mut forward_rules: AyaHashMap<_, rfw_common::PortForwardKey, rfw_common::PortForwardValue> =
        match ebpf.map_mut("FORWARD_RULES") {
            Some(m) => m.try_into().unwrap(),
            None => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "FORWARD_RULES map not found")
                    .into_response()
            }
        };

    let protocol = match req.protocol.to_uppercase().as_str() {
        "TCP" => 6,
        "UDP" => 17,
        _ => return (StatusCode::BAD_REQUEST, "Invalid protocol").into_response(),
    };

    let new_dst_ip: Ipv4Addr = match req.new_dst_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid IP").into_response(),
    };

    let key = rfw_common::PortForwardKey {
        dst_port: req.dst_port,
        protocol,
        _padding: 0,
    };

    let value = rfw_common::PortForwardValue {
        new_dst_ip: u32::from(new_dst_ip).to_be(),
        new_dst_port: req.new_dst_port,
        _padding: [0; 2],
    };

    match forward_rules.insert(key, value, 0) {
        Ok(_) => {
            info!(
                "通过 API 添加端口转发: {}/{} -> {}:{}",
                req.dst_port, req.protocol, req.new_dst_ip, req.new_dst_port
            );
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// 删除端口转发
async fn delete_forward(
    State(state): State<AppState>,
    Path((port, protocol)): Path<(u16, String)>,
) -> impl IntoResponse {
    let protocol_num = match protocol.to_uppercase().as_str() {
        "TCP" => 6,
        "UDP" => 17,
        _ => return (StatusCode::BAD_REQUEST, "Invalid protocol").into_response(),
    };

    let mut ebpf = state.ebpf.lock().await;
    let mut forward_rules: AyaHashMap<_, rfw_common::PortForwardKey, rfw_common::PortForwardValue> =
        match ebpf.map_mut("FORWARD_RULES") {
            Some(m) => m.try_into().unwrap(),
            None => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "FORWARD_RULES map not found")
                    .into_response()
            }
        };

    let key = rfw_common::PortForwardKey {
        dst_port: port,
        protocol: protocol_num,
        _padding: 0,
    };

    match forward_rules.remove(&key) {
        Ok(_) => {
            info!("通过 API 删除端口转发: {}/{}", port, protocol);
            StatusCode::OK.into_response()
        }
        Err(_) => {
            (StatusCode::NOT_FOUND, format!("Forward rule {}:{} not found", port, protocol))
                .into_response()
        }
    }
}

// 删除域名黑名单
async fn delete_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let mut ebpf = state.ebpf.lock().await;
    let mut domain_blacklist: AyaHashMap<_, [u8; 64], u8> =
        match ebpf.map_mut("DOMAIN_BLACKLIST") {
            Some(m) => m.try_into().unwrap(),
            None => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "DOMAIN_BLACKLIST map not found")
                    .into_response()
            }
        };

    let mut domain_bytes = [0u8; 64];
    let domain_len = domain.len().min(64);
    domain_bytes[..domain_len].copy_from_slice(&domain.as_bytes()[..domain_len]);

    match domain_blacklist.remove(&domain_bytes) {
        Ok(_) => {
            info!("通过 API 删除域名黑名单: {}", domain);
            StatusCode::OK.into_response()
        }
        Err(_) => {
            (StatusCode::NOT_FOUND, format!("Domain {} not found in blacklist", domain))
                .into_response()
        }
    }
}

// 配置访问日志
async fn set_logging_config(
    State(state): State<AppState>,
    Json(req): Json<LoggingConfigRequest>,
) -> impl IntoResponse {
    let mut ebpf = state.ebpf.lock().await;
    let mut config_map: Array<_, u32> = match ebpf.map_mut("CONFIG") {
        Some(m) => m.try_into().unwrap(),
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG map not found").into_response()
        }
    };

    let current_flags = config_map.get(&0, 0).unwrap_or(0);
    let new_flags = if req.enabled {
        current_flags | rfw_common::RULE_LOG_PORT_ACCESS
    } else {
        current_flags & !rfw_common::RULE_LOG_PORT_ACCESS
    };

    match config_map.set(0, new_flags, 0) {
        Ok(_) => {
            if req.enabled {
                // 尝试 pin map
                if let Some(map) = ebpf.map("PORT_ACCESS_LOG") {
                    if let Err(e) = map.pin("/sys/fs/bpf/rfw_port_access_log") {
                        warn!("Failed to pin PORT_ACCESS_LOG: {}", e);
                    } else {
                        info!("Pinned PORT_ACCESS_LOG to /sys/fs/bpf/rfw_port_access_log");
                    }
                }
            }

            let action = if req.enabled { "enabled" } else { "disabled" };
            info!("通过 API {} 访问日志记录", action);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            warn!("设置日志配置失败: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

// 启动 API 服务器
async fn start_api(addr: &str, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/stats", get(get_stats))
        .route("/api/config/flags", post(update_config_flags))
        .route("/api/rules/port", post(set_port_rule))
        .route("/api/rules/port/:port", delete(delete_port_rule))
        .route("/api/rules/forward", post(add_forward))
        .route("/api/rules/forward/:port/:protocol", delete(delete_forward))
        .route("/api/rules/domain/:domain", delete(delete_domain))
        .route("/api/rules/logging", post(set_logging_config))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("WebAPI 服务正在监听: {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run_firewall(cli).await
}

async fn run_firewall(cli: Cli) -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program
    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rfw"
    )))?;

    let ebpf = Arc::new(Mutex::new(ebpf));

    // Initialize eBPF logger
    {
        let mut ebpf = ebpf.lock().await;
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }
    }

    // Set initial CONFIG = 0 (no rules)
    {
        let mut ebpf = ebpf.lock().await;
        let mut config_map: Array<_, u32> = ebpf.map_mut("CONFIG").unwrap().try_into()?;
        config_map.set(0, 0, 0)?;
        info!("防火墙初始化: 无规则激活");
    }

    // Attach XDP program
    {
        let mut ebpf = ebpf.lock().await;

        let xdp_flags = match cli.xdp_mode.to_lowercase().as_str() {
            "skb" => {
                info!("使用 SKB 模式附加 XDP 程序");
                XdpFlags::SKB_MODE
            }
            "drv" | "driver" => {
                info!("使用驱动模式附加 XDP 程序");
                XdpFlags::DRV_MODE
            }
            "hw" | "hardware" => {
                info!("使用硬件模式附加 XDP 程序");
                XdpFlags::HW_MODE
            }
            _ => {
                info!("使用自动模式附加 XDP 程序");
                XdpFlags::default()
            }
        };

        let program: &mut Xdp = ebpf.program_mut("rfw").unwrap().try_into()?;
        program.load()?;
        program.attach(&cli.iface, xdp_flags).context(format!(
            "Failed to attach XDP program to interface {}",
            cli.iface
        ))?;

        info!("XDP 程序已附加到接口: {}", cli.iface);

        // Try to attach TC program (for egress)
        let tc_program: &mut SchedClassifier = ebpf.program_mut("rfw_egress").unwrap().try_into()?;
        tc_program.load()?;
        if let Err(e) = tc_program.attach(&cli.iface, TcAttachType::Egress) {
            warn!("Failed to attach TC egress program: {}", e);
        } else {
            info!("TC egress 程序已附加到接口: {}", cli.iface);
        }
    }

    // Start API server
    let app_state = AppState {
        ebpf: ebpf.clone(),
        iface: cli.iface.clone(),
    };

    tokio::spawn({
        let api_addr = cli.api_addr.clone();
        async move {
            if let Err(e) = start_api(&api_addr, app_state).await {
                warn!("API 服务启动失败: {}", e);
            }
        }
    });

    println!("防火墙运行中，按 Ctrl-C 退出...");
    println!("API 地址: http://{}", cli.api_addr);

    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("退出中...");

    Ok(())
}
