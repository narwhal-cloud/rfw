use anyhow::Context as _;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
    Json, Router,
};
use aya::maps::{Array, LpmTrie};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use rfw_common::{
    FirewallRule, ACTION_BLOCK, ACTION_PASS, DIR_IN, DIR_OUT, IP_TYPE_ANY, IP_TYPE_CIDR,
    IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL, PROTO_TCP, PROTO_UDP,
};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

// ========== GeoIP 数据获取 ==========

async fn fetch_geoip_data(country_code: &str) -> anyhow::Result<Vec<String>> {
    const GEOIP_URL_TEMPLATE: &str =
        "https://raw.githubusercontent.com/Loyalsoldier/geoip/refs/heads/release/text/{}.txt";

    let url = GEOIP_URL_TEMPLATE.replace("{}", &country_code.to_lowercase());
    info!("正在下载 {} 的 GeoIP 数据: {}", country_code.to_uppercase(), url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!(
            "下载 {} GeoIP 数据失败: HTTP {}",
            country_code,
            response.status()
        );
    }

    let text = response.text().await?;
    let cidrs: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    info!("已获取 {} 的 {} 条 CIDR", country_code.to_uppercase(), cidrs.len());
    Ok(cidrs)
}

async fn fetch_multiple_geoip(country_codes: &[String]) -> anyhow::Result<Vec<String>> {
    let mut all_cidrs = Vec::new();
    for code in country_codes {
        match fetch_geoip_data(&code.to_uppercase()).await {
            Ok(cidrs) => all_cidrs.extend(cidrs),
            Err(e) => warn!("获取 {} GeoIP 数据失败: {}", code, e),
        }
    }
    if all_cidrs.is_empty() {
        anyhow::bail!("所有国家的 GeoIP 数据下载均失败");
    }
    Ok(all_cidrs)
}

// 解析 "1.0.1.0/24" 为 (network_ip_host_order, prefix_len)
fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let prefix_len: u32 = prefix.parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let parts: Vec<u8> = addr
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.len() != 4 {
        return None;
    }
    let ip: u32 = ((parts[0] as u32) << 24)
        | ((parts[1] as u32) << 16)
        | ((parts[2] as u32) << 8)
        | (parts[3] as u32);
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    Some((ip & mask, prefix_len))
}

// ========== 状态 ==========

#[derive(Clone)]
struct RuleEntry {
    id: u64,
    rule: FirewallRule,
    // 仅用于展示/响应
    direction_str: String,
    protocol_str: String,
    ip_type_str: String,
    action_str: String,
    cidr: Option<String>,
    countries: Vec<String>,
    // GeoIP 规则缓存的 CIDR 列表（用于重建 GEOIP_MAP）
    cached_cidrs: Vec<String>,
}

struct RulesState {
    entries: Vec<RuleEntry>,
    next_id: u64,
}

#[derive(Clone)]
struct AppState {
    ebpf: Arc<Mutex<Ebpf>>,
    iface: String,
    rules: Arc<Mutex<RulesState>>,
}

// ========== eBPF 同步 ==========

fn sync_rules(ebpf: &mut Ebpf, entries: &[RuleEntry]) -> anyhow::Result<()> {
    let mut sorted: Vec<&RuleEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| b.rule.priority.cmp(&a.rule.priority));

    let empty = FirewallRule {
        priority: 0,
        enabled: 0,
        direction: 0,
        protocol: 0,
        action: 0,
        port_start: 0,
        port_end: 0,
        ip_type: 0,
        _padding: [0; 3],
        src_ip: 0,
        src_prefix_len: 0,
    };

    let mut rules_map: Array<_, FirewallRule> = ebpf
        .map_mut("RULES")
        .context("RULES map not found")?
        .try_into()?;

    for i in 0..MAX_RULES as usize {
        let rule = sorted.get(i).map(|e| e.rule).unwrap_or(empty);
        rules_map.set(i as u32, rule, 0)?;
    }

    Ok(())
}

fn update_geoip(ebpf: &mut Ebpf, entries: &[RuleEntry]) -> anyhow::Result<()> {
    let mut geoip_map: LpmTrie<_, u32, u8> = ebpf
        .map_mut("GEOIP_MAP")
        .context("GEOIP_MAP not found")?
        .try_into()?;

    for entry in entries {
        if entry.rule.ip_type != IP_TYPE_GEOIP {
            continue;
        }
        for cidr in &entry.cached_cidrs {
            if let Some((ip_host, prefix_len)) = parse_cidr(cidr) {
                let key = aya::maps::lpm_trie::Key::new(prefix_len, ip_host.to_be());
                let _ = geoip_map.insert(&key, 1, 0);
            }
        }
    }

    Ok(())
}

// ========== API Types ==========

#[derive(serde::Deserialize)]
struct CreateRuleRequest {
    priority: u32,
    #[serde(default = "bool_true")]
    enabled: bool,
    direction: String,           // "in" | "out"
    protocol: String,            // "tcp" | "udp" | "all"
    port_start: u16,             // 0 = 所有端口
    port_end: Option<u16>,       // 默认等于 port_start
    ip_type: String,             // "any" | "cidr" | "geoip"
    ip: Option<String>,          // CIDR，ip_type="cidr" 时必填
    countries: Option<Vec<String>>, // 国家代码，ip_type="geoip" 时必填
    action: String,              // "block" | "pass"
}

fn bool_true() -> bool {
    true
}

#[derive(serde::Serialize)]
struct RuleResponse {
    id: u64,
    priority: u32,
    enabled: bool,
    direction: String,
    protocol: String,
    port_start: u16,
    port_end: u16,
    ip_type: String,
    ip: Option<String>,
    countries: Option<Vec<String>>,
    action: String,
}

impl From<&RuleEntry> for RuleResponse {
    fn from(e: &RuleEntry) -> Self {
        RuleResponse {
            id: e.id,
            priority: e.rule.priority,
            enabled: e.rule.enabled != 0,
            direction: e.direction_str.clone(),
            protocol: e.protocol_str.clone(),
            port_start: e.rule.port_start,
            port_end: e.rule.port_end,
            ip_type: e.ip_type_str.clone(),
            ip: e.cidr.clone(),
            countries: if e.countries.is_empty() {
                None
            } else {
                Some(e.countries.clone())
            },
            action: e.action_str.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct StatusResponse {
    iface: String,
    api_version: &'static str,
    rule_count: usize,
}

// ========== API Handlers ==========

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state.rules.lock().await;
    Json(StatusResponse {
        iface: state.iface.clone(),
        api_version: "2.0",
        rule_count: rules.entries.len(),
    })
}

async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state.rules.lock().await;
    let mut resp: Vec<RuleResponse> = rules.entries.iter().map(RuleResponse::from).collect();
    resp.sort_by(|a, b| b.priority.cmp(&a.priority));
    Json(resp)
}

async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
    // 解析方向
    let direction = match req.direction.to_lowercase().as_str() {
        "in" | "inbound" => DIR_IN,
        "out" | "outbound" => DIR_OUT,
        _ => {
            return (StatusCode::BAD_REQUEST, "direction must be 'in' or 'out'").into_response()
        }
    };

    // 解析协议
    let protocol = match req.protocol.to_lowercase().as_str() {
        "tcp" => PROTO_TCP,
        "udp" => PROTO_UDP,
        "all" => PROTO_ALL,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "protocol must be 'tcp', 'udp', or 'all'",
            )
                .into_response()
        }
    };

    // 解析动作
    let action = match req.action.to_lowercase().as_str() {
        "block" => ACTION_BLOCK,
        "pass" | "allow" => ACTION_PASS,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "action must be 'block' or 'pass'",
            )
                .into_response()
        }
    };

    let port_start = req.port_start;
    let port_end = req.port_end.unwrap_or(port_start);

    // 解析 IP 类型，获取 GeoIP 数据（在加锁前异步获取）
    let ip_type_str = req.ip_type.to_lowercase();
    let ip_type = match ip_type_str.as_str() {
        "any" => IP_TYPE_ANY,
        "cidr" => IP_TYPE_CIDR,
        "geoip" | "geo" => IP_TYPE_GEOIP,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "ip_type must be 'any', 'cidr', or 'geoip'",
            )
                .into_response()
        }
    };

    let (src_ip, src_prefix_len, cidr_str, countries, cached_cidrs) = match ip_type {
        IP_TYPE_ANY => (0u32, 0u32, None, vec![], vec![]),
        IP_TYPE_CIDR => {
            let cidr = match req.ip {
                Some(ref s) => s.clone(),
                None => {
                    return (StatusCode::BAD_REQUEST, "ip is required for ip_type='cidr'")
                        .into_response()
                }
            };
            let (ip_host, prefix_len) = match parse_cidr(&cidr) {
                Some(x) => x,
                None => return (StatusCode::BAD_REQUEST, "Invalid CIDR format").into_response(),
            };
            (ip_host.to_be(), prefix_len, Some(cidr), vec![], vec![])
        }
        IP_TYPE_GEOIP => {
            let codes = match req.countries {
                Some(ref c) if !c.is_empty() => c.clone(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "countries is required for ip_type='geoip'",
                    )
                        .into_response()
                }
            };
            // 在加锁前异步下载 GeoIP 数据
            let cidrs = match fetch_multiple_geoip(&codes).await {
                Ok(c) => c,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }
            };
            (0u32, 0u32, None, codes, cidrs)
        }
        _ => unreachable!(),
    };

    let rule = FirewallRule {
        priority: req.priority,
        enabled: if req.enabled { 1 } else { 0 },
        direction,
        protocol,
        action,
        port_start,
        port_end,
        ip_type,
        _padding: [0; 3],
        src_ip,
        src_prefix_len,
    };

    let direction_str = if direction == DIR_IN { "in" } else { "out" }.to_string();
    let protocol_str = match protocol {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "all",
    }
    .to_string();
    let action_str = if action == ACTION_BLOCK { "block" } else { "pass" }.to_string();

    let mut rules_guard = state.rules.lock().await;
    rules_guard.next_id += 1;
    let id = rules_guard.next_id;

    rules_guard.entries.push(RuleEntry {
        id,
        rule,
        direction_str,
        protocol_str,
        ip_type_str,
        action_str,
        cidr: cidr_str,
        countries,
        cached_cidrs,
    });

    let mut ebpf = state.ebpf.lock().await;
    if let Err(e) = sync_rules(&mut ebpf, &rules_guard.entries) {
        warn!("同步规则失败: {}", e);
        rules_guard.entries.pop();
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if ip_type == IP_TYPE_GEOIP {
        if let Err(e) = update_geoip(&mut ebpf, &rules_guard.entries) {
            warn!("更新 GeoIP map 失败: {}", e);
        }
    }

    info!("规则已创建: id={} priority={}", id, req.priority);
    #[derive(serde::Serialize)]
    struct Resp { id: u64 }
    Json(Resp { id }).into_response()
}

async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let mut rules_guard = state.rules.lock().await;
    let pos = rules_guard.entries.iter().position(|e| e.id == id);
    match pos {
        None => return (StatusCode::NOT_FOUND, "Rule not found").into_response(),
        Some(i) => {
            rules_guard.entries.remove(i);
        }
    }

    let mut ebpf = state.ebpf.lock().await;
    if let Err(e) = sync_rules(&mut ebpf, &rules_guard.entries) {
        warn!("同步规则失败: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    info!("规则已删除: id={}", id);
    StatusCode::OK.into_response()
}

// ========== CLI ==========

#[derive(Debug, Parser)]
#[clap(name = "rfw", version, about = "基于 eBPF/XDP 的高性能防火墙")]
struct Cli {
    /// 网络接口名称（如 eth0, ens33）
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// API 监听地址
    #[clap(long, default_value = "0.0.0.0:8080")]
    api_addr: String,

    /// XDP 附加模式 (auto|skb|drv|hw)
    #[clap(long, default_value = "auto")]
    xdp_mode: String,
}

// ========== 启动 ==========

async fn start_api(addr: &str, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("API 服务监听: {}", addr);
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

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rfw"
    )))?;
    let ebpf = Arc::new(Mutex::new(ebpf));

    // 初始化 eBPF 日志
    {
        let mut ebpf = ebpf.lock().await;
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => warn!("eBPF logger 初始化失败: {e}"),
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

    // 附加 XDP 程序（入站）
    {
        let mut ebpf = ebpf.lock().await;
        let xdp_flags = match cli.xdp_mode.to_lowercase().as_str() {
            "skb" => XdpFlags::SKB_MODE,
            "drv" | "driver" => XdpFlags::DRV_MODE,
            "hw" | "hardware" => XdpFlags::HW_MODE,
            _ => XdpFlags::default(),
        };
        let program: &mut Xdp = ebpf.program_mut("rfw").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&cli.iface, xdp_flags)
            .context(format!("XDP 附加失败: {}", cli.iface))?;
        info!("XDP 程序已附加到接口: {}", cli.iface);

        // 附加 TC 程序（出站）
        let tc_program: &mut SchedClassifier =
            ebpf.program_mut("rfw_egress").unwrap().try_into()?;
        tc_program.load()?;
        if let Err(e) = tc_program.attach(&cli.iface, TcAttachType::Egress) {
            warn!("TC egress 附加失败: {}", e);
        } else {
            info!("TC egress 程序已附加到接口: {}", cli.iface);
        }
    }

    let app_state = AppState {
        ebpf: ebpf.clone(),
        iface: cli.iface.clone(),
        rules: Arc::new(Mutex::new(RulesState {
            entries: Vec::new(),
            next_id: 0,
        })),
    };

    tokio::spawn({
        let api_addr = cli.api_addr.clone();
        let state = app_state.clone();
        async move {
            if let Err(e) = start_api(&api_addr, state).await {
                warn!("API 服务失败: {}", e);
            }
        }
    });

    println!("防火墙运行中，按 Ctrl-C 退出...");
    println!("API 地址: http://{}", cli.api_addr);

    signal::ctrl_c().await?;
    println!("退出中...");
    Ok(())
}
