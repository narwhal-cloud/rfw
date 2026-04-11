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
    IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL, PROTO_HTTP, PROTO_SOCKS5, PROTO_TCP, PROTO_UDP,
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

// ========== API Types & Enums ==========

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Direction {
    In,
    Out,
}

impl Direction {
    fn to_u8(&self) -> u8 {
        match self {
            Self::In => DIR_IN,
            Self::Out => DIR_OUT,
        }
    }
    fn from_u8(v: u8) -> Self {
        if v == DIR_OUT { Self::Out } else { Self::In }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Tcp,
    Udp,
    Http,
    Socks5,
    All,
}

impl Protocol {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Tcp => PROTO_TCP,
            Self::Udp => PROTO_UDP,
            Self::Http => PROTO_HTTP,
            Self::Socks5 => PROTO_SOCKS5,
            Self::All => PROTO_ALL,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            PROTO_TCP => Self::Tcp,
            PROTO_UDP => Self::Udp,
            PROTO_HTTP => Self::Http,
            PROTO_SOCKS5 => Self::Socks5,
            _ => Self::All,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::All => "all",
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Action {
    Block,
    Pass,
}

impl Action {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Block => ACTION_BLOCK,
            Self::Pass => ACTION_PASS,
        }
    }
    fn from_u8(v: u8) -> Self {
        if v == ACTION_PASS { Self::Pass } else { Self::Block }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Pass => "pass",
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(tag = "ip_type", rename_all = "lowercase")]
enum IpConfig {
    Any,
    Cidr { ip: String },
    Geoip { countries: Vec<String> },
}

// ========== 状态 ==========

struct RuleEntry {
    id: u64,
    rule: FirewallRule,
    // 原始配置信息，用于展示和重建缓存
    config: RuleConfig,
    // GeoIP 规则缓存的 CIDR 列表
    cached_cidrs: Vec<String>,
}

#[derive(Clone, Debug)]
struct RuleConfig {
    priority: u32,
    enabled: bool,
    direction: Direction,
    protocol: Protocol,
    port_start: u16,
    port_end: u16,
    ip_config: IpConfig,
    action: Action,
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
    // 仅选择已启用的规则，并按优先级降序排列
    let mut active_entries: Vec<&RuleEntry> = entries
        .iter()
        .filter(|e| e.config.enabled)
        .collect();
    active_entries.sort_by(|a, b| b.config.priority.cmp(&a.config.priority));

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
        let rule = active_entries.get(i).map(|e| e.rule).unwrap_or(empty);
        rules_map.set(i as u32, rule, 0)?;
    }

    if active_entries.len() > MAX_RULES as usize {
        warn!(
            "活动规则数量 ({}) 超过了最大限制 ({})，超出部分将被忽略",
            active_entries.len(),
            MAX_RULES
        );
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
    direction: Direction,
    protocol: Protocol,
    port_start: u16,
    port_end: Option<u16>,
    #[serde(flatten)]
    ip_config: IpConfig,
    action: Action,
}

fn bool_true() -> bool {
    true
}

#[derive(serde::Serialize)]
struct RuleResponse {
    id: u64,
    priority: u32,
    enabled: bool,
    direction: &'static str,
    protocol: &'static str,
    port_start: u16,
    port_end: u16,
    #[serde(flatten)]
    ip_config: IpConfig,
    action: &'static str,
}

impl From<&RuleEntry> for RuleResponse {
    fn from(e: &RuleEntry) -> Self {
        RuleResponse {
            id: e.id,
            priority: e.config.priority,
            enabled: e.config.enabled,
            direction: e.config.direction.as_str(),
            protocol: e.config.protocol.as_str(),
            port_start: e.config.port_start,
            port_end: e.config.port_end,
            ip_config: e.config.ip_config.clone(),
            action: e.config.action.as_str(),
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
    let port_start = req.port_start;
    let port_end = req.port_end.unwrap_or(port_start);

    // 解析 IP 类型并获取必要数据
    let (ip_type, src_ip, src_prefix_len, cached_cidrs) = match &req.ip_config {
        IpConfig::Any => (IP_TYPE_ANY, 0u32, 0u32, vec![]),
        IpConfig::Cidr { ip } => {
            let (ip_host, prefix_len) = match parse_cidr(ip) {
                Some(x) => x,
                None => return (StatusCode::BAD_REQUEST, "Invalid CIDR format").into_response(),
            };
            (IP_TYPE_CIDR, ip_host.to_be(), prefix_len, vec![])
        }
        IpConfig::Geoip { countries } => {
            if countries.is_empty() {
                return (StatusCode::BAD_REQUEST, "countries list cannot be empty").into_response();
            }
            let cidrs = match fetch_multiple_geoip(countries).await {
                Ok(c) => c,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }
            };
            (IP_TYPE_GEOIP, 0u32, 0u32, cidrs)
        }
    };

    let config = RuleConfig {
        priority: req.priority,
        enabled: req.enabled,
        direction: req.direction,
        protocol: req.protocol,
        port_start,
        port_end,
        ip_config: req.ip_config.clone(),
        action: req.action,
    };

    let rule = FirewallRule {
        priority: config.priority,
        enabled: if config.enabled { 1 } else { 0 },
        direction: config.direction.to_u8(),
        protocol: config.protocol.to_u8(),
        action: config.action.to_u8(),
        port_start,
        port_end,
        ip_type,
        _padding: [0; 3],
        src_ip,
        src_prefix_len,
    };

    let mut rules_guard = state.rules.lock().await;
    rules_guard.next_id += 1;
    let id = rules_guard.next_id;

    rules_guard.entries.push(RuleEntry {
        id,
        rule,
        config,
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
    struct Resp {
        id: u64,
    }
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
