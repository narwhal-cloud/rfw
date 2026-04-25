use anyhow::Context as _;
use std::mem::size_of;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{delete, get},
    Json, Router,
};
use aya::maps::{Array, LpmTrie, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use rfw_common::{
    BlockEvent, FirewallRule, ACTION_BLOCK, ACTION_PASS, DIR_IN, DIR_OUT, IP_TYPE_ANY,
    IP_TYPE_CIDR, IP_TYPE_GEOIP, MAX_RULES, PROTO_ALL, PROTO_FET, PROTO_HTTP, PROTO_SOCKS5,
    PROTO_TCP, PROTO_TLS, PROTO_UDP,
};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

// ========== GeoIP 数据获取 ==========

async fn download_geoip(country_code: &str) -> anyhow::Result<Vec<String>> {
    const GEOIP_URL_TEMPLATE: &str =
        "https://raw.githubusercontent.com/Loyalsoldier/geoip/refs/heads/release/text/{}.txt";

    let url = GEOIP_URL_TEMPLATE.replace("{}", &country_code.to_lowercase());
    info!("下载 GeoIP {} ...", country_code);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("下载 {} GeoIP 失败: HTTP {}", country_code, response.status());
    }

    let text = response.text().await?;
    let cidrs: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.contains(':')) // 只保留 IPv4
        .collect();

    info!("GeoIP {} 下载完成: {} 条前缀", country_code, cidrs.len());
    Ok(cidrs)
}

/// 加载单个国家的 GeoIP 数据：优先读本地缓存，缓存不存在时下载并写入缓存
async fn load_geoip_country(code: &str, geoip_dir: &str) -> anyhow::Result<Vec<String>> {
    let code = code.to_uppercase();
    let cache_path = format!("{}/{}.txt", geoip_dir, code);

    if let Ok(content) = std::fs::read_to_string(&cache_path) {
        let cidrs: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if !cidrs.is_empty() {
            info!("GeoIP {} 从缓存加载: {} 条前缀", code, cidrs.len());
            return Ok(cidrs);
        }
    }

    // 缓存不存在或为空，下载并写入缓存
    let cidrs = download_geoip(&code).await?;
    if let Err(e) = std::fs::write(&cache_path, cidrs.join("\n")) {
        warn!("GeoIP {} 写入缓存失败: {}", code, e);
    }
    Ok(cidrs)
}

async fn fetch_multiple_geoip(country_codes: &[String], geoip_dir: &str) -> anyhow::Result<Vec<String>> {
    let mut all_cidrs = Vec::new();
    for code in country_codes {
        match load_geoip_country(code, geoip_dir).await {
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
    Fet,
    All,
}

impl Protocol {
    fn to_u8(&self) -> u8 {
        match self {
            Self::Tcp => PROTO_TCP,
            Self::Udp => PROTO_UDP,
            Self::Http => PROTO_HTTP,
            Self::Socks5 => PROTO_SOCKS5,
            Self::Fet => PROTO_FET,
            Self::All => PROTO_ALL,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Fet => "fet",
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
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
    /// 当前写入 GEOIP_MAP 的所有 key (ip_be, prefix_len)，用于全量清除
    geoip_keys: Vec<(u32, u32)>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedEntry {
    id: u64,
    config: RuleConfig,
    // cached_cidrs 不再序列化，启动时根据 countries code 重新拉取
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedState {
    next_id: u64,
    entries: Vec<PersistedEntry>,
}

#[derive(Clone)]
struct AppState {
    ebpf: Arc<Mutex<Ebpf>>,
    iface: String,
    rules: Arc<Mutex<RulesState>>,
    rules_path: String,
    geoip_dir: String,
}

// ========== 持久化 ==========

fn rule_entry_from_persisted(p: PersistedEntry) -> RuleEntry {
    let (ip_type, src_ip, src_prefix_len) = match &p.config.ip_config {
        IpConfig::Any => (IP_TYPE_ANY, 0u32, 0u32),
        IpConfig::Cidr { ip } => match parse_cidr(ip) {
            Some((h, prefix)) => (IP_TYPE_CIDR, h.to_be(), prefix),
            None => (IP_TYPE_CIDR, 0, 0),
        },
        IpConfig::Geoip { .. } => (IP_TYPE_GEOIP, 0, 0),
    };
    let rule = FirewallRule {
        priority: p.config.priority,
        enabled: if p.config.enabled { 1 } else { 0 },
        direction: p.config.direction.to_u8(),
        protocol: p.config.protocol.to_u8(),
        action: p.config.action.to_u8(),
        port_start: p.config.port_start,
        port_end: p.config.port_end,
        ip_type,
        _padding: [0; 3],
        src_ip,
        src_prefix_len,
    };
    RuleEntry { id: p.id, rule, config: p.config, cached_cidrs: vec![] }
}

async fn refresh_geoip_caches(entries: &mut Vec<RuleEntry>, geoip_dir: &str) {
    for entry in entries.iter_mut() {
        if let IpConfig::Geoip { countries } = &entry.config.ip_config {
            if !countries.is_empty() {
                match fetch_multiple_geoip(countries, geoip_dir).await {
                    Ok(cidrs) => {
                        info!("GeoIP rule#{} 已拉取 {} 条前缀", entry.id, cidrs.len());
                        entry.cached_cidrs = cidrs;
                    }
                    Err(e) => warn!("GeoIP rule#{} 拉取失败: {}", entry.id, e),
                }
            }
        }
    }
}

fn save_rules(path: &str, state: &RulesState) {
    let persisted = PersistedState {
        next_id: state.next_id,
        entries: state.entries.iter().map(|e| PersistedEntry {
            id: e.id,
            config: e.config.clone(),
        }).collect(),
    };
    match serde_json::to_string(&persisted) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                warn!("规则持久化写入失败: {}", e);
            }
        }
        Err(e) => warn!("规则序列化失败: {}", e),
    }
}

fn load_rules(path: &str) -> RulesState {
    let json = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return RulesState { entries: Vec::new(), next_id: 0, geoip_keys: Vec::new() },
    };
    match serde_json::from_str::<PersistedState>(&json) {
        Ok(p) => RulesState {
            next_id: p.next_id,
            entries: p.entries.into_iter().map(rule_entry_from_persisted).collect(),
            geoip_keys: Vec::new(),
        },
        Err(e) => {
            warn!("规则文件解析失败，使用空规则: {}", e);
            RulesState { entries: Vec::new(), next_id: 0, geoip_keys: Vec::new() }
        }
    }
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


fn update_geoip(ebpf: &mut Ebpf, state: &mut RulesState) -> anyhow::Result<()> {
    let mut geoip_map: LpmTrie<_, u32, u8> = ebpf
        .map_mut("GEOIP_MAP")
        .context("GEOIP_MAP not found")?
        .try_into()?;

    // 全量清除上次写入的 key
    for (ip_be, prefix_len) in state.geoip_keys.drain(..) {
        let key = aya::maps::lpm_trie::Key::new(prefix_len, ip_be);
        let _ = geoip_map.remove(&key);
    }

    // 合并所有 GeoIP 规则，只写 IPv4，去重
    let mut seen = std::collections::HashSet::new();
    for entry in &state.entries {
        if entry.rule.ip_type != IP_TYPE_GEOIP {
            continue;
        }
        for cidr in &entry.cached_cidrs {
            if let Some((ip_host, prefix_len)) = parse_cidr(cidr) {
                let ip_be = ip_host.to_be();
                if seen.insert((ip_be, prefix_len)) {
                    let key = aya::maps::lpm_trie::Key::new(prefix_len, ip_be);
                    if geoip_map.insert(&key, 1, 0).is_ok() {
                        state.geoip_keys.push((ip_be, prefix_len));
                    }
                }
            }
        }
    }

    info!("GEOIP_MAP 已更新: {} 条 IPv4 前缀", state.geoip_keys.len());
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

// ========== 通用错误响应 ==========

#[derive(serde::Serialize)]
struct ErrResp {
    error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> axum::response::Response {
    (status, Json(ErrResp { error: msg.into() })).into_response()
}

// ========== 静态资源 ==========

static INDEX_HTML: &str = include_str!("index.html");

async fn serve_index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

// ========== API Handlers ==========

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state.rules.lock().await;
    Json(StatusResponse {
        iface: state.iface.clone(),
        api_version: "0.1.0",
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
                None => return err(StatusCode::BAD_REQUEST, "Invalid CIDR format"),
            };
            (IP_TYPE_CIDR, ip_host.to_be(), prefix_len, vec![])
        }
        IpConfig::Geoip { countries } => {
            if countries.is_empty() {
                return err(StatusCode::BAD_REQUEST, "countries list cannot be empty");
            }
            let cidrs = match fetch_multiple_geoip(countries, &state.geoip_dir).await {
                Ok(c) => c,
                Err(e) => {
                    return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
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
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    if let Err(e) = update_geoip(&mut ebpf, &mut rules_guard) {
        warn!("更新 GeoIP map 失败: {}", e);
    }

    info!("规则已创建: id={} priority={}", id, req.priority);
    save_rules(&state.rules_path, &rules_guard);
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
        None => return err(StatusCode::NOT_FOUND, "Rule not found"),
        Some(i) => {
            rules_guard.entries.remove(i);
        }
    }

    let mut ebpf = state.ebpf.lock().await;
    if let Err(e) = sync_rules(&mut ebpf, &rules_guard.entries) {
        warn!("同步规则失败: {}", e);
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    if let Err(e) = update_geoip(&mut ebpf, &mut rules_guard) {
        warn!("更新 GeoIP map 失败: {}", e);
    }

    info!("规则已删除: id={}", id);
    save_rules(&state.rules_path, &rules_guard);
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

    /// 规则持久化文件路径
    #[clap(long, default_value = "rfw.json")]
    rules_file: String,

    /// GeoIP 缓存目录
    #[clap(long, default_value = "geoip")]
    geoip_dir: String,
}

// ========== 启动 ==========

async fn start_api(addr: &str, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rfw"
    )))?;
    // 取出 RingBuf map，启动阻断事件日志任务
    let block_events_map = ebpf.take_map("BLOCK_EVENTS");
    let ebpf = Arc::new(Mutex::new(ebpf));

    if let Some(map) = block_events_map {
        match RingBuf::try_from(map) {
            Ok(ring) => { tokio::spawn(drain_block_events(ring)); }
            Err(e) => warn!("RingBuf init failed: {e}"),
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
        let _ = tc::qdisc_add_clsact(&cli.iface); // 忽略"已存在"错误
        let tc_program: &mut SchedClassifier =
            ebpf.program_mut("rfw_egress").unwrap().try_into()?;
        tc_program.load()?;
        if let Err(e) = tc_program.attach(&cli.iface, TcAttachType::Egress) {
            warn!("TC egress 附加失败: {}", e);
        } else {
            info!("TC egress 程序已附加到接口: {}", cli.iface);
        }
    }

    // 启动时清空 GeoIP 缓存目录，确保每次拉取最新数据
    if std::path::Path::new(&cli.geoip_dir).exists() {
        if let Ok(rd) = std::fs::read_dir(&cli.geoip_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("txt") {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    if let Err(e) = std::fs::create_dir_all(&cli.geoip_dir) {
        warn!("创建 GeoIP 缓存目录失败: {}", e);
    }

    let mut initial_rules = load_rules(&cli.rules_file);
    if !initial_rules.entries.is_empty() {
        // GeoIP 规则只持久化 country code，启动时重新拉取 CIDR（优先读本地缓存）
        refresh_geoip_caches(&mut initial_rules.entries, &cli.geoip_dir).await;
        let mut ebpf_guard = ebpf.lock().await;
        if let Err(e) = sync_rules(&mut ebpf_guard, &initial_rules.entries) {
            warn!("加载持久化规则到 eBPF 失败: {}", e);
        }
        if let Err(e) = update_geoip(&mut ebpf_guard, &mut initial_rules) {
            warn!("加载持久化 GeoIP 规则失败: {}", e);
        }
        info!("已加载 {} 条持久化规则", initial_rules.entries.len());
    }

    let app_state = AppState {
        ebpf: ebpf.clone(),
        iface: cli.iface.clone(),
        rules: Arc::new(Mutex::new(initial_rules)),
        rules_path: cli.rules_file.clone(),
        geoip_dir: cli.geoip_dir.clone(),
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

async fn drain_block_events(mut ring: RingBuf<aya::maps::MapData>) {
    use std::net::Ipv4Addr;
    use std::os::fd::AsFd;
    use tokio::io::unix::AsyncFd;

    let fd = match AsyncFd::new(ring.as_fd().try_clone_to_owned().unwrap()) {
        Ok(f) => f,
        Err(e) => { warn!("block_events AsyncFd: {e}"); return; }
    };

    loop {
        match fd.readable().await {
            Err(e) => { warn!("block_events poll: {e}"); break; }
            Ok(mut guard) => {
                guard.clear_ready();
                while let Some(item) = ring.next() {
                    if item.len() < size_of::<BlockEvent>() { continue; }
                    let ev = unsafe { &*(item.as_ptr() as *const BlockEvent) };
                    let dir = if ev.direction == DIR_IN { "IN " } else { "OUT" };
                    let app = match ev.app_proto {
                        PROTO_FET    => "FET",
                        PROTO_HTTP   => "HTTP",
                        PROTO_TLS    => "TLS",
                        PROTO_SOCKS5 => "SOCKS5",
                        _            => "-",
                    };
                    let l4 = match ev.protocol {
                        6  => "TCP",
                        17 => "UDP",
                        _  => "?",
                    };
                    let verdict = if ev.action == ACTION_BLOCK { "BLOCK" } else { "PASS " };
                    let rule_info = if ev.rule_idx as u32 == MAX_RULES {
                        "no-rule".to_string()
                    } else {
                        format!("rule={}", ev.rule_idx)
                    };
                    info!("[{} {}] {}:{} -> {}:{} l4={} app={} {}",
                        verdict, dir,
                        Ipv4Addr::from(u32::from_be(ev.src_ip)), ev.src_port,
                        Ipv4Addr::from(u32::from_be(ev.dst_ip)), ev.dst_port,
                        l4, app, rule_info);
                }
            }
        }
    }
}
