use anyhow::Context as _;
use aya::maps::{Array, HashMap as AyaHashMap, LpmTrie};
use aya::programs::{Xdp, XdpFlags};
use clap::{Parser, Subcommand};
#[rustfmt::skip]
use log::{debug, info, warn};
use rfw_common::{PortAccessKey, PortAccessStats};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use tokio::signal;

// GeoIP 数据JSON结构
#[derive(Debug, Deserialize)]
struct GeoIpData {
    rules: Vec<GeoIpRule>,
}

#[derive(Debug, Deserialize)]
struct GeoIpRule {
    ip_cidr: Vec<String>,
}

// 从 URL 下载并解析指定国家的 GeoIP 数据
async fn fetch_geoip_data(country_code: &str) -> anyhow::Result<GeoIpData> {
    const GEOIP_URL_TEMPLATE: &str = "https://raw.githubusercontent.com/lyc8503/sing-box-rules/refs/heads/rule-set-geoip/geoip-{}.json";

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

    let geo_data: GeoIpData = response.json().await?;

    // 统计总的 CIDR 条目数
    let total_cidrs: usize = geo_data.rules.iter().map(|r| r.ip_cidr.len()).sum();
    info!(
        "成功下载并解析 {} 的 {} 个 IP CIDR 前缀",
        country_code.to_uppercase(),
        total_cidrs
    );

    Ok(geo_data)
}

// 批量下载多个国家的 GeoIP 数据
async fn fetch_multiple_geoip_data(
    country_codes: &[String],
) -> anyhow::Result<Vec<(String, GeoIpData)>> {
    let mut results = Vec::new();

    for code in country_codes {
        let code_upper = code.to_uppercase();
        match fetch_geoip_data(&code_upper).await {
            Ok(data) => {
                results.push((code_upper.clone(), data));
            }
            Err(e) => {
                warn!("获取 {} 的 GeoIP 数据失败: {}", code_upper, e);
                // 继续处理其他国家,不中断
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

    // 解析 IP 地址
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

    // 解析前缀长度
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }

    // 计算网络掩码
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };

    // 计算网络地址（应用掩码）
    let network_ip = ip & mask;

    // 返回网络地址和前缀长度
    Some((network_ip, prefix_len))
}

fn run_stats(opt: StatsOpt) -> anyhow::Result<()> {
    //  使用 reuse_pinned_maps 加载 eBPF，以便访问已 pin 的 map
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(
            "PORT_ACCESS_LOG",
            std::path::Path::new("/sys/fs/bpf/rfw_port_access_log"),
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/rfw"
        )))
        .context("无法加载 eBPF 程序")?;

    let port_access_map: AyaHashMap<_, PortAccessKey, PortAccessStats> = ebpf
        .take_map("PORT_ACCESS_LOG")
        .context("无法找到 PORT_ACCESS_LOG map，请确保 rfw 正在运行并启用了 --log-port-access")?
        .try_into()?;

    // 读取所有记录
    let mut records: Vec<(PortAccessKey, PortAccessStats)> = Vec::new();

    for item in port_access_map.iter() {
        let (key, stats) = item?;

        // 应用过滤
        if let Some(port_filter) = opt.port {
            if key.dst_port != port_filter {
                continue;
            }
        }

        if let Some(ref ip_filter) = opt.ip {
            let ip: Ipv4Addr = ip_filter.parse()?;
            if key.src_ip != u32::from(ip).to_be() {
                continue;
            }
        }

        if opt.blocked_only && stats.blocked_count == 0 {
            continue;
        }

        if opt.allowed_only && stats.allowed_count == 0 {
            continue;
        }

        records.push((key, stats));
    }

    if records.is_empty() {
        println!("没有找到匹配的访问记录");
        println!("提示: 请确保 rfw 使用 --log-port-access 参数运行");
        return Ok(());
    }

    // 排序：优先显示阻断最多的
    records.sort_by(|a, b| {
        b.1.blocked_count
            .cmp(&a.1.blocked_count)
            .then_with(|| b.1.allowed_count.cmp(&a.1.allowed_count))
    });

    let total_count = records.len();

    if opt.group_by_port {
        // 按端口分组显示
        let mut port_groups: BTreeMap<(u16, u8), Vec<(PortAccessKey, PortAccessStats)>> =
            BTreeMap::new();
        for (key, stats) in records {
            port_groups
                .entry((key.dst_port, key.protocol))
                .or_insert_with(Vec::new)
                .push((key, stats));
        }

        for ((port, protocol), entries) in port_groups {
            let protocol_name = if protocol == 6 { "TCP" } else { "UDP" };
            println!("\nPort {}/{}", port, protocol_name);
            println!(
                "{:<16} {:>12} {:>12} {:>12}",
                "Source IP", "Allowed", "Blocked", "Total"
            );
            println!("{}", "-".repeat(56));

            for (key, stats) in entries {
                let src_ip = Ipv4Addr::from(u32::from_be(key.src_ip));
                let total = stats.allowed_count + stats.blocked_count;
                println!(
                    "{:<16} {:>12} {:>12} {:>12}",
                    src_ip.to_string(), stats.allowed_count, stats.blocked_count, total
                );
            }
        }
    } else {
        // 列表显示
        println!(
            "{:<16} {:<8} {:>8} {:>12} {:>12} {:>12}",
            "Source IP", "Proto", "Port", "Allowed", "Blocked", "Total"
        );
        println!("{}", "-".repeat(72));

        for (key, stats) in records {
            let src_ip = Ipv4Addr::from(u32::from_be(key.src_ip));
            let protocol_name = if key.protocol == 6 { "TCP" } else { "UDP" };
            let total = stats.allowed_count + stats.blocked_count;

            println!(
                "{:<16} {:<8} {:>8} {:>12} {:>12} {:>12}",
                src_ip.to_string(),
                protocol_name,
                key.dst_port,
                stats.allowed_count,
                stats.blocked_count,
                total
            );
        }
    }

    println!("\nTotal records: {}", total_count);

    Ok(())
}

#[derive(Debug, Parser)]
#[clap(name = "rfw", version, about = "基于 eBPF/XDP 的高性能防火墙")]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,

    #[clap(flatten)]
    run_opts: RunOpt,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// 查看端口访问统计
    Stats(StatsOpt),
}

#[derive(Debug, Parser)]
struct StatsOpt {
    /// 按端口号过滤
    #[clap(short, long)]
    port: Option<u16>,

    /// 按源 IP 地址过滤
    #[clap(short, long)]
    ip: Option<String>,

    /// 只显示被阻断的访问
    #[clap(long)]
    blocked_only: bool,

    /// 只显示被允许的访问
    #[clap(long)]
    allowed_only: bool,

    /// 按端口分组显示
    #[clap(short, long)]
    group_by_port: bool,
}

#[derive(Debug, Parser)]
struct RunOpt {
    /// 网络接口名称（如 eth0, ens33, wlan0）
    ///
    /// 使用 'ip link' 或 'ifconfig' 查看可用接口
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// GeoIP 国家代码列表(逗号分隔,如: CN,RU,KP)
    ///
    /// 指定要过滤的国家,与协议规则配合使用
    /// 例如: --countries CN,RU --block-http
    /// 不指定则协议规则应用于所有流量
    #[clap(long, value_delimiter = ',')]
    countries: Vec<String>,

    /// 白名单国家代码列表(逗号分隔)
    ///
    /// 只允许来自这些国家的流量,阻止其他所有国家
    /// 例如: --allow-only-countries US,JP,KR
    /// 与 --countries 互斥
    #[clap(long, value_delimiter = ',', conflicts_with = "countries")]
    allow_only_countries: Vec<String>,

    /// 快捷方式: 阻止指定国家的所有入站流量
    ///
    /// 等价于: --countries X --block-all
    /// 例如: --block-all-from CN,RU
    #[clap(long, value_delimiter = ',', conflicts_with = "countries")]
    block_all_from: Vec<String>,

    /// 屏蔽发送邮件流量
    ///
    /// 仅阻止 SMTP 发送端口: 25, 587 (STARTTLS), 465 (SMTPS), 2525
    /// 允许接收邮件: POP3 (110, 995), IMAP (143, 993)
    ///
    /// 用途: 防止服务器被滥用发送垃圾邮件
    #[clap(long)]
    block_email: bool,

    /// 屏蔽 HTTP/HTTPS 入站连接
    ///
    /// 使用协议深度检测识别 HTTP 请求（GET/POST/HEAD/PUT 等）
    /// 配合 --countries 限定国家,或不指定则应用于所有流量
    ///
    /// 注意: 仅检测入站流量，不影响出站访问
    #[clap(long)]
    block_http: bool,

    /// 屏蔽 SOCKS5 代理入站连接
    ///
    /// 检测 SOCKS5 握手协议特征
    /// 配合 --countries 限定国家,或不指定则应用于所有流量
    #[clap(long)]
    block_socks5: bool,

    /// 屏蔽全加密流量 (FET) - 严格模式
    ///
    /// 基于 GFW 研究论文的检测算法:
    /// - 熵值检测 (popcount 3.4-4.6)
    /// - 可打印字符检测
    /// - TLS/HTTP 协议豁免
    ///
    /// 严格模式: 不满足豁免条件的流量默认【阻止】
    /// 适用于: 高安全要求场景，可能误判少量合法流量
    ///
    /// 参考: https://gfw.report/publications/usenixsecurity23/
    #[clap(long, conflicts_with = "block_fet_loose")]
    block_fet_strict: bool,

    /// 屏蔽全加密流量 (FET) - 宽松模式
    ///
    /// 使用与严格模式相同的检测算法，但:
    /// 宽松模式: 不满足豁免条件的流量默认【放过】
    /// 适用于: 平衡安全与可用性，降低误判率
    ///
    /// 建议: 先使用宽松模式测试，观察日志后决定是否切换严格模式
    #[clap(long, conflicts_with = "block_fet_strict")]
    block_fet_loose: bool,

    /// 屏蔽 WireGuard VPN 入站连接
    ///
    /// 检测 WireGuard 协议特征:
    /// - 握手消息 (type 1/2/3)
    /// - 数据包特征 (type 4)
    ///
    /// 配合 --countries 限定国家,或不指定则应用于所有流量
    #[clap(long)]
    block_wireguard: bool,

    /// 屏蔽 QUIC 协议入站连接
    ///
    /// 检测 QUIC 协议特征:
    /// - QUIC v1 (RFC 9000)
    /// - QUIC v2 (RFC 9369)
    /// - Google QUIC
    ///
    /// 配合 --countries 限定国家,或不指定则应用于所有流量
    #[clap(long)]
    block_quic: bool,

    /// 屏蔽所有入站流量（不限协议）
    ///
    /// 最激进的规则，直接在 IP 层阻止所有入站连接
    /// 配合 --countries 限定国家,或不指定则应用于所有流量
    ///
    /// 警告: 启用此规则会使所有其他协议检测规则失效
    #[clap(long)]
    block_all: bool,

    /// XDP 附加模式
    ///
    /// - auto: 自动选择最佳模式(默认)
    /// - skb: SKB 模式 - 兼容性最好,适用于所有网卡,但性能较低
    /// - drv: 驱动模式 - 需要网卡驱动支持,性能较高
    /// - hw: 硬件模式 - 需要网卡硬件支持,性能最高
    ///
    /// 如果默认模式附加失败,请尝试使用 --xdp-mode skb
    #[clap(long, default_value = "auto")]
    xdp_mode: String,

    /// 记录端口访问日志
    ///
    /// 启用后会记录所有端口被哪些 IP 访问，以及是否被阻断
    /// 可以使用 `rfw-stats` 命令查看统计信息
    #[clap(long)]
    log_port_access: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // 处理子命令
    match cli.command {
        Some(Commands::Stats(stats_opt)) => run_stats(stats_opt),
        None => run_firewall(cli.run_opts).await,
    }
}

async fn run_firewall(opt: RunOpt) -> anyhow::Result<()> {
    // 只有真正运行程序时才初始化日志和 eBPF
    env_logger::init();

    // 简化参数处理
    let (opt_http, opt_socks5, opt_fet_strict, opt_fet_loose, opt_wg, opt_quic, opt_all) = (
        opt.block_http,
        opt.block_socks5,
        opt.block_fet_strict,
        opt.block_fet_loose,
        opt.block_wireguard,
        opt.block_quic,
        opt.block_all,
    );

    // 处理国家列表配置
    let mut target_countries = Vec::new();
    let mut whitelist_mode = false;

    if !opt.block_all_from.is_empty() {
        target_countries = opt.block_all_from.clone();
        info!("使用快捷模式: 阻止来自 {:?} 的所有流量", target_countries);
    } else if !opt.allow_only_countries.is_empty() {
        target_countries = opt.allow_only_countries.clone();
        whitelist_mode = true;
        info!("使用白名单模式: 仅允许来自 {:?} 的流量", target_countries);
    } else if !opt.countries.is_empty() {
        target_countries = opt.countries.clone();
        info!("GeoIP 过滤国家: {:?}", target_countries);
    }

    // 检查是否至少启用了一个规则
    if !opt.block_email
        && !opt_http
        && !opt_socks5
        && !opt_fet_strict
        && !opt_fet_loose
        && !opt_wg
        && !opt_quic
        && !opt_all
    {
        println!("警告: 未启用任何防火墙规则，程序将运行但不执行任何过滤操作");
        println!("使用 'rfw --help' 查看可用规则列表");
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rfw"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
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
    // 配置防火墙规则
    let mut config_flags: u32 = 0;

    if opt.block_email {
        config_flags |= rfw_common::RULE_BLOCK_EMAIL;
        info!("启用规则: 屏蔽发送 Email");
    }

    // 如果指定了国家,启用 GeoIP 过滤
    if !target_countries.is_empty() {
        config_flags |= rfw_common::RULE_GEOIP_ENABLED;
        if whitelist_mode {
            config_flags |= rfw_common::RULE_GEOIP_WHITELIST;
        }
    }

    if opt_http {
        config_flags |= rfw_common::RULE_BLOCK_HTTP;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!("启用规则: 屏蔽 {} 的 HTTP 入站", scope);
    }

    if opt_socks5 {
        config_flags |= rfw_common::RULE_BLOCK_SOCKS5;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!("启用规则: 屏蔽 {} 的 SOCKS5 入站", scope);
    }

    if opt_fet_strict {
        config_flags |= rfw_common::RULE_BLOCK_FET_STRICT;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!(
            "启用规则: 屏蔽 {} 的全加密流量入站 (严格模式 - 默认阻止)",
            scope
        );
    }

    if opt_fet_loose {
        config_flags |= rfw_common::RULE_BLOCK_FET_LOOSE;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!(
            "启用规则: 屏蔽 {} 的全加密流量入站 (宽松模式 - 默认放过)",
            scope
        );
    }

    if opt_wg {
        config_flags |= rfw_common::RULE_BLOCK_WIREGUARD;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!("启用规则: 屏蔽 {} 的 WireGuard VPN 入站", scope);
    }

    if opt_quic {
        config_flags |= rfw_common::RULE_BLOCK_QUIC;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!("启用规则: 屏蔽 {} 的 QUIC 入站", scope);
    }

    if opt_all {
        config_flags |= rfw_common::RULE_BLOCK_ALL;
        let scope = if target_countries.is_empty() {
            "所有来源".to_string()
        } else {
            format!("{:?} 国家", target_countries)
        };
        info!("启用规则: 屏蔽 {} 的所有入站流量", scope);
    }

    if opt.log_port_access {
        config_flags |= rfw_common::RULE_LOG_PORT_ACCESS;
        info!("启用规则: 记录端口访问日志");

        // Pin PORT_ACCESS_LOG map 到 bpffs 以便其他进程访问
        let port_access_map = ebpf
            .map("PORT_ACCESS_LOG")
            .context("无法找到 PORT_ACCESS_LOG map")?;
        port_access_map
            .pin("/sys/fs/bpf/rfw_port_access_log")
            .context("无法 pin PORT_ACCESS_LOG map，请确保 /sys/fs/bpf 已挂载且有写权限")?;
        info!("已将端口访问日志 map pin 到 /sys/fs/bpf/rfw_port_access_log");
    }

    // 将配置写入 eBPF map
    let mut config_map: Array<_, u32> = ebpf.map_mut("CONFIG").unwrap().try_into()?;
    config_map.set(0, config_flags, 0)?;
    info!("防火墙配置已设置: flags = 0x{:x}", config_flags);

    // 如果需要 GeoIP 规则，从网络下载 IP 段数据
    if !target_countries.is_empty() {
        info!(
            "检测到需要 GeoIP 规则，正在下载 {:?} 的 IP 数据...",
            target_countries
        );

        // 批量下载所有国家的 GeoIP 数据
        let geo_data_list = fetch_multiple_geoip_data(&target_countries)
            .await
            .context("下载 GeoIP 数据失败，请检查网络连接")?;

        // 使用 LpmTrie 进行高效的 IP 前缀匹配
        let mut geoip_map: LpmTrie<_, u32, u8> = ebpf.map_mut("GEOIP_MAP").unwrap().try_into()?;

        let mut loaded_count = 0;
        let mut insert_errors = 0;

        // 处理所有国家的数据
        for (country_code, geo_data) in geo_data_list {
            info!("正在加载 {} 的 IP 前缀...", country_code);

            for rule in &geo_data.rules {
                for cidr in &rule.ip_cidr {
                    // 解析 CIDR（如 "1.0.1.0/24"）
                    if let Some((ip, prefix_len)) = parse_cidr_to_lpm(cidr) {
                        // 构造 LpmTrie Key
                        // 注意：IP地址必须转换为网络字节序（大端）
                        let key = aya::maps::lpm_trie::Key::new(prefix_len, ip.to_be());

                        // 插入到 LpmTrie，value=1 表示匹配的IP
                        // 注意: 在当前实现中,所有国家共用同一个 map,value 统一为 1
                        // 未来可以扩展 value 存储国家代码
                        if let Err(e) = geoip_map.insert(&key, 1, 0) {
                            if insert_errors < 5 {
                                warn!(
                                    "插入 {} IP 前缀 {} (0x{:08x}/{}) 失败: {}",
                                    country_code, cidr, ip, prefix_len, e
                                );
                            }
                            insert_errors += 1;
                        } else {
                            loaded_count += 1;
                        }
                    }
                }
            }

            info!("已加载 {} 的 IP 前缀", country_code);
        }

        if insert_errors > 0 {
            warn!(
                "共有 {} 个IP前缀插入失败（可能是重复或map已满,最大容量 65536）",
                insert_errors
            );
        }

        info!(
            "成功加载 {} 个 IP 前缀到防火墙 (LpmTrie),覆盖国家: {:?}",
            loaded_count, target_countries
        );
    }

    let RunOpt {
        iface, xdp_mode, ..
    } = opt;

    // 根据用户选择确定 XDP 模式
    let xdp_flags = match xdp_mode.to_lowercase().as_str() {
        "skb" => {
            info!("使用 SKB 模式附加 XDP 程序 (兼容模式)");
            XdpFlags::SKB_MODE
        }
        "drv" | "driver" => {
            info!("使用驱动模式附加 XDP 程序 (需要驱动支持)");
            XdpFlags::DRV_MODE
        }
        "hw" | "hardware" => {
            info!("使用硬件模式附加 XDP 程序 (需要硬件支持)");
            XdpFlags::HW_MODE
        }
        "auto" => {
            info!("使用自动模式附加 XDP 程序");
            XdpFlags::default()
        }
        mode => {
            warn!("未知的 XDP 模式 '{}', 使用自动模式", mode);
            XdpFlags::default()
        }
    };

    let program: &mut Xdp = ebpf.program_mut("rfw").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, xdp_flags)
        .context(format!(
            "无法以 {} 模式附加 XDP 程序到接口 {}。\n提示: 如果附加失败，请尝试使用 --xdp-mode skb 选项",
            xdp_mode, iface
        ))?;

    info!("XDP 程序已成功附加到接口: {} (模式: {})", iface, xdp_mode);
    let ctrl_c = signal::ctrl_c();
    println!("防火墙运行中，按 Ctrl-C 退出...");
    ctrl_c.await?;
    println!("退出中...");

    // 清理 pinned map
    if opt.log_port_access {
        if let Err(e) = std::fs::remove_file("/sys/fs/bpf/rfw_port_access_log") {
            warn!("清理 pinned map 失败: {}", e);
        } else {
            info!("已清理端口访问日志 map");
        }
    }

    Ok(())
}
