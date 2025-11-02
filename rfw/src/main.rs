use anyhow::Context as _;
use aya::maps::{Array, LpmTrie};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use serde::Deserialize;
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

// 从 URL 下载并解析 GeoIP 数据
async fn fetch_geoip_data() -> anyhow::Result<GeoIpData> {
    const GEOIP_URL: &str = "https://raw.githubusercontent.com/lyc8503/sing-box-rules/refs/heads/rule-set-geoip/geoip-cn.json";

    info!("正在从 {} 下载中国 GeoIP 数据...", GEOIP_URL);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(GEOIP_URL).send().await?;
    let geo_data: GeoIpData = response.json().await?;

    // 统计总的 CIDR 条目数
    let total_cidrs: usize = geo_data.rules.iter().map(|r| r.ip_cidr.len()).sum();
    info!("成功下载并解析 {} 个中国 IP CIDR 前缀", total_cidrs);

    Ok(geo_data)
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

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// 屏蔽发送 email (仅阻止 SMTP: 25/587/465/2525，允许接收 POP3/IMAP)
    #[clap(long)]
    block_email: bool,

    /// 屏蔽来自中国的 HTTP 入站流量 (端口: 80, 443)
    #[clap(long)]
    block_cn_http: bool,

    /// 屏蔽来自中国的 SOCKS5 入站流量 (端口: 1080)
    #[clap(long)]
    block_cn_socks5: bool,

    /// 屏蔽来自中国的全加密流量 (Fully Encrypted Traffic) 入站 - 严格模式
    /// 严格模式：不满足豁免条件的流量默认阻止
    #[clap(long)]
    block_cn_fet_strict: bool,

    /// 屏蔽来自中国的全加密流量 (Fully Encrypted Traffic) 入站 - 宽松模式
    /// 宽松模式：不满足豁免条件的流量默认放过（降低误判）
    #[clap(long)]
    block_cn_fet_loose: bool,

    /// 屏蔽来自中国的 WireGuard VPN 入站
    #[clap(long)]
    block_cn_wg: bool,

    /// 屏蔽来自中国的所有入站流量（不限协议）
    #[clap(long)]
    block_cn_all: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

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
    if opt.block_cn_http {
        config_flags |= rfw_common::RULE_BLOCK_CN_HTTP;
        info!("启用规则: 屏蔽中国 IP 的 HTTP 入站");
    }
    if opt.block_cn_socks5 {
        config_flags |= rfw_common::RULE_BLOCK_CN_SOCKS5;
        info!("启用规则: 屏蔽中国 IP 的 SOCKS5 入站");
    }
    if opt.block_cn_fet_strict {
        config_flags |= rfw_common::RULE_BLOCK_CN_FET_STRICT;
        info!("启用规则: 屏蔽中国 IP 的全加密流量入站 (严格模式 - 默认阻止)");
    }
    if opt.block_cn_fet_loose {
        config_flags |= rfw_common::RULE_BLOCK_CN_FET_LOOSE;
        info!("启用规则: 屏蔽中国 IP 的全加密流量入站 (宽松模式 - 默认放过)");
    }
    if opt.block_cn_wg {
        config_flags |= rfw_common::RULE_BLOCK_CN_WIREGUARD;
        info!("启用规则: 屏蔽中国 IP 的 WireGuard VPN 入站");
    }
    if opt.block_cn_all {
        config_flags |= rfw_common::RULE_BLOCK_CN_ALL;
        info!("启用规则: 屏蔽中国 IP 的所有入站流量");
    }

    // 将配置写入 eBPF map
    let mut config_map: Array<_, u32> = ebpf.map_mut("CONFIG").unwrap().try_into()?;
    config_map.set(0, config_flags, 0)?;
    info!("防火墙配置已设置: flags = 0x{:x}", config_flags);

    // 如果需要 GeoIP 规则，从网络下载中国 IP 段数据
    if opt.block_cn_http
        || opt.block_cn_socks5
        || opt.block_cn_fet_strict
        || opt.block_cn_fet_loose
        || opt.block_cn_wg
        || opt.block_cn_all
    {
        info!("检测到需要 GeoIP 规则，正在下载中国 IP 数据...");

        // 下载并解析 GeoIP 数据
        let geo_data = fetch_geoip_data()
            .await
            .context("下载 GeoIP 数据失败，请检查网络连接")?;

        // 使用 LpmTrie 进行高效的 IP 前缀匹配
        let mut geoip_map: LpmTrie<_, u32, u8> = ebpf.map_mut("GEOIP_CN").unwrap().try_into()?;

        // 将所有 CIDR 前缀加载到 LpmTrie（支持最多 65536 个条目）
        let max_entries = 65536.min(geo_data.rules.len());
        let mut loaded_count = 0;

        let mut insert_errors = 0;
        for rule in geo_data.rules.iter().take(max_entries) {
            for cidr in &rule.ip_cidr {
                // 解析 CIDR（如 "1.0.1.0/24"）
                if let Some((ip, prefix_len)) = parse_cidr_to_lpm(cidr) {
                    // 构造 LpmTrie Key
                    // 注意：IP地址必须转换为网络字节序（大端）
                    let key = aya::maps::lpm_trie::Key::new(prefix_len, ip.to_be());

                    // 插入到 LpmTrie，value=1 表示中国IP
                    if let Err(e) = geoip_map.insert(&key, 1, 0) {
                        if insert_errors < 5 {
                            warn!(
                                "插入 IP 前缀 {} (0x{:08x}/{}) 失败: {}",
                                cidr, ip, prefix_len, e
                            );
                        }
                        insert_errors += 1;
                    } else {
                        loaded_count += 1;
                    }
                }
            }
        }

        if insert_errors > 0 {
            warn!(
                "共有 {} 个IP前缀插入失败（可能是重复或map已满）",
                insert_errors
            );
        }

        if geo_data.rules.len() > max_entries {
            warn!(
                "GeoIP 数据包含 {} 条规则，但 eBPF map 仅处理了前 {} 条",
                geo_data.rules.len(),
                max_entries
            );
        }

        info!("成功加载 {} 个中国 IP 前缀到防火墙 (LpmTrie)", loaded_count);
    }

    let Opt { iface, .. } = opt;
    let program: &mut Xdp = ebpf.program_mut("rfw").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("XDP 程序已附加到接口: {}", iface);
    let ctrl_c = signal::ctrl_c();
    println!("防火墙运行中，按 Ctrl-C 退出...");
    ctrl_c.await?;
    println!("退出中...");

    Ok(())
}
