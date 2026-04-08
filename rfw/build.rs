use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use std::env;

fn main() -> anyhow::Result<()> {
    // 增加 BPF 栈大小限制以避免 "stack limit exceeded" 错误
    // BPF 默认栈大小是 512 字节，增加到 2048 字节
    unsafe {
        env::set_var("LLVMFLAGS", "-bpf-stack-size=2048");
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "rfw-ebpf")
        .ok_or_else(|| anyhow!("rfw-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        features: &[],
        no_default_features: false,
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
