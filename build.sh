#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔨 RFW 防火墙构建脚本${NC}"
echo "========================================="

# 确定目标架构
if [[ "$1" == "x86_64" ]]; then
    TARGET="x86_64-unknown-linux-musl"
    CC="x86_64-linux-musl-gcc"
    ARCH="x86_64"
elif [[ "$1" == "aarch64" || "$1" == "" ]]; then
    TARGET="aarch64-unknown-linux-musl"
    CC="aarch64-linux-musl-gcc"
    ARCH="aarch64"
else
    echo -e "${RED}❌ 无效的架构${NC}"
    echo "用法: $0 [x86_64|aarch64]"
    exit 1
fi

echo -e "${BLUE}📦 目标架构: $ARCH${NC}"
echo ""

# ===== 依赖检查和安装 =====
echo -e "${YELLOW}📋 检查依赖...${NC}"
echo ""

# 1. 检查 Homebrew（仅在 macOS）
if [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v brew &> /dev/null; then
        echo -e "${RED}❌ 未找到 Homebrew${NC}"
        echo -e "${YELLOW}💡 请先安装 Homebrew: https://brew.sh${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Homebrew 已安装${NC}"
fi

# 2. 检查/安装 Rust
if command -v rustc &> /dev/null; then
    echo -e "${GREEN}✅ Rust 已安装 ($(rustc --version))${NC}"
else
    echo -e "${YELLOW}📥 安装 Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    echo -e "${GREEN}✅ Rust 安装成功${NC}"
fi

# 3. 检查/安装 nightly 工具链
echo -e "${YELLOW}检查 Nightly 工具链...${NC}"
if rustup toolchain list | grep -q nightly; then
    echo -e "${GREEN}✅ Nightly 已安装${NC}"
else
    echo -e "${YELLOW}📥 安装 nightly...${NC}"
    rustup toolchain install nightly --component rust-src
    echo -e "${GREEN}✅ Nightly 安装成功${NC}"
fi

# 4. 检查/添加编译目标
for target in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
    if rustup target list | grep "^$target (installed)" > /dev/null; then
        echo -e "${GREEN}✅ $target 已安装${NC}"
    else
        echo -e "${YELLOW}📥 安装 $target...${NC}"
        rustup target add $target
        echo -e "${GREEN}✅ $target 安装成功${NC}"
    fi
done

# 5. Homebrew 包（仅在 macOS）
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${YELLOW}检查 LLVM...${NC}"
    if brew list llvm &>/dev/null; then
        echo -e "${GREEN}✅ LLVM 已安装${NC}"
    else
        echo -e "${YELLOW}📥 安装 LLVM...${NC}"
        brew install llvm
        echo -e "${GREEN}✅ LLVM 安装成功${NC}"
    fi

    echo -e "${YELLOW}检查 musl-cross...${NC}"
    if brew list musl-cross &>/dev/null; then
        echo -e "${GREEN}✅ musl-cross 已安装${NC}"
    else
        echo -e "${YELLOW}📥 安装 musl-cross...${NC}"
        brew tap FiloSottile/musl-cross
        brew install musl-cross
        echo -e "${GREEN}✅ musl-cross 安装成功${NC}"
    fi
fi

# 6. 检查/安装 bpf-linker
echo -e "${YELLOW}检查 bpf-linker...${NC}"
if command -v bpf-linker &> /dev/null; then
    echo -e "${GREEN}✅ bpf-linker 已安装 ($(bpf-linker --version 2>&1 | head -1))${NC}"
else
    echo -e "${YELLOW}📥 安装 bpf-linker...${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        cargo install bpf-linker --no-default-features
    else
        cargo install bpf-linker
    fi
    echo -e "${GREEN}✅ bpf-linker 安装成功${NC}"
fi

# 配置环境变量（仅在 macOS）
if [[ "$OSTYPE" == "darwin"* ]]; then
    export LLVM_HOME=$(brew --prefix llvm)
    export PATH="$LLVM_HOME/bin:$PATH"
fi

# 验证所有工具
echo ""
echo -e "${YELLOW}验证所有工具...${NC}"
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ $1 未找到${NC}"
        exit 1
    fi
}

check_tool "rustc"
check_tool "cargo"
check_tool "bpf-linker"
check_tool "$CC"

# ===== 编译 =====
echo ""
echo -e "${BLUE}🏗️  编译 RFW ($ARCH)...${NC}"
if CC=$CC cargo build --package rfw --release --target=$TARGET; then
    echo -e "${GREEN}✅ 编译成功${NC}"
else
    echo -e "${RED}❌ 编译失败${NC}"
    exit 1
fi

# ===== 验证输出 =====
OUTPUT_PATH="target/$TARGET/release/rfw"
if [ -f "$OUTPUT_PATH" ]; then
    SIZE=$(ls -lh "$OUTPUT_PATH" | awk '{print $5}')
    FILE_INFO=$(file "$OUTPUT_PATH")

    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}✅ 编译成功！${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${BLUE}📍 二进制位置:${NC} $(pwd)/$OUTPUT_PATH"
    echo -e "${BLUE}📊 文件大小:${NC} $SIZE"
    echo -e "${BLUE}📋 文件信息:${NC} $(echo $FILE_INFO | cut -d: -f2-)"
    echo ""
    echo -e "${BLUE}🚀 部署到 Linux 服务器:${NC}"
    echo "   scp $OUTPUT_PATH user@server:/tmp/"
    echo "   ssh user@server 'sudo /tmp/rfw --iface eth0 --api-addr 0.0.0.0:8080'"
    echo ""
    echo -e "${BLUE}🌐 验证防火墙:${NC}"
    echo "   curl http://server:8080/api/status"
    echo ""
else
    echo -e "${RED}❌ 编译失败 - 未找到输出文件${NC}"
    exit 1
fi
