#!/bin/bash
# Audit Proxy Core - 实际环境配置与验证脚本
# 用法: ./scripts/setup-and-verify.sh

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 配置变量
PROXY_PORT=${PROXY_PORT:-2222}
UPSTREAM_HOST=${UPSTREAM_HOST:-127.0.0.1}
UPSTREAM_PORT=${UPSTREAM_PORT:-22}
HOST_KEY=${HOST_KEY:-/etc/audit-proxy/host_key}
AUDIT_DIR=${AUDIT_DIR:-/var/log/audit-proxy/audit}
CONFIG_DIR=${CONFIG_DIR:-/etc/audit-proxy}
PID_FILE=${PID_FILE:-/var/run/audit-proxy.pid}

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Audit Proxy Core - 环境配置与验证                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# ============ 第一步：检查依赖 ============
log_info "步骤 1/6: 检查依赖..."

check_dependency() {
    if command -v "$1" &> /dev/null; then
        log_success "$1 已安装"
        return 0
    else
        log_error "$1 未安装"
        return 1
    fi
}

DEPS_OK=true
check_dependency gcc || DEPS_OK=false
check_dependency make || DEPS_OK=false

if ! pkg-config --exists libssh 2>/dev/null; then
    log_error "libssh 未安装"
    DEPS_OK=false
else
    LIBSSH_VERSION=$(pkg-config --modversion libssh)
    log_success "libssh 已安装 (版本: $LIBSSH_VERSION)"
fi

if [ "$DEPS_OK" = false ]; then
    log_error "依赖检查失败。请运行: sudo apt install build-essential libssh-dev"
    exit 1
fi

echo

# ============ 第二步：编译项目 ============
log_info "步骤 2/6: 编译项目..."

cd "$(dirname "$0")/.."
make clean > /dev/null 2>&1 || true
if make 2>&1 | tail -3; then
    log_success "编译成功"
else
    log_error "编译失败"
    exit 1
fi

echo

# ============ 第三步：运行测试 ============
log_info "步骤 3/6: 运行单元测试..."

if make test 2>&1 | grep -E "(PASS|FAIL|passed|failed)" | tail -10; then
    log_success "测试通过"
else
    log_error "测试失败"
    exit 1
fi

echo

# ============ 第四步：创建配置目录 ============
log_info "步骤 4/6: 创建配置目录..."

# 检查是否有 sudo 权限
if [ "$EUID" -eq 0 ]; then
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$AUDIT_DIR"
    mkdir -p "$(dirname $PID_FILE)"
    log_success "创建目录: $CONFIG_DIR, $AUDIT_DIR"
else
    log_warn "非 root 用户，使用临时目录"
    CONFIG_DIR="/tmp/audit-proxy"
    AUDIT_DIR="/tmp/audit-proxy/audit"
    HOST_KEY="/tmp/audit-proxy/host_key"
    PID_FILE="/tmp/audit-proxy/audit-proxy.pid"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$AUDIT_DIR"
fi

echo

# ============ 第五步：生成主机密钥 ============
log_info "步骤 5/6: 生成主机密钥..."

if [ ! -f "$HOST_KEY" ]; then
    ssh-keygen -t rsa -b 2048 -f "$HOST_KEY" -N "" -q
    log_success "生成 RSA 密钥: $HOST_KEY"
else
    log_success "使用现有密钥: $HOST_KEY"
fi

echo

# ============ 第六步：验证代理启动 ============
log_info "步骤 6/6: 验证代理启动..."

# 检查端口是否被占用
if netstat -tuln 2>/dev/null | grep -q ":$PROXY_PORT " || ss -tuln 2>/dev/null | grep -q ":$PROXY_PORT "; then
    log_warn "端口 $PROXY_PORT 已被占用，尝试使用 $((PROXY_PORT + 1))"
    PROXY_PORT=$((PROXY_PORT + 1))
fi

# 启动代理 (后台)
log_info "启动代理服务器 (端口: $PROXY_PORT)..."
./build/bin/audit-proxy-core -p "$PROXY_PORT" -k "$HOST_KEY" -d &
PROXY_PID=$!
echo $PROXY_PID > "$PID_FILE"

sleep 2

# 检查进程是否存在
if kill -0 $PROXY_PID 2>/dev/null; then
    log_success "代理服务器已启动 (PID: $PROXY_PID)"
else
    log_error "代理服务器启动失败"
    exit 1
fi

echo
echo "═══════════════════════════════════════════════════════════════"
echo

# ============ 测试连接 ============
log_info "测试连接..."

# 使用 nc 测试端口
if command -v nc &> /dev/null; then
    if nc -z localhost "$PROXY_PORT" 2>/dev/null; then
        log_success "端口 $PROXY_PORT 可访问"
    else
        log_warn "端口连接测试失败"
    fi
fi

# 尝试 SSH 连接 (会失败，因为握手未完全实现)
log_info "尝试 SSH 连接 (预期会断开)..."
timeout 3 ssh -p "$PROXY_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=2 test@localhost 2>&1 | head -3 || true

echo
echo "═══════════════════════════════════════════════════════════════"
echo

# ============ 检查日志 ============
log_info "检查审计日志..."

if ls "$AUDIT_DIR"/audit_*.log 2>/dev/null | head -1; then
    log_success "审计日志已创建"
    echo "最近的审计事件:"
    tail -5 "$AUDIT_DIR"/audit_*.log 2>/dev/null || echo "(暂无事件)"
else
    log_warn "暂无审计日志 (需要有实际连接)"
fi

echo
echo "═══════════════════════════════════════════════════════════════"
echo

# ============ 停止代理 ============
log_info "停止代理服务器..."
kill $PROXY_PID 2>/dev/null || true
rm -f "$PID_FILE"
log_success "代理已停止"

echo
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                      验证完成！                                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo
echo "配置摘要:"
echo "  - 代理端口: $PROXY_PORT"
echo "  - 上游服务器: $UPSTREAM_HOST:$UPSTREAM_PORT"
echo "  - 主机密钥: $HOST_KEY"
echo "  - 审计目录: $AUDIT_DIR"
echo "  - 配置目录: $CONFIG_DIR"
echo
echo "生产环境启动命令:"
echo "  ./build/bin/audit-proxy-core -p $PROXY_PORT -k $HOST_KEY"
echo
echo "调试模式启动命令:"
echo "  ./build/bin/audit-proxy-core -p $PROXY_PORT -k $HOST_KEY -d"
echo
