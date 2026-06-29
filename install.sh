#!/usr/bin/env bash
set -e

APP_NAME="X-MILI"
REPO="https://github.com/Aimilibot/X-MILI"
RAW="${X_MILI_RAW_BASE:-https://raw.githubusercontent.com/Aimilibot/X-MILI/main}"
GO_VERSION="${X_MILI_GO_VERSION:-1.26.2}"
INSTALL_DIR="${XUI_MAIN_FOLDER:-/usr/local/x-ui}"
DATA_DIR="/etc/x-ui"
LANG_DIR="/etc/x-mili"
LANG_FILE="$LANG_DIR/lang"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

log() { echo -e "${green}[X-MILI]${plain} $*"; }
warn() { echo -e "${yellow}[X-MILI]${plain} $*"; }
fail() { echo -e "${red}[X-MILI]${plain} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && fail "请使用 root 运行 / Please run as root"

choose_language() {
    [[ -f "$LANG_FILE" ]] && X_MILI_LANG=$(cat "$LANG_FILE")
    if [[ -z "$X_MILI_LANG" ]]; then
        echo -e "${green}1.${plain} English"
        echo -e "${green}2.${plain} 简体中文"
        read -rp "Please choose language / 请选择语言 [1-2]: " choice
        [[ "$choice" == "2" ]] && X_MILI_LANG="zh_CN" || X_MILI_LANG="en_US"
        mkdir -p "$LANG_DIR"
        echo "$X_MILI_LANG" > "$LANG_FILE"
    fi
}

is_zh() { [[ "$X_MILI_LANG" == "zh_CN" ]]; }

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y ca-certificates curl tar gzip unzip gcc g++ make
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates curl tar gzip unzip gcc gcc-c++ make
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ca-certificates curl tar gzip unzip gcc gcc-c++ make
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache ca-certificates curl tar gzip unzip build-base
    else
        fail "Unsupported package manager / 不支持的包管理器"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "amd64" ;;
        i386 | i686) echo "i386" ;;
        aarch64 | arm64) echo "arm64" ;;
        armv7* | armv6* | arm*) echo "arm" ;;
        *) echo "amd64" ;;
    esac
}

detect_go_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "amd64" ;;
        i386 | i686) echo "386" ;;
        aarch64 | arm64) echo "arm64" ;;
        armv6* | armv7* | arm*) echo "armv6l" ;;
        *) echo "amd64" ;;
    esac
}

install_go() {
    local go_arch
    go_arch=$(detect_go_arch)
    local url="https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz"
    log "Installing Go ${GO_VERSION}"
    curl -fL "$url" -o /tmp/x-mili-go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/x-mili-go.tar.gz
    rm -f /tmp/x-mili-go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
}

clean_old_runtime() {
    is_zh && log "清理旧程序和安装缓存" || log "Cleaning old runtime and install cache"
    is_zh && warn "保留数据目录 ${DATA_DIR}" || warn "Keeping data directory ${DATA_DIR}"
    systemctl stop x-ui >/dev/null 2>&1 || true
    rm -rf /tmp/x-mili-go.tar.gz /tmp/x-mili-install.* /tmp/x-mili-src.*
    if [[ -n "$INSTALL_DIR" && "$INSTALL_DIR" != "/" ]]; then
        rm -rf "$INSTALL_DIR"
    fi
    rm -f /usr/bin/ml /usr/bin/x-ui
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LANG_DIR"
}

install_service() {
    cat > /etc/systemd/system/x-ui.service <<EOF
[Unit]
Description=X-MILI Service
After=network.target
Wants=network.target

[Service]
EnvironmentFile=-/etc/default/x-ui
Environment="XRAY_VMESS_AEAD_FORCED=false"
Type=simple
WorkingDirectory=${INSTALL_DIR}/
ExecStart=${INSTALL_DIR}/x-ui
ExecReload=kill -USR1 \$MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now x-ui
}

choose_language
is_zh && log "开始安装/更新 ${APP_NAME}" || log "Installing/updating ${APP_NAME}"

command -v systemctl >/dev/null 2>&1 || fail "需要 systemd / systemd is required"
install_deps
install_go
clean_old_runtime

tmp_dir=$(mktemp -d -t x-mili-install.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

log "Downloading source: ${REPO}"
curl -fL "${REPO}/archive/refs/heads/main.tar.gz" -o "$tmp_dir/source.tar.gz"
mkdir -p "$tmp_dir/src"
tar -xzf "$tmp_dir/source.tar.gz" -C "$tmp_dir/src" --strip-components=1

cd "$tmp_dir/src"
/usr/local/go/bin/go build -ldflags "-w -s" -o build/x-ui main.go
chmod +x DockerInit.sh
./DockerInit.sh "$(detect_arch)"

cp -r build/* "$INSTALL_DIR/"
install -m 755 x-ui.sh /usr/bin/x-ui
install -m 755 x-ui.sh /usr/bin/ml
echo "$X_MILI_LANG" > "$LANG_FILE"

install_service

is_zh && log "安装完成。命令：ml" || log "Done. Command: ml"
is_zh && warn "默认数据目录仍为 ${DATA_DIR}，用于兼容旧数据。" || warn "Data directory remains ${DATA_DIR} for compatibility."
