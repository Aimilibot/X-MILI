#!/usr/bin/env bash
set -e

APP_NAME="X-MILI"
REPO="https://github.com/Aimilibot/X-MILI"
RELEASE_TAG="${X_MILI_RELEASE_TAG:-latest}"
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
step() { echo -e "${green}[X-MILI]${plain} ${yellow}[$1/$2]${plain} $3"; }

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

install_runtime_deps() {
    is_zh && log "正在安装运行依赖和 OpenVPN..." || log "Installing runtime dependencies and OpenVPN..."
    if command -v apt-get >/dev/null 2>&1; then
        is_zh && warn "如果系统自动更新正在运行，将等待 apt/dpkg 锁释放。" || warn "Waiting for apt/dpkg lock if unattended upgrades are running."
        apt-get -o DPkg::Lock::Timeout=1800 update
        apt-get -o DPkg::Lock::Timeout=1800 install -y ca-certificates curl tar gzip openvpn
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates curl tar gzip openvpn
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ca-certificates curl tar gzip openvpn
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache ca-certificates curl tar gzip openvpn
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm ca-certificates curl tar gzip openvpn
    elif command -v zypper >/dev/null 2>&1; then
        zypper refresh
        zypper -q install -y ca-certificates curl tar gzip openvpn
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

gen_random_string() {
    local length="$1"
    tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "$length"
}

get_server_ip() {
    local ip
    ip=$(curl -s --max-time 3 https://api.ipify.org || true)
    [[ -n "$ip" ]] || ip=$(curl -s --max-time 3 https://4.ident.me || true)
    [[ -n "$ip" ]] && echo "$ip" || echo "服务器IP"
}

normalize_web_path() {
    local path="$1"
    [[ -n "$path" ]] || path="/"
    [[ "$path" == /* ]] || path="/${path}"
    [[ "$path" == */ ]] || path="${path}/"
    echo "$path"
}

extract_setting() {
    local info="$1"
    local key="$2"
    echo "$info" | awk -v k="${key}:" '$1 == k {print $2; exit}'
}

read_panel_port() {
    local current_port="${1:-2053}"
    while true; do
        if is_zh; then
            read -rp "请设置登录面板的端口 [默认 ${current_port}]: " panel_port
        else
            read -rp "Panel port [default ${current_port}]: " panel_port
        fi
        panel_port="${panel_port:-$current_port}"
        if [[ "$panel_port" =~ ^[0-9]+$ ]] && ((panel_port >= 1 && panel_port <= 65535)); then
            return
        fi
        is_zh && warn "端口必须是 1-65535" || warn "Port must be 1-65535"
    done
}

read_initial_panel_settings() {
    local info current_port
    info=$("${INSTALL_DIR}/x-ui" setting -show true 2>/dev/null || true)
    current_port=$(extract_setting "$info" "port")
    current_port="${current_port:-2053}"

    panel_username="${X_MILI_USERNAME:-}"
    panel_password="${X_MILI_PASSWORD:-}"
    panel_web_path="${X_MILI_WEB_BASE_PATH:-}"
    panel_port="${X_MILI_PANEL_PORT:-}"

    if [[ -t 0 ]]; then
        echo ""
        if is_zh; then
            echo -e "${green}首次安装向导：请设置面板登录信息。直接回车将随机生成，更安全。${plain}"
            read -rp "请设置登录面板的账号 [随机]: " panel_username
            read -rp "请设置登录面板的密码 [随机]: " panel_password
            if [[ -z "${X_MILI_PANEL_PORT:-}" ]]; then
                read_panel_port "$current_port"
            fi
            read -rp "请设置登录面板的安全后缀 [随机，例如 /$(gen_random_string 8)/]: " panel_web_path
        else
            echo -e "${green}First-time setup: configure panel login. Press Enter to generate secure random values.${plain}"
            read -rp "Panel username [random]: " panel_username
            read -rp "Panel password [random]: " panel_password
            if [[ -z "${X_MILI_PANEL_PORT:-}" ]]; then
                read_panel_port "$current_port"
            fi
            read -rp "Panel secure URL suffix [random, e.g. /$(gen_random_string 8)/]: " panel_web_path
        fi
    fi

    panel_username="${panel_username:-$(gen_random_string 10)}"
    panel_password="${panel_password:-$(gen_random_string 18)}"
    panel_web_path="${panel_web_path:-$(gen_random_string 18)}"
    panel_web_path=$(normalize_web_path "$panel_web_path")
    panel_port="${panel_port:-$current_port}"
}

panel_needs_initialization() {
    local info
    info=$("${INSTALL_DIR}/x-ui" setting -show true 2>/dev/null || true)
    [[ -z "$info" ]] && return 0
    echo "$info" | grep -q "hasDefaultCredential: true"
}

init_panel_settings() {
    panel_credentials_initialized=0
    if panel_needs_initialization; then
        read_initial_panel_settings

        "${INSTALL_DIR}/x-ui" setting \
            -username "$panel_username" \
            -password "$panel_password" \
            -port "$panel_port" \
            -resetTwoFactor true >/dev/null 2>&1
        "${INSTALL_DIR}/x-ui" setting -webBasePath "$panel_web_path" >/dev/null 2>&1
        panel_credentials_initialized=1
        is_zh && log "已设置初始面板账号、密码、端口和访问路径" || log "Initial panel username, password, port and web path configured"
    else
        is_zh && log "检测到已有非默认面板账号，保留现有登录信息" || log "Existing non-default panel account detected, keeping current login"
    fi
}

print_install_guide() {
    local info port web_path server_ip cert protocol
    info=$("${INSTALL_DIR}/x-ui" setting -show true 2>/dev/null || true)
    port=$(extract_setting "$info" "port")
    web_path=$(extract_setting "$info" "webBasePath")
    port="${port:-2053}"
    web_path=$(normalize_web_path "$web_path")
    server_ip=$(get_server_ip)
    cert=$("${INSTALL_DIR}/x-ui" setting -getCert true 2>/dev/null | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]' || true)
    [[ -n "$cert" ]] && protocol="https" || protocol="http"

    echo ""
    if is_zh; then
        echo -e "${green}================ X-MILI 安装完成 ================${plain}"
        echo -e "管理命令: ${green}ml${plain}"
        echo -e "面板地址: ${green}${protocol}://${server_ip}:${port}${web_path}${plain}"
        if [[ "$panel_credentials_initialized" == "1" ]]; then
            echo -e "登录账号: ${green}${panel_username}${plain}"
            echo -e "登录密码: ${green}${panel_password}${plain}"
            echo -e "安全后缀: ${green}${web_path}${plain}"
        else
            echo -e "登录信息: ${yellow}已保留现有账号和密码${plain}"
        fi
        echo -e "数据目录: ${yellow}${DATA_DIR}${plain}"
        echo -e "${green}=================================================${plain}"
    else
        echo -e "${green}================ X-MILI Installed ================${plain}"
        echo -e "Command: ${green}ml${plain}"
        echo -e "URL: ${green}${protocol}://${server_ip}:${port}${web_path}${plain}"
        if [[ "$panel_credentials_initialized" == "1" ]]; then
            echo -e "Username: ${green}${panel_username}${plain}"
            echo -e "Password: ${green}${panel_password}${plain}"
            echo -e "Secure suffix: ${green}${web_path}${plain}"
        else
            echo -e "Login: ${yellow}existing username and password preserved${plain}"
        fi
        echo -e "Data directory: ${yellow}${DATA_DIR}${plain}"
        echo -e "${green}==================================================${plain}"
    fi
    echo ""
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

install_prebuilt_bundle() {
    local arch url package_dir
    arch=$(detect_arch)
    url="${REPO}/releases/download/${RELEASE_TAG}/x-mili-linux-${arch}.tar.gz"
    package_dir="$tmp_dir/package"

    is_zh && log "尝试下载预编译一体包: ${url}" || log "Trying prebuilt bundle: ${url}"
    mkdir -p "$package_dir"
    if ! curl -fL "$url" -o "$tmp_dir/package.tar.gz"; then
        return 1
    fi
    tar -xzf "$tmp_dir/package.tar.gz" -C "$package_dir"
    [[ -x "$package_dir/x-ui" && -f "$package_dir/x-ui.sh" && -d "$package_dir/bin" ]] || return 1

    cp -a "$package_dir"/. "$INSTALL_DIR/"
    install -m 755 "$package_dir/x-ui.sh" /usr/bin/ml
    chmod +x "$INSTALL_DIR/x-ui" "$INSTALL_DIR"/bin/xray-linux-* 2>/dev/null || true
    return 0
}

install_program_files() {
    if install_prebuilt_bundle; then
        is_zh && log "已使用预编译一体包，服务器不进行编译。" || log "Prebuilt bundle installed. No server-side build."
    else
        fail "未找到当前架构的一体包。请等待 GitHub Actions 构建完成后重试。"
    fi
    echo "$X_MILI_LANG" > "$LANG_FILE"
}

choose_language
is_zh && log "开始安装/更新 ${APP_NAME}" || log "Installing/updating ${APP_NAME}"

command -v systemctl >/dev/null 2>&1 || fail "需要 systemd / systemd is required"
is_zh && step 1 5 "安装运行依赖和 OpenVPN" || step 1 5 "Installing runtime dependencies and OpenVPN"
install_runtime_deps
is_zh && step 2 5 "清理旧程序文件，保留面板数据" || step 2 5 "Cleaning old runtime files, keeping panel data"
clean_old_runtime

tmp_dir=$(mktemp -d -t x-mili-install.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

is_zh && step 3 5 "安装 X-MILI 程序文件" || step 3 5 "Installing X-MILI program files"
install_program_files

is_zh && step 4 5 "配置面板账号、端口和安全后缀" || step 4 5 "Configuring panel login, port and secure suffix"
init_panel_settings
is_zh && step 5 5 "安装并启动系统服务" || step 5 5 "Installing and starting system service"
install_service
print_install_guide

is_zh && log "安装完成。命令：ml" || log "Done. Command: ml"
is_zh && warn "默认数据目录仍为 ${DATA_DIR}，用于兼容旧数据。" || warn "Data directory remains ${DATA_DIR} for compatibility."

if [[ "$panel_credentials_initialized" == "1" ]]; then
    # Actively open the menu for the first installation
    /usr/bin/ml
fi
