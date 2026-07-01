#!/usr/bin/env bash
set -euo pipefail

APP_NAME="X-MILI"
REPO="https://github.com/Aimilibot/X-MILI"
API_REPO="https://api.github.com/repos/Aimilibot/X-MILI"
INSTALL_DIR="${XUI_MAIN_FOLDER:-/usr/local/x-ui}"
COMMIT_FILE="${INSTALL_DIR}/.x-mili-commit"
RELEASE_TAG="${X_MILI_RELEASE_TAG:-latest}"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

log() { echo -e "${green}[${APP_NAME}]${plain} $*"; }
warn() { echo -e "${yellow}[${APP_NAME}]${plain} $*"; }
fail() { echo -e "${red}[${APP_NAME}]${plain} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && fail "请使用 root 运行 / Please run as root"
command -v systemctl >/dev/null 2>&1 || fail "需要 systemd / systemd is required"
[[ -d "$INSTALL_DIR" ]] || fail "未找到安装目录 ${INSTALL_DIR}，请先安装"

command -v curl >/dev/null 2>&1 || fail "缺少 curl"
command -v tar >/dev/null 2>&1 || fail "缺少 tar"

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "amd64" ;;
        i386 | i686) echo "i386" ;;
        aarch64 | arm64) echo "arm64" ;;
        armv7* | armv6* | arm*) echo "arm" ;;
        *) echo "amd64" ;;
    esac
}

remote_commit="$(curl -fsSL "${API_REPO}/git/ref/heads/main" | sed -n 's/.*"sha": "\([0-9a-f]\{40\}\)".*/\1/p' || true)"
local_commit="$(cat "$COMMIT_FILE" 2>/dev/null || true)"

if [[ -n "$remote_commit" && "$remote_commit" == "$local_commit" && "${X_MILI_FORCE_UPDATE:-0}" != "1" ]]; then
    log "已是最新版本，无需更新。"
    exit 0
fi

tmp_dir="$(mktemp -d -t x-mili-update.XXXXXX)"
backup_dir="$(mktemp -d -t x-mili-update-backup.XXXXXX)"
trap 'rm -rf "$tmp_dir" "$backup_dir"' EXIT

download_prebuilt_bundle() {
    local arch url package_dir package_commit
    arch=$(detect_arch)
    url="${REPO}/releases/download/${RELEASE_TAG}/x-mili-linux-${arch}.tar.gz"
    package_dir="$tmp_dir/package"

    log "尝试下载预编译一体包: ${url}"
    mkdir -p "$package_dir"
    if ! curl -fL "$url" -o "$tmp_dir/package.tar.gz"; then
        return 1
    fi
    tar -xzf "$tmp_dir/package.tar.gz" -C "$package_dir"
    [[ -x "$package_dir/x-ui" && -f "$package_dir/x-ui.sh" ]] || return 1
    package_commit="$(cat "$package_dir/.x-mili-commit" 2>/dev/null || true)"
    [[ -z "$remote_commit" || -z "$package_commit" || "$package_commit" == "$remote_commit" ]] || return 1
    return 0
}

if download_prebuilt_bundle; then
    update_dir="$tmp_dir/package"
    log "已使用预编译一体包，服务器不进行编译。"
else
    fail "未找到当前架构的一体包。请等待 GitHub Actions 构建完成后重试。"
fi

log "备份当前程序..."
mkdir -p "$backup_dir/install"
cp -a "$INSTALL_DIR"/. "$backup_dir/install"/
[[ -f /usr/bin/ml ]] && cp -a /usr/bin/ml "$backup_dir/ml"

rollback() {
    warn "更新失败，正在回滚..."
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -a "$backup_dir/install"/. "$INSTALL_DIR"/
    [[ -f "$backup_dir/ml" ]] && install -m 755 "$backup_dir/ml" /usr/bin/ml
    systemctl restart x-ui >/dev/null 2>&1 || true
}

log "替换程序文件和菜单..."
cp -a "$update_dir"/. "$INSTALL_DIR"/
install -m 755 "$update_dir/x-ui.sh" /usr/bin/ml
chmod +x "$INSTALL_DIR/x-ui" "$INSTALL_DIR"/bin/xray-linux-* 2>/dev/null || true
[[ -n "$remote_commit" ]] && echo "$remote_commit" > "$COMMIT_FILE"

log "重启面板..."
if ! systemctl restart x-ui; then
    rollback
    fail "面板重启失败，已回滚。请查看：journalctl -u x-ui -e --no-pager"
fi

sleep 2
if ! systemctl is-active --quiet x-ui; then
    rollback
    fail "面板启动后状态异常，已回滚。请查看：journalctl -u x-ui -e --no-pager"
fi

log "更新完成。已保留面板数据、账号密码、安全设置、Xray 配置和 OpenVPN。"
