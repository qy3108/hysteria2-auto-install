
#!/usr/bin/env bash
set -Eeuo pipefail

# 检查交互终端
if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    echo "[ERROR] 无法访问交互终端，请使用 SSH 终端运行脚本"
    exit 1
fi

# ============================================================
# Debian VPS 自动初始化
# IPv4 + 指定防火墙端口 + Hysteria 2 + 自签证书
#
# 防火墙规则只添加，不清空、不重置、不修改默认策略
# 首次安装时生成 Hy2 config.yaml；已有完整配置时直接复用，不覆盖
# ============================================================

VERSION="1.0.0"

HY2_PORT="10086"
HOP_START="20000"
HOP_END="20500"

BACKUP_DIR="/var/backups/hy2-vps-$(date +%Y%m%d-%H%M%S)"
CERT_DIR="/etc/hysteria"
CERT_KEY="${CERT_DIR}/server.key"
CERT_CRT="${CERT_DIR}/server.crt"

log()  { echo -e "\033[32m[INFO]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[31m[ERROR]\033[0m $*" >&2; }

fail() {
    err "$*"
    exit 1
}

# ------------------------------------------------------------
# 1. Root 检查
# ------------------------------------------------------------

[[ "$EUID" -eq 0 ]] || fail "请使用 root 运行此脚本"

mkdir -p "$BACKUP_DIR"

log "备份目录：$BACKUP_DIR"

# ------------------------------------------------------------
# 2. 安装基础软件
# ------------------------------------------------------------

log "更新 Debian 软件源并安装基础工具..."

export DEBIAN_FRONTEND=noninteractive

apt-get update


apt-get install -y \
    curl \
    wget \
    sudo \
    openssl \
    iproute2 \
    iptables \
    iptables-persistent \
    ca-certificates \
    python3 \
    qrencode


unset DEBIAN_FRONTEND


# ------------------------------------------------------------
# 检查并复用已有 Hysteria 2 配置
# ------------------------------------------------------------

declare -A HY2_USERS=()
HY2_USER_SUMMARY=""
USER_COUNT=0
HY2_CONFIG_REUSED=0

load_existing_hy2_config() {
    local config="${CERT_DIR}/config.yaml"
    local users_text cert_pub key_pub hex_fp hyper_fp pub_b64 username password
    local parsed_summary=""
    local -A parsed_users=()

    # 配置、证书、私钥和服务单元必须同时存在
    [[ -s "$config" && -s "$CERT_CRT" && -s "$CERT_KEY" ]] || return 1
    systemctl cat hysteria-server.service >/dev/null 2>&1 || return 1

    # 验证证书和私钥均可读取，且确实属于同一对密钥
    openssl x509 -in "$CERT_CRT" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$CERT_KEY" -noout >/dev/null 2>&1 || return 1

    cert_pub="$(openssl x509 -in "$CERT_CRT" -pubkey -noout 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null |
        sha256sum | awk '{print $1}')" || return 1
    key_pub="$(openssl pkey -in "$CERT_KEY" -pubout -outform DER 2>/dev/null |
        sha256sum | awk '{print $1}')" || return 1
    [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || return 1

    # 验证配置监听端口、证书路径和 userpass 账号段，并读取原账号密码
    users_text="$(python3 - "$config" <<'PYTHON'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
if not re.search(r"(?m)^listen:\s*:10086\s*$", text):
    raise SystemExit(1)
if not re.search(r"(?m)^\s{2}cert:\s*/etc/hysteria/server\.crt\s*$", text):
    raise SystemExit(1)
if not re.search(r"(?m)^\s{2}key:\s*/etc/hysteria/server\.key\s*$", text):
    raise SystemExit(1)

lines = text.splitlines()
auth_index = next((i for i, line in enumerate(lines)
                   if re.match(r"^auth:\s*$", line)), None)
if auth_index is None:
    raise SystemExit(1)

userpass_index = None
for i in range(auth_index + 1, len(lines)):
    if re.match(r"^\s{2}userpass:\s*$", lines[i]):
        userpass_index = i
        break
    if lines[i].strip() and not lines[i].startswith(" "):
        break
if userpass_index is None:
    raise SystemExit(1)

accounts = []
for line in lines[userpass_index + 1:]:
    if not line.strip():
        continue
    indent = len(line) - len(line.lstrip())
    if indent <= 2:
        break
    match = re.match(r'^\s{4,}"([^"\r\n]+)"\s*:\s*"([^"\r\n]+)"\s*$', line)
    if match:
        username, password = match.groups()
        if "\t" in username or "\n" in username or "\t" in password or "\n" in password:
            raise SystemExit(1)
        accounts.append((username, password))

if not accounts:
    raise SystemExit(1)
for username, password in accounts:
    print(f"{username}\t{password}")
PYTHON
    )" || return 1

    [[ -n "$users_text" ]] || return 1

    while IFS=$'\t' read -r username password; do
        [[ -n "$username" && -n "$password" ]] || continue
        parsed_users["$username"]="$password"
        parsed_summary+="${username}: ${password}"$'\n'
    done <<< "$users_text"

    [[ "${#parsed_users[@]}" -gt 0 ]] || return 1

    # 从现有证书重新计算指纹，不生成新证书
    hex_fp="$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_CRT" |
        cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f')" || return 1
    [[ "$hex_fp" =~ ^[0-9a-f]{64}$ ]] || return 1
    hyper_fp="${hex_fp^^}"

    pub_b64="$(openssl x509 -in "$CERT_CRT" -pubkey -noout |
        openssl pkey -pubin -outform der |
        openssl dgst -sha256 -binary |
        openssl enc -base64)" || return 1

    # 上述检查全部成功后，才提交读取结果，避免失败时残留半套变量
    HY2_USERS=()
    for username in "${!parsed_users[@]}"; do
        HY2_USERS["$username"]="${parsed_users[$username]}"
    done
    HY2_USER_SUMMARY="$parsed_summary"
    USER_COUNT="${#HY2_USERS[@]}"
    HEX_FP="$hex_fp"
    HYPER_FP="$hyper_fp"
    PUB_B64="$pub_b64"

    # 只补齐缺失的指纹文件；不改动现有证书、账号和 Hy2 配置
    if [[ ! -s "${CERT_DIR}/fingerprint.txt" ]]; then
        cat > "${CERT_DIR}/fingerprint.txt" <<EOF
通用无冒号指纹 (v2rayN/Shadowrocket/Clash):
$HEX_FP

sing-box 1.14 专用指纹 (certificate_public_key_sha256):
$PUB_B64
EOF
        chmod 644 "${CERT_DIR}/fingerprint.txt"
    fi

    return 0
}

if load_existing_hy2_config; then
    HY2_CONFIG_REUSED=1
    log "检测到已有完整 Hy2 配置，将保留原账号、密码、证书和指纹"
    log "现有 Hy2 账号数量：${USER_COUNT}"
else
    log "未检测到完整可复用的 Hy2 配置，将执行首次安装/配置"
fi



# ------------------------------------------------------------
# 3. 自动识别网卡
# ------------------------------------------------------------

log "正在自动识别 IPv4 网卡..."

# 优先识别 IPv4 默认路由对应的网卡
NIC="$(ip -4 route show default 2>/dev/null |
    awk 'NR==1 {
        for (i=1; i<=NF; i++) {
            if ($i=="dev") {
                print $(i+1)
                exit
            }
        }
    }')"

# 检查该网卡是否具有全局 IPv4 地址
if [[ -n "$NIC" ]] &&
   ! ip -o -4 addr show dev "$NIC" scope global 2>/dev/null | grep -q 'inet '; then
    NIC=""
fi

# 如果没有找到，尝试识别系统中唯一的全局 IPv4 网卡
if [[ -z "$NIC" ]]; then
    mapfile -t IPV4_NICS < <(
        ip -o -4 addr show scope global 2>/dev/null |
        awk '{print $2}' |
        sort -u
    )

    if [[ "${#IPV4_NICS[@]}" -eq 1 ]]; then
        NIC="${IPV4_NICS[0]}"
    elif [[ "${#IPV4_NICS[@]}" -gt 1 ]]; then
        echo "[ERROR] 检测到多个具有全局 IPv4 地址的网卡："
        printf '  %s\n' "${IPV4_NICS[@]}"
        fail "无法唯一确定 IPv4 网卡，请检查 VPS 网络配置"
    else
        fail "未检测到具有全局 IPv4 地址的网卡"
    fi
fi

# 最终检查网卡是否存在
ip link show dev "$NIC" >/dev/null 2>&1 ||
    fail "识别出的网卡 ${NIC} 不存在"

# 获取该网卡的 IPv4 地址
NIC_IPV4="$(ip -o -4 addr show dev "$NIC" scope global |
    awk 'NR==1 {
        split($4, a, "/")
        print a[1]
    }')"

[[ -n "$NIC_IPV4" ]] ||
    fail "网卡 ${NIC} 没有可用的全局 IPv4 地址"

echo
echo "============================================"
echo "        VPS IPv4 + Hy2 自动安装"
echo "============================================"
echo

log "自动识别网卡成功"
log "网卡名称：$NIC"
log "IPv4 地址：$NIC_IPV4"

# ------------------------------------------------------------
# 9. SSH 端口
# ------------------------------------------------------------

SSH_PORT="10085"  #ssh端口，一般新建vps默认是22，我这里自己修改为10085，有需要请自行修改！

log "SSH TCP 端口固定为：${SSH_PORT}"

# ------------------------------------------------------------
# 10. IPv4 防火墙规则
#
# 不清空现有规则
# 不修改默认策略
# 不改变其他端口规则
# 使用 -C 检查，避免重复添加
# ------------------------------------------------------------

add_v4_input() {
    if ! iptables -C INPUT "$@" 2>/dev/null; then
        iptables -I INPUT 1 "$@"
    fi
}

add_v4_nat() {
    if ! iptables -t nat -C PREROUTING "$@" 2>/dev/null; then
        iptables -t nat -I PREROUTING 1 "$@"
    fi
}

log "添加 IPv4 指定端口规则..."

# SSH TCP 10085
add_v4_input -p tcp --dport "$SSH_PORT" -j ACCEPT

# HTTP / HTTPS
for PORT in 80 443; do
    add_v4_input -p tcp --dport "$PORT" -j ACCEPT
done

# UDP Hy2 主端口
add_v4_input -p udp --dport "$HY2_PORT" -j ACCEPT

# UDP 端口跳跃范围
add_v4_input -p udp --dport "${HOP_START}:${HOP_END}" -j ACCEPT

# IPv4 端口跳跃转发到本机 Hy2 端口
add_v4_nat -i "$NIC" \
    -p udp \
    --dport "${HOP_START}:${HOP_END}" \
    -j REDIRECT --to-ports "$HY2_PORT"

# ------------------------------------------------------------
# 11. 持久化防火墙规则
# ------------------------------------------------------------

log "保存现有防火墙规则..."

netfilter-persistent save

systemctl enable netfilter-persistent >/dev/null 2>&1 || true

if [[ "$HY2_CONFIG_REUSED" -eq 0 ]]; then
# ------------------------------------------------------------
# 12. 安装 Hysteria 2
# ------------------------------------------------------------

log "开始安装 Hysteria 2..."

HY2_INSTALLER="/tmp/get.hy2.sh"

curl -fsSL https://get.hy2.sh/ -o "$HY2_INSTALLER" ||
    fail "下载 Hy2 官方安装脚本失败"

bash "$HY2_INSTALLER" ||
    fail "Hy2 安装失败"

rm -f "$HY2_INSTALLER"

log "Hy2 安装程序执行完毕"

# ------------------------------------------------------------
# 13. 生成自签证书
# ------------------------------------------------------------

log "生成 Hysteria 2 自签证书..."

mkdir -p "$CERT_DIR"

# 设置 Hy2 配置目录权限
chown root:hysteria "$CERT_DIR"
chmod 750 "$CERT_DIR"

# 如果已有配置文件，先备份
if [[ -f "$CERT_DIR/config.yaml" ]]; then
    cp -a "$CERT_DIR/config.yaml" "$BACKUP_DIR/config.yaml.before"
fi

# 如果已有证书，先备份
if [[ -f "$CERT_KEY" ]]; then
    cp -a "$CERT_KEY" "$BACKUP_DIR/server.key.before"
fi

if [[ -f "$CERT_CRT" ]]; then
    cp -a "$CERT_CRT" "$BACKUP_DIR/server.crt.before"
fi

umask 077

openssl req \
    -x509 \
    -nodes \
    -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout "$CERT_KEY" \
    -out "$CERT_CRT" \
    -subj "/CN=bing.com" \
    -days 36500 ||
    fail "自签证书生成失败"

# 按官方安装后的 hysteria 用户设置权限
if id hysteria >/dev/null 2>&1; then
    chown hysteria "$CERT_KEY"
    chown hysteria "$CERT_CRT"
else
    fail "未找到 hysteria 用户，请检查 Hy2 安装结果"
fi


chmod 600 "$CERT_KEY"
chmod 644 "$CERT_CRT"

# ------------------------------------------------------------
# 动态配置 Hysteria 2 用户账号
# ------------------------------------------------------------

log "开始自动生成 Hysteria 2 用户账号..."

# 每次运行自动生成 1 组随机账号和密码
USER_COUNT=1


# 随机生成用户名：hy2-加8位随机十六进制字符
USERNAME="hy2-$(openssl rand -hex 4)"

# 随机生成32位十六进制密码
PASSWORD="$(openssl rand -hex 16)"

# 保存账号密码
HY2_USERS["$USERNAME"]="$PASSWORD"

# 保存最终输出信息
HY2_USER_SUMMARY+="${USERNAME}: ${PASSWORD}"$'\n'

log "随机账号生成成功"
log "账号：$USERNAME"
log "正在生成 Hy2 配置文件..."

umask 077

{
    cat << 'EOF'
listen: :10086

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s

auth:
  type: userpass
  userpass:
EOF

    for username in "${!HY2_USERS[@]}"; do
        printf '    "%s": "%s"\n' "$username" "${HY2_USERS[$username]}"
    done

    cat << 'EOF'

resolver:
  type: https
  https:
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false

acl:
  inline:
    - reject(geoip:cn)

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true
EOF
} > "$CERT_DIR/config.yaml"

chown root:hysteria "$CERT_DIR/config.yaml"
chmod 640 "$CERT_DIR/config.yaml"

HY2_USER_NAMES=$(printf '%s\n' "${!HY2_USERS[@]}" | sort)
unset PASSWORD USERNAME

log "Hy2 配置文件生成完成，共创建 ${USER_COUNT} 个账号"


# ------------------------------------------------------------
# 生成并保存 Hy2 证书指纹
# ------------------------------------------------------------

log "生成 Hy2 证书指纹..."

HEX_FP=$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_CRT" \
    | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f')

# 分享链接使用的大写 SHA256 指纹
HYPER_FP="${HEX_FP^^}"

PUB_B64=$(openssl x509 -in "$CERT_CRT" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64)

cat > "$CERT_DIR/fingerprint.txt" << EOF
通用无冒号指纹 (v2rayN/Shadowrocket/Clash):
$HEX_FP

sing-box 1.14 专用指纹 (certificate_public_key_sha256):
$PUB_B64
EOF

chmod 644 "$CERT_DIR/fingerprint.txt"

log "证书指纹已保存至 $CERT_DIR/fingerprint.txt"

else
    log "复用现有 Hy2 配置，跳过安装、证书生成、账号生成和 config.yaml 写入"
fi

# ------------------------------------------------------------
# 启用 Hy2 开机启动并启动服务
# ------------------------------------------------------------

log "启用 Hy2 开机启动..."

systemctl enable hysteria-server.service

if [[ "$HY2_CONFIG_REUSED" -eq 1 ]] && systemctl is-active --quiet hysteria-server.service; then
    log "现有 Hy2 服务已经运行，不重启服务，避免影响正在使用的协议族"
else
    log "启动 Hy2 服务..."
    systemctl restart hysteria-server.service
fi

log "检查 Hy2 服务状态..."

systemctl status hysteria-server.service --no-pager

# ------------------------------------------------------------
# 15. 输出结果
# ------------------------------------------------------------


# ------------------------------------------------------------
# 15. 输出最终结果
# ------------------------------------------------------------


# ------------------------------------------------------------
# 15. 输出最终结果
# ------------------------------------------------------------

echo
echo "================================================"
echo "              VPS 初始化完成"
echo "================================================"

echo
echo "【网卡】"
echo "$NIC"

echo
echo "【SSH】"
echo "TCP ${SSH_PORT}"

echo
echo "【开放端口】"
echo "TCP: ${SSH_PORT}, 80, 443"
echo "UDP: ${HY2_PORT}, ${HOP_START}-${HOP_END}"

echo
echo "【Hy2】"
echo "主端口：UDP ${HY2_PORT}"
echo "配置文件：$CERT_DIR/config.yaml"
echo "证书：$CERT_CRT"
echo "私钥：$CERT_KEY"
echo "服务状态："
systemctl is-active hysteria-server.service || true

echo
echo "【防火墙】"
echo "原有规则未清空"
echo "默认策略未修改"
echo "只添加本脚本指定的 IPv4 端口规则；已有 Hy2 配置不会被覆盖"

echo
echo "【备份目录】"
echo "$BACKUP_DIR"

echo
echo "【Hy2 账号数量】"
echo "$USER_COUNT"

echo
echo "【Hy2 账号及密码】"
echo "$HY2_USER_SUMMARY"

echo
echo "【通用 SHA256 证书指纹】"
echo "$HEX_FP"

echo
echo "【sing-box 1.14 公钥 SHA256 指纹】"
echo "$PUB_B64"

echo
echo "【指纹文件】"
echo "$CERT_DIR/fingerprint.txt"



# ------------------------------------------------------------
# 16. 生成 IPv4 分享链接及二维码
# ------------------------------------------------------------

log "开始生成 Hy2 IPv4 分享链接及二维码..."

# 获取服务器公网 IPv4
SERVER_IP="$(curl -4fsS --connect-timeout 8 --max-time 12 \
    https://api.ipify.org 2>/dev/null || true)"
[[ -n "$SERVER_IP" ]] || fail "未检测到公网 IPv4，无法生成 IPv4 分享链接"

HYPER_FP="${HEX_FP^^}"
QR_SCALE=3
QR_MARGIN=1

command -v qrencode >/dev/null 2>&1 ||
    fail "未找到 qrencode，请先安装 qrencode"

SHARE_DIR="/root/hy2-share"
mkdir -p "$SHARE_DIR"
chmod 700 "$SHARE_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo
echo "================================================"
echo "       Hy2 IPv4 分享链接生成"
echo "================================================"
echo
echo "IPv4：${SERVER_IP}"
echo "Hy2 主端口：${HY2_PORT}"
echo "UDP 跳跃端口：${HOP_START}-${HOP_END}"
echo "证书 SHA256 指纹：${HYPER_FP}"

for USERNAME in "${!HY2_USERS[@]}"; do
    PASSWORD="${HY2_USERS[$USERNAME]}"

    echo
    echo "================================================"
    echo "账号：$USERNAME"
    echo "================================================"

    # V2Ray 格式分享链接
    URL_V2RAY="$(python3 - \
        "$USERNAME" "$PASSWORD" "$SERVER_IP" \
        "$HY2_PORT" "$HOP_START" "$HOP_END" "$HYPER_FP" <<'PY'
import sys
from urllib.parse import quote

user, password, host, port, hop_start, hop_end, pin = sys.argv[1:]
auth = quote(user + ":" + password, safe="")
remark = quote(user + " IPv4", safe="")
host_part = "{host}".format(host=host)

print(
    f"hysteria2://{auth}@{host_part}:{port}"
    f"?security=tls"
    f"&insecure=1"
    f"&mport={hop_start}-{hop_end}"
    f"&pinSHA256={pin}"
    f"&sni=bing.com"
    f"#{remark}"
)
PY
    )" || fail "V2Ray IPv4 分享链接生成失败"

    # Apple 小火箭格式分享链接
    URL_APPLE="$(python3 - \
        "$USERNAME" "$PASSWORD" "$SERVER_IP" \
        "$HY2_PORT" "$HOP_START" "$HOP_END" "$HYPER_FP" <<'PY'
import sys
from urllib.parse import quote

user, password, host, port, hop_start, hop_end, pin = sys.argv[1:]
auth = quote(user, safe="") + ":" + quote(password, safe="")
remark = quote(user + " IPv4", safe="")
host_part = "{host}".format(host=host)

print(
    f"hysteria2://{auth}@{host_part}:{port}"
    f"?peer=bing.com"
    f"&insecure=1"
    f"&upmbps=50"
    f"&downmbps=100"
    f"&keepalive=60"
    f"&hpkp={pin}"
    f"&fingerprint=Safari26_3"
    f"&mport={hop_start}-{hop_end}"
    f"#{remark}"
)
PY
    )" || fail "Apple IPv4 分享链接生成失败"

    printf '%s\n' "$URL_V2RAY" > "$SHARE_DIR/${USERNAME}-V2Ray-IPv4.txt"
    printf '%s\n' "$URL_APPLE" > "$SHARE_DIR/${USERNAME}-IPv4.txt"

    qrencode -o "$SHARE_DIR/${USERNAME}-V2Ray-IPv4.png" \
        -s "$QR_SCALE" -m "$QR_MARGIN" "$URL_V2RAY"
    qrencode -o "$SHARE_DIR/${USERNAME}-IPv4.png" \
        -s "$QR_SCALE" -m "$QR_MARGIN" "$URL_APPLE"

    qrencode -t ANSIUTF8 "$URL_V2RAY" > "$TMP_DIR/V2Ray.qr"
    qrencode -t ANSIUTF8 "$URL_APPLE" > "$TMP_DIR/Apple.qr"

    echo
    echo "【V2Ray IPv4 分享链接】"
    echo "$URL_V2RAY"
    echo
    echo "【V2Ray IPv4 二维码】"
    cat "$TMP_DIR/V2Ray.qr"

    echo
    echo "【Apple 小火箭 IPv4 分享链接】"
    echo "$URL_APPLE"
    echo
    echo "【Apple 小火箭 IPv4 二维码】"
    cat "$TMP_DIR/Apple.qr"

    chmod 600 "$SHARE_DIR/${USERNAME}"-*.txt
    chmod 600 "$SHARE_DIR/${USERNAME}"-*.png

    echo
    echo "【二维码图片文件】"
    echo "V2Ray：$SHARE_DIR/${USERNAME}-V2Ray-IPv4.png"
    echo "Apple：$SHARE_DIR/${USERNAME}-IPv4.png"
done

echo
echo "================================================"
echo "IPv4 分享链接及二维码生成完成"
echo "保存目录：$SHARE_DIR"
echo "================================================"

unset PASSWORD USERNAME

echo
echo "================================================"
echo "        Hysteria 2 安装及配置完成"
echo "================================================"
