#!/usr/bin/env bash
# =============================================================================
#  dsh-web-hardening.sh — DSH Web 一键部署 + 加固
#  One-shot installer + hardening for DeepSeek Harness (DSH) web profile
#  Version: 3.0.1     License: MIT
# =============================================================================
#
#  变更记录
#  ────────
#  v3.0.1（修两个会让"脚本报成功、浏览器 500"的坑）
#    1) htpasswd 权限：不再只 chown 一次就算完，而是先拿到 Nginx worker 的
#       【真实】user/group（user 指令 + worker 进程实际身份），改完再【以该
#       身份真的读一次】；chown 失败不再被 `|| true` 吞掉。
#       症状：日志 open() "...htpasswd" failed (13: Permission denied) → 500。
#    2) 凭据验证不再是假阳性：location = / 里的 `if (...) return 302` 在
#       rewrite 阶段执行，早于 auth_basic 的 access 阶段 —— 拿 / 当探针时，
#       错误密码同样返回 302 且没有 WWW-Authenticate，旧检查必定通过。
#       现在改为探必定经过 access 阶段的 /_dsh_boot，并且直接按
#       HTTP 状态码判定（401/403/500 都算失败）。
#
#  一条命令做到：装 Node/DSH → 设账号密码 → 浏览器打开 https://<本机IP> 直接进
#
#      sudo ./dsh-web-hardening.sh
#
#  最终形态：
#
#      [浏览器] --https + 密码--> [Nginx] --127.0.0.1--> [DSH 只监听回环]
#
#  它解决什么问题
#  ──────────────
#  DSH 的 web profile 默认只监听 127.0.0.1。社区常见的"让别人也能访问"
#  做法是安装第三方插件（dsh-access-gate / dsh-lan-access / dsh-webui-auth
#  之类）把绑定改成 0.0.0.0，并在请求层改写 Host / Origin。这类方案有两个
#  严重问题：
#
#    1) 【安全】放行模式下（默认未设密码），任何能连上该端口的人都会被
#       "改写成回环形态"后放行 —— 因为 DSH 的信任护栏只看请求头、不看
#       socket 来源。再叠加某些插件用被改写的 Host 去拼重定向，会把进程级
#       launch token 直接写进 302 的 Location 头：未认证者一条 curl 就能拿到
#       主令牌，换取会话 cookie，调用 settings.* / llm.* 等特权接口。
#       而 DSH Web 本质是能执行任意命令的 agent —— 等价于远程代码执行。
#
#    2) 【可维护】这些插件依赖 DSH 内部实现细节（覆盖 server.emit、篡改
#       req.headers、注入 index.html），DSH 每升一个 rc 版本都可能失效。
#
#  本脚本用 DSH【原生能力】+ Nginx 重建等价功能，不改 DSH 源码、不装第三方插件：
#
#    * 绑定不改 0.0.0.0      → DSH 留在回环，Nginx 反代
#    * 不改写 Host 穿透护栏   → 官方参数 --trusted-host + 原样透传 Host
#    * 不删 Origin           → Host 保留后 Origin 自然一致
#    * 不注入 randomUUID 补丁 → 用 HTTPS（安全上下文下浏览器原生支持）
#    * 不注入 ownsHost       → Nginx sub_filter 一行搞定（DSH 之外）
#    * 密码登录              → Nginx auth_basic
#
#  关于 launch token（为什么你能"打开就进"）
#  ────────────────────────────────────────
#  DSH 核心要求：每个浏览器先用一次进程级 launch token 换取签名 cookie。
#  本脚本可选地在回环起一个极小的"引导侧车"（Node，PM2 托管），由它替你完成
#  token→cookie 交换并只把 Set-Cookie 转给浏览器 —— 你的浏览器和 URL 里
#  永远不会出现 token。想关掉用 --no-auto-token。
#
#  用法
#  ────
#    sudo ./dsh-web-hardening.sh                    # 一键：自动判断当前状态并做对的事
#    sudo ./dsh-web-hardening.sh --update           # 先升级 DSH 包，再重新加固
#    sudo ./dsh-web-hardening.sh --check            # 只体检，不改动任何东西
#    sudo ./dsh-web-hardening.sh --set-credentials  # 只改账号密码（不重启 DSH）
#    sudo ./dsh-web-hardening.sh --set-autostart    # 只调整开机自启
#    sudo ./dsh-web-hardening.sh --uninstall        # 卸载：只清理本脚本的配置文件
#    sudo ./dsh-web-hardening.sh --help
#
#  它会自己判断该做什么
#  ──────────────────────
#    运行 install 模式（默认）时先做环境检测并打印结论，例如：
#      DSH        : 未安装 / 已安装 v0.1.5-rc.1
#      profile    : 未初始化 / 已存在
#      加固状态   : 未加固 / 已加固 / 部分（上次中断，需修复）
#      DSH 进程   : 未运行 / 127.0.0.1:3080 ✓ / 0.0.0.0:3080 ← 有风险
#      开机自启   : 已启用 / 未启用
#    => 本次将执行：全新安装 / 重新加固（幂等修复）/ 升级后重新加固
#    所以同一个命令可以反复安全执行：装、修、升级后重建都用它。
#
#  开机自启可选
#  ────────────
#    交互运行时脚本会问你要不要设置开机自启（直接回车 = 要）；
#    非交互时用 --autostart / --no-autostart 明确指定。
#    只想改这一项？用 --set-autostart（不动其他任何东西）。
#
#  账号密码完全由你决定
#  ────────────────────
#    装的时候：脚本会【提示你输入】用户名和密码，你自己设。
#      用户名 回车 = 沿用括号里的默认值（默认 dsh）
#      密码   回车 = 已有密码则保持不变；首次安装则随机生成 20 位
#    不想交互 / 批量部署：
#      --auth-user <用户名>   默认 dsh
#      --password <密码>
#    -y（非交互）且没给 --password 时才会随机生成。
#
#    以后想单独改密码（不重启 DSH，只重载 Nginx）：
#      sudo ./dsh-web-hardening.sh --set-credentials
#      sudo ./dsh-web-hardening.sh --set-credentials --auth-user alice --password '新密码'
#
#  卸载行为（重要）
#  ────────────────
#    --uninstall 只删除【本脚本创建的配置文件】并停掉引导侧车：
#      Nginx 站点 / map / 代理片段 / htpasswd / 自签证书 / patch 覆盖层 / 侧车脚本
#    它【不会卸载任何软件包】（nginx、nodejs、pm2、@deepseek-ai/dsh 都保留），
#    也不会动 DSH 自己的数据目录 ~/.dsh。想连软件一起清理会打印对应命令。
#    加 --purge 可额外移除 PM2 开机自启单元与 NodeSource 源配置。
#
#  常用选项
#  ────────
#    --update               先检查并升级 @deepseek-ai/dsh 到最新版，再重新加固
#    --autostart            设置 PM2 开机自启
#    --no-autostart         不设置（或关闭）开机自启
#    --set-autostart        只调整开机自启，其他一律不动
#    --set-credentials      只设置/修改访问账号密码（不重启 DSH，只重载 Nginx）
#    --uninstall            卸载：只清理配置，不卸载软件
#    --purge                配合 --uninstall，额外移除 PM2 自启单元与 NodeSource 源
#    --auth-user <用户名>   Nginx basic auth 用户名，默认 dsh
#    --password <密码>      Nginx basic auth 密码（不给则交互提示或随机生成）
#    --host <地址>          对外访问地址；默认自动探测主网卡 IPv4
#    --trusted-host <地址>  额外信任的 Host（可重复）。用别的域名/IP 访问时必加
#    --https-port <端口>    Nginx HTTPS 端口（默认 443）
#    --http-port <端口>     HTTP 跳转端口（默认 80）
#    --dsh-port <端口>      DSH 监听端口（默认 3080）
#    --user <用户名>        DSH 运行用户（默认从 sudo 调用者/家目录推断）
#    --profile <名称>       DSH profile（默认 web）
#    --cookie-days <n>      会话 cookie 有效期，默认 400（浏览器上限）
#    --node-major <n>       需要的 Node 主版本，默认 22
#    --cn-mirror            一键使用国内镜像（等价于同时指定下面两个）
#    --node-source <url>    Node【发行包镜像】基址（注意：不是 npm 包源！）
#                           默认依次尝试 nodejs.org/dist 与
#                           https://registry.npmmirror.com/-/binary/node
#                           只填 https://registry.npmmirror.com 也会被自动补全
#    --npm-registry <url>   npm【包源】；默认沿用 npm 现有配置，失败自动回退 npmmirror
#                           填 npmmirror 时会自动推断出对应的 Node 镜像
#    --credentials-file <路径>  凭据保存位置，默认 /root/dsh-web-credentials.txt
#    --no-save-credentials  不保存明文凭据
#    --show-credentials     打印已保存的凭据
#    --allow-root-dsh       允许以 root 身份运行 DSH（默认拒绝并要求确认）
#    --no-install-node      缺 Node 时不自动安装
#    --no-install-dsh       缺 DSH 时不自动 npm 安装
#    --no-install-pm2       缺 PM2 时不自动安装
#    --no-auto-token        不装引导侧车（改为手动粘贴一次 token URL）
#    --no-http-redirect     不占用 80 端口做 HTTP→HTTPS 跳转
#    --no-firewall          不自动放行 80/443（绝不改动 22/SSH）
#    --keep-plugins         不卸载已知问题插件（只做网络加固）
#    --no-deps              缺 nginx 时不自动安装
#    -y, --yes              全程非交互（配合 --password 使用）
#    --log <路径>           日志文件；安装/卸载默认写到 /var/log/dsh-web-<时间>.log
#    --detach               放到后台跑（setsid），SSH 断线/关终端都不会中断安装
#                           配合 --detach 时请用 -y --password 或 --allow-root-dsh
#
#  关于"记住密码"
#  ──────────────
#    设置/生成的密码会另存到 /root/dsh-web-credentials.txt（权限 600），
#    方便你事后取回；用 --no-save-credentials 可关闭，--show-credentials 可打印。
#    ⚠️ 那个文件是【明文】，请自行妥善保存后删除。
#
#    /etc/nginx/.dsh-web.htpasswd 里只有 apr1 哈希：
#      * 不能直接拿来登录（HTTP Basic 必须提交明文，nginx 自己算哈希比对）；
#      * 但它可被离线暴力破解，所以同样不要外传 —— 真正要保护的是明文那份。
#
#  发行版支持
#  ──────────
#    Debian / Ubuntu 系（apt、sites-available、www-data）
#    RHEL / CentOS / Rocky / Alma / Fedora / openEuler 系（dnf/yum、conf.d、nginx 组）
#    会按实际情况自动选择路径，并处理 SELinux（httpd_can_network_connect）与
#    firewalld/ufw 的端口放行。Node 用官方发行包安装到 /usr/local，不依赖任何
#    第三方软件源。
#
#  ⚠️ 脚本会重启 DSH。若你正通过 DSH 网页里的 agent 运行它，那次重启会切断
#     网页连接 —— 请改在 SSH 会话里执行。
# =============================================================================

set -euo pipefail

# 兜底：任何命令在 set -e 下失败，都先打印"哪一行、哪条命令、退出码"，
# 避免命令输出被重定向到 /dev/null 时出现"无声退出"（排查噩梦）。
trap 'rc=$?; printf "\n\033[1;31m✗ 脚本中断：第 %s 行执行失败（退出码 %s）\n  命令：%s\033[0m\n" "$LINENO" "$rc" "$BASH_COMMAND" >&2; exit "$rc"' ERR

VERSION="3.0.1"

# 保存原始参数（解析会把它们 shift 掉，而 detach 重新执行时要原样传回）
ORIG_ARGS=("$@")

# ── 默认参数 ────────────────────────────────────────────────────────────────
PROFILE="web"
DSH_PORT="3080"
BOOT_PORT="3081"
HTTPS_PORT="443"
HTTP_PORT="80"
HTTP_REDIRECT=1
AUTH_USER="dsh"
AUTH_PASS=""
COOKIE_DAYS="400"
HOST_ARG=""
TARGET_USER=""
MODE="install"
KEEP_PLUGINS=0
NO_DEPS=0
INSTALL_DSH=1
INSTALL_PM2=1
INSTALL_NODE=1
AUTO_TOKEN=1
ASSUME_YES=0
FIREWALL=1
PURGE=0
NODE_MAJOR="22"
NPM_REGISTRY=""
NODE_SOURCE=""
CRED_FILE=""
SAVE_CRED=1
ALLOW_ROOT_DSH=0
LOG_FILE=""
DETACH=0
UPDATE_DSH=0
AUTOSTART_WANT=""      # ""=询问/默认开  1=开  0=关
TRUSTED_EXTRA=()

KNOWN_BAD_PLUGINS=(dsh-access-gate dsh-webui-auth dsh-lan-access)
SITE_NAME="dsh-web"
MAP_FILE="/etc/nginx/conf.d/${SITE_NAME}-map.conf"
PROXY_SNIPPET="/etc/nginx/snippets/${SITE_NAME}-proxy.conf"
HTPASSWD="/etc/nginx/.${SITE_NAME}.htpasswd"
# CERT / KEY 的真实路径在"发行版探测"之后确定（RHEL 与 Debian 惯例不同）
CERT=""
KEY=""
BOOT_APP="dsh-bootstrap"

# ── 输出 ────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_R=$'\033[1;36m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_E=$'\033[1;31m'; C_0=$'\033[0m'
else
  C_R=; C_G=; C_Y=; C_E=; C_0=
fi
step() { printf '\n%s== %s%s\n' "$C_R" "$*" "$C_0"; }
ok()   { printf '   %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '   %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
err()  { printf '   %s✗%s %s\n' "$C_E" "$C_0" "$*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0; }

# ── 参数解析 ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --check)            MODE="check" ;;
    --uninstall)        MODE="uninstall" ;;
    --set-credentials)  MODE="credentials" ;;
    --purge)            PURGE=1 ;;
    --host)             HOST_ARG="${2:?--host 需要参数}"; shift ;;
    --trusted-host)     TRUSTED_EXTRA+=("${2:?--trusted-host 需要参数}"); shift ;;
    --https-port)       HTTPS_PORT="${2:?}"; shift ;;
    --http-port)        HTTP_PORT="${2:?}"; shift ;;
    --dsh-port)         DSH_PORT="${2:?}"; shift ;;
    --boot-port)        BOOT_PORT="${2:?}"; shift ;;
    --user)             TARGET_USER="${2:?}"; shift ;;
    --auth-user)        AUTH_USER="${2:?}"; shift ;;
    --password)         AUTH_PASS="${2:?}"; shift ;;
    --profile)          PROFILE="${2:?}"; shift ;;
    --cookie-days)      COOKIE_DAYS="${2:?}"; shift ;;
    --node-major)       NODE_MAJOR="${2:?}"; shift ;;
    --node-source)      NODE_SOURCE="${2:?}"; shift ;;
    --npm-registry)     NPM_REGISTRY="${2:?}"; shift ;;
    --cn-mirror)        NPM_REGISTRY="https://registry.npmmirror.com"
                        NODE_SOURCE="https://registry.npmmirror.com/-/binary/node" ;;
    --credentials-file) CRED_FILE="${2:?}"; shift ;;
    --no-save-credentials) SAVE_CRED=0 ;;
    --show-credentials) MODE="showcredentials" ;;
    --allow-root-dsh)   ALLOW_ROOT_DSH=1 ;;
    --log)              LOG_FILE="${2:?}"; shift ;;
    --detach)           DETACH=1 ;;
    --update)           UPDATE_DSH=1 ;;
    --autostart)        AUTOSTART_WANT=1 ;;
    --no-autostart)     AUTOSTART_WANT=0 ;;
    --set-autostart)    MODE="autostart" ;;
    --no-http-redirect) HTTP_REDIRECT=0 ;;
    --keep-plugins)     KEEP_PLUGINS=1 ;;
    --no-deps)          NO_DEPS=1 ;;
    --no-install-dsh)   INSTALL_DSH=0 ;;
    --no-install-pm2)   INSTALL_PM2=0 ;;
    --no-install-node)  INSTALL_NODE=0 ;;
    --no-auto-token)    AUTO_TOKEN=0 ;;
    --no-firewall)      FIREWALL=0 ;;
    -y|--yes)           ASSUME_YES=1 ;;
    -h|--help)          usage ;;
    -V|--version)       echo "$VERSION"; exit 0 ;;
    *)                  die "未知参数：$1（用 --help 查看用法）" ;;
  esac
  shift
done

# ── 日志 / 后台运行：避免 SSH 断线把"半截安装 + 日志"一起带走 ────────────────
if [ "$MODE" = "install" ] || [ "$MODE" = "uninstall" ]; then
  # 被 detach 重新执行时沿用父进程定好的日志路径
  [ -n "${DSH_HARDEN_LOG:-}" ] && LOG_FILE="$DSH_HARDEN_LOG"
  [ -z "$LOG_FILE" ] && LOG_FILE="/var/log/${SITE_NAME}-$(date +%Y%m%d-%H%M%S).log"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || LOG_FILE="/tmp/$(basename "$LOG_FILE")"
  export DSH_HARDEN_LOG="$LOG_FILE"
  if [ "$DETACH" = "1" ] && [ "${DSH_HARDEN_DETACHED:-0}" != "1" ]; then
    export DSH_HARDEN_DETACHED=1
    setsid nohup "$0" "${ORIG_ARGS[@]}" >/dev/null 2>&1 </dev/null &
    sleep 1
    echo "已在后台运行 —— 断开 SSH 或关闭终端都不会中断安装。"
    echo "  日志文件：$LOG_FILE"
    echo "  实时查看：tail -f $LOG_FILE"
    echo "  重新连接后可用该日志确认结果。"
    exit 0
  fi
  # 注意：detach 的子进程也要走这里（只是不再 detach），否则日志是空的
  exec > >(tee -a "$LOG_FILE") 2>&1
  printf '日志：%s\n\n' "$LOG_FILE"
fi

if [ "$MODE" != "check" ] && [ "$(id -u)" -ne 0 ]; then
  die "请以 root 运行：sudo $0 $*"
fi

# ── 小工具 ──────────────────────────────────────────────────────────────────
is_ip() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

detect_ip() {
  local ip=""
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  printf '%s' "$ip"
}

detect_user() {
  if [ -n "$TARGET_USER" ]; then printf '%s' "$TARGET_USER"; return; fi
  local d u
  # 1) 已有 DSH 数据目录的家 → 最可信
  for d in /home/*; do
    if [ -d "$d/.dsh" ]; then basename "$d"; return; fi
  done
  # 2) sudo 调用者（排除 root）
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s' "$SUDO_USER"; return; fi
  # 3) /home 下第一个普通用户（uid>=1000）—— 避免默认落到 root
  for d in /home/*; do
    [ -d "$d" ] || continue
    u="$(basename "$d")"
    if [ "$(id -u "$u" 2>/dev/null || echo 0)" -ge 1000 ]; then printf '%s' "$u"; return; fi
  done
  # 4) 兜底：当前用户
  id -un
}

as_user() {
  # install/uninstall 以 root 运行 → 降权到目标用户；--check 可能以普通用户运行
  if [ "$(id -u)" -eq 0 ]; then
    runuser -u "$TARGET_USER" -- env \
      HOME="$TARGET_HOME" PM2_HOME="$PM2_HOME" \
      DSH_BIN="$DSH_BIN" PROFILE="$PROFILE" OVERLAY="$OVERLAY" \
      PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      "$@"
  else
    env HOME="$TARGET_HOME" PM2_HOME="$PM2_HOME" \
      DSH_BIN="$DSH_BIN" PROFILE="$PROFILE" OVERLAY="$OVERLAY" \
      PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      "$@"
  fi
}

# ── 发行版探测 ──────────────────────────────────────────────────────────────
PKG_FAMILY=""; PKG_INSTALL=""; NGINX_GROUP=""
if [ -f /etc/debian_version ]; then
  PKG_FAMILY="deb"; PKG_INSTALL="apt-get install -y -qq"
elif [ -f /etc/redhat-release ] || grep -qiE 'rhel|centos|fedora|rocky|almalinux|openeuler|anolis|kylin|uos' /etc/os-release 2>/dev/null; then
  PKG_FAMILY="rpm"
  if have dnf; then PKG_INSTALL="dnf install -y -q"; else PKG_INSTALL="yum install -y -q"; fi
else
  PKG_FAMILY="unknown"
fi

if [ "$PKG_FAMILY" = "deb" ] && [ -d /etc/nginx/sites-available ]; then
  SITE_AVAIL="/etc/nginx/sites-available/$SITE_NAME"
  SITE_ENABLED="/etc/nginx/sites-enabled/$SITE_NAME"
  SITE_LINKED=1
else
  SITE_AVAIL="/etc/nginx/conf.d/$SITE_NAME.conf"
  SITE_ENABLED="$SITE_AVAIL"
  SITE_LINKED=0
fi
if getent group www-data >/dev/null 2>&1; then NGINX_GROUP="www-data"
elif getent group nginx  >/dev/null 2>&1; then NGINX_GROUP="nginx"
else NGINX_GROUP="root"; fi

# 证书目录按发行版惯例选择：RHEL 系用 /etc/pki/tls，Debian 系用 /etc/ssl。
# 这一步很关键 —— RHEL 默认【没有】/etc/ssl/private，直接写会导致
# openssl 报 "Can't open ... No such file or directory"。
if [ "$PKG_FAMILY" = "rpm" ] || [ -d /etc/pki/tls ]; then
  CERT_DIR="/etc/pki/tls/certs"; KEY_DIR="/etc/pki/tls/private"
else
  CERT_DIR="/etc/ssl/certs"; KEY_DIR="/etc/ssl/private"
fi
CERT="$CERT_DIR/${SITE_NAME}.crt"
KEY="$KEY_DIR/${SITE_NAME}.key"

pkg_install() {
  [ "$PKG_FAMILY" = "unknown" ] && return 1
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive $PKG_INSTALL "$@" >/dev/null 2>&1
}

# 让 nginx 加载当前配置：未运行则【启动】，运行中则重载，并确保开机自启。
# 必须区分这两种情况 —— RHEL 系安装 nginx 后【不会】自动启动
#（Debian 系会自动），只调用 reload 会得到 "nginx.service is not active"。
nginx_apply() {
  have nginx || return 1
  systemctl enable nginx >/dev/null 2>&1 || true
  if systemctl is-active nginx >/dev/null 2>&1; then
    systemctl reload nginx
  else
    warn "nginx 当前未在运行，正在启动 ..."
    systemctl start nginx
  fi
}

# ── 环境探测 ────────────────────────────────────────────────────────────────
TARGET_USER="$(detect_user)"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ] || die "找不到用户 $TARGET_USER 的家目录"
DSH_HOME="$TARGET_HOME/.dsh"
PROFILE_DIR="$DSH_HOME/profiles/$PROFILE"
PM2_HOME="$TARGET_HOME/.pm2"
OVERLAY="$DSH_HOME/${SITE_NAME}.patch.yml"
BOOT_SCRIPT="$DSH_HOME/${SITE_NAME}-bootstrap.mjs"
DSH_LOG="$TARGET_HOME/.pm2/logs/dsh-web-out.log"

DSH_BIN="$(command -v dsh 2>/dev/null || true)"
PM2_BIN="$(command -v pm2 2>/dev/null || true)"
NGINX_BIN="$(command -v nginx 2>/dev/null || true)"

LAN_IP="$(detect_ip)"
ACCESS_HOST="${HOST_ARG:-$LAN_IP}"
[ -n "$ACCESS_HOST" ] || die "无法探测本机 IP，请用 --host 指定对外访问地址"

TRUSTED=()
add_trusted() {
  local h="$1"; [ -n "$h" ] || return 0
  local x; for x in "${TRUSTED[@]:-}"; do [ "$x" = "$h" ] && return 0; done
  TRUSTED+=("$h")
}
add_trusted "$ACCESS_HOST"; add_trusted "$LAN_IP"
for h in "${TRUSTED_EXTRA[@]:-}"; do add_trusted "$h"; done

INSIDE_DSH=0
[ -n "${DSH_SESSION_ID:-}" ] && INSIDE_DSH=1

bad_plugins_found() {
  local p
  [ -d "$PROFILE_DIR" ] || return 0
  for p in "${KNOWN_BAD_PLUGINS[@]}"; do
    if [ -d "$PROFILE_DIR/node_modules/$p" ] || grep -q "\"$p\"" "$PROFILE_DIR/package.json" 2>/dev/null; then
      printf '%s\n' "$p"
    fi
  done
}

# ── 安装依赖 ────────────────────────────────────────────────────────────────
npm_install_global() {
  # 注意：必须分成两条 local。bash 的 local 会先把本行所有名字声明为局部（未赋值）
  # 再逐个赋值，所以 `local pkg="$1" args=(-g "$pkg")` 在 set -u 下会报
  # "pkg: unbound variable"，即使没有 set -u 也会拿到空值。
  local pkg="$1"
  local -a args=(-g "$pkg")
  [ -n "$NPM_REGISTRY" ] && args+=(--registry "$NPM_REGISTRY")
  npm install "${args[@]}" >/dev/null 2>&1 && return 0
  if [ -z "$NPM_REGISTRY" ]; then
    warn "npm 安装 $pkg 失败，改用镜像源重试：https://registry.npmmirror.com"
    npm install -g "$pkg" --registry https://registry.npmmirror.com >/dev/null 2>&1 && return 0
  fi
  return 1
}

node_major() { node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }

node_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo x64 ;;
    aarch64|arm64)  echo arm64 ;;
    armv7l)         echo armv7l ;;
    ppc64le)        echo ppc64le ;;
    s390x)          echo s390x ;;
    *)              echo "" ;;
  esac
}

# 把用户可能填错的镜像地址规整成「Node 发行包基址」。
# 常见错误：把 npm 包源地址（registry.npmmirror.com）当成 Node 镜像填进来。
normalize_node_source() {
  local u="${1%/}"
  case "$u" in
    *"/-/binary/node")                    printf '%s' "$u" ;;
    *"cdn.npmmirror.com/binaries/node")   printf 'https://registry.npmmirror.com/-/binary/node' ;;
    "https://registry.npmmirror.com"|"https://npmmirror.com"|"https://registry.npm.taobao.org")
                                          printf '%s/-/binary/node' "$u" ;;
    *)                                    printf '%s' "$u" ;;
  esac
}

# 从 npm 源推断对应的 Node 二进制镜像（目前只有 npmmirror/淘宝有这层关系）
npm_registry_node_source() {
  case "${NPM_REGISTRY:-}" in
    *npmmirror.com*|*npm.taobao.org*) printf 'https://registry.npmmirror.com/-/binary/node' ;;
  esac
  return 0
}

# 在给定镜像基址上解析出最新的 v<major> linux tarball 名。
# 注意：不能用命令替换调用（子 shell 里赋值传不出来），
# 成功设 NODE_NAME，失败设 NODE_ERR 并返回非 0。
NODE_NAME=""; NODE_ERR=""
node_resolve() { # $1=base $2=arch
  local base="${1%/}" arch="$2" url code listing name
  url="$base/latest-v${NODE_MAJOR}.x/"
  NODE_NAME=""; NODE_ERR=""
  listing="$(curl -fsSL --max-time 30 "$url" 2>/dev/null)" || {
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$url" 2>/dev/null || true)"
    [ -n "$code" ] || code=000
    case "$code" in
      000) NODE_ERR="连不上 $url —— DNS 解析失败 / 网络不通 / 被代理拦截（HTTP 000）" ;;
      403) NODE_ERR="被拒绝 $url（HTTP 403，该镜像可能屏蔽了你的出口 IP）" ;;
      404) NODE_ERR="该镜像没有这个路径 $url（HTTP 404，可能不是 Node 发行包镜像）" ;;
      *)   NODE_ERR="下载 $url 失败（HTTP $code）" ;;
    esac
    return 1
  }
  name="$(printf '%s' "$listing" \
    | grep -oE "node-v[0-9]+\.[0-9]+\.[0-9]+-linux-${arch}\.tar\.xz" \
    | sort -uV | tail -1)"
  if [ -z "$name" ]; then
    NODE_ERR="能访问 $url，但列表里没有 linux-${arch} 的 Node ${NODE_MAJOR}.x 包（镜像可能未同步）"
    return 1
  fi
  NODE_NAME="$name"
  return 0
}

# 网络自检：把真正卡住的原因摆出来
net_diag() {
  echo "   ── 网络自检 ─────────────────────────────────────────"
  echo "   默认路由     : $(ip route show default 2>/dev/null | head -1 | sed 's/^ *//' || echo 无)"
  echo "   DNS 服务器   : $(awk '/^nameserver/{printf "%s ",$2}' /etc/resolv.conf 2>/dev/null || echo 无)"
  echo "   代理环境变量 : http_proxy=${http_proxy:-<未设>}  https_proxy=${https_proxy:-<未设>}"
  local rc=""; [ -f /etc/curlrc ] && rc="/etc/curlrc"; [ -f "$HOME/.curlrc" ] && rc="$rc $HOME/.curlrc"
  echo "   curl 配置文件: ${rc:-<无>}"
  local h ip code
  for h in nodejs.org registry.npmmirror.com; do
    ip="$(getent hosts "$h" 2>/dev/null | awk '{print $1}' | head -1 || true)"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$h/" 2>/dev/null || true)"
    [ -n "$code" ] || code=000
    printf '   %-26s DNS=%-16s HTTPS=%s\n' "$h" "${ip:-解析失败}" "$code"
  done
  echo "   ─────────────────────────────────────────────────────"
}

# 最后兜底：用发行版自带的 nodejs 模块（仅 RHEL 系能按版本选）
try_distro_node() {
  [ "$PKG_FAMILY" = "rpm" ] || return 1
  have dnf || return 1
  dnf module list nodejs 2>/dev/null | grep -qE "nodejs[[:space:]]+${NODE_MAJOR}([[:space:]]|$)" || return 1
  warn "  改用发行版模块：dnf module install -y nodejs:${NODE_MAJOR}"
  dnf module install -y "nodejs:${NODE_MAJOR}" >/dev/null 2>&1 || return 1
  hash -r 2>/dev/null || true
  have node || return 1
  [ "$(node_major)" -ge "$NODE_MAJOR" ] 2>/dev/null || return 1
  return 0
}

# 从某个镜像安装 Node 到 /usr/local（官方发行包，自带 npm）
install_node_from() { # $1=base
  local base="${1%/}" arch name url tmp want got
  arch="$(node_arch)"
  [ -n "$arch" ] || { warn "  不支持的 CPU 架构：$(uname -m)"; return 1; }
  node_resolve "$base" "$arch" || { warn "  ${NODE_ERR:-解析失败}"; return 1; }
  name="$NODE_NAME"
  url="$base/latest-v${NODE_MAJOR}.x/$name"
  tmp="$(mktemp -d)"
  warn "  下载 $name"
  if ! curl -fsSL --max-time 600 -o "$tmp/node.tar.xz" "$url" 2>/dev/null; then
    rm -rf "$tmp"; warn "  下载失败：$url"; return 1
  fi
  want="$(curl -fsSL --max-time 30 "$base/latest-v${NODE_MAJOR}.x/SHASUMS256.txt" 2>/dev/null \
          | awk -v n="$name" '$2==n{print $1; exit}' || true)"
  if [ -n "$want" ]; then
    got="$(sha256sum "$tmp/node.tar.xz" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
      rm -rf "$tmp"; warn "  SHA256 校验失败（期望 $want，实际 $got），已放弃该镜像"; return 1
    fi
    ok "  SHA256 校验通过"
  else
    warn "  该镜像未提供 SHASUMS256.txt，跳过校验"
  fi
  if ! tar -xJf "$tmp/node.tar.xz" -C /usr/local --strip-components=1 --no-same-owner 2>/dev/null; then
    rm -rf "$tmp"; warn "  解包到 /usr/local 失败"; return 1
  fi
  rm -rf "$tmp"
  # SELinux 下新解出的二进制可能需要重贴标签
  if have getenforce && [ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ] && have restorecon; then
    restorecon -R /usr/local/bin /usr/local/lib /usr/local/include /usr/local/share >/dev/null 2>&1 || true
  fi
  hash -r 2>/dev/null || true
  return 0
}

ensure_node() {
  if have node && [ "$(node_major)" -ge "$NODE_MAJOR" ] 2>/dev/null; then
    ok "node: $(node -v)"; have npm && ok "npm : $(npm -v)" || die "缺少 npm"
    return
  fi
  [ "$INSTALL_NODE" = "0" ] && die "未找到 Node >= $NODE_MAJOR（--no-install-node 已禁用自动安装）"
  have node && warn "现有 Node $(node -v) 低于要求的 $NODE_MAJOR，将升级"
  have curl || die "需要 curl 才能下载 Node"
  warn "开始安装 Node ${NODE_MAJOR}.x（官方发行包 → /usr/local，不依赖第三方软件源）"

  # 组装候选镜像并去重：用户显式指定 > 从 npm 源推断 > 内置（官方 + npmmirror）
  local -a sources=()
  local cand s x dup
  for cand in \
      "$([ -n "$NODE_SOURCE" ] && normalize_node_source "$NODE_SOURCE")" \
      "$(npm_registry_node_source)" \
      "https://nodejs.org/dist" \
      "https://registry.npmmirror.com/-/binary/node" ; do
    [ -n "$cand" ] || continue
    cand="${cand%/}"
    dup=0
    for x in "${sources[@]:-}"; do [ "$x" = "$cand" ] && dup=1; done
    [ "$dup" = 1 ] || sources+=("$cand")
  done
  [ -n "$NODE_SOURCE" ] && ok "你指定的 Node 镜像：$(normalize_node_source "$NODE_SOURCE")"
  [ -z "$NODE_SOURCE" ] && [ -n "$NPM_REGISTRY" ] && [ -n "$(npm_registry_node_source)" ] \
    && ok "已从你的 npm 源自动推断出 Node 镜像"

  local installed=0
  local -a tried=()
  for s in "${sources[@]}"; do
    tried+=("$s")
    if install_node_from "$s"; then installed=1; break; fi
    warn "  该镜像不可用：$s"
  done

  if [ "$installed" != "1" ]; then
    echo
    warn "所有 Node 镜像都失败了。"
    if try_distro_node; then
      ok "已改由发行版模块装好 Node（$(node -v)）"
    else
      net_diag
      die "Node 自动安装失败。已尝试的镜像：
$(printf '     - %s\n' "${tried[@]}")
   常见原因与对策：
     * 机器上不了外网 / DNS 不通 → 用内网镜像：--node-source <你司镜像>/nodejs
     * 出口被代理拦截           → 先 export https_proxy=... 再重跑
     * 只想用系统自带 Node       → 手工装好 Node >= $NODE_MAJOR 后加 --no-install-node
     * 国内环境                 → --cn-mirror"
    fi
  fi
  have node || die "解包后仍找不到 node（确认 /usr/local/bin 在 PATH 中）"
  [ "$(node_major)" -ge "$NODE_MAJOR" ] 2>/dev/null || die "安装后的 Node 版本仍低于 $NODE_MAJOR"
  ok "node: $(node -v) ($(command -v node))"
  have npm && ok "npm : $(npm -v)" || die "缺少 npm（官方发行包应自带）"
}

ensure_dsh() {
  if [ -n "$DSH_BIN" ]; then ok "dsh: $DSH_BIN"; return; fi
  [ "$INSTALL_DSH" = "0" ] && die "未安装 dsh（--no-install-dsh 已禁用自动安装）"
  warn "未安装 dsh，开始 npm 全局安装 @deepseek-ai/dsh ..."
  npm_install_global "@deepseek-ai/dsh" || die "dsh 安装失败。可试：--npm-registry https://registry.npmmirror.com"
  hash -r 2>/dev/null || true
  DSH_BIN="$(command -v dsh 2>/dev/null || true)"
  [ -n "$DSH_BIN" ] || die "安装后仍找不到 dsh，请确认 npm 全局 bin 目录在 PATH 中"
  ok "dsh: $DSH_BIN（$(dsh --version 2>/dev/null || echo '?')）"
}

ensure_pm2() {
  if [ -n "$PM2_BIN" ]; then ok "pm2: $PM2_BIN"; return; fi
  [ "$INSTALL_PM2" = "0" ] && { warn "未安装 PM2（--no-install-pm2）；将跳过进程托管与开机自启"; return; }
  warn "未安装 pm2，开始 npm 全局安装 ..."
  if npm_install_global pm2; then
    hash -r 2>/dev/null || true
    PM2_BIN="$(command -v pm2 2>/dev/null || true)"
    [ -n "$PM2_BIN" ] && ok "pm2: $PM2_BIN" || warn "pm2 安装后仍找不到，将跳过托管"
  else
    warn "pm2 安装失败，将跳过进程托管与开机自启"
  fi
}

ensure_profile() {
  if [ -d "$PROFILE_DIR" ]; then ok "profile 已存在：$PROFILE_DIR"; return; fi
  warn "profile '$PROFILE' 尚未初始化，正在创建 ..."
  as_user "$DSH_BIN" --profile "$PROFILE" --dump-config >/dev/null 2>&1 \
    || die "profile 初始化失败，请手工运行一次：dsh --profile $PROFILE --dump-config"
  [ -d "$PROFILE_DIR" ] || die "profile 初始化后目录仍不存在：$PROFILE_DIR"
  ok "profile 已初始化：$PROFILE_DIR"
}

# ── 账号密码 ────────────────────────────────────────────────────────────────
prompt_credentials() {
  [ "$ASSUME_YES" = "1" ] && return 0
  [ -t 0 ] || return 0
  echo
  printf '   设置访问账号密码（直接回车 = 用括号里的默认值）\n'
  local u
  read -r -p "   用户名 [$AUTH_USER]: " u || true
  [ -n "${u:-}" ] && AUTH_USER="$u"
  if [ -z "$AUTH_PASS" ]; then
    local hint p1 p2
    if [ -f "$HTPASSWD" ]; then hint="留空 = 保持现有密码不变"
    else                        hint="留空 = 自动生成 20 位随机密码"
    fi
    read -r -s -p "   密码（$hint）: " p1 || true; echo
    if [ -n "${p1:-}" ]; then
      read -r -s -p "   再输一次确认: " p2 || true; echo
      [ "$p1" = "${p2:-}" ] || die "两次输入的密码不一致，已中止"
      AUTH_PASS="$p1"
    fi
  fi
}

# ── htpasswd 权限：必须让 Nginx worker 真的读得到 ───────────────────────────
# 踩坑记录（v3.0.0 → v3.0.1）：
#   Nginx 的 master 是 root，但【真正读密码文件的是 worker】，而 worker 会
#   setuid 成配置里 user 指定的身份。文件若是 root:root 640，worker 读不到，
#   auth_basic 在 access 阶段直接失败，浏览器只看到 500，日志里只有一行：
#     [crit] open() "/etc/nginx/.dsh-web.htpasswd" failed (13: Permission denied)
#   旧版把 chown 的失败用 `|| true` 吞掉，于是"脚本报 ✓、浏览器 500"。
#   现在：先确定 worker 的真实身份，改完再【以该身份真的读一次】。
NGINX_RUN_USER=""; NGINX_RUN_GROUP=""

detect_nginx_worker() {
  local line u g pid pu pg
  # 1) nginx -T 会打出 include 之后的完整配置（root 运行时最权威）
  line="$( { nginx -T 2>/dev/null || true; } \
    | sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([^;]*\);.*/\1/p' | head -1 )"
  # 2) 退回主配置（非 root 跑 --check 时 nginx -T 会失败）
  [ -n "$line" ] || line="$( sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([^;]*\);.*/\1/p' \
    /etc/nginx/nginx.conf 2>/dev/null | head -1 )"
  # 指令形如：user <用户> [组];   —— 用 set -- 切词，避免手写去空白的坑
  # shellcheck disable=SC2086
  set -- $line
  u="${1:-}"; g="${2:-}"
  # 3) 最可信：worker 进程的【实际】身份（配置写了什么、实际成了什么，以它为准）
  pid="$(ps -eo pid,args 2>/dev/null | awk '/nginx: worker process/ && !/awk/ {print $1; exit}')"
  if [ -n "${pid:-}" ]; then
    pu="$(ps -o user=  -p "$pid" 2>/dev/null | tr -d ' ')"
    pg="$(ps -o group= -p "$pid" 2>/dev/null | tr -d ' ')"
    [ -n "${pu:-}" ] && u="$pu"
    [ -n "${pg:-}" ] && g="$pg"
  fi
  # 4) 没有 user 指令 = 以启动者身份（通常 root）运行
  [ -n "${u:-}" ] || u="root"
  [ -n "${g:-}" ] || g="$(id -gn "$u" 2>/dev/null || echo root)"
  NGINX_RUN_USER="$u"; NGINX_RUN_GROUP="$g"
}

# 仅按权限位推断（无法切换身份时用；普通用户跑 --check 会走这里）
htpasswd_readable_by_bits() {
  local mode owner group d
  mode="$(stat -c '%a' "$HTPASSWD" 2>/dev/null || true)"
  [ -n "$mode" ] || return 1
  owner="$(stat -c '%U' "$HTPASSWD" 2>/dev/null || true)"
  group="$(stat -c '%G' "$HTPASSWD" 2>/dev/null || true)"
  d="${mode: -3}"
  [ "$owner" = "$NGINX_RUN_USER" ] && [ $(( ${d:0:1} & 4 )) -ne 0 ] && return 0
  [ "$group" = "$NGINX_RUN_GROUP" ] && [ $(( ${d:1:1} & 4 )) -ne 0 ] && return 0
  [ $(( ${d:2:1} & 4 )) -ne 0 ] && return 0
  return 1
}

# 以 Nginx worker 的身份真的读一次 —— 光看权限位不够（补充组 / ACL / SELinux
# 都可能让"看着能读"变成 Permission denied）。
htpasswd_readable_by_worker() {
  detect_nginx_worker
  [ -f "$HTPASSWD" ] || return 1
  [ "$NGINX_RUN_USER" = "root" ] && return 0
  if [ "$(id -u)" -eq 0 ]; then
    if have runuser; then
      runuser -u "$NGINX_RUN_USER" -- test -r "$HTPASSWD" 2>/dev/null && return 0 || return 1
    fi
    if have su; then
      su -s /bin/sh -c "test -r '$HTPASSWD'" "$NGINX_RUN_USER" 2>/dev/null && return 0 || return 1
    fi
    if have setpriv; then
      setpriv --reuid "$NGINX_RUN_USER" --regid "$NGINX_RUN_GROUP" --clear-groups \
        test -r "$HTPASSWD" 2>/dev/null && return 0 || return 1
    fi
    return 0   # root 但没有任何切换工具：无法判断，放行（下面 HTTP 探针会兜底）
  fi
  if have sudo && sudo -n -u "$NGINX_RUN_USER" test -r "$HTPASSWD" 2>/dev/null; then return 0; fi
  htpasswd_readable_by_bits
}

# 目标：root 可写 + nginx worker 可读（640）。绝不 644/777 —— 这是认证凭据。
fix_htpasswd_perms() {
  detect_nginx_worker
  local u="$NGINX_RUN_USER" g="$NGINX_RUN_GROUP"
  [ -n "$g" ] || g="$NGINX_GROUP"
  # SELinux 开着时，新建的点文件可能没贴上 httpd_config_t 标签
  if have getenforce && [ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ] && have restorecon; then
    restorecon -F "$HTPASSWD" >/dev/null 2>&1 || true
  fi
  chmod 640 "$HTPASSWD" 2>/dev/null || true
  chown "root:$g" "$HTPASSWD" 2>/dev/null || true
  if htpasswd_readable_by_worker; then
    ok "$HTPASSWD 权限：root:$g 640（nginx worker「$u」可读）"
    return 0
  fi
  # 退路：直接归 worker 用户所有（仍是 640，其他用户读不到）
  if [ "$u" != "root" ]; then
    chown "$u:$g" "$HTPASSWD" 2>/dev/null || true
    if htpasswd_readable_by_worker; then
      ok "$HTPASSWD 权限：$u:$g 640（nginx worker 可读）"
      return 0
    fi
  fi
  return 1
}

ensure_htpasswd_readable() {
  htpasswd_readable_by_worker && return 0
  detect_nginx_worker
  err "Nginx worker「$NGINX_RUN_USER」读不到 $HTPASSWD —— 浏览器只会得到 500"
  err "  （Nginx 日志特征是：open() \"$HTPASSWD\" failed (13: Permission denied)）"
  err "  当前权限：$(stat -c '%U:%G %a' "$HTPASSWD" 2>/dev/null || echo 缺失)"
  err "  手工修：chown root:$NGINX_RUN_GROUP $HTPASSWD && chmod 640 $HTPASSWD && systemctl reload nginx"
  exit 1
}

write_htpasswd() {
  printf '%s:%s\n' "$AUTH_USER" "$(openssl passwd -apr1 "$AUTH_PASS")" > "$HTPASSWD"
  fix_htpasswd_perms || true
  ensure_htpasswd_readable
}

https_url_local() {
  if [ "$HTTPS_PORT" = "443" ]; then printf 'https://127.0.0.1/'; else printf 'https://127.0.0.1:%s/' "$HTTPS_PORT"; fi
}

# 探针必须选一个【一定会经过 access 阶段】的入口。
#   location = / 里的 `if ($dsh_need_boot) { return 302 /_dsh_boot; }` 是
#   rewrite 阶段，比 auth_basic 的 access 阶段更早 —— 拿 / 验凭据时，
#   错误密码也照样 302 且没有 WWW-Authenticate（实测），验证等于没做。
#   /_dsh_boot 没有 if 短路，必然过 auth_basic，才是有效探针。
gate_probe_url() {
  local u; u="$(https_url_local)"     # 总是以 / 结尾
  if [ -f "$MAP_FILE" ] && grep -q 'dsh_need_boot' "$MAP_FILE" 2>/dev/null; then
    printf '%s_dsh_boot' "$u"
  else
    printf '%s' "$u"
  fi
}

# 门禁验证：无凭据必须 401 + WWW-Authenticate；正确凭据不能是 401/403/500。
# 只按 HTTP 状态码判定 —— 旧版"WWW-Authenticate 头为 0 就算通过"在
# 500（htpasswd 读不了）时同样是 0，属于假阳性。
verify_gate() { # $1 = 明文密码；为空则只做无凭据验证
  local probe code www pass_code
  probe="$(gate_probe_url)"
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "$probe" 2>/dev/null || true)"
  www="$(curl -sk -i --max-time 6 "$probe" 2>/dev/null | grep -ci '^www-authenticate' || true)"
  printf '   无密码  ：探针 %s → HTTP %s，WWW-Authenticate %s 个（期望 401 + 1 个）\n' \
    "${probe#https://127.0.0.1}" "${code:-连接失败}" "${www:-0}"
  if [ "${code:-}" != "401" ] || [ "${www:-0}" = "0" ]; then
    [ "${code:-}" = "500" ] && err "HTTP 500：典型原因是 Nginx worker 读不到 $HTPASSWD（权限 13）"
    die "Nginx 门禁未就绪（无凭据应为 401 + WWW-Authenticate，实际 $code）。已中止，DSH 未做任何改动。"
  fi
  ok "无密码被拒（401 + WWW-Authenticate）"

  [ -n "${1:-}" ] || { warn "未拿到明文密码，跳过「正确密码」验证"; return 0; }
  pass_code="$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH_USER:$1" --max-time 6 "$probe" 2>/dev/null || true)"
  printf '   正确密码：探针 %s → HTTP %s（期望：非 401/403/500）\n' \
    "${probe#https://127.0.0.1}" "${pass_code:-连接失败}"
  case "${pass_code:-}" in
    401|403) die "正确密码仍被拒（HTTP $pass_code）—— htpasswd 里的用户/密码与本次设置不一致。已中止。" ;;
    500)     die "HTTP 500 —— Nginx worker 读不到 $HTPASSWD（日志：Permission denied）。已中止。" ;;
    200|201|204|301|302|303|307|308) ok "凭据可用（HTTP $pass_code，已穿过 Nginx）" ;;
    502|503|504) ok "凭据可用（HTTP $pass_code ＝ 认证已通过，只是上游还没就绪）" ;;
    4??)     ok "凭据可用（HTTP $pass_code ＝ 认证已通过，4xx 来自上游 DSH 而非门禁）" ;;
    *)       warn "凭据验证返回 HTTP ${pass_code:-连接失败}，无法确定；请用浏览器实测" ;;
  esac
}

cred_path() {
  if [ -n "$CRED_FILE" ]; then printf '%s' "$CRED_FILE"
  elif [ "$(id -u)" -eq 0 ]; then printf '/root/%s-credentials.txt' "$SITE_NAME"
  else printf '%s/%s-credentials.txt' "$HOME" "$SITE_NAME"
  fi
}

# 把明文凭据另存一份（600），方便事后取回；--no-save-credentials 可关闭
save_credentials() {
  [ "$SAVE_CRED" = "1" ] || return 0
  [ -n "$AUTH_PASS" ] || return 0
  local f; f="$(cred_path)"
  {
    echo "# 由 dsh-web-hardening.sh v$VERSION 生成于 $(date -Is)"
    echo "#"
    echo "# ⚠️ 本文件是【明文】凭据（权限 600）—— 请妥善保存，不需要后请自行删除。"
    echo "#"
    echo "# 另：/etc/nginx/.dsh-web.htpasswd 里只有 apr1 哈希："
    echo "#   * 不能直接用于登录 —— HTTP Basic 必须提交明文，nginx 收到后自己算哈希比对；"
    echo "#   * 但它可被离线暴力破解，所以同样不要外传。真正要保护的是下面这份明文。"
    echo
    echo "url      = https://$ACCESS_HOST$([ "$HTTPS_PORT" = "443" ] && echo "" || echo ":$HTTPS_PORT")/"
    echo "username = $AUTH_USER"
    echo "password = $AUTH_PASS"
  } > "$f"
  chmod 600 "$f"
  ok "凭据已保存：$f（600，明文，请妥善保管）"
}

do_show_credentials() {
  local f; f="$(cred_path)"
  [ -f "$f" ] || die "找不到凭据文件：$f（安装时可能用了 --no-save-credentials）"
  cat "$f"
}

do_credentials() {
  step "设置访问账号密码"
  have openssl || die "缺少 openssl"
  if [ -f "$HTPASSWD" ]; then ok "将更新 $HTPASSWD"
  else warn "尚未发现 $HTPASSWD（若还没跑过完整安装，请先执行：sudo $0）"; fi

  prompt_credentials

  if [ -z "$AUTH_PASS" ]; then
    if [ -f "$HTPASSWD" ]; then
      ok "未输入新密码 —— 保持现有密码不变"
      echo; echo "  用户名（未变）：$AUTH_USER"; echo
      return 0
    fi
    AUTH_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)"
    ok "已生成 20 位随机密码"
  else
    ok "使用你设置的密码"
  fi

  write_htpasswd
  ok "已写入 $HTPASSWD（用户：$AUTH_USER）"

  if nginx -t >/dev/null 2>&1; then
    nginx_apply >/dev/null 2>&1 && ok "nginx 已加载新配置（不需要重启 DSH）" || warn "nginx 启动/重载失败"
  else
    warn "nginx 配置检查失败，未重载；请先确认 Nginx 站点配置正常"
  fi

  verify_gate "$AUTH_PASS"
  echo
  echo "============================================================"
  echo "  用户名 : $AUTH_USER"
  echo "  密码   : $AUTH_PASS"
  echo "============================================================"
  echo
  save_credentials
  echo
}

# ── 环境状态检测：决定这次该"全新安装"还是"重新加固/修复" ──────────────────
# 结果放在 STATE_* 里，并给出一个结论 STATE = fresh | reapply | repair
detect_state() {
  STATE_DSH=0; STATE_PROFILE=0; STATE_HARDENED=0; STATE_RUNNING=0
  STATE_LOOPBACK=0; STATE_AUTOSTART=0; STATE_NGINX=0; STATE_BOOT=0; STATE_LISTEN=""
  if [ -n "$DSH_BIN" ]; then STATE_DSH=1; fi
  if [ -d "$PROFILE_DIR" ]; then STATE_PROFILE=1; fi
  if [ -f "$SITE_AVAIL" ] && [ -f "$HTPASSWD" ] && [ -f "$CERT" ]; then STATE_HARDENED=1; fi
  if [ -n "$PM2_BIN" ] && pm2_has_dsh; then STATE_RUNNING=1; fi
  STATE_LISTEN="$(ss -tlnH "sport = :$DSH_PORT" 2>/dev/null | awk '{print $4}' | head -1 || true)"
  if [ "$STATE_LISTEN" = "127.0.0.1:$DSH_PORT" ]; then STATE_LOOPBACK=1; fi
  if systemctl is-enabled "pm2-$TARGET_USER" >/dev/null 2>&1; then STATE_AUTOSTART=1; fi
  if systemctl is-enabled nginx >/dev/null 2>&1; then STATE_NGINX=1; fi
  if [ -f "$BOOT_SCRIPT" ]; then STATE_BOOT=1; fi

  if [ "$STATE_HARDENED" = "1" ]; then STATE="reapply"; else STATE="fresh"; fi
  # 上次中断留下的半成品 → 修复
  if [ "$STATE_HARDENED" = "0" ] && { [ -f "$SITE_AVAIL" ] || [ -f "$OVERLAY" ] || [ -f "$BOOT_SCRIPT" ]; }; then
    STATE="repair"
  fi
  # 装了有问题的插件、或 DSH 暴露在非回环 → 必须修复
  if [ -n "$(bad_plugins_found)" ]; then STATE="repair"; fi
  if [ "$STATE_RUNNING" = "1" ] && [ "$STATE_LOOPBACK" = "0" ]; then STATE="repair"; fi
  return 0
}

report_state() {
  local dsh_txt prof_txt hard_txt run_txt auto_txt
  if [ "$STATE_DSH" = "1" ]; then dsh_txt="已安装 $("$DSH_BIN" --version 2>/dev/null || echo '?')（$DSH_BIN）"; else dsh_txt="未安装（将自动安装）"; fi
  if [ "$STATE_PROFILE" = "1" ]; then prof_txt="已存在"; else prof_txt="未初始化（将自动创建）"; fi
  case "$STATE" in
    reapply) hard_txt="已加固（本次为幂等重新应用）" ;;
    repair)  hard_txt="部分/异常 —— 需要修复" ;;
    *)       hard_txt="未加固（本次为全新安装）" ;;
  esac
  if [ "$STATE_RUNNING" = "1" ]; then
    run_txt="运行中（监听 ${STATE_LISTEN:-?}）"
    [ "$STATE_LOOPBACK" = "1" ] && run_txt="$run_txt ✓ 仅回环" || run_txt="$run_txt ← 暴露在局域网，需要修复"
  else
    run_txt="未运行"
  fi
  [ "$STATE_AUTOSTART" = "1" ] && auto_txt="已启用" || auto_txt="未启用"
  printf '   %-14s %s\n' "DSH"        "$dsh_txt"
  printf '   %-14s %s\n' "profile"    "$prof_txt"
  printf '   %-14s %s\n' "加固状态"   "$hard_txt"
  printf '   %-14s %s\n' "DSH 进程"   "$run_txt"
  printf '   %-14s %s / %s\n' "nginx" "$([ "$STATE_NGINX" = 1 ] && echo 已启用自启 || echo 未启用自启)" "$(systemctl is-active nginx 2>/dev/null || echo 未运行)"
  printf '   %-14s %s\n' "开机自启"   "$auto_txt"
}

# ── 开机自启：应用 / 询问 ──────────────────────────────────────────────────
apply_autostart() { # $1 = 1 开启, 0 关闭
  local want="$1"
  if [ -z "$PM2_BIN" ]; then
    warn "未检测到 PM2，无法设置开机自启（进程托管也已跳过）"
    return 0
  fi
  if [ "$want" = "1" ]; then
    if systemctl is-enabled "pm2-$TARGET_USER" >/dev/null 2>&1; then
      ok "开机自启已启用：pm2-$TARGET_USER.service"
    else
      env PATH="$PATH" "$PM2_BIN" startup systemd -u "$TARGET_USER" --hp "$TARGET_HOME" >/dev/null 2>&1 || true
      if systemctl is-enabled "pm2-$TARGET_USER" >/dev/null 2>&1; then
        ok "已启用开机自启：pm2-$TARGET_USER.service"
      else
        warn "开机自启未能装上（可能缺 systemd 权限）。可手工执行："
        warn "  sudo env PATH=\$PATH $PM2_BIN startup systemd -u $TARGET_USER --hp $TARGET_HOME"
      fi
    fi
    as_user "$PM2_BIN" save >/dev/null 2>&1 && ok "已保存进程列表（pm2 save）"
  else
    if systemctl is-enabled "pm2-$TARGET_USER" >/dev/null 2>&1; then
      systemctl disable "pm2-$TARGET_USER" >/dev/null 2>&1 || true
      ok "已关闭开机自启（单元文件保留，随时可用 --autostart 重新开启）"
    else
      ok "开机自启本来就是关闭的"
    fi
    warn "注意：不设开机自启时，机器重启后 DSH 不会自动起来"
  fi
}

# 决定这次要不要开机自启：显式参数 > 非交互默认开 > 交互询问
resolve_autostart() {
  if [ "$AUTOSTART_WANT" = "1" ] || [ "$AUTOSTART_WANT" = "0" ]; then
    printf '%s' "$AUTOSTART_WANT"; return 0
  fi
  if [ "$ASSUME_YES" = "1" ] || [ ! -t 0 ]; then printf '1'; return 0; fi
  local a
  printf '   是否设置开机自启（pm2 + nginx）？[Y/n]: ' >&2
  read -r a || true
  case "${a:-Y}" in [nN]*) printf '0' ;; *) printf '1' ;; esac
}

do_set_autostart() {
  step "调整开机自启"
  detect_state
  if [ "$AUTOSTART_WANT" = "1" ] || [ "$AUTOSTART_WANT" = "0" ]; then
    apply_autostart "$AUTOSTART_WANT"
  else
    printf '   当前状态：%s\n' "$([ "$STATE_AUTOSTART" = "1" ] && echo 启用 || echo 关闭)"
    apply_autostart "$(resolve_autostart)"
  fi
  echo
  if systemctl is-enabled "pm2-$TARGET_USER" >/dev/null 2>&1; then
    echo "  现在：开机自启 = 启用（pm2-$TARGET_USER.service）"
  else
    echo "  现在：开机自启 = 关闭"
  fi
  echo
}

# ── PM2 辅助 ────────────────────────────────────────────────────────────────
pm2_has_dsh() {
  [ -n "$PM2_BIN" ] || return 1
  as_user "$PM2_BIN" jlist 2>/dev/null | node -e '
    let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
      try{const l=JSON.parse(s);
        const p=l.find(x=>x.name==="dsh-web")
             || l.find(x=>x.pm2_env&&x.pm2_env.pm_exec_path===process.env.DSH_BIN);
        process.exit(p?0:1);
      }catch(e){process.exit(1)}
    })' 2>/dev/null
}

current_pm2_args_filtered() {
  as_user "$PM2_BIN" jlist 2>/dev/null | node -e '
    let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
      let out=[];
      try{
        const l=JSON.parse(s);
        const p=l.find(x=>x.name==="dsh-web")
             || l.find(x=>x.pm2_env&&x.pm2_env.pm_exec_path===process.env.DSH_BIN);
        let a=(p&&(p.args||(p.pm2_env&&p.pm2_env.args)))||[];
        if(typeof a==="string") a=a.split(/\s+/).filter(Boolean);
        const ov=process.env.OVERLAY||"";
        for(let i=0;i<a.length;i++){
          const t=a[i];
          if(t==="--trusted-host"){ i++; continue; }
          if(t.startsWith("--trusted-host=")) continue;
          if(t==="--patch"&&a[i+1]===ov){ i++; continue; }
          if(t==="--patch="+ov) continue;
          out.push(t);
        }
      }catch(e){}
      if(out.length===0) out=["--profile", process.env.PROFILE||"web"];
      process.stdout.write(out.join("\n")+"\n");
    })' 2>/dev/null
}

# ── 引导侧车 ────────────────────────────────────────────────────────────────
write_bootstrap() {
  cat > "$BOOT_SCRIPT" <<BOOTEOF
// ${SITE_NAME} 引导侧车 —— 由 dsh-web-hardening.sh v${VERSION} 生成
//
// 作用：DSH 核心要求每个浏览器先用一次进程级 launch token 换取签名 cookie。
// 本进程替你完成这次交换，只把 Set-Cookie 转给浏览器 —— 浏览器 URL 里
// 永远不会出现 token。仅监听 127.0.0.1，且只能经 Nginx 的密码门禁到达。
import http from "node:http";
import fs from "node:fs";

const PORT = Number(process.env.DSH_BOOT_PORT || ${BOOT_PORT});
const DSH_PORT = Number(process.env.DSH_DSH_PORT || ${DSH_PORT});
const LOG = process.env.DSH_DSH_LOG || ${DSH_LOG@Q};

function currentToken() {
  try {
    const txt = fs.readFileSync(LOG, "utf8");
    const m = [...txt.matchAll(/token=([A-Za-z0-9_-]{20,})/g)];
    return m.length ? m[m.length - 1][1] : null;
  } catch {
    return null;
  }
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET" || !String(req.url).startsWith("/_dsh_boot")) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
    return;
  }
  const token = currentToken();
  if (token === null) {
    res.writeHead(503, { "content-type": "text/html; charset=utf-8", "retry-after": "3" });
    res.end("<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=3>"
      + "<title>DSH 正在启动</title>"
      + "<body style='font-family:system-ui;padding:2rem'>DSH 正在启动，3 秒后自动重试…</body>");
    return;
  }
  const host = req.headers.host || ("127.0.0.1:" + DSH_PORT);
  const upstream = http.request(
    { host: "127.0.0.1", port: DSH_PORT, path: "/?token=" + encodeURIComponent(token), method: "GET", headers: { host } },
    (up) => {
      const headers = { location: "/", "cache-control": "no-store" };
      const sc = up.headers["set-cookie"];
      if (typeof sc !== "undefined") headers["set-cookie"] = sc;
      res.writeHead(303, headers);
      res.end();
    }
  );
  upstream.on("error", (e) => {
    res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    res.end("bootstrap failed: " + String(e));
  });
  upstream.end();
});

server.listen(PORT, "127.0.0.1", () => {
  console.log("${BOOT_APP} listening on 127.0.0.1:" + PORT);
});
BOOTEOF
  chown "$TARGET_USER:$TARGET_USER" "$BOOT_SCRIPT" 2>/dev/null || true
  chmod 600 "$BOOT_SCRIPT"
  ok "引导侧车脚本：$BOOT_SCRIPT"
}

start_bootstrap() {
  [ -n "$PM2_BIN" ] || { warn "无 PM2，跳过引导侧车（请手动打开一次带 token 的地址）"; return; }
  as_user "$PM2_BIN" delete "$BOOT_APP" >/dev/null 2>&1 || true
  as_user env DSH_BOOT_PORT="$BOOT_PORT" DSH_DSH_PORT="$DSH_PORT" DSH_DSH_LOG="$DSH_LOG" \
    "$PM2_BIN" start "$BOOT_SCRIPT" --name "$BOOT_APP" --interpreter node >/dev/null \
      || { warn "引导侧车启动失败（将退化为手动 token 方式）"; return; }
  local i up=""
  for i in $(seq 1 15); do
    if ss -tlnH "sport = :$BOOT_PORT" 2>/dev/null | grep -q "127\.0\.0\.1:$BOOT_PORT"; then up=1; break; fi
    sleep 1
  done
  [ -n "$up" ] && ok "引导侧车已监听 127.0.0.1:$BOOT_PORT（等待 ${i}s）" \
               || warn "引导侧车未就绪，请查看：sudo -u $TARGET_USER pm2 logs $BOOT_APP"
}

# ── 体检 ────────────────────────────────────────────────────────────────────
do_check() {
  local listen https_code token_leak bad boot_listen
  step "系统 / 环境"
  printf '   %-26s %s\n' "发行版族"        "$PKG_FAMILY（包管理：${PKG_INSTALL:-未知}）"
  printf '   %-26s %s\n' "DSH 用户"        "$TARGET_USER ($TARGET_HOME)"
  printf '   %-26s %s\n' "dsh 可执行文件"  "${DSH_BIN:-未安装}"
  printf '   %-26s %s\n' "profile 目录"    "$([ -d "$PROFILE_DIR" ] && echo "$PROFILE_DIR" || echo 缺失)"
  printf '   %-26s %s\n' "node / npm"      "$(node -v 2>/dev/null || echo 未安装) / $(npm -v 2>/dev/null || echo -)"
  printf '   %-26s %s\n' "PM2"             "${PM2_BIN:-未安装}"
  printf '   %-26s %s\n' "本机 IP"         "${LAN_IP:-<无>}"
  # ⚠️ 下面这几行刻意【不用】带引号的 awk：bash 在 "..." 内扫描 $( ) 时，
  # awk 程序里的引号/括号会把引号配对搞乱（已实测复现）。统一改用 sed/tr/cut。
  printf '   %-26s %s\n' "运行时长"        "$(uptime -p 2>/dev/null | sed 's/^up //' || echo '?')"
  printf '   %-26s %s\n' "内存 已用"    "$(free -h 2>/dev/null | sed -n '2p' | tr -s ' ' | cut -d' ' -f3 || true)"
  printf '   %-26s %s\n' "根分区 可用"      "$(df -h / 2>/dev/null | sed -n '2p' | tr -s ' ' | cut -d' ' -f4 || true)"
  printf '   %-26s %s\n' "SELinux"         "$(getenforce 2>/dev/null || echo 未启用)"

  step "外网连通性（Node 自动安装依赖）"
  local h
  for h in nodejs.org registry.npmmirror.com rpm.nodesource.com; do
    local hip hcode
    hip="$(getent hosts "$h" 2>/dev/null | awk '{print $1}' | head -1 || true)"
    hcode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "https://$h/" 2>/dev/null || true)"
    [ -n "$hcode" ] || hcode=000
    printf '   %-24s DNS=%-16s HTTPS=%s\n' "$h" "${hip:-解析失败}" "$hcode"
  done
  printf '   %-24s %s\n' "代理变量" "http_proxy=${http_proxy:-<未设>} https_proxy=${https_proxy:-<未设>}"

  step "网络边界（最关键）"
  listen="$(ss -tlnH "sport = :$DSH_PORT" 2>/dev/null | awk '{print $4}' | head -1 || true)"
  printf '   %-26s %s\n' "$DSH_PORT 监听地址" "${listen:-<未监听>}"
  if [ "${listen:-}" = "127.0.0.1:$DSH_PORT" ]; then ok "DSH 只监听回环，局域网无法绕过 Nginx 直连"
  elif [ -n "${listen:-}" ]; then err "DSH 监听在 ${listen} —— 局域网可绕过 Nginx 直接访问！"
  else warn "DSH 未在监听 $DSH_PORT"; fi
  token_leak="$(curl -s -i --max-time 5 "http://127.0.0.1:$DSH_PORT/" 2>/dev/null | grep -ci 'token=' || true)"
  printf '   %-26s %s\n' "本机 GET / 泄漏 token" "$([ "${token_leak:-0}" != "0" ] && echo '是 ✗（说明装了有问题的插件）' || echo '否 ✓')"
  bad="$(bad_plugins_found | tr '\n' ' ' | sed -E 's/ +$//')"
  printf '   %-26s %s\n' "已知问题插件"    "${bad:-无 ✓}"

  step "Nginx 门禁"
  printf '   %-26s %s\n' "nginx 服务"   "$(systemctl is-enabled nginx 2>/dev/null || echo 未安装) / $(systemctl is-active nginx 2>/dev/null || echo -)"
  printf '   %-26s %s\n' "站点文件"     "$([ -f "$SITE_AVAIL" ] && echo "$SITE_AVAIL" || echo 缺失)"
  printf '   %-26s %s\n' "TLS 证书"     "$([ -f "$CERT" ] && echo 存在 || echo 缺失)"
  printf '   %-26s %s\n' "basic auth"   "$([ -f "$HTPASSWD" ] && echo 存在 || echo 缺失)"
  # 这一行专门用来提前发现"浏览器 500"：worker 读不到 htpasswd 时，
  # auth_basic 直接失败，日志只有 open() ... Permission denied。
  local hp_perm hp_read
  if [ -f "$HTPASSWD" ]; then
    hp_perm="$(stat -c '%U:%G %a' "$HTPASSWD" 2>/dev/null || echo '?')"
    if htpasswd_readable_by_worker; then hp_read="可读 ✓"; else hp_read="不可读 ✗ → 浏览器会 500"; fi
  else hp_perm="缺失"; hp_read="-"; fi
  detect_nginx_worker
  printf '   %-26s %s\n' "htpasswd 权限" "$hp_perm（nginx worker「$NGINX_RUN_USER:$NGINX_RUN_GROUP」：$hp_read）"
  # 探针同样要走 /_dsh_boot：/ 的 302 在 auth_basic 之前返回，拿 / 体检会误报
  local url; url="https://$ACCESS_HOST$([ "$HTTPS_PORT" = "443" ] && echo "" || echo ":$HTTPS_PORT")/"
  if [ -f "$MAP_FILE" ] && grep -q 'dsh_need_boot' "$MAP_FILE" 2>/dev/null; then url="${url}_dsh_boot"; fi
  https_code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "$url" 2>/dev/null || true)"
  printf '   %-26s %s\n' "HTTPS 无密码"  "${https_code:-连接失败}  (期望 401)"
  if [ "${https_code:-}" = "401" ]; then
    ok "密码门禁生效"
  elif [ "${https_code:-}" = "500" ]; then
    err "门禁返回 500：Nginx 读不到密码文件 —— 看上面 htpasswd 权限那一行"
  else
    warn "门禁未生效，或证书/端口未就绪"
  fi

  step "自动登录（引导侧车）"
  boot_listen="$(ss -tlnH "sport = :$BOOT_PORT" 2>/dev/null | awk '{print $4}' | head -1 || true)"
  printf '   %-26s %s\n' "$BOOT_PORT 监听" "${boot_listen:-<未运行>}"
  [ -n "${boot_listen:-}" ] && ok "侧车在跑 → 浏览器打开站点即可，无需手动粘 token" \
                            || warn "侧车未运行 → 首次进入需手动打开一次带 token 的地址"

  step "开机自启"
  printf '   %-26s %s\n' "pm2-$TARGET_USER" "$(systemctl is-enabled "pm2-$TARGET_USER" 2>/dev/null || echo 缺失) / $(systemctl is-active "pm2-$TARGET_USER" 2>/dev/null || echo -)"
  printf '   %-26s %s\n' "nginx"            "$(systemctl is-enabled nginx 2>/dev/null || echo 缺失)"
  printf '   %-26s %s\n' "cookieMaxAgeDays" "$(grep -o 'cookieMaxAgeDays: *[0-9]*' "$OVERLAY" 2>/dev/null || echo '未设置（默认 30 天）')"
  echo
}

# ── 卸载：只清配置，不卸软件 ────────────────────────────────────────────────
do_uninstall() {
  local removed=0
  step "卸载：只清理本脚本创建的配置（不会卸载任何软件包）"

  # 1. 引导侧车
  if [ -n "$PM2_BIN" ]; then
    if as_user "$PM2_BIN" delete "$BOOT_APP" >/dev/null 2>&1; then ok "已停止并移除引导侧车进程"; fi
  fi
  if [ -f "$BOOT_SCRIPT" ]; then rm -f "$BOOT_SCRIPT"; ok "已删除侧车脚本 $BOOT_SCRIPT"; removed=1; fi

  # 2. Nginx 站点与辅助配置
  local f
  for f in "$SITE_ENABLED" "$SITE_AVAIL" "$MAP_FILE" "$PROXY_SNIPPET"; do
    if [ -e "$f" ] || [ -L "$f" ]; then rm -f "$f"; ok "已删除 $f"; removed=1; fi
  done

  # 3. 凭据与证书（两种发行版惯例的路径都清一遍，避免换过发行版后留残留）
  for f in "$HTPASSWD" "$CERT" "$KEY" \
           "/etc/ssl/certs/${SITE_NAME}.crt"  "/etc/ssl/private/${SITE_NAME}.key" \
           "/etc/pki/tls/certs/${SITE_NAME}.crt" "/etc/pki/tls/private/${SITE_NAME}.key"; do
    if [ -f "$f" ]; then rm -f "$f"; ok "已删除 $f"; removed=1; fi
  done

  # 4. patch 覆盖层
  if [ -f "$OVERLAY" ]; then rm -f "$OVERLAY"; ok "已删除 $OVERLAY"; removed=1; fi

  # 5. 重载 Nginx（站点已被移除，配置应仍合法）
  if have nginx; then
    if nginx -t >/dev/null 2>&1; then nginx_apply >/dev/null 2>&1 && ok "nginx 已加载新配置" || warn "nginx 启动/重载失败"; else warn "nginx 配置检查失败，请手工检查"; fi
  fi

  # 6. 把 DSH 启动参数里的本脚本痕迹去掉（否则重启会引用已删除的 overlay 而失败）
  if [ -n "$PM2_BIN" ] && pm2_has_dsh; then
    local -a args; mapfile -t args < <(current_pm2_args_filtered)
    # 同安装路径：保证非空且带 --profile（否则 set -u 会炸，或 DSH 起不来）
    local has_profile=0 a
    for a in "${args[@]:-}"; do [ "$a" = "--profile" ] && has_profile=1; done
    [ "$has_profile" = "1" ] || args=("--profile" "$PROFILE" "${args[@]:-}")
    as_user "$PM2_BIN" delete dsh-web >/dev/null 2>&1 || true
    as_user "$PM2_BIN" start "$DSH_BIN" --name dsh-web -- "${args[@]}" >/dev/null 2>&1 || true
    as_user "$PM2_BIN" save >/dev/null 2>&1 || true
    ok "DSH 启动参数已还原（仍只监听回环）"
  fi

  # 7. --purge：额外移除本脚本引入的系统级配置
  if [ "$PURGE" = "1" ]; then
    local unit="/etc/systemd/system/pm2-$TARGET_USER.service"
    if [ -f "$unit" ]; then
      systemctl disable "pm2-$TARGET_USER" >/dev/null 2>&1 || true
      rm -f "$unit"; systemctl daemon-reload >/dev/null 2>&1 || true
      ok "已移除 PM2 开机自启单元 $unit"
    fi
    local ns
    for ns in /etc/apt/sources.list.d/nodesource.list /etc/yum.repos.d/nodesource*.repo; do
      [ -f "$ns" ] && { rm -f "$ns"; ok "已移除 NodeSource 源配置 $ns"; }
    done
    rm -f /etc/apt/keyrings/nodesource.gpg /usr/share/keyrings/nodesource.gpg 2>/dev/null || true
  fi

  [ "$removed" = "0" ] && warn "没有发现本脚本创建的配置文件（可能已卸载过）"

  echo
  echo "============================================================"
  echo "  卸载完成 —— 只删了配置，软件包全部保留"
  echo
  echo "  DSH 仍只监听 127.0.0.1，请通过 SSH 隧道访问："
  echo "      ssh -N -L $DSH_PORT:127.0.0.1:$DSH_PORT $TARGET_USER@$ACCESS_HOST"
  echo "      浏览器打开 DSH 启动日志里的 http://127.0.0.1:$DSH_PORT/?token=..."
  echo
  echo "  本脚本可能安装过以下软件包，如需一并清理请自行执行："
  case "$PKG_FAMILY" in
    deb) echo "      apt-get purge -y nginx nodejs && npm uninstall -g pm2 @deepseek-ai/dsh" ;;
    rpm) echo "      dnf remove -y nginx nodejs && npm uninstall -g pm2 @deepseek-ai/dsh" ;;
    *)   echo "      请按你的包管理器清理 nginx / nodejs / pm2 / @deepseek-ai/dsh" ;;
  esac
  echo "  注意：~/.dsh（DSH 自己的数据与配置）始终不会被本脚本删除。"
  echo "============================================================"
  echo
}

# =============================================================================
#  install
# =============================================================================
do_install() {
  echo
  echo "============================================================"
  echo "  DSH Web 一键部署 + 加固   v$VERSION"
  echo "============================================================"
  printf '  发行版      : %s（%s）\n' "${PKG_FAMILY:-unknown}" "${PKG_INSTALL:-未知包管理}"
  printf '  DSH 用户    : %s\n' "$TARGET_USER"
  printf '  访问地址    : https://%s%s/\n' "$ACCESS_HOST" "$([ "$HTTPS_PORT" = "443" ] && echo "" || echo ":$HTTPS_PORT")"
  printf '  trustedHosts: %s\n' "${TRUSTED[*]}"
  printf '  自动登录    : %s\n' "$([ "$AUTO_TOKEN" = "1" ] && echo '启用（浏览器无需 token）' || echo '关闭（首次需手动粘 token）')"
  echo "============================================================"
  echo
  detect_state
  report_state
  case "$STATE" in
    reapply) echo "   => 本次将执行：重新加固（幂等，安全可重复）" ;;
    repair)  echo "   => 本次将执行：修复（检测到半成品 / 暴露 / 冲突插件）" ;;
    *)       echo "   => 本次将执行：全新安装" ;;
  esac
  echo "============================================================"

  if [ "$TARGET_USER" = "root" ]; then
    echo
    warn "════════════════════════════════════════════════════════════"
    warn " DSH 运行用户是 root —— 风险很高："
    warn " DSH Web 等于一个能执行任意命令的 agent；用 root 跑意味着"
    warn " 任何一次进入都等同于拿到整台机器的 root 权限。"
    warn ""
    warn " 建议先建专用用户再装（推荐）："
    warn "   useradd -m -s /bin/bash dsh"
    warn "   ./dsh-web-hardening.sh --user dsh --node-source <镜像> ..."
    warn "════════════════════════════════════════════════════════════"
    if [ "$ALLOW_ROOT_DSH" != "1" ]; then
      if [ "$ASSUME_YES" = "1" ] || [ ! -t 0 ]; then
        die "已拒绝：以 root 身份运行 DSH 需显式加 --allow-root-dsh"
      fi
      local ans
      read -r -p "   确定继续？输入 yes 确认：" ans || true
      [ "${ans:-}" = "yes" ] || die "已取消（可用 --user <用户名> 指定普通用户）"
    fi
  fi

  if [ "$INSIDE_DSH" = "1" ]; then
    echo
    warn "检测到你在 DSH 会话【内部】运行本脚本。脚本会重启 DSH，"
    warn "从而切断当前连接。建议改在 SSH 会话中执行。"
  fi
  if [ "$PKG_FAMILY" = "unknown" ]; then
    warn "无法识别发行版：自动安装 nginx/node 将不可用，请确保它们已就绪"
  fi

  [ "$ASSUME_YES" != "1" ] && prompt_credentials

  # ── 1. 依赖 ───────────────────────────────────────────────────────────────
  step "1/9 检查依赖"
  ensure_node
  if [ -z "$NGINX_BIN" ]; then
    [ "$NO_DEPS" = "1" ] && die "未安装 nginx（--no-deps 已禁用自动安装）"
    [ "$PKG_FAMILY" = "unknown" ] && die "未安装 nginx，且无法识别发行版自动安装"
    warn "未安装 nginx，开始安装 ..."
    pkg_install nginx || die "nginx 安装失败，请手工安装后重跑"
    hash -r 2>/dev/null || true
    NGINX_BIN="$(command -v nginx || true)"
    [ -n "$NGINX_BIN" ] || die "安装后仍找不到 nginx"
  fi
  ok "nginx: $NGINX_BIN"
  have openssl || die "缺少 openssl"
  ok "openssl: $(command -v openssl)"
  have curl || die "缺少 curl"
  ensure_pm2

  # nginx 版本决定 http2 写法（1.25.1 起推荐独立的 `http2 on;`）
  local nv http2_new=0
  nv="$("$NGINX_BIN" -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p')"
  if [ -n "$nv" ] && ver_ge "$nv" "1.25.1"; then http2_new=1; fi
  # 预先把可选片段算好，避免在 heredoc 里做命令替换（set -e 下不稳）
  local LISTEN_HTTP2=" http2" HTTP2_LINE=""
  if [ "$http2_new" = "1" ]; then LISTEN_HTTP2=""; HTTP2_LINE="    http2 on;"; fi
  # 无 IPv6 的机器上 listen [::] 会导致 bind 失败，提前判断
  # 注意：HTTP 跳转块和 HTTPS 块需要【两条不同的】IPv6 行 ——
  # 给 80 端口套上 "ssl" 会让 nginx 报
  #   no "ssl_certificate" is defined for the "listen ... ssl" directive
  local IPV6_LINES="" IPV6_LINES_PLAIN=""
  if [ -f /proc/net/if_inet6 ]; then
    IPV6_LINES="    listen [::]:##PORT## ssl$LISTEN_HTTP2;"
    IPV6_LINES_PLAIN="    listen [::]:##PORT##;"
  fi
  local h2text ipv6text
  if [ "$http2_new" = "1" ]; then h2text="新式"; else h2text="经典"; fi
  if [ -n "$IPV6_LINES" ];  then ipv6text="有"; else ipv6text="无"; fi
  ok "nginx 版本 $nv（http2 写法：$h2text；IPv6：$ipv6text）"

  # ── 2. DSH ────────────────────────────────────────────────────────────────
  step "2/9 准备 DSH"
  ensure_dsh
  if [ "$UPDATE_DSH" = "1" ]; then
    local cur latest
    cur="$("$DSH_BIN" --version 2>/dev/null || echo 未知)"
    warn "检查 DSH 更新（当前 $cur）..."
    if [ -n "$NPM_REGISTRY" ]; then
      latest="$(npm view @deepseek-ai/dsh version --registry "$NPM_REGISTRY" 2>/dev/null || true)"
    else
      latest="$(npm view @deepseek-ai/dsh version 2>/dev/null || true)"
    fi
    if [ -z "$latest" ]; then
      warn "查询最新版失败（网络或 npm 源问题），本次跳过升级"
    elif [ "$latest" = "$cur" ]; then
      ok "已是最新版（$cur）"
    else
      warn "发现新版本 $latest（当前 $cur），正在升级 ..."
      npm_install_global "@deepseek-ai/dsh@$latest" || die "DSH 升级失败"
      hash -r 2>/dev/null || true
      ok "已升级到 $latest（稍后重启 DSH 生效）"
    fi
  fi
  ensure_profile

  # ── 3. 凭据与证书 ─────────────────────────────────────────────────────────
  step "3/9 准备凭据与 TLS 证书"
  if [ -n "$AUTH_PASS" ]; then
    write_htpasswd; ok "已写入你设置的密码"
  elif [ -f "$HTPASSWD" ]; then
    ok "复用已有 $HTPASSWD（密码未变更；要重置请加 --password 或 --set-credentials）"
    # 关键：旧版本/手工改过权限的文件会在这里被修好并复验，
    # 否则"复用"分支会把一个浏览器必然 500 的文件一路带到安装结束
    fix_htpasswd_perms || true
  else
    AUTH_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)"
    write_htpasswd; ok "已生成随机密码（结尾会打印，请务必保存）"
  fi
  ok "$HTPASSWD（用户：$AUTH_USER，openssl apr1，无需 apache2-utils）"
  ensure_htpasswd_readable

  if [ ! -f "$CERT" ]; then
    local san="" ossl_err cfg ok_cert=0 has_addext=0
    if is_ip "$ACCESS_HOST"; then san="IP:$ACCESS_HOST"; else san="DNS:$ACCESS_HOST"; fi
    [ -n "$LAN_IP" ] && [ "$LAN_IP" != "$ACCESS_HOST" ] && san="$san,IP:$LAN_IP"
    san="$san,IP:127.0.0.1,DNS:localhost"

    # 目录可能不存在（RHEL 默认没有 /etc/ssl/private）—— 先建好
    mkdir -p "$CERT_DIR" "$KEY_DIR" 2>/dev/null || true

    # 先【探测】-addext 是否真的支持。不能因为命令失败就断定选项不支持：
    # 之前正是"目录不存在"被误判成"OpenSSL 太老"，白绕一圈。
    if openssl req -help 2>&1 | grep -q -- "-addext"; then has_addext=1; fi

    ossl_err="$(mktemp)"
    if [ "$has_addext" = "1" ]; then
      openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -subj "/CN=$ACCESS_HOST" -addext "subjectAltName=$san" >/dev/null 2>"$ossl_err" && ok_cert=1
    fi
    if [ "$ok_cert" != "1" ]; then
      if [ "$has_addext" != "1" ]; then
        warn "本机 openssl 不支持 -addext（$(openssl version 2>/dev/null)），改用配置文件方式"
      fi
      cfg="$(mktemp)"
      { echo "[req]"; echo "distinguished_name = dn"; echo "x509_extensions = v3"; echo "prompt = no"
        echo "[dn]"; echo "CN = $ACCESS_HOST"
        echo "[v3]"; echo "subjectAltName = $san"; } > "$cfg"
      openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -config "$cfg" -extensions v3 >/dev/null 2>"$ossl_err" && ok_cert=1
      rm -f "$cfg"
    fi

    if [ "$ok_cert" != "1" ]; then
      warn "证书生成失败。openssl 版本：$(openssl version 2>/dev/null || echo 未知)"
      warn "错误行（已过滤 openssl 的进度噪声）："
      grep -viE "^[.+*]+$" "$ossl_err" 2>/dev/null | tail -5 | sed "s/^/     /" >&2 || true
      local cert_w key_w
      if [ -w "$CERT_DIR" ]; then cert_w="是"; else cert_w="否"; fi
      if [ -w "$KEY_DIR" ];  then key_w="是";  else key_w="否";  fi
      warn "证书目录：$CERT_DIR（可写：$cert_w）"
      warn "私钥目录：$KEY_DIR（可写：$key_w）"
      rm -f "$ossl_err" "$KEY" "$CERT"
      die "无法生成自签 TLS 证书。可手工生成后重跑，或检查上面两个目录"
    fi
    rm -f "$ossl_err"
    chmod 600 "$KEY" 2>/dev/null || true
    ok "自签证书已生成（SAN: $san）"
  else
    ok "复用已有证书 $CERT"
  fi

  # ── 4. Nginx 配置 ─────────────────────────────────────────────────────────
  step "4/9 写入 Nginx 配置"
  {
    echo "# 由 dsh-web-hardening.sh v$VERSION 生成（http 上下文）"
    echo "map \$http_upgrade \$connection_upgrade {"
    echo "    default upgrade;"
    echo "    ''      close;"
    echo "}"
    if [ "$AUTO_TOKEN" = "1" ]; then
      echo
      echo "# 自动登录：无 DSH 会话 cookie 且未带 token 时，先去引导侧车换取 cookie"
      echo "map \$http_cookie \$dsh_authed {"
      echo "    default 0;"
      echo "    ~*dsh-auth- 1;"
      echo "}"
      echo "map \"\$dsh_authed:\$arg_token\" \$dsh_need_boot {"
      echo "    \"0:\" 1;"
      echo "    default 0;"
      echo "}"
    fi
  } > "$MAP_FILE"
  ok "$MAP_FILE"

  mkdir -p "$(dirname "$PROXY_SNIPPET")"
  {
    echo "# 由 dsh-web-hardening.sh v$VERSION 生成 —— 供 location 复用的代理设置"
    echo "proxy_pass         http://127.0.0.1:$DSH_PORT;"
    echo "proxy_http_version 1.1;"
    echo
    echo "# ★ 原样保留浏览器发来的 Host。DSH 护栏要求 Origin.host == Host.host，"
    echo "#   且 Host 必须在 trustedHosts 内。不要改成 127.0.0.1:$DSH_PORT，"
    echo "#   也不要删 Origin —— 那会造成护栏被绕过、launch token 从 302 泄漏。"
    echo "proxy_set_header Host              \$http_host;"
    echo "proxy_set_header X-Real-IP         \$remote_addr;"
    echo "proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;"
    echo "proxy_set_header X-Forwarded-Proto \$scheme;"
    echo
    echo "# SSE / WebSocket 实时性"
    echo "proxy_set_header Upgrade    \$http_upgrade;"
    echo "proxy_set_header Connection \$connection_upgrade;"
    echo "proxy_buffering off;"
    echo "proxy_read_timeout 3600s;"
    echo
    echo "# 关闭上游压缩以便 sub_filter 改写 index.html；"
    echo "# 注入 ownsHost=true，让远程页面被视为\"宿主可信\"，否则浏览器端设置"
    echo "# 会退化为 memory 持久化（刷新即丢）。它只是客户端标记，不授予任何"
    echo "# 服务端权限，且只发给已过密码的页面。"
    echo "proxy_set_header Accept-Encoding \"\";"
    echo "sub_filter_once on;"
    echo "sub_filter '</head>' '<script>globalThis.__DSH_TRANSPORT__=Object.assign({},globalThis.__DSH_TRANSPORT__,{ownsHost:true});</script></head>';"
  } > "$PROXY_SNIPPET"
  ok "$PROXY_SNIPPET"

  local SERVER_NAMES="$ACCESS_HOST"
  [ -n "$LAN_IP" ] && [ "$LAN_IP" != "$ACCESS_HOST" ] && SERVER_NAMES="$SERVER_NAMES $LAN_IP"
  {
    echo "# 由 dsh-web-hardening.sh v$VERSION 生成 —— 重跑脚本会覆盖本文件"
    echo "#"
    echo "#  1) DSH 只监听 127.0.0.1，本文件是唯一入口；"
    echo "#  2) 认证在 Nginx，完全在 DSH 之外 => DSH 升级不受影响；"
    echo "#  3) 必须 HTTPS：明文 HTTP 下浏览器不暴露 crypto.randomUUID，前端会崩；"
    echo "#  4) 故意不配 IP 白名单：写错会把自己的 SSH/浏览器挡在门外；"
    echo "#  5) 刻意【不用】 default_server：避免和发行版自带站点冲突，"
    echo "#     从而不需要改动任何系统原有配置（卸载时也就无残留）。"
    echo
    if [ "$HTTP_REDIRECT" = "1" ]; then
      cat <<EOF
server {
    listen $HTTP_PORT;
${IPV6_LINES_PLAIN//##PORT##/$HTTP_PORT}
    server_name $SERVER_NAMES;
    return 301 https://\$host\$request_uri;
}

EOF
    fi
    cat <<EOF
server {
    listen $HTTPS_PORT ssl$LISTEN_HTTP2;
${IPV6_LINES//##PORT##/$HTTPS_PORT}
$HTTP2_LINE
    server_name $SERVER_NAMES;

    ssl_certificate     $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:SSL:10m;

    auth_basic           "DSH - authorized users only";
    auth_basic_user_file $HTPASSWD;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options        DENY    always;
    add_header Referrer-Policy        no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 300m;   # 对齐 DSH maxRequestBodyBytes 默认值

    # 根路径：没有 DSH 会话 cookie 时先去侧车换 cookie（浏览器看不到 token）
    location = / {
EOF
    [ "$AUTO_TOKEN" = "1" ] && echo "        if (\$dsh_need_boot) { return 302 /_dsh_boot; }"
    echo "        include $PROXY_SNIPPET;"
    echo "    }"
    if [ "$AUTO_TOKEN" = "1" ]; then
      cat <<EOF

    # 引导侧车：仅回环可访问，且继承上面的 auth_basic
    location = /_dsh_boot {
        proxy_pass http://127.0.0.1:$BOOT_PORT;
        proxy_set_header Host \$http_host;
        proxy_read_timeout 30s;
    }
EOF
    fi
    cat <<EOF

    location / {
        include $PROXY_SNIPPET;
    }
}
EOF
  } > "$SITE_AVAIL"

  if [ "$SITE_LINKED" = "1" ]; then
    ln -sf "$SITE_AVAIL" "$SITE_ENABLED"
    ok "站点已启用：$SITE_ENABLED -> $SITE_AVAIL"
  else
    ok "站点已写入：$SITE_AVAIL"
  fi
  if ! nginx -t >/dev/null 2>&1; then
    nginx -t || true
    die "nginx 配置检查失败 —— 已中止，DSH 未做任何改动（站点文件：$SITE_AVAIL）"
  fi
  if ! nginx_apply; then
    err "nginx 启动/重载失败。排查："
    err "  systemctl status nginx"
    err "  journalctl -u nginx -n 40 --no-pager"
    err "  ss -tlnp | grep -E ':$HTTP_PORT|:$HTTPS_PORT'   # 端口是否被别的进程占用"
    die "已中止，DSH 未做任何改动（站点文件：$SITE_AVAIL）"
  fi
  ok "nginx 已加载新配置"

  # SELinux / 防火墙
  if have getenforce && [ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ]; then
    if have setsebool && setsebool -P httpd_can_network_connect 1 2>/dev/null; then
      ok "SELinux: 已允许 nginx 反向代理到回环（httpd_can_network_connect）"
    else
      warn "SELinux 处于 Enforcing，可能阻断 nginx 反代。请手工执行："
      warn "  setsebool -P httpd_can_network_connect 1"
    fi
  fi
  if [ "$FIREWALL" = "1" ]; then
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
      ufw allow "$HTTP_PORT"/tcp >/dev/null 2>&1 || true
      ufw allow "$HTTPS_PORT"/tcp >/dev/null 2>&1 || true
      ok "ufw: 已放行 $HTTP_PORT/$HTTPS_PORT（未触碰 22/SSH）"
    elif have firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="$HTTP_PORT"/tcp >/dev/null 2>&1 || true
      firewall-cmd --permanent --add-port="$HTTPS_PORT"/tcp >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
      ok "firewalld: 已放行 $HTTP_PORT/$HTTPS_PORT（未触碰 22/SSH）"
    fi
  fi

  # ── 5. 验证门禁 ───────────────────────────────────────────────────────────
  step "5/9 验证门禁（必须在动 DSH 之前通过）"
  # 只认 HTTP 状态码，并且用 /_dsh_boot 当探针：location = / 的 302 属 rewrite
  # 阶段，会在 auth_basic（access 阶段）之前返回 —— 拿 / 验证必然是假阳性。
  verify_gate "$AUTH_PASS"

  # ── 6. DSH 配置 ───────────────────────────────────────────────────────────
  step "6/9 调整 DSH 配置"
  if [ "$KEEP_PLUGINS" = "0" ]; then
    local -a found; mapfile -t found < <(bad_plugins_found)
    if [ "${#found[@]}" -gt 0 ]; then
      warn "检测到已知问题插件：${found[*]}"
      as_user "$DSH_BIN" plugin --profile "$PROFILE" remove "${found[@]}" >/dev/null 2>&1 \
        || warn "dsh plugin remove 失败，改用直接编辑 package.json"
      as_user node -e '
        const fs=require("fs"),p=process.argv[1],bad=process.argv.slice(2);
        const j=JSON.parse(fs.readFileSync(p,"utf8"));
        for(const b of bad) delete (j.dependencies||{})[b];
        if(j.dsh&&j.dsh.profile&&Array.isArray(j.dsh.profile.bundles))
          j.dsh.profile.bundles=j.dsh.profile.bundles.filter(x=>!bad.includes(x));
        fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
      ' "$PROFILE_DIR/package.json" "${found[@]}" 2>/dev/null || true
      local p; for p in "${found[@]}"; do rm -rf "$PROFILE_DIR/node_modules/$p"; done
      ok "已卸载并清除：${found[*]}"
    else
      ok "未发现已知问题插件"
    fi
  else
    warn "--keep-plugins：跳过插件卸载（只做网络加固）"
  fi

  {
    echo "# 由 dsh-web-hardening.sh v$VERSION 生成 —— 重跑脚本会覆盖本文件"
    echo "#"
    echo "# 为什么单独一层：DSH 的 patch 对 config 是【整体替换】而非深合并"
    echo "# （dsh-app-boot/lib/index.js 的 applyEntryPatches：target[key] = value），"
    echo "# 所以必须把 trustedHosts 一起写全，否则它会被抹掉 -> 所有 /api 变 403。"
    echo "#"
    echo "# 换 IP / 换域名访问时，把新地址加进 trustedHosts 并重跑脚本。"
    echo "- id: connection"
    echo "  config:"
    echo "    trustedHosts:"
    local h; for h in "${TRUSTED[@]}"; do echo "      - $h"; done
    echo "    cookieMaxAgeDays: $COOKIE_DAYS"
  } > "$OVERLAY"
  chown "$TARGET_USER:$TARGET_USER" "$OVERLAY" 2>/dev/null || true
  chmod 600 "$OVERLAY"
  ok "配置覆盖层：$OVERLAY（cookieMaxAgeDays=$COOKIE_DAYS）"

  # ── 7. 引导侧车 ───────────────────────────────────────────────────────────
  step "7/9 配置自动登录"
  if [ "$AUTO_TOKEN" = "1" ]; then write_bootstrap; start_bootstrap
  else warn "--no-auto-token：跳过。首次进入需手动打开一次带 token 的地址"; fi

  # ── 8. 重启 DSH ───────────────────────────────────────────────────────────
  step "8/9 以回环绑定重启 DSH"
  if [ -n "$PM2_BIN" ]; then
    local -a args; mapfile -t args < <(current_pm2_args_filtered)
    local has_profile=0 a
    for a in "${args[@]:-}"; do [ "$a" = "--profile" ] && has_profile=1; done
    [ "$has_profile" = "1" ] || args=("--profile" "$PROFILE" "${args[@]:-}")
    args+=("--patch" "$OVERLAY")
    local h; for h in "${TRUSTED[@]}"; do args+=("--trusted-host" "$h"); done
    printf '   启动参数：%s\n' "${args[*]}"

    if ! pm2_has_dsh && ss -tlnH "sport = :$DSH_PORT" 2>/dev/null | grep -q .; then
      warn "端口 $DSH_PORT 已被占用，但 PM2 里没有 dsh 进程 —— DSH 像是手工启动的。"
      warn "已跳过自动重启，避免两个实例抢端口。请先停掉手工实例，再用下面的参数启动："
      warn "  dsh ${args[*]}"
    else
      as_user "$PM2_BIN" delete dsh-web >/dev/null 2>&1 || true
      as_user "$PM2_BIN" start "$DSH_BIN" --name dsh-web -- "${args[@]}" >/dev/null \
        || warn "pm2 start 失败，请查看：sudo -u $TARGET_USER pm2 logs dsh-web"
      local i bound=""
      for i in $(seq 1 40); do
        if ss -tlnH "sport = :$DSH_PORT" 2>/dev/null | grep -q "127\.0\.0\.1:$DSH_PORT"; then bound=1; break; fi
        sleep 1
      done
      [ -n "$bound" ] && ok "DSH 已监听 127.0.0.1:$DSH_PORT（等待 ${i}s）" \
                      || warn "等待 40s 仍未在回环监听，请查看：sudo -u $TARGET_USER pm2 logs dsh-web"
      as_user "$PM2_BIN" save >/dev/null 2>&1 && ok "pm2 save 完成"
    fi

    apply_autostart "$(resolve_autostart)"
  else
    warn "未检测到 PM2。请手工以如下参数重启 DSH（务必让它只监听回环）："
    warn "  dsh --profile $PROFILE --patch $OVERLAY $(for h in "${TRUSTED[@]}"; do printf -- '--trusted-host %s ' "$h"; done)"
  fi

  [ "$AUTO_TOKEN" = "1" ] && [ -n "$PM2_BIN" ] && as_user "$PM2_BIN" restart "$BOOT_APP" >/dev/null 2>&1 || true

  # ── 9. 总结 ───────────────────────────────────────────────────────────────
  step "9/9 完成"
  local final_url
  final_url="https://$ACCESS_HOST$([ "$HTTPS_PORT" = "443" ] && echo "" || echo ":$HTTPS_PORT")/"
  echo
  echo "============================================================"
  echo "  ✅ 部署 + 加固完成"
  echo
  echo "  访问地址 : $final_url"
  echo "  用户名   : $AUTH_USER"
  if [ -n "$AUTH_PASS" ]; then echo "  密码     : $AUTH_PASS"
  else echo "  密码     : （未变更，沿用原有 htpasswd；重置请用 --set-credentials）"; fi
  echo
  save_credentials
  echo
  echo "  浏览器会提示自签证书不受信 —— 选择\"继续访问\"即可。"
  if [ "$AUTO_TOKEN" = "1" ]; then
    echo "  直接输入上面的地址即可进入，无需任何 token。"
  else
    echo "  首次进入需要一次带 token 的地址（token 在 DSH 启动日志里）："
    echo "      sudo -u $TARGET_USER pm2 logs dsh-web --lines 20"
  fi
  echo "  会话 cookie 有效 $COOKIE_DAYS 天，且跨 DSH 重启有效。"
  if systemctl is-enabled "pm2-$TARGET_USER" >/dev/null 2>&1; then
    echo "  开机自启 : 已启用（systemd → pm2 → DSH）"
  else
    echo "  开机自启 : 未启用（要开就用 --set-autostart）"
  fi
  echo
  echo "  改密码 : sudo $0 --set-credentials"
  echo "  体检   : sudo $0 --check"
  echo "  卸载   : sudo $0 --uninstall      （只清配置，不卸软件）"
  echo "============================================================"
  echo
}

case "$MODE" in
  check)           do_check ;;
  uninstall)       do_uninstall ;;
  credentials)     do_credentials ;;
  showcredentials) do_show_credentials ;;
  autostart)       do_set_autostart ;;
  install)         do_install ;;
esac
