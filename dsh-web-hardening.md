# dsh-web-hardening.sh

**一条命令把 DeepSeek Harness (DSH) 从零装好并加固到「浏览器打开就能用」：**

```bash
sudo ./dsh-web-hardening.sh
```

它会：装 DSH（缺则 npm 安装）→ 让你设置访问账号密码 → 配好 HTTPS + 密码门禁 →
启动进程并设为开机自启 → 之后浏览器打开 `https://<本机IP>/`，输入账号密码即可进入。

```
[浏览器] --https + 密码--> [Nginx] --127.0.0.1--> [DSH 只监听回环]
```

不修改 DSH 源码、不依赖任何第三方插件，**DSH 升级不受影响**。

---

## 为什么需要它：现有「暴露 DSH」方案的两个硬伤

DSH 的 `web` profile 默认只监听 `127.0.0.1`。社区常见的"让别人也能访问"做法是安装
`dsh-access-gate` / `dsh-lan-access` / `dsh-webui-auth` 这类插件，把绑定改成 `0.0.0.0`
并在请求层改写 `Host` / `Origin`。

### 硬伤 1：未认证者可以直接拿到主令牌

这类插件在**未设密码时是"放行模式"**（默认如此）：对任何非回环来源的请求，它把
`Host` 改写成 `127.0.0.1`、删掉 `Origin`，然后放行 —— 因为 DSH 的信任护栏
（`dsh-client-connection` 的 `isTrustedApiRequest`）**只看请求头，不看 socket 来源地址**。

更糟的是，某些插件在"引导浏览器完成核心认证"时，会用**已被改写的 Host** 去拼接重定向
URL，把**进程级 launch token** 直接写进 `302` 的 `Location` 头：

```console
$ curl -i http://<你的DSH>:3080/
HTTP/1.1 302 Found
location: http://127.0.0.1/?token=<43字符的主令牌>     # ← 白送给任何未认证的人
```

于是任何人都能两步取得管理员权限：

```bash
TOK=$(curl -si http://<host>:3080/ | grep -i '^location' | sed 's/.*token=//')
curl -c jar "http://<host>:3080/?token=$TOK"
curl -b jar -X POST -H 'Content-Type: application/json' \
  -d '{"type":"client-request","rpcId":"1","method":"settings/describe","payload":{"args":{}}}' \
  http://<host>:3080/api/settings/describe        # {"ok":true,...}
```

而 DSH Web 本质是一个**能执行任意命令的 agent** —— 等价于远程代码执行。

### 硬伤 2：这类插件天然跟着 DSH 版本走

它们依赖 DSH 内部实现细节（覆盖 `server.emit`、篡改 `req.headers`、注入 `index.html`），
DSH 每升一个 rc 版本都可能失效。

### 本脚本的做法

把认证从**插件层**搬到 **DSH 之外的 Nginx**，用 DSH 的**原生能力**完成原本需要篡改请求头
才能做到的事：

| 原本靠插件 | 现在靠 |
|---|---|
| 绑定改成 `0.0.0.0` | 不暴露 —— DSH 留在回环，Nginx 反代 |
| 改写 `Host` 穿透护栏 | `--trusted-host <你的地址>`（官方参数） |
| 删 `Origin` / `sec-fetch-*` | **不删** —— 原样透传 `Host`，`Origin` 自然一致 |
| 注入 `crypto.randomUUID` polyfill | 用 **HTTPS**（安全上下文下浏览器原生支持） |
| 注入 `ownsHost` 让设置可持久化 | Nginx `sub_filter` 一行（DSH 之外） |
| 密码登录 | Nginx `auth_basic` |

---

## 环境要求

| 项目 | 说明 |
|---|---|
| 发行版 | **Debian / Ubuntu 系**（apt、`sites-available`、`www-data`）<br>**RHEL / CentOS / Rocky / Alma / Fedora / openEuler 系**（dnf/yum、`conf.d`、`nginx` 组）<br>自动识别并选择正确路径 |
| Node | **>= 22**。缺失或版本过低时自动安装：下载**官方发行包**解到 `/usr/local`（自带 npm），**不依赖 NodeSource 等第三方软件源**，并校验 SHA256。默认先试 `nodejs.org`，失败自动回退 `npmmirror`；也可用 `--node-source <url>` 指定任意镜像 |
| nginx / pm2 / dsh | 缺失时自动安装（分别走系统包管理器 / npm / npm） |
| 其他 | `openssl`、`curl`（缺失时脚本会提示） |

脚本还会自动处理两件在 RHEL 上必踩的事：

- **SELinux**：Enforcing 时执行 `setsebool -P httpd_can_network_connect 1`，
  否则 nginx 反代回环会被拦成 502；
- **防火墙**：`firewalld` / `ufw` 处于活动状态时放行 80/443
  —— **绝不会触碰 22/SSH**（`--no-firewall` 可关闭）。

---

## 快速开始

```bash
chmod +x dsh-web-hardening.sh

# 一键：装 DSH + 设账号密码 + 加固 + 开机自启
sudo ./dsh-web-hardening.sh

# 运行时会【提示你输入】用户名和密码，你自己设：
#   用户名 回车 = 沿用括号里的默认值（默认 dsh）
#   密码   回车 = 已有密码则保持不变；首次安装则随机生成 20 位
# 结束后浏览器打开 https://<本机IP>/ ，输入账号密码即可
```

浏览器会提示自签证书不受信 —— 选择「继续访问」即可（自签证书同样满足
浏览器对"安全上下文"的要求）。

### 账号密码由你决定

```bash
# 交互：脚本会问你（推荐）
sudo ./dsh-web-hardening.sh

# 非交互 / 批量部署：显式指定
sudo ./dsh-web-hardening.sh -y --auth-user alice --password 'YourStrongPass'

# 以后单独改账号密码 —— 只重载 Nginx，【不重启 DSH】
sudo ./dsh-web-hardening.sh --set-credentials
sudo ./dsh-web-hardening.sh --set-credentials --auth-user alice --password '新密码'
```

| 情况 | 行为 |
|---|---|
| 交互输入了密码 | 用你输入的 |
| 交互留空，且已有密码文件 | **保持不变**（不会偷偷换掉） |
| 交互留空，且首次安装 | 随机生成 20 位并在结尾打印 |
| `-y` 且未给 `--password` | 随机生成 20 位并在结尾打印 |
| 显式 `--password xxx` | 用你给的 |

> 密码以 `apr1` 哈希写入 `/etc/nginx/.dsh-web.htpasswd`（权限 `640 root:www-data`）——
> 落盘的是不可逆哈希，明文只在你输入的那一刻存在。

### 记住密码

设置或生成的密码会**另存一份明文**到 `/root/dsh-web-credentials.txt`（权限 `600`），
方便你事后取回：

```bash
sudo ./dsh-web-hardening.sh --show-credentials     # 打印已保存的凭据
sudo ./dsh-web-hardening.sh --credentials-file /path/to/file   # 换个保存位置
sudo ./dsh-web-hardening.sh --no-save-credentials  # 不保存
```

**关于"密文能不能登录"** —— 不能：

| 文件 | 内容 | 能否直接登录 |
|---|---|---|
| `/etc/nginx/.dsh-web.htpasswd` | `apr1` 哈希 | **不能**。HTTP Basic 必须提交明文，nginx 收到后自己算哈希再比对；拿哈希去填密码框一定失败 |
| `/root/dsh-web-credentials.txt` | **明文** | 能 —— 所以这个才是要重点保护的（`600`、root-only） |

⚠️ 一点补充：哈希虽然不能直接登录，但 `apr1` 是 MD5 系、可被**离线暴力破解**，
所以 `.htpasswd` 也别外传；密码本身请用强口令。

### 非交互 / 自动化

```bash
sudo ./dsh-web-hardening.sh -y \
  --auth-user alice --password 'YourStrongPass' \
  --host 192.168.1.50
```

### 同一个命令，自己判断该做什么

默认（install）模式会先做环境检测并打印结论，所以**同一条命令可以反复安全执行**：
装、修、升级后重建都用它。

```
== 环境检测
   DSH            已安装 0.1.5-rc.1（/usr/local/bin/dsh）
   profile        已存在
   加固状态       已加固（本次为幂等重新应用）
   DSH 进程       运行中（监听 127.0.0.1:3080） ✓ 仅回环
   nginx          已启用自启 / active
   开机自启       已启用
   => 本次将执行：重新加固（幂等，安全可重复）
```

判断规则：

| 检测到的状态 | 结论 |
|---|---|
| 没有 DSH / 没有加固产物 | **全新安装** |
| 加固产物齐全 | **重新加固**（幂等） |
| 有半成品（上次中断）、有已知问题插件、或 DSH 监听在 `0.0.0.0` | **修复** |

### 升级 DSH

```bash
sudo ./dsh-web-hardening.sh --update          # 升级 npm 包 + 重新加固 + 重启
```

只升级、不动加固的话也可以直接：

```bash
npm i -g @deepseek-ai/dsh@latest --registry https://registry.npmmirror.com
pm2 restart dsh-web && pm2 restart dsh-bootstrap
sudo ./dsh-web-hardening.sh --check           # 确认一切正常
```

加固点全在 DSH 之外（nginx / 侧车 / patch 覆盖层 / PM2 参数），所以升级本身不会破坏它。
已实测：**schema 变化导致的最坏情况是「可见的失败」（403 或起不来），不会静默变成漏洞**。

### 开机自启可自选

交互运行时脚本会问一次：

```
   是否设置开机自启（pm2 + nginx）？[Y/n]:
```

非交互场景用 `--autostart` / `--no-autostart` 明确指定。只想改这一项：

```bash
sudo ./dsh-web-hardening.sh --set-autostart                # 交互询问
sudo ./dsh-web-hardening.sh --set-autostart --autostart    # 打开
sudo ./dsh-web-hardening.sh --set-autostart --no-autostart # 关闭
```

### 长任务怕断线？用 --detach

安装要下载 Node、装 npm 包、配 Nginx、重启 DSH，几分钟很正常。**中途 SSH 掉线，半截安装和日志会一起没掉** —— 所以：

```bash
sudo ./dsh-web-hardening.sh --detach -y --password '你的密码'
# 已在后台运行 —— 断开 SSH 或关闭终端都不会中断安装。
#   日志文件：/var/log/dsh-web-20260917-154500.log
#   实时查看：tail -f /var/log/dsh-web-20260917-154500.log
```

断线重连后 `tail -f` 那个日志即可看到全过程与结果。不加 `--detach` 时也会写日志，
只是进程仍挂在这个终端下。

> 注：`--detach` 下没有交互输入，请配 `-y --password`（root 用户还需 `--allow-root-dsh`）。

### 国内网络 / 镜像源

最省事：

```bash
sudo ./dsh-web-hardening.sh --cn-mirror
```

它等价于同时指定下面两个 —— 而这两个是**不同的 URL**，很容易搞混：

| 用途 | 地址 | 说明 |
|---|---|---|
| **npm 包源** | `https://registry.npmmirror.com` | 给 `npm install -g` 用（装 dsh、pm2） |
| **Node 发行包镜像** | `https://registry.npmmirror.com/-/binary/node` | 镜像了 `nodejs.org/dist` 的**目录结构**，用来下 Node 二进制 |

```bash
sudo ./dsh-web-hardening.sh \
  --npm-registry https://registry.npmmirror.com \
  --node-source  https://registry.npmmirror.com/-/binary/node
```

**填错也不会卡住** —— 脚本会自动纠正：

- 只给了 `--npm-registry https://registry.npmmirror.com`
  → 自动推断出对应的 Node 镜像，并**优先**使用它；
- 把 npm 源地址误填进 `--node-source`
  → 自动补全成 `…/-/binary/node`；
- 老地址 `https://cdn.npmmirror.com/binaries/node` → 自动映射到新路径。

不指定任何镜像也可以，脚本对两条链路都有自动回退：

| 链路 | 尝试顺序 |
|---|---|
| Node 发行包 | 你指定的 → 从 npm 源推断的 → `nodejs.org/dist` → npmmirror |
| npm 包 | 你指定的 → 失败后 `registry.npmmirror.com` |

`--node-source` 也可以指向任何镜像了 `nodejs.org/dist` 结构的站点
（清华 TUNA 的 `nodejs-release` 等）；脚本会在同一镜像取 `SHASUMS256.txt`
做 SHA256 校验，校验不通过就换下一个源；全部失败时会列出**尝试过的每个地址**。

### ⚠️ 不要用 root 跑 DSH

如果脚本推断出的 DSH 运行用户是 `root`（例如你在 root shell 里、且 `/home`
下没有普通用户），它会**停下来警告并要求确认**：

```
 DSH 运行用户是 root —— 风险很高：
 DSH Web 等于一个能执行任意命令的 agent；用 root 跑意味着
 任何一次进入都等同于拿到整台机器的 root 权限。

 建议先建专用用户再装（推荐）：
   useradd -m -s /bin/bash dsh
   ./dsh-web-hardening.sh --user dsh ...
```

非交互（`-y`）下必须显式加 `--allow-root-dsh` 才会继续。

---

## 命令行选项

| 选项 | 说明 |
|---|---|
| `--check` | 只体检，不改动任何东西（任何用户可跑，无需 root） |
| `--update` | 先检查并升级 `@deepseek-ai/dsh` 到最新版，再重新加固 |
| `--autostart` | 设置 PM2 开机自启 |
| `--no-autostart` | 不设置（或关闭）开机自启 |
| `--set-autostart` | **只**调整开机自启，其他一律不动 |
| `--set-credentials` | 只设置/修改访问账号密码（只重载 Nginx，**不重启 DSH**） |
| `--uninstall` | 卸载，回到「仅回环 + SSH 隧道访问」 |
| `--help` / `-h` | 显示完整文档 |
| `--version` / `-V` | 显示版本 |
| `-y`, `--yes` | 全程非交互（配合 `--password` 使用） |
| `--log <路径>` | 日志文件；安装/卸载默认写到 `/var/log/dsh-web-<时间>.log` |
| `--detach` | 放到后台跑（`setsid`），**SSH 断线/关终端都不会中断安装** |
| `--auth-user <用户名>` | Nginx basic auth 用户名，默认 `dsh` |
| `--password <密码>` | Nginx basic auth 密码；不指定则交互提示或随机生成 |
| `--host <地址>` | 对外访问地址；默认自动探测主网卡 IPv4 |
| `--trusted-host <地址>` | 额外信任的 Host，可重复。**用别的域名/IP 访问时必须加** |
| `--https-port <端口>` | Nginx HTTPS 端口，默认 `443` |
| `--http-port <端口>` | HTTP 跳转端口，默认 `80` |
| `--dsh-port <端口>` | DSH 监听端口，默认 `3080` |
| `--boot-port <端口>` | 引导侧车端口，默认 `3081` |
| `--user <用户名>` | DSH 运行用户，默认从 sudo 调用者推断 |
| `--profile <名称>` | DSH profile，默认 `web` |
| `--cookie-days <n>` | 会话 cookie 有效期天数，默认 `400`（浏览器上限） |
| `--npm-registry <url>` | npm 包源 |
| `--node-source <url>` | Node 发行包镜像基址（**不是 npm 包源**，填 npm 源地址会被自动纠正） |
| `--cn-mirror` | 一键使用国内镜像（等价于同时指定上面两个的 npmmirror 地址） |
| `--credentials-file <路径>` | 明文凭据保存位置，默认 `/root/dsh-web-credentials.txt` |
| `--no-save-credentials` | 不保存明文凭据 |
| `--show-credentials` | 打印已保存的凭据 |
| `--allow-root-dsh` | 允许以 root 身份运行 DSH（默认会拒绝并要求确认，见下方说明） |
| `--no-install-dsh` | 缺 DSH 时不自动安装 |
| `--no-install-pm2` | 缺 PM2 时不自动安装 |
| `--no-auto-token` | 不装引导侧车（首次进入需手动粘一次 token） |
| `--no-http-redirect` | 不占用 80 端口做跳转 |
| `--node-major <n>` | 需要的 Node 主版本，默认 `22` |
| `--no-install-node` | 缺 Node 时不自动安装 |
| `--no-firewall` | 不自动放行 80/443（本来就不会动 22/SSH） |
| `--purge` | 配合 `--uninstall`，额外移除 PM2 自启单元与 NodeSource 源配置 |
| `--keep-plugins` | 不卸载已知问题插件（只做网络加固） |
| `--no-deps` | 缺 nginx 时不自动安装 |

---

## 关于 token：为什么你能"打开就进"

DSH 核心的机制是：**每个浏览器必须先用一次进程级 launch token 换取签名 cookie**。

- **launch token**：进程级的，每次启动 `randomBytes(32)` 重新生成
  （源码 `dsh-client-connection/lib/index.js` 的 `processLaunchToken`），
  唯一作用就是换取 cookie。
- **会话 cookie**：用一把**持久化**密钥签名，密钥存在 `~/.dsh/.credentials.yaml` 的
  `client-connection/browser-session` 记录里。cookie 里带 `authority`（即 Host）和过期时间。

本来这会让"打开 IP 就能进"打折扣。本脚本默认在回环起一个极小的**引导侧车**
（Node，PM2 托管，监听 `127.0.0.1:3081`）：当 Nginx 发现浏览器还没有 DSH 会话 cookie 时，
先把请求转给它，由它**在服务端**完成 `token → cookie` 交换，只把 `Set-Cookie` 转给浏览器。

结果是：

- **浏览器地址栏和 URL 里永远不会出现 token**；
- 你只需要输入账号密码，然后就直接进入 DSH；
- 想关掉这个行为用 `--no-auto-token`（之后首次进入需手动打开一次带 token 的地址）。

侧车只监听回环，且只能经 Nginx 的密码门禁到达；它本身不持有任何特权，只读 DSH 自己的启动日志。

---

## 设计上的几个刻意选择

**强制 HTTPS。** 浏览器只在安全上下文（HTTPS 或 localhost）暴露 `crypto.randomUUID`；
经明文 HTTP + IP 访问时 DSH 前端 RPC 会直接报错。所以明文方案不是"稍微不安全"，
而是根本跑不起来（原插件靠注入 polyfill 兜底，本脚本选择从根上解决）。

**不配 IP 白名单。** 加 `allow 192.168.x.0/24; deny all;` 看起来更安全，但只要你的
SSH 或浏览器来自别的网段（VPN、跳板机、多网卡），就会把自己彻底锁在门外。
门禁交给密码，不交给网段。

**`config` 是整体替换而非深合并。** DSH 的 patch 机制里
（`dsh-app-boot/lib/index.js` 的 `applyEntryPatches`），对同一个 plugin row 的 `config`
是**整体赋值**：

```js
for (const [key, value] of Object.entries(overrides)) {
    if (key === "id") continue;
    target[key] = value;        // ← 浅覆盖
}
```

所以覆盖 `connection` 配置时**必须把 `trustedHosts` 一起写全**，否则它会被抹掉、
护栏失去白名单、所有 `/api` 变成 `403`。本脚本把这份覆盖写进**自己独占的 patch 文件**
（`~/.dsh/dsh-web.patch.yml`），不改动你自己的 `cordis.patch.yml`，从根本上避开合并问题。

**认证必须在 DSH 之外。** 这是"不破坏 DSH 升级"的关键：脚本不碰
`/usr/lib/node_modules/@deepseek-ai/dsh` 里的任何文件，只用官方 CLI 参数
（`--patch` / `--trusted-host`）和 profile 目录下的配置文件。

**先过门禁，再动 DSH。** 脚本在把 DSH 收回回环之前，会先确认 Nginx 站点
`nginx -t` 通过、能 reload、无密码返回 `401` 且带 `WWW-Authenticate`、**带正确密码能穿过
Nginx**。任何一步不过就立即中止，**不会动 DSH** —— 不存在"改到一半把自己锁在门外"。

---

## FAQ

### 重启后还要再找 token 吗？

不用。会话 cookie 用持久化密钥签名，**跨 DSH 重启有效**；有效期默认 400 天
（浏览器对 cookie 生命期的钳制上限），且开机自启由 `pm2 startup` 保证。
所以配置一次之后，日常就是"打开浏览器 → 输密码 → 进入"。

### 为什么 `/` 有时返回 302 而不是 401？

这是 **nginx 执行阶段顺序**导致的，不影响安全：

- `auth_basic` 属于 **access 阶段**；
- `if (...) { return 302 ...; }` 属于 **rewrite 阶段**，**先于** access 阶段执行。

所以开启自动登录后，无凭据访问 `/` 会先拿到 `302 → /_dsh_boot`，而**重定向目标
`/_dsh_boot` 同样要求认证** —— 无凭据访问它得到的是 `401`。实测：

```
无凭据 GET /            → 302
无凭据 GET /_dsh_boot   → 401 Unauthorized   ← 侧车受认证保护，拿不到任何东西
带凭据 GET /_dsh_boot   → 到达侧车
```

**没有任何令牌或凭据泄漏**，浏览器体验也正常（302 → 401 → 弹密码框 → 输入后继续）。
脚本的门禁校验因此会跟随重定向判断最终结果，而不是死认 401。

### 会不会挡住我自己的 SSH？

不会，脚本完全不碰 sshd，也不配置防火墙。唯一占用的是 80/443。
即使 Nginx 挂了，你仍可以：

```bash
ssh -N -L 3080:127.0.0.1:3080 <dsh用户>@<主机>
# 浏览器打开 DSH 启动日志里的 http://127.0.0.1:3080/?token=...
```

这条通道不经过 Nginx、不经过密码、不经过 cookie，是最后的落脚点。

### 为什么没有"回滚到加固前"？

因为"加固前"＝**有漏洞的状态**。保留一键回滚到那里，等于给自己留了个随时会踩的坑。
脚本提供的是**幂等重建**：直接重跑 `sudo ./dsh-web-hardening.sh` 即可恢复到已验证的
加固状态；不想要了就 `--uninstall`（回到仅回环 + SSH 隧道，仍然不是漏洞状态）。

### DSH 升级后要做什么？

什么都不用做。升级 `/usr/lib/node_modules/@deepseek-ai/dsh` 不会碰到 Nginx，
也不会碰到 profile 目录里的 patch 文件。

唯一要注意：**改了 PM2 启动参数后记得再跑一次 `pm2 save`**，
否则开机恢复（`pm2 resurrect`）会用旧参数。

### 换了 IP 或域名怎么办？

重跑一次即可（脚本会把新地址写进 `trustedHosts`）：

```bash
sudo ./dsh-web-hardening.sh --host <新地址>
```

没重跑就访问新地址会得到 `403`（护栏拒绝了未知 Host）。

---

## 验证与体检

```bash
sudo ./dsh-web-hardening.sh --check
```

报告监听地址、门禁状态、是否仍有已知问题插件、引导侧车、开机自启、cookie 有效期等。

**装不上 Node 时先跑这一条** —— 它包含一段外网连通性自检，会直接告诉你是哪一层出了问题：

```
== 外网连通性（Node 自动安装依赖）
   nodejs.org               DNS=2606:4700::6810:d583 HTTPS=307
   registry.npmmirror.com   DNS=2408:8720:0:26:3::b   HTTPS=200
   rpm.nodesource.com       DNS=2606:4700:10::6814:2dbe HTTPS=200
   代理变量             http_proxy=<未设> https_proxy=<未设>
```

Node 下载失败时，脚本也会**区分三种完全不同的原因**，而不是笼统说"找不到"：

| 情况 | 提示 |
|---|---|
| DNS/网络不通、被代理拦 | `连不上 …（HTTP 000）` |
| 路径不对（例如把 npm 源当镜像） | `该镜像没有这个路径 …（HTTP 404，可能不是 Node 发行包镜像）` |
| 能访问但镜像没同步该版本 | `能访问 …，但列表里没有 linux-x64 的 Node 22.x 包` |

全部镜像都失败时，脚本还会：① 打印网络自检；② 尝试**发行版自带的 nodejs 模块**
（RHEL 系 `dnf module install nodejs:22`，仅当发行版确实提供该版本）；③ 列出尝试过的每个地址。

---

## 卸载

```bash
sudo ./dsh-web-hardening.sh --uninstall
```

**只删除本脚本创建的配置文件，不卸载任何软件包。**

会清理：

| 类型 | 路径 |
|---|---|
| Nginx 站点 | `/etc/nginx/sites-available/dsh-web`（RHEL 为 `/etc/nginx/conf.d/dsh-web.conf`）及其软链 |
| Nginx 辅助 | `/etc/nginx/conf.d/dsh-web-map.conf`、`/etc/nginx/snippets/dsh-web-proxy.conf` |
| 凭据与证书 | `/etc/nginx/.dsh-web.htpasswd`、`/etc/ssl/certs/dsh-web.crt`、`/etc/ssl/private/dsh-web.key` |
| patch 覆盖层 | `~/.dsh/dsh-web.patch.yml` |
| 引导侧车 | `~/.dsh/dsh-web-bootstrap.mjs` 及其 PM2 进程 |

**不会做**：卸载 nginx / nodejs / pm2 / `@deepseek-ai/dsh`；不会删除 `~/.dsh`
（DSH 自己的数据与配置始终保留）；不会改动任何系统原有配置
（因为脚本刻意不使用 `default_server`，从不覆盖发行版自带站点）。

`--purge` 会额外移除 PM2 开机自启单元 `/etc/systemd/system/pm2-<user>.service`
与 NodeSource 源配置。脚本结尾还会打印"如果想连软件一起清理"的对应命令。

卸载后 **DSH 仍只监听回环**，继续通过 SSH 隧道访问 —— 卸载不会把你退回到漏洞状态。

---

## License

MIT
