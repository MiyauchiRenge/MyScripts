# MyScripts

平时攒下来的一些脚本，顺手扔这儿备份。基本都是自己用，所以按"能跑、能看懂"的标准写，没做通用化包装。

用之前建议把脚本本身看一眼，尤其是要 sudo 跑的那些。

## 里面有什么

| 文件 | 干什么 | 跑在什么上 |
| --- | --- | --- |
| `dsh-web-hardening.sh` | 给 DSH 的 Web 界面套一层 HTTPS + 密码，把"远程访问 DSH"这件事做安全 | Linux，Debian / RHEL 系 |
| `Linux_dependencies` | 按依赖关系排序并批量安装 deb 包，内网外网都能用 | Linux x86-64 |
| `fix_details.js` | 把 Markdown 里 `<details>` 块的正文转成 HTML，解决 Typora / Obsidian 展不开的问题 | 有 Node.js 就行 |

`THIRD_PARTY_NOTICES.md` 是第三方组件声明（目前只有 `fix_details.js` 内联的 markdown-it）。

---

## dsh-web-hardening.sh

DSH（DeepSeek Harness）的 Web profile 默认只听 `127.0.0.1`。想从别的机器访问，常见做法是装
`dsh-access-gate` / `dsh-lan-access` 之类的插件把监听改成 `0.0.0.0` —— 但这类插件默认没密码，
而且它们靠改写请求头工作，会顺带把 DSH 自己的信任护栏绕过去，最坏的情况是**未认证的人一条 curl
就能拿到会话令牌**。这个脚本换个思路：

```
[浏览器] --https + 密码--> [Nginx] --127.0.0.1--> [DSH 只监听回环]
```

认证放在 Nginx，DSH 本体一行都不改，所以升级 DSH 不受影响。

### 用

```bash
sudo ./dsh-web-hardening.sh                  # 一键：自己判断该装还是该修
sudo ./dsh-web-hardening.sh --cn-mirror      # 国内网络
sudo ./dsh-web-hardening.sh --update         # 升级 DSH 后重新加固
sudo ./dsh-web-hardening.sh --check          # 只体检，不改任何东西（不用 root）
```

跑完浏览器开 `https://<本机IP>/`，输账号密码就进去了。

第一次装的时候它会逐项问你（用户名、密码、要不要开机自启），也可以全部用参数指定：

```bash
sudo ./dsh-web-hardening.sh --cn-mirror --user dsh -y \
  --auth-user alice --password '你的密码' --autostart
```

### 其它模式

```bash
sudo ./dsh-web-hardening.sh --set-credentials       # 只改密码，不重启 DSH
sudo ./dsh-web-hardening.sh --set-autostart         # 只改开机自启
sudo ./dsh-web-hardening.sh --uninstall             # 卸载：删配置，不卸软件
sudo ./dsh-web-hardening.sh --detach -y --password x # 后台跑，SSH 断了也不影响
```

`--uninstall` 只删它自己创建的文件（Nginx 站点、证书、htpasswd、覆盖层、引导侧车），
nginx / nodejs / pm2 / dsh 这些包一个都不动，`~/.dsh` 也不碰。

### 会自己判断状态

默认模式会先检测环境再决定做什么，所以同一条命令反复跑是安全的：

```
== 环境检测
   DSH            已安装 0.1.5-rc.1（/usr/local/bin/dsh）
   profile        已存在
   加固状态       已加固（本次为幂等重新应用）
   DSH 进程       运行中（监听 127.0.0.1:3080） ✓ 仅回环
   开机自启       已启用
   => 本次将执行：重新加固（幂等，安全可重复）
```

没装过就是全新安装，装过就是重新应用，发现半成品或者 DSH 监听在 `0.0.0.0` 就是修复。

### 装之前知道这几件事

- **会自己装东西**：缺 Node 会从官方发行包装（可指定镜像，带 SHA256 校验），缺 nginx 用系统包管理器装，缺 pm2 / dsh 用 npm 装。不想要这些行为加 `--no-install-node` / `--no-install-dsh` / `--no-install-pm2`。
- **Linux 发行版差别是真的多**：Nginx 站点路径、证书目录（`/etc/ssl` vs `/etc/pki/tls`）、装完会不会自动启动，Debian 系和 RHEL 系都不一样。脚本都分别处理了，但这也是它最容易出问题的地方。
- **不改系统原有配置**：刻意不用 `default_server`，所以不需要去停用发行版自带的站点。
- **openSSL 版本**：`-addext` 要 OpenSSL ≥ 1.1.1，老版本会自动退回配置文件写法。
- **首次进入**：默认开了自动登录侧车，浏览器直接进；加 `--no-auto-token` 关掉，改成手工粘一次带 token 的地址。

### 详细文档

完整选项、设计取舍、常见问题和排错都在这份文档里：

→ [`dsh-web-hardening.md`](dsh-web-hardening.md)

---

## Linux_dependencies

按依赖关系给一堆 deb 包排序，并把缺的依赖下下来装上。内网环境也能用。

目录里放一个 `path` 文件夹，把要装的 deb 包丢进去，然后：

```bash
chmod +x Linux_dependencies
./Linux_dependencies
```

它会做这几件事：

- 扫描 `path` 里的包，分析依赖关系并排序
- 缺的依赖下载到 `dependencies` 目录
- 排序结果放在 `tmp` 下
- 在根目录生成日志和版本信息文件

配合现有 README 的用法说明一起看。

**注意**：仓库里放的是**编译好的 ELF 可执行文件（x86-64），没有源码**。介意的话就别跑，
或者自己反编译看一遍。另外它只认 deb 系（apt/dpkg），RHEL 系用不了。

---

## fix_details.js

专门治 Typora / Obsidian 里 `<details>` 折叠块展不开的毛病。

Typora 对 HTML 块有两个要求：块内不能有空行，标签内部的 Markdown 不会被解析。所以下面这种写法
在某些情况下点了没反应：

```markdown
<details open>
<summary>参数解释：</summary>

- net.ipv4.ip_forward = 1 # 开启 IPv4 路由转发

</details>
```

脚本把它转成纯 HTML：

```html
<details open>
<summary>参数解释：</summary>
<ul>
<li>net.ipv4.ip_forward = 1 # 开启 IPv4 路由转发</li>
</ul>
</details>
```

### 用

```bash
node fix_details.js 笔记.md                  # 生成 笔记.fixed.md，不动原文件
node fix_details.js 笔记.md --check          # 只体检，列出哪些块需要处理
node fix_details.js 笔记.md --in-place       # 原地改，自动备份 .bak-时间戳
node fix_details.js ./笔记目录                # 处理目录下所有 .md
node fix_details.js ./笔记目录 -r             # 递归子目录
```

常用选项：

| 选项 | 说明 |
| --- | --- |
| `-o, --out <路径>` | 指定输出文件（目录模式下不可用） |
| `--state=keep\|open\|closed` | 折叠默认状态，默认 `keep`（保留原有 `open`） |
| `--breaks=on\|off` | 单个换行是否转 `<br>`，默认 `on`（和 Typora 显示一致） |
| `--code-blank=zwsp\|keep` | 代码块内空行怎么处理，默认 `zwsp` |
| `--no-backup` | `--in-place` 时不生成备份 |
| `-q, --quiet` | 不逐块打印 |

`--check` 显示"转换 0 个块"就说明没有需要处理的。

单文件、零依赖，内联了 markdown-it 14.1.0（MIT，见 `THIRD_PARTY_NOTICES.md`），
拷到哪台机器上装了 Node 就能直接跑。Node 14+。

**它只碰 `<details>` 块内部**，块外一个字节都不改。

---

## 说明

- 这些脚本主要给自己用，没有做全面的发行版兼容性测试，遇到问题欢迎提 issue。
- 要 sudo 跑的脚本，建议先看一遍再跑。尤其 `dsh-web-hardening.sh` 会改 Nginx 配置、装 npm 包、
  重启进程。
- 许可证：没特别声明，默认按 MIT 理解；第三方组件的许可见 `THIRD_PARTY_NOTICES.md`。
