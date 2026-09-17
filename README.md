# 脚本记录

本页面对平时使用的脚本进行记录。

## 📥 脚本列表

| 文件名 | 说明 | 运行环境 | 依赖/需求 |
|--------|------|----------|-----------|
| `Linux_dependencies` | 依赖自动检查、排序、下载、安装脚本，互联网内网通用。 | Linux (x86-64) | 脚本目录下创建 path 文件夹，将需要安装的 deb 包放入，缺少的依赖会放在该目录下自动创建的 dependencies 目录。脚本会在脚本根目录生成日志和版本信息，tmp 文件夹下生成排序文件。 |
| `fix_details.js` | 批量把 Markdown 里 `<details>…</details>` 块中的 Markdown 正文转换成 HTML，并消除块内空行，让 Typora 能正确渲染并支持点击展开/折叠。 | Windows / macOS / Linux | Node.js 14+。**单文件、零依赖**（markdown-it 已内联），无需 `npm install`。 |

---

## 🚀 使用方法

### Linux_dependencies

1. **赋予执行权限：**

```bash
chmod +x Linux_dependencies
./Linux_dependencies
```

### fix_details.js

> 用途：Typora（以及 Obsidian）对 HTML 块有两条硬性限制——块内**不能有空行**，且
> **HTML 标签内部的 Markdown 不会被解析**。所以下面这种常见的折叠写法在 Typora 里点不开：
>
> ```markdown
> <details open>
> <summary>参数解释：</summary>
>
> -   net.ipv4.ip_forward = 1 # 开启 IPv4 路由转发
>
> </details>
> ```
>
> 本脚本把块内正文机械转换成真实 HTML 标签，并去掉块内空行，变成 Typora 能正确渲染的形式：
>
> ```html
> <details open>
> <summary>参数解释：</summary>
> <ul>
> <li>net.ipv4.ip_forward = 1 # 开启 IPv4 路由转发</li>
> </ul>
> </details>
> ```

**1. 先体检（只读，不会修改任何文件）**

```bash
# 检查单个文件
node fix_details.js "笔记.md" --check

# 检查整个目录（自动跳过 .bak-* 和 .fixed.md）
node fix_details.js "D:\笔记" --check
```

看输出里的表格：**「转换 0 个块」= 格式已经合规，不用动**；显示 `← 有 N 个块需要转换` 就是会被改写的块数。

**2. 转换**

```bash
# 稳妥路线：输出到 新文件.fixed.md，原文件不动
node fix_details.js "D:\笔记"

# 直接原地修改（每个被改动的文件自动备份为 .bak-<时间戳>）
node fix_details.js "D:\笔记" --in-place
```

**3. 出问题就还原**

```bash
# 全部还原
for f in *.bak-*; do cp "$f" "${f%%.bak-*}"; done
# 确认没问题后删除备份
rm *.bak-*
```

**常用选项**

| 选项 | 说明 |
|------|------|
| `-c, --check` | 只体检不写入 |
| `-i, --in-place` | 原地修改，自动生成 `.bak-<时间戳>` 备份 |
| `-o, --out <路径>` | 指定输出文件 |
| `-r, --recursive` | 目录模式下递归处理子目录 |
| `--state=keep\|open\|closed` | 折叠默认状态，默认 `keep`（保留原有 `open` 属性） |
| `--breaks=on\|off` | 单个换行是否转 `<br>`，默认 `on`（与 Typora 显示一致） |
| `--code-blank=zwsp\|keep` | 代码块内空行的处理方式，默认 `zwsp` |
| `--max-block-kb=<数字>` | 单个块正文上限，超过则跳过，默认 `64` |
| `--summary-markdown` | 把 `<summary>` 里的行内 Markdown 也转成 HTML，默认关闭 |
| `--no-backup` | `--in-place` 时不备份 |
| `-q, --quiet` | 不逐块打印，只保留汇总结论 |
| `-h, --help` | 显示帮助 |

**脚本保证的事**

- **只改 `<details>` 块内部**，块外的正文一个字节都不动。
- **幂等**：同一个文件跑几次结果都一样，第二次会直接报告「转换 0 个块」。
- 围栏代码块、行内代码、HTML 注释里的 `<details>` 不会被误处理。
- 已经合规的块原样保留；孤儿 `</details>`、未闭合块、缺 `<summary>` 的块只告警不修改，并给出行号。
- 单块正文超过 `--max-block-kb` 自动跳过，避免标签配对错误时误改半篇文档。

**需要知道的代价**

1. 转换后块内是 HTML，**不再是 Markdown**——在 Typora 里点进去看到的是 HTML 源码，不能再以所见即所得方式编辑块内的列表/表格。
2. 文件体积会略有增加（实测约 +1%）。
3. 代码块内的空行会被替换成零宽空格（否则 HTML 块会在空行处截断），复制这段代码可能带上不可见字符；报告里会列出行号，可用 `--code-blank=keep` 关闭该行为。
4. 如果原文件**混用了 CRLF 和 LF 两种换行符**，脚本会统一成占多数的那种，并给出告警。

---

## 📄 许可

脚本内联了 [markdown-it](https://github.com/markdown-it/markdown-it)（MIT 协议），
其版权声明与许可全文见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
