# 脚本记录

本页面对平时使用的脚本进行记录。

## 📥 脚本列表

| 文件名                  | 说明                                                            | 运行环境                    | 依赖/需求                                                                                              |
| -------------------- | ------------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------- |
| `Linux_dependencies` | 依赖自动检查、排序、下载、安装脚本，互联网内网通用。                                    | Linux (x86-64)          | 脚本目录下创建 `path` 文件夹，将需要安装的 deb 包放入，缺少的依赖会自动下载到 `dependencies` 目录。脚本会在根目录生成日志和版本信息，`tmp` 文件夹下生成排序文件。 |
| `fix_details.js`     | 用来处理 Markdown 中 `<details>` 折叠块，让 Typora / Obsidian 能正常显示和展开。 | Windows / macOS / Linux | Node.js 14+，单文件，无需安装其他依赖。                                                                          |

---

## 🚀 使用方法

### Linux_dependencies

```bash
chmod +x Linux_dependencies
./Linux_dependencies
```

### fix_details.js

这个脚本主要是解决 Typora / Obsidian 中 `<details>` 折叠块的问题。

例如下面这种写法：

```markdown
<details open>
<summary>参数解释：</summary>

- net.ipv4.ip_forward = 1 # 开启 IPv4 路由转发

</details>
```

在部分情况下不能正常展开。

运行脚本后，会把 `<details>` 里面的 Markdown 转成 HTML，并删除块内多余的空行，例如：

```html
<details open>
<summary>参数解释：</summary>
<ul>
<li>net.ipv4.ip_forward = 1 # 开启 IPv4 路由转发</li>
</ul>
</details>
```

### 检查文件

只检查，不修改文件：

```bash
node fix_details.js "笔记.md" --check
```

检查整个目录：

```bash
node fix_details.js "D:\笔记" --check
```

显示 `转换 0 个块`，说明没有需要处理的内容。

### 转换文件

默认生成一个新的 `.fixed.md` 文件：

```bash
node fix_details.js "D:\笔记"
```

如果希望直接修改原文件：

```bash
node fix_details.js "D:\笔记" --in-place
```

使用 `--in-place` 时，修改前会自动生成 `.bak-<时间戳>` 备份。

### 常用选项

| 选项                           | 说明                           |
| ---------------------------- | ---------------------------- |
| `-c, --check`                | 只检查，不修改                      |
| `-i, --in-place`             | 直接修改原文件，并创建备份                |
| `-o, --out <路径>`             | 指定输出文件                       |
| `-r, --recursive`            | 递归处理子目录                      |
| `--state=keep\|open\|closed` | 设置折叠块默认状态                    |
| `--breaks=on\|off`           | 是否将普通换行转换为 `<br>`            |
| `--code-blank=zwsp\|keep`    | 代码块空行的处理方式                   |
| `--max-block-kb=<数字>`        | 限制单个 `<details>` 块大小，默认 `64` |
| `--summary-markdown`         | 同时处理 `<summary>` 中的 Markdown |
| `--no-backup`                | 不创建备份                        |
| `-q, --quiet`                | 减少输出                         |
| `-h, --help`                 | 查看帮助                         |

### 注意

转换以后，`<details>` 内部的 Markdown 会变成 HTML。

所以在 Typora 中打开时，块内的列表、表格等内容可能会看到 HTML 标签。如果还需要继续编辑 Markdown，建议先保留原文件或者使用脚本自动生成的 `.fixed.md` 文件。

另外，代码块中的空行默认会使用零宽空格处理。如果不希望这样，可以使用：

```bash
--code-blank=keep
```

脚本只处理 `<details>` 块，块外的 Markdown 不会修改。

重复运行同一个文件不会继续重复转换。

---

## 📄 许可

`fix_details.js` 内置了 [markdown-it](https://github.com/markdown-it/markdown-it)，使用 MIT 协议。

相关版权声明和许可文本见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
