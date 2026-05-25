# unhide-rs — 使用手册

> English version: [USAGE.md](USAGE.md)

UnHide Rust 版的实用指南：每个子命令、选项、测试列表、可运行的案例、常用场景，
以及如何解读输出。

---

## 1. 它做什么、怎么做

UnHide 是一个**取证**工具。它用来发现**存在于系统、却对常规工具（`ps`、
`ss`/`netstat`）隐藏**的进程与 TCP/UDP 端口——这是 rootkit 或恶意内核模块的典型特征。

核心思想是**交叉比对两个独立视角**：

- `/bin/ps`（或 `ss`/`netstat`）报告了什么，对比
- 内核实际知道什么（通过 `/proc`、系统调用，或直接探测 PID / 端口空间）。

如果内核能看到某个进程/端口，而 `ps`/`ss` 看不到 → 它是**隐藏的**。
如果 `ps` 显示了一个内核无法确认的线程 → 它是**伪造的**（被篡改的 `ps`）。
由于 `ps` 本身可能被植入木马，工具刻意以"直接查询内核"作为可信的一侧。

> 运行 `linux`、`tcp`、`rb` 需要 **root**（要读取每个 `/proc` 项、发起特权系统调用、
> 绑定每个端口）。

---

## 2. 获取方式

- **预编译**：从 GitHub Release 下载对应平台的归档（见主 README），解压后运行
  `./unhide`。
- **自行构建**：`cd unhide-rs && cargo build --release -p unhide-cli`
  → 二进制在 `unhide-rs/target/release/unhide`。

下文示例里的 `unhide` 即该二进制（若不在 `PATH` 中，用 `sudo ./unhide ...`）。

---

## 3. 命令结构

原版是四个独立程序；这里合并为一个二进制的子命令：

```
unhide linux [options] <test_list>     # 隐藏进程（Linux ≥ 2.6）
unhide posix <proc|sys>                # 隐藏进程（通用 Unix）
unhide tcp   [options]                 # 隐藏 TCP/UDP 端口
unhide rb                              # unhide.rb 的玩具移植（Linux）
unhide --help                          # 列出子命令
unhide <sub> --help                    # 某子命令的帮助
```

---

## 4. `unhide linux` — 隐藏进程

### 4.1 用法

```
sudo unhide linux [options] <test_list>
```

`<test_list>` 是一个或多个测试名（标准或基础），如 `quick reverse`、
`sys procall brute`。

### 4.2 选项

| 短 | 长 | 含义 |
|---|---|---|
| `-V` | `--version` | 打印版本头并退出 |
| `-v` | `--verbose` | 详细模式（显示警告）；可叠加（`-vv`） |
| `-h` | `--help` | 显示帮助并退出 |
| `-m` | `--morecheck` | 额外检查（影响 `procfs`、`checkopendir`、`checkchdir`）；隐含 `-v` |
| `-r` | `--alt-sysinfo` | 在 meta 测试中用备用 sysinfo 测试（为兼容保留，当前与原版一样无实际作用） |
| `-f` | | 在当前目录写日志 `unhide-linux_<日期>.log` |
| `-o` | `--log` | 同 `-f` |
| `-d` | `--brute-doublecheck` | 在 `brute` 测试中双重检查（减少误报） |
| `-u` | | 子进程 stdout 不缓冲（给 `ps` 加 `stdbuf` 前缀；被管道时有用） |
| `-H` | `--human-frienly` | 更友好的输出（增加"未发现隐藏进程"/"Done !"等提示） |

> root 检查在选项处理**之前**，所以非 root 下即便 `unhide linux -h` 也会先打印头部、
> 再输出 `Error : You must be root ...`——与原版完全一致。

### 4.3 测试列表

**标准测试**（每个会展开为若干基础测试）：

| 测试 | 作用 |
|---|---|
| `proc` | 用 `stat` 比对 `/proc` 与 `ps` |
| `procfs` | 比对 `ps` 与遍历 procfs（`chdir` + `opendir` + `readdir`） |
| `procall` | `proc` + `procfs` 合并 |
| `sys` | 比对 `ps` 与系统调用（`kill`、`getpriority`、`getpgid`、`getsid`、`sched_*` 等） |
| `quick` | 快速组合 proc/procfs/sys——约快 20 倍，可能更多误报 |
| `reverse` | 验证 `ps` 显示的每个线程内核是否也看得到（发现**伪造** PID） |
| `brute` | 用 fork + 线程暴力遍历整个 PID 空间（最彻底、最慢） |

**基础测试**（只跑某一项检查）：`checkproc`、`checkchdir`、`checkopendir`、
`checkreaddir`、`checkgetprio`、`checkgetpgid`、`checkgetsid`、`checkgetaffinity`、
`checkgetparam`、`checkgetsched`、`checkRRgetinterval`、`checkkill`、
`checknoprocps`、`checkquick`、`checkreverse`、`checkbrute`、`checksysinfo`、
`checksysinfo2`、`checksysinfo3`。

要点：
- 测试按**固定的内部顺序**执行，与你输入的顺序无关。
- `sysinfo` 测试**不**属于 `sys`/`quick`（易误报）；需用 `checksysinfo[2|3]` 显式触发。
- `brute` 刻意做到穷尽：遍历 PID `301..pid_max`（64 位上 `pid_max` 为 `2^22`），
  因此可能很慢。用于深度扫描，而非快速排查。

### 4.4 案例

```sh
# 最快排查（组合快速扫描）
sudo unhide linux quick

# 快速 + 验证 ps 未被篡改
sudo unhide linux quick reverse

# 标准扫描
sudo unhide linux sys proc

# 深度/彻底扫描：双重检查、额外检查、友好输出
sudo unhide linux -m -d sys procall brute reverse

# 详细模式 + 写日志
sudo unhide linux -v -o sys

# 单个基础检查
sudo unhide linux checkproc
```

### 4.5 解读输出

干净的运行只打印头部、各测试的起始行，没有别的。发现隐藏进程时报告为：

```
Found HIDDEN PID: 12345
	Cmdline: "/usr/sbin/evil --daemon"
	Executable: "/usr/sbin/evil"
	Command: "evil"
	$USER=root
	$PWD=/
```

- `Cmdline` —— `/proc/<pid>/cmdline` 的第一个参数（空则 `<none>`）。
- `Executable` —— `/proc/<pid>/exe` 链接目标（不可读则 `<no link>` / `<nonexistant>`）。
- `Command` —— `/proc/<pid>/comm`；内核线程显示为 `[name]`。
- `$USER` / `$PWD` —— 来自进程环境。

`reverse` 测试则把篡改报告为：
`Found FAKE PID: 12345  Command = ...  not seen by N system function(s)`。

### 4.6 退出码

- `0` —— 未发现隐藏/伪造进程
- `1` —— 发现至少一个隐藏/伪造进程（以及：非 root、或无参数 `argc < 2`）

脚本里很实用：`sudo unhide linux quick reverse || echo "可疑"`。

---

## 5. `unhide tcp` — 隐藏端口

### 5.1 用法

```
sudo unhide tcp [options]
```

它扫描**全部** TCP 与 UDP 端口（1..65535），找出"在用但不被 `ss`（或 `netstat`）
报告"的端口，作为隐藏端口报告。

### 5.2 选项

| 短 | 长 | 含义 |
|---|---|---|
| `-h` | `--help` | 显示帮助并退出 |
| `-V` | | 打印版本头并退出 |
| `-v` | `--verbose` | 显示警告（可叠加） |
| | `--brief` | 抑制警告（默认） |
| `-f` | `--fuser` | 对每个隐藏端口显示 `fuser` 输出（FreeBSD：`sockstat`） |
| `-l` | `--lsof` | 对每个隐藏端口显示 `lsof` 输出 |
| `-n` | `--netstat` | 用 `netstat` 而非 `ss`（端口多的主机会更慢） |
| `-s` | `--server` | 面向开放端口很多的服务器的极快扫描策略 |
| `-o` | `--log` | 写日志 `unhide-tcp_<日期>.log` |

### 5.3 案例

```sh
# 默认扫描（Linux 上用 ss）
sudo unhide tcp

# 显示每个隐藏端口的占用者、详细、写日志
sudo unhide tcp -flov

# 繁忙服务器用快速策略，附带 lsof + fuser 细节
sudo unhide tcp -fls

# 强制用 netstat
sudo unhide tcp -n
```

### 5.4 输出与退出码

隐藏端口报告为：

```
Found Hidden port that not appears in ss: 31337
	fuser reports :
	31337/tcp:            4242
	lsof reports :
	...
```

退出码编码了发现的内容（便于自动化）：

| 码 | 含义 |
|---|---|
| `0` | 无隐藏 |
| `4` | 有隐藏 **TCP** 端口 |
| `8` | 有隐藏 **UDP** 端口 |
| `12` | TCP 与 UDP 都有 |

在开放端口很多的主机上，`-s`（server）比 `ss` 方法快几百倍、比 `netstat` 快上万倍；
那种场景下优先用它。

---

## 6. `unhide posix` — 通用 Unix

面向非 Linux 的 Unix（及极老的 Linux）。恰好接收一个参数：

```sh
sudo unhide posix proc     # /proc 扫描，与 ps 交叉比对
sudo unhide posix sys      # getpriority/getpgid/getsid 扫描
```

这是遗留引擎，**可能比 `unhide linux` 产生更多误报**；能用 `unhide linux` 时就优先用它。
隐藏进程打印为 `Found HIDDEN PID: <pid>` 加命令行。

---

## 7. `unhide rb` — 玩具

```sh
sudo unhide rb
```

老 `unhide.rb` 的忠实移植。它自己的横幅就称其为"proof of fake"/玩具，并警告不要依赖它
（测试更少、更不准、误报很多）。它跑两个阶段（`Phase 1` 后接 `Phase 2` 双重检查），打印
`Suspicious PID <n>:` 块，列出哪些探测器看到了该 PID。发现任何东西退出码为 `-2`（254），
否则 `0`。正经工作请改用 `unhide linux quick reverse`。

---

## 8. `unhide-gui` — 图形前端

`unhide-gui` 是独立二进制（仅桌面平台）。它替你拼命令并运行：

1. 选 **Unhide-linux** 或 **Unhide-tcp** 标签页。
2. 勾选选项与测试。勾一个*复合*测试（如 `procfs`）会自动勾上它的基础测试，反之亦然。
3. 底部显示拼好的命令；**Generate** 刷新它，**Copy to ClipBoard** 复制它。
4. **Run** 执行命令并把输出流式显示到一个窗口（Close / Clear）。

它调用的是同样的 `unhide linux` / `unhide tcp` 子命令，因此要能找到 `unhide` 二进制
（同目录，或在 `PATH` 中）。请以 root 运行以便扫描生效。

---

## 9. 常用场景（playbook）

**对可疑主机快速排查**
```sh
sudo unhide linux quick reverse      # 进程（快） + ps 完整性检查
sudo unhide tcp -s                   # 端口（快速 server 策略）
```

**彻底取证扫描（收集证据）**
```sh
sudo unhide linux -v -o -m -d sys procall brute reverse
sudo unhide tcp -flov                # 写日志 + fuser/lsof 归因
```
`-o` 会在当前目录留下带时间戳的 `.log` 文件。

**只猎取隐藏的监听端口，并归因**
```sh
sudo unhide tcp -fl                  # 谁占用了每个隐藏端口
echo "exit=$?"                       # 4=TCP, 8=UDP, 12=两者
```

**检查 `ps` 本身是否被篡改**
```sh
sudo unhide linux reverse            # 若 ps 说谎则报 "FAKE PID"
```

**用于监控脚本**
```sh
if ! sudo unhide linux -u quick reverse > /var/log/unhide.txt 2>&1; then
    alert "unhide 发现隐藏/伪造进程"
fi
```
`-u` 让子进程输出不缓冲，被管道时更友好。

---

## 10. 解读误报

对存活系统做进程/端口扫描天然存在竞态，偶发误报在所难免，尤其是：

- **繁忙主机**（进程/端口在扫描途中出现又消失），
- `sysinfo` 系列测试（基于计数；可能多报——这正是它们不在 `sys`/`quick` 里的原因），
- `unhide posix` 与 `unhide rb`（设计上就不够精确），
- 短命进程（`bash` 单行命令、构建步骤、`<defunct>` 僵尸）。

用 `-d`（`brute` 的双重检查）并在系统空闲时复跑，可把真实发现与噪声区分开。**真正**的
隐藏进程是可复现的，且其 cmdline/exe 通常可疑或为 `<none>`/`<nonexistant>`。

---

## 11. 与原版的差异

- 四个工具现在是一个 `unhide` 二进制的子命令（原版分别是 `unhide-linux`、
  `unhide-posix`、`unhide-tcp`、`unhide_rb`）。选项、测试名、输出、退出码其余均一致。
- `--help` 与非法选项的报错文案由参数解析器生成，措辞可能与原版 `getopt` 略有不同；
  但选项*语义*与退出码一致。
- GUI 调用的是 `unhide linux` / `unhide tcp`，而非各自独立的二进制。

---

## 12. 参见

- 原版手册页：`man/unhide.8`、`man/unhide-tcp.8`。
- 项目 README：[../README_zh.md](../README_zh.md)（English：[../README.md](../README.md)）。
