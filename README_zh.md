<!-- 顶部 banner 由 socialify (https://socialify.git.ci) 生成，自动抓取 GitHub 仓库描述与 star/fork/issue/pull 数量。 -->
<div align="center">

<img src="https://socialify.git.ci/zihaveaDream/unhide-rs/image?description=1&font=Inter&forks=1&issues=1&name=1&owner=1&pattern=Charlie+Brown&pulls=1&stargazers=1&theme=Light" alt="unhide-rs" width="640" />

# unhide-rs

**UnHide 取证工具的 Rust 忠实复刻——跨平台，单一二进制，专门发现被 rootkit 隐藏的进程与 TCP/UDP 端口。**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/zihaveaDream/unhide-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/zihaveaDream/unhide-rs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/zihaveaDream/unhide-rs?sort=semver)](https://github.com/zihaveaDream/unhide-rs/releases)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20*BSD-lightgrey)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

[English](README.md) · **中文**

</div>

---

## 这是什么？

UnHide 是一个**取证**工具，用来发现"存在于系统、却对常规工具（`ps`、`ss`/`netstat`）
隐藏"的进程和 TCP/UDP 端口——这是 rootkit 或恶意内核模块的典型特征。它的原理是
**交叉比对**：把用户态工具报告的内容，与内核实际知道的内容（`/proc`、系统调用、
直接探测 PID/端口空间）做对比。

`unhide-rs` 用 Rust 完整重写整套工具，输出、退出码、检测语义与原版**逐字节/逐码对齐**，
同时做成单一二进制 + 可选 GUI，并提供多平台 release 构建。

## 特性

- 🦀 **纯 Rust**，单一 `unhide` 二进制，四个子命令。
- 🔍 **原版全部技术**：`/proc` vs `ps`、procfs 遍历、系统调用扫描、PID 暴力遍历、
  reverse（反篡改）检查，以及 TCP/UDP 隐藏端口探测。
- 🖥️ **可选 GUI**（`unhide-gui`，egui）——点选测试、可视化运行。
- 🎯 **忠实**：字符串、退出码、语义与 UnHide v20240510 完全一致。
- 📦 **多平台 release**（GitHub Actions）——多架构 musl 静态 Linux、macOS（Intel + Apple Silicon）、FreeBSD。
- ✅ 已与原版 C 二进制逐项对照验证。

## 子命令

原版是四个独立程序；这里合并为一个二进制的子命令：

| 命令 | 原版 | 平台 |
|---|---|---|
| `unhide linux [options] <test_list>` | `unhide-linux` | Linux ≥ 2.6 |
| `unhide posix <proc\|sys>` | `unhide-posix` | 通用 Unix |
| `unhide tcp [options]` | `unhide-tcp` | Linux/macOS/*BSD |
| `unhide rb` | `unhide_rb` | Linux |

> 与原版一样，运行 `linux` / `tcp` / `rb` 需要 **root**。

## 安装

从 [Releases](https://github.com/zihaveaDream/unhide-rs/releases) 下载对应平台的归档，解压后运行
`./unhide`；或从源码构建（见下）。

**Linux 该选哪个？**

| 产物 | 链接方式 | 适用 |
|---|---|---|
| `…-linux-musl`（x86_64 / aarch64 / armv7 / i686 / riscv64） | **静态** | 服务器、老发行版、任意 Linux——不依赖 glibc（**推荐**）。仅 CLI。 |
| `…-linux-gnu`（x86_64） | 动态 glibc | 较新的桌面系统；**额外含 GUI**（`unhide-gui`），需要较新的 glibc。 |

> 如果 `gnu` 版报 `GLIBC_2.xx not found`，说明你系统的 glibc 太旧（如 CentOS 7/8）——
> 改用 **musl** 版：完全静态、到处能跑。GUI 无法静态链接，所以只在 `gnu` 桌面归档里。

## 快速上手

```sh
sudo unhide linux quick reverse      # 快速进程扫描 + 反篡改检查
sudo unhide linux -m -d sys procall brute reverse   # 深度取证扫描
sudo unhide tcp -s                   # 快速隐藏端口扫描（server 策略）
sudo unhide tcp -flov                # 隐藏端口 + fuser/lsof 归因 + 写日志
```

完整的**[使用手册](docs/USAGE_zh.md)**（English：[docs/USAGE.md](docs/USAGE.md)）
涵盖每个选项、测试列表、可运行案例与场景 playbook。

## 构建

```sh
cargo build --release                 # 全部（含 GUI，需图形开发库）
cargo build --release -p unhide-cli   # 只构建 CLI（无图形依赖）
```

Linux 下构建 GUI 需要图形开发库（Debian/Ubuntu）：

```sh
sudo apt-get install -y libclang-dev libgtk-3-dev libxcb-render0-dev \
  libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

## 发布

推送 `v*` tag 会触发 `.github/workflows/release.yml`，自动交叉编译并发布归档：

- **Linux**（musl 静态）：x86_64 / aarch64 / armv7 / i686 / riscv64
- **Linux x86_64 桌面** 与 **macOS**（Intel + Apple Silicon）：CLI + GUI
- **FreeBSD**：CLI（best-effort）

## 测试

```sh
cargo test --workspace
```

## 忠实度

- 输出字符串、退出码、检测语义与原版一致（errno vs 返回值、PID 范围、测试执行顺序、
  标准测试展开等）。
- 已在 Linux 上以 root 与原版 C 二进制逐项对照验证（proc/procfs/sys/quick/reverse、
  全部基础测试、tcp 各模式、posix、rb），输出一致（仅时序性误报因运行时刻不同而异）。

## License

[GPL-3.0-or-later](LICENSE)（与原版 UnHide 一致）。
