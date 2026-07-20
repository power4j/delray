# delray

面向资源受限 Linux 服务器的命令行网络流量分析工具。在异常网络流量发生时，定位流量来源（进程与 IP）。

## 依赖

### 运行环境（目标机）

| 依赖 | 要求 | 说明 |
|---|---|---|
| Linux | 仅支持 Linux | x86_64；1 CPU / 1G 内存 / 20G 磁盘可运行 |
| glibc | ≥ 2.28 | 约等于 Debian 10、RHEL 8 及更新发行版 |
| libpcap 运行库 | — | Debian/Ubuntu：`apt install libpcap0.8`；RHEL 系：`yum install libpcap` |
| 权限 | root 或 `CAP_NET_RAW` | 抓包需要；`sudo` 运行或对二进制 `setcap cap_net_raw+ep ./delray`（`setcap` 由 `libcap2-bin` 提供） |

### 开发环境（本机）

| 依赖 | 版本 / 安装方式 |
|---|---|
| Rust | ≥ 1.88（edition 2024，MSRV 由 `Cargo.toml` 的 `rust-version` 强制检查） |
| libpcap 开发包 | Debian/Ubuntu：`apt install libpcap-dev`；RHEL 系：`yum install libpcap-devel` |
| zig | 交叉编译所需：从 [ziglang.org](https://ziglang.org/download/) 下载解压并加入 `PATH` |
| cargo-zigbuild | `cargo install cargo-zigbuild` |

开发编译无需 root：

```bash
# 安装 zig（如未安装）
# 下载 zig 官方 tar.xz，解压，export PATH="$PATH:/path/to/zig"

# 安装 cargo-zigbuild
cargo install cargo-zigbuild

# 本地开发编译（需 libpcap-dev 已安装）
cargo build

# 裁剪检查
cargo clippy -- -D warnings
cargo fmt --check
cargo test
```

### Windows x86_64 build (target platform)

Windows `x86_64` is still a target platform under validation and is not yet a supported release platform. Building from source requires Rust 1.88, Npcap Runtime, and the Npcap SDK. Npcap is installed separately by the environment; Delray does not bundle it.

The Npcap SDK x64 `Lib` directory must contain `wpcap.lib` and `Packet.lib`. Set `LIBPCAP_LIBDIR` to that directory in the current PowerShell session before building:

```powershell
$env:LIBPCAP_LIBDIR = 'path-to-npcap-sdk\Lib\x64'

cargo +1.88.0 check --locked
cargo +1.88.0 build --release --locked
```

The release executable is `target\release\delray.exe`. If MSVC reports `LNK1181: cannot open input file 'wpcap.lib'`, check that `LIBPCAP_LIBDIR` points to the SDK x64 `Lib` directory, not the Npcap Runtime installation directory or an x86 library directory.

## 构建分发二进制

以 glibc 2.28 为基线交叉构建，产物兼容 glibc ≥ 2.28 的目标机：

```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.28
```

产物位于 `target/x86_64-unknown-linux-gnu/release/delray`（约 1.4M），拷贝到目标机即可运行。

验证产物依赖版本：

```bash
readelf -d target/x86_64-unknown-linux-gnu/release/delray | grep NEEDED
# 应输出：libpcap.so.0.8, libc.so.6, libpthread.so.0, libdl.so.2
```

## 用法

```
Network traffic analyzer

Usage: delray [OPTIONS] [INTERFACE]

Arguments:
  [INTERFACE]  Network interface to capture on (omit to select interactively in plain foreground mode)

Options:
      --proc-refresh <PROC_REFRESH>  Process table refresh interval in seconds (must be > 0) [default: 2]
      --output <OUTPUT>              Output file for background mode (omit for foreground terminal display)
  -f, --format <FORMAT>              Output format: plain (default) or json [default: plain] [possible values: plain, json]
  -n, --top-n <TOP_N>                Number of entries per top-N list (default: 10, min: 1) [default: 10]
      --diagnostics                  Emit process attribution diagnostics to stderr on each output refresh
  -h, --help                         Print help
  -V, --version                      Print version
```

示例：

```bash
# 前台 TUI 交互。未指定网卡时先进入网卡选择界面
./delray

# 前台 TUI 交互，并直接打开 eth0
./delray eth0

# 后台写文件（tab 排版，无样式）
./delray eth0 --output /tmp/stats.txt

# JSONL 流到 stdout
./delray eth0 -f json

# JSON 对象覆盖写文件
./delray eth0 -f json --output /tmp/stats.json

# 只显 top 3
./delray eth0 -n 3

# 输出 JSONL，同时把进程归属诊断写到 stderr
./delray eth0 -f json --diagnostics
```

### 前台 TUI

前台模式提供概览、进程、IP 和关于页面。启动时未指定 `INTERFACE` 会先显示网卡选择界面；运行中按 `i` 可重新打开网卡选择界面并切换抓包网卡。

进程列表显示进程名、PID、路径身份对应的流量累计、`Last seen` 和未归属流量。进程详情页会保留所选进程的最后一份数据；当进程离开当前 top-N 或进程快照过期时，详情页显示 `Tracking paused` 状态，而不是自动退出。

### 统计边界

接口总流量在捕获到数据包时立即累计。进程归属是 best-effort：权限、网络命名空间、容器、WSL 代理路径、端口复用和系统快照时序都可能导致部分流量进入 `<unattributed traffic>`。

TCP/UDP 本机 socket 查询未命中时，Delray 会把近期流量放入一个短窗口待归属队列。新进程表发布后，只有找到唯一 PID 时才提交到对应进程；超时、歧义、查询失败、陈旧进程表或队列溢出时提交到未归属流量。已经提交到进程或未归属流量的历史数据不会被后续查询追溯修改。

loopback 设备可能同时看到同一传输的入站帧和出站帧。例如本机下载 10 MB 数据时，`lo` 或 WSL 的 loopback 路径可能显示约 10 MB In 和 10 MB Out，合计接近 20 MB。这是系统抓包语义，不表示公网实际下载了两倍数据。
