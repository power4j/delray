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
| Rust | ≥ 1.85（edition 2024，MSRV 由 `Cargo.toml` 的 `rust-version` 强制检查） |
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
  [INTERFACE]  Network interface to capture on (omit to list available interfaces)

Options:
      --proc-refresh <SECONDS>  /proc inode-table rebuild interval (must be > 0) [default: 2]
      --output <FILE>           Output file for background mode (omit for foreground display)
  -f, --format <FORMAT>         Output format: plain (default) or json [default: plain]
  -n, --top-n <N>               Entries per top-N list (min: 1) [default: 10]
  -h, --help                    Print help
  -V, --version                 Print version
```

示例：

```bash
# 前台 TUI 交互（多页：概览/进程/IP/关于）
./delray eth0

# 后台写文件（tab 排版，无样式）
./delray eth0 --output /tmp/stats.txt

# JSONL 流到 stdout
./delray eth0 -f json

# JSON 对象覆盖写文件
./delray eth0 -f json --output /tmp/stats.json

# 只显 top 3
./delray eth0 -n 3
```
