# delray

面向资源受限 Linux 服务器的命令行网络流量分析工具。在异常网络流量发生时，定位流量来源（进程与 IP）。

## 运行前提

- 仅支持 Linux
- 抓包需要 root 权限，或具备 `CAP_NET_RAW` 能力；非 root 运行可对二进制设置能力：`setcap cap_net_raw+ep ./delray`（`setcap` 由 `libcap2-bin` 提供）
- 动态链接 libpcap，目标机需安装运行库：Debian / Ubuntu 安装 `libpcap0.8`，RHEL 系安装 `libpcap`
- 二进制以 glibc 2.28 为最低基线构建，目标机 glibc 版本不低于 2.28，约对应 Debian 10 及更新发行版

## 构建

以 glibc 2.28 为基线交叉构建，产物兼容 glibc 2.28 及以上的服务器：

```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.28
```

构建前置：

- 安装 zig 与 cargo-zigbuild（`cargo install cargo-zigbuild`）
- 安装 libpcap 开发包：Debian / Ubuntu 安装 `libpcap-dev`，RHEL 系安装 `libpcap-devel`

产物位于 `target/x86_64-unknown-linux-gnu.2.28/release/delray`，拷贝到目标机即可运行。

## 相关文档

- [产品定义 v2](docs/public/idea-v2.md) — 产品定位、v1 功能范围、约束与技术方案
