# 使用 listeners 并将 MSRV 提高到 Rust 1.88

Delray 使用 `listeners 0.6` 作为进程查询基础，不自行维护 Linux 和 Windows 的系统 API 实现。Delray 主要交付预编译应用，低编译器版本不会提高目标机兼容性；`listeners 0.6.0` 已验证可在 Rust 1.88 编译，但不能在 Rust 1.85 编译，因此将 MSRV 提高到 Rust 1.88。Linux 运行兼容性仍由 glibc 2.28 和 libpcap 基线独立保障。

`listeners` 应封装在 Delray 的进程查询接口后，通过 `get_all()` 建立包含本机 IP、端口和协议的索引。项目锁定依赖版本并持续使用 Rust 1.88 验证 MSRV；依赖升级确有需要时可以提高 MSRV。查询不到的流量继续计入「未归属流量」。
