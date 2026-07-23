# 固定 Release 构建工具链

Release 制品使用固定的 Rust `1.96.0`、Zig 和 `cargo-zigbuild` 版本；Linux 构建继续使用 glibc `2.28` 目标。日常 CI 可以额外验证 stable，但正式制品不随 hosted runner 或构建工具的默认版本漂移。构建完成后必须检查 Linux ELF 依赖和 glibc 基线。
