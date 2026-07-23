# 使用正式版本号配合草稿 Release 管理预发布

发布流水线只接受 `major`、`minor` 或 `patch` bump，并且只能基于当前版本向前生成一个新的 `MAJOR.MINOR.PATCH` 正式版本，同时更新 Cargo 包元数据、创建对应的 annotated `vX.Y.Z` Git tag，并创建 GitHub 草稿 Release。任何通过 GitHub Release 通道发布的版本都必须执行 bump；预发布需求通过 GitHub Release 的预发布标记表达，不把 `beta` 或 `rc` 后缀写入 Cargo 版本号或 Git tag，也不为同一版本创建多个候选 Release。当前 `0.1.0` 作为开发基线，首次 GitHub Release 通过 `patch` bump 生成 `0.1.1`。维护者先编辑草稿 Release 的文案，再人工发布。这样可以保持代码版本、tag 和 Release 的唯一对应关系，同时保留发布前的人工审核机会。
