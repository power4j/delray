# tag 推送后按已有版本恢复发布

如果 Release 工作流已经推送版本提交或 `vX.Y.Z` tag，后续 Draft Release 创建失败，维护者不得直接重跑完整版本 bump。该版本号和 tag 已被占用，恢复操作必须针对已有 tag 创建或补齐 Draft Release，必要时只重跑失败的 Release job；只有远端版本元数据尚未写入时，才允许重新执行完整 Release 工作流。这样可以避免发布重试意外跳过版本或创建错误的新版本。
