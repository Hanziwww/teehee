# Git Hooks 安装指南

## 📋 功能说明

Pre-commit hook 会在每次 `git commit` 前自动运行以下检查（与 GitHub CI 流水线完全对齐）：

1. **代码格式检查** - `cargo fmt --all -- --check`
2. **Clippy 代码检查** - `cargo clippy -- -D warnings`
3. **运行测试** - `cargo test`

只有所有检查都通过，才允许提交。这可以确保提交的代码质量，避免 CI 失败。

## 🚀 安装方法

在项目根目录运行以下命令：

```bash
git config core.hooksPath .githooks
```

## ✅ 验证安装

安装后，尝试提交一些修改：

```bash
git add .
git commit -m "test commit"
```

你应该会看到 pre-commit hook 自动运行三个检查。

## 🔧 临时跳过 Hook（不推荐）

如果在紧急情况下需要跳过检查：

```bash
git commit --no-verify -m "urgent fix"
```

⚠️ **注意**：跳过 pre-commit 检查可能导致 CI 失败！

## 🛠️ 手动运行检查

你也可以手动运行各项检查：

```bash
# 格式化代码
cargo fmt --all

# 运行 Clippy
cargo clippy --all-targets --all-features -- -D warnings

# 运行测试
cargo test
```

## 📝 Windows 用户注意事项

如果在 Windows 上遇到权限问题，可以使用 Git Bash 或确保 `.githooks/pre-commit` 文件有执行权限。

Git 会自动处理跨平台的 shell 脚本执行。

## 🔄 卸载 Hook

如果需要禁用 pre-commit hook：

```bash
git config --unset core.hooksPath
```

这会恢复到 Git 默认的 `.git/hooks` 目录。

