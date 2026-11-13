# 发布

发布由 GitHub Actions 的 `.github/workflows/release.yml` 完成：推送标签 `v<版本>` 后，它在 GitHub 的 macOS、Windows 与
Ubuntu 机器上各自运行 `cargo xtask package`，把得到的安装包连同 `SHA256SUMS` 发布成一个 GitHub Release，应用的
[更新检查](../architecture/desktop.md#更新)找的就是它。

## 发布的文件

| 文件 | 系统 | 打包 |
| --- | --- | --- |
| `Egrio_<版本>_aarch64.dmg` | macOS 13 起，Apple 芯片 | [macOS 应用包](../platforms/macos.md#产品身份签名与服务安装) |
| `Egrio_<版本>_x64.dmg` | macOS 13 起，Intel | 同上，在 Apple 芯片机器上交叉编译 |
| `Egrio_<版本>_x64-setup.exe` | Windows 10 22H2 起与 Windows 11，x64 | [Windows 安装程序](../platforms/windows.md#安装程序) |
| `egrio_<版本>_amd64.deb` | Ubuntu 24.04 起与其他基于 Debian 的 x64 系统 | [Linux 发行包](../platforms/linux.md#发行包)，在 Ubuntu 24.04 上构建 |
| `SHA256SUMS` | 以上文件的 SHA-256，`sha256sum` 的格式 | |

文件名是打包任务、工作流与应用共同的约定（应用按 `updates.rs` 的 `installer_name` 找本机的安装包），改名时三处一起改。
版本带 `-` 后缀（如 `0.2.0-beta.1`）的发布标成预发布，更新检查不提示它。

## 准备

- 根目录的 [LICENSE](../../LICENSE) 是三个平台打包的共同输入，随安装包携带；安装后的路径见对应平台文档。
- 发布页面须能取得对应版本的源码与 `LICENSE`；使用独立发行仓库时，提供实际源码版本或标签的链接。
- 仓库的 Actions secrets：
  - `MACOS_CERTIFICATE`：Developer ID Application 证书连同私钥导出的 `.p12`，base64 编码；`MACOS_CERTIFICATE_PASSWORD`
    是导出时设的密码。
  - `APPLE_ID`、`APPLE_TEAM_ID` 与 `APPLE_APP_PASSWORD`：公证用的 Apple ID、团队 ID 与 App 专用密码，工作流用它们
    存下 `notarytool` 的钥匙串配置。
- 应用匿名读取 GitHub 的 REST API，发布所在的仓库必须公开。源码仓库私有时，另建一个公开仓库放发布（它至少要有一个
  提交，标签才建得出来），在 Actions 变量 `RELEASES_REPOSITORY` 里写它的 `owner/name`，在 secret `RELEASES_TOKEN` 里放
  一个对它有 Contents 读写权限的细粒度令牌。工作流把这个仓库名编进应用（`EGRIO_RELEASES_REPOSITORY`），没有这个变量时
  是源码仓库自己。

## 步骤

1. 把工作区 `Cargo.toml` 里 `[workspace.package]` 的 `version` 改成新版本，提交并推送。
2. 推送同名标签：`git tag v<版本>`，再 `git push origin v<版本>`。标签与工作区的版本不一致时工作流在第一步失败。
3. macOS 两个架构、Windows 与 Linux 四个打包作业都成功后，发布作业算出 `SHA256SUMS` 并建立发布；任何一个失败都不
   发布，修好后删掉标签再推。

在 Actions 页面手动运行工作流只打包、不发布，安装包留作这次运行的产物；没有证书 secret 时 macOS 包临时签名、不公证，
只用来检查打包。
