# obs-mount

用 Rust 编写的 Linux FUSE 工具，把华为云 OBS **对象桶**挂成本地目录，供备份、恢复和 OpenList 等服务使用。采用 OBS 原生 REST 签名，不支持 POSIX/文件桶。

支持读写、目录、重命名、符号链接、Unix 元数据和扩展属性。写入先暂存本地，在 `fsync` 或关闭时上传，大文件自动分段上传。

## 安装与运行

按 `uname -m` 选择 Release 中的静态包，支持 Debian 13 / Ubuntu：

| 架构 | 下载文件 |
|---|---|
| x86_64（Intel / AMD） | `obs-mount-x86_64-linux-musl.tar.gz` |
| aarch64 / ARM64 | `obs-mount-aarch64-linux-musl.tar.gz` |

```sh
sudo apt-get install -y fuse3  # Debian / Ubuntu；其他发行版安装对应的 FUSE 3 包
tar -xzf "obs-mount-$(uname -m)-linux-musl.tar.gz"
sudo install -d /etc/obs /mnt/obs
sudo install -m 0755 obs /etc/obs/obs
sudo install -m 0600 obs-mount.yaml.example /etc/obs/obs.yaml
sudoedit /etc/obs/obs.yaml
```

填写配置，`mountpoint` 目录需已存在：

```yaml
mountpoint: /mnt/obs
bucket: your-bucket
endpoint: https://obs.cn-north-4.myhuaweicloud.com
ak: YOUR_ACCESS_KEY
sk: YOUR_SECRET_KEY
```

建议使用仅有目标桶权限的 IAM 子账号。`endpoint` 使用桶所在区域的地址；程序会自动补上桶名，也接受带桶名的地址。

```sh
sudo /etc/obs/obs -c /etc/obs/obs.yaml
# 另一个终端中使用
ls /mnt/obs
cp backup.tar.gz /mnt/obs/
```

程序前台运行，默认配置路径为 `/etc/obs/obs.yaml`。命令行 > 环境变量 > 配置文件；环境变量支持 `OBS_BUCKET`、`OBS_ENDPOINT`、`OBS_AK`、`OBS_SK`，配置路径可用 `OBS_MOUNT_CONFIG` 指定。分段上传参数见[配置模板](obs-mount.yaml.example)，完整参数见 `obs --help`。

## 开机挂载

将仓库中的 [obs-mount.service](obs-mount.service) 保存到本地后执行：

```sh
sudo install -m 0644 obs-mount.service /etc/systemd/system/obs.service
sudo systemctl daemon-reload
sudo systemctl enable --now obs
```

停止并卸载：`sudo systemctl stop obs`。查看错误：`journalctl -u obs`。

## 使用前须知

- **共享访问**：能到达挂载点的本地用户均可读写。`chmod` / `chown` 保存并显示属性，但不用于访问控制；需要隔离时限制挂载点父目录权限。普通用户挂载需在 `/etc/fuse.conf` 中启用 `user_allow_other`。
- **本地空间**：修改文件需要暂存完整内容。暂存位置为 `$TMPDIR`（默认 `/tmp`），请预留足够磁盘空间。
- **对象存储语义**：有改动的文件每次同步均全量上传，重命名是非原子的 Copy + Delete；删除源对象失败会记录 ERROR 并保留残留对象。多机写同一对象时最后写入者覆盖，不适合数据库或虚拟机磁盘。不支持硬链接和设备文件。
- **性能与容量**：列目录和查询属性需要远端请求，遍历大目录较慢。`df` 使用桶配额；无配额时显示约 16 TiB 的合成容量，并非实际容量上限。用量统计有延迟。

## 上传失败与排查

上传失败时，数据保留在 `obs-mount-staging-*` 目录，日志会输出路径。同名 `.yaml` 文件记录桶、对象 key 和元数据，不含凭据。

当前会话可重新打开文件并通过 `fsync` / 关闭重试；重启后需按记录人工恢复，不会自动覆盖远端。不要删除含数据的暂存目录，并留意系统临时目录清理策略。不同挂载各用独立目录，运行中的目录由锁保护。

默认只输出错误。需要详细日志时运行：

```sh
sudo env RUST_LOG=debug /etc/obs/obs -c /etc/obs/obs.yaml
```

挂载失败先检查 FUSE 3、`/dev/fuse`、AK/SK、桶所在区域及系统时间。

## 开发与测试

需要 Rust stable 和 C/C++ 构建工具（Debian / Ubuntu：`build-essential cmake perl pkg-config`）。

源码集中在 `src/`：`main.rs` 负责启动和配置，`fs.rs` 实现 FUSE，`obs.rs` 封装 OBS API。测试直接写在各模块的 `#[cfg(test)] mod tests` 中；`test_support.rs` 提供仅在测试时编译的模拟服务和临时资源管理。

```sh
cargo build --release  # target/release/obs-mount
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

# 显式运行 CLI 和真实挂载测试，需要上面构建的二进制、/dev/fuse 和 fuse3
cargo test -- --ignored --nocapture
```

测试在进程内启动模拟 OBS 服务，覆盖签名、读写、元数据、分段上传、上传失败保留与恢复，无需 Python 或云端凭据。CLI 和挂载测试默认标记为 `ignored`，可用 `OBS_MOUNT_BIN` 指定待测二进制；CI 在 x86_64、ARM64 的 Ubuntu 24.04 原生 runner 上分别构建并强制执行挂载测试，任一架构失败都会阻止发布。真实 OBS、长期稳定性和断网恢复仍需另外验证。

推送 `v*` tag 触发 CI 构建并发布静态 musl 包；构建与发布步骤见 [CI 配置](.github/workflows/ci.yml)。
