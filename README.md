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

建议使用仅有目标桶权限的 IAM 子账号。修改权限、时间和扩展属性使用 OBS 的 [SetObjectMetadata](https://support.huaweicloud.com/api-obs/obs_04_0091.html)，需授予对应的修改对象元数据权限。`endpoint` 使用桶所在区域的地址；程序会自动补上桶名，也接受带桶名的地址。

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

停止并卸载：`sudo systemctl stop obs`。SIGTERM / Ctrl-C 会先卸载，再等待最多 3 秒让正在执行的请求结束；未上传的暂存数据继续保留，不会无限等待其他进程关闭文件。查看错误：`journalctl -u obs`。

## 使用前须知

- **共享访问**：能到达挂载点的本地用户均可读写。`chmod` / `chown` 保存并显示属性，但不用于访问控制；需要隔离时限制挂载点父目录权限。普通用户挂载需在 `/etc/fuse.conf` 中启用 `user_allow_other`。
- **本地空间**：修改文件需要暂存完整内容；删除或覆盖仍打开的文件，也会为旧句柄保留完整内容。暂存位置为 `$TMPDIR`（默认 `/tmp`），默认保留 64 MiB 空闲空间，空间不足时返回 `ENOSPC`；可用 `min_free_space` 调整。检查与实际写入间仍可能被其他进程占用空间。
- **对象存储语义**：有改动的文件每次同步均全量上传，重命名是非原子的 Copy + Delete，超过单次复制上限时使用分段复制。所有复制结果经正文校验后才删除源对象；目录复制中途失败会保留源目录和已复制的目标条目。删除源对象失败会记录 ERROR 并保留残留对象。`RENAME_EXCHANGE` / `RENAME_WHITEOUT` 不支持；`NOREPLACE` 只能保证本挂载内的检查，无法排除其他客户端同时写入。多机写同一对象时最后写入者覆盖，不适合数据库或虚拟机磁盘。不支持硬链接和设备文件。
- **读取一致性**：远端只读句柄固定打开时的 ETag，使用独立读缓存（不支持对这类句柄做 `mmap`）；其他客户端改写对象后，后续读取可能返回 `ESTALE`，重新打开文件读取新版。外部上传对象的修改时间使用 OBS `Last-Modified`。
- **性能与容量**：目录首次读取仍需完整列举，此后同一目录句柄复用快照；重新打开目录可查看变更。元数据缓存目标上限默认 10000 条，活跃请求期间每秒检查回收；突发请求和本地暂存文件可使条目数暂时超过上限。4 个 FUSE 工作线程允许远端读取和普通写回并发；某个文件上传期间，该文件的修改会等待，其他已打开文件仍可读写。重命名、删除等命名空间操作仍会串行等待。`df` 使用桶配额；无配额时显示约 16 TiB 的合成容量，并非实际容量上限。用量统计有延迟。

## 上传失败与排查

连接失败、HTTP 暂时错误和下载正文中断共用最多 5 次请求尝试；每次按配置超时，重试间指数退避。

上传失败时，数据保留在 `obs-mount-staging-*` 目录，日志会输出路径。同名 `.yaml` 文件记录 endpoint、桶、对象 key 和元数据，不含凭据。分段上传另有 `.upload.yaml`，记录 uploadId、已上传段和完成阶段；取消失败或完成结果不确定时保留记录。

当前会话可重新打开文件并通过 `fsync` / 关闭重试；有上次分段记录时先取消该任务，再从暂存文件重新上传，取消失败则停止重试并保留数据。重启后需按记录人工恢复，不会自动覆盖远端。不要按目录年龄删除待恢复数据，并留意系统临时目录清理策略。重启后会在默认日志级别提示遗留目录。对 `.upload.yaml` 中的未完成任务，可在核对 endpoint、桶、key 和 uploadId 后使用 OBS 工具定向取消；取消只释放未完成分段，不回滚已完成对象。桶的未完成分段生命周期规则可作为崩溃时的清理补充。不同挂载各用独立目录，运行中的目录由锁保护。

默认只输出错误。需要详细日志时运行：

```sh
sudo env RUST_LOG=debug /etc/obs/obs -c /etc/obs/obs.yaml
```

挂载失败先检查 FUSE 3、`/dev/fuse`、AK/SK、桶所在区域及系统时间。

## 开发与测试

需要 Rust stable（源码至少 1.88）和 C/C++ 构建工具（Debian / Ubuntu：`build-essential cmake perl pkg-config`）。

源码集中在 `src/`：`main.rs` 负责启动和配置，`fs.rs` 实现 FUSE，`obs.rs` 封装 OBS API。测试直接写在各模块的 `#[cfg(test)] mod tests` 中；`test_support.rs` 提供仅在测试时编译的模拟服务和临时资源管理。

```sh
cargo build --release  # target/release/obs-mount
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

# 显式运行 CLI 和真实挂载测试，需要上面构建的二进制、/dev/fuse 和 fuse3
cargo test -- --ignored --nocapture
```

测试在进程内启动模拟 OBS 服务，覆盖签名、响应正文错误、读取版本校验、原生元数据更新、分段复制、分段上传及取消失败恢复；真实挂载测试覆盖打开文件时重命名、删除、覆盖、远端对象变化以及慢上传期间的并发读写，无需 Python 或云端凭据。CLI 和挂载测试默认标记为 `ignored`，可用 `OBS_MOUNT_BIN` 指定待测二进制；CI 在 x86_64、ARM64 的 Ubuntu 24.04 原生 runner 上分别构建并强制执行挂载测试，任一架构失败都会阻止发布。真实 OBS、长期稳定性和断网恢复仍需另外验证。

推送 `v*` tag 触发 CI 构建并发布静态 musl 包；构建与发布步骤见 [CI 配置](.github/workflows/ci.yml)。
