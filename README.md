# obs-mount

把华为云 OBS **对象桶**挂成本地目录的 FUSE 程序（Rust edition 2024）。

**只走 OBS 原生 REST 签名**（HMAC-SHA1，`Authorization: OBS <AK>:<签名>`，
`x-obs-*` 头），不含任何 S3/SigV4 代码路径。签名规则见
[OBS API 参考](https://support.huaweicloud.com/api-obs/obs_04_0011.html)
（`StringToSign`、`CanonicalizedHeaders`、`CanonicalizedResource`）。

## 项目结构

```text
obs-mount/
  Cargo.toml / Cargo.lock
  LICENSE                 # MIT
  .github/workflows/ci.yml  # 格式/静态检查/测试 + glibc & musl 双构建，tag 发版
  src/
    main.rs   # CLI（clap）：mountpoint、bucket/endpoint/AK/SK（环境变量）、
              #   分段阈值（可选，默认 8 MiB，学 AWS CLI/boto3）；staging 固定在系统临时目录，
              #   allow_root 恒开；启动先做桶可达自检，不过不挂载；
              #   检测 fusermount，缺失时降级挂载（无 auto_unmount）并提示装 fuse3；
              #   日志到 stderr（systemd journal 直接收）
    obs.rs    # OBS 原生客户端：签名（HMAC-SHA1 + 规范头/规范资源/子资源白名单）、
              #   ListObjects（含翻页）、HeadObject、GetObject Range 读、
              #   PutObject、DeleteObject、CopyObject（rename 用）、
              #   分段上传（初始化/传段/合并/取消）+ XML 解析 + 单测
    fs.rs     # FUSE 文件系统（fuser 0.18）：inode↔key 映射、元数据缓存（5 秒 TTL）、
              #   写 staging（按句柄引用计数管理生命周期）、关闭时整文件上传、
              #   rename 时 inode 号保持不变只改指向
  obs-mount.service       # systemd 单元（见“部署”）
  obs-mount.yaml.example  # 配置模板（YAML，唯一格式；占位符，无真实凭据）
```

## 已实现的 FUSE 操作

| 操作 | OBS 实现 |
|---|---|
| `lookup` / `getattr` | `HEAD /<key>`；目录先查 `<dir>/` 占位对象，再用 `prefix=<dir/>&delimiter=/&max-keys=1` 探查 |
| `readdir` | `GET ?prefix=<dir/>&delimiter=/` 翻页聚合（`CommonPrefixes` + `Contents`），含 `.` / `..` |
| `open` / `read` | 读模式直接 Range GET（先 HEAD 定长，越过 EOF 返回空）；写模式把远端内容（如有）下载到 staging 做 read-modify-write。会话内已有 staging 时读写句柄都用它，避免读到尚未上传的旧内容 |
| `create` / `write` | 只写本地 staging 文件，不逐次 PUT |
| `flush` / `fsync` / `release` | 关闭/刷盘时上传：小于阈值单 PUT，大于等于阈值分段上传（默认 8 MiB，学 AWS CLI/boto3），分片 8 MiB（超 80 GiB 的文件自动放大分片以不超 10000 片上限）、4 路并行上传，失败先等齐在途分片再 abort 整个分段上传 |
| `mkdir` / `rmdir` | PUT `<dir>/` 零字节占位对象 / 非空检查后删占位对象 |
| `unlink` | `DELETE /<key>` |
| `rename` | **Copy + Delete，非原子**（目录递归逐 key；中途失败不回滚，已在日志中明示）。成功后 inode 号不变、只把映射指向新 key，打开中的句柄同样改 key |
| `setattr` | 仅截断（下载→本地截断→重传）；mode/uid/gid/atime 等忽略（OBS 不存 Unix 权限），以免 `cp -p` 类工具失败。截断不再销毁仍被句柄使用的 staging，`echo x > file` 可重复执行 |
| `statfs` | 未重写，用 fuser 默认固定值（`df` 数字是假的，以控制台为准） |

未实现（默认返回 `ENOSYS` 或内核默认）：`symlink` / `hardlink`（OBS 无此语义）、
`chmod` / `chown` / `xattr`（无存储位置）、`mknod`。`forget` 未重写，
inode 映射在进程生命周期内只增不减（备份场景可接受，长期挂载会缓慢增长；
`rename` 会重映射而不是新增条目）。

**并发模型**：fuser 0.18 的 trait 走 `&self`，全部可变状态放在一个
`Mutex` 后，请求（含 OBS 往返）串行执行。备份场景够用，高并发场景需改分片锁。

## 配置（环境变量，不进代码、不进仓库）

```text
OBS_AK=...                    # 访问密钥（不要用主账号，建议 IAM 子账号 + 仅该桶权限）
OBS_SK=...                    # 密钥（0600 的 YAML 配置文件）
OBS_BUCKET=my-bucket
OBS_ENDPOINT=https://my-bucket.obs.cn-north-4.myhuaweicloud.com
OBS_MULTIPART_THRESHOLD=8388608               # 可选，不配就默认 8 MiB（AWS CLI/boto3 默认）
```

配置只有一种格式：YAML（`/etc/obs/obs-mount.yaml`），只含 mountpoint、
bucket、endpoint、ak、sk，以及可选的 multipart_threshold。staging 固定用
系统临时目录下的 `obs-mount-staging`（`$TMPDIR/obs-mount-staging`，未设
`TMPDIR` 时为 `/tmp/obs-mount-staging`，启动时自动创建并清理上次残留），
allow_root 恒开（root 与挂载用户均可见），不支持临时 AK 与 allow_other。
**不兼容旧版本**：配置文件出现未知字段时启动直接报错，不静默忽略；旧的
env 文件（`/etc/obs/obs-mount.env`）不再被 systemd 单元加载，旧配置请按
obs-mount.yaml.example 重写一份。

`OBS_ENDPOINT` 必须是桶虚拟主机域名，不要用裸 service endpoint；
不要跨区域挂载。服务器时钟必须 NTP 对时（签名 Date 偏差超 15 分钟即 403）。

## 构建

需要 Rust stable（edition 2024）。两条路线都验证过：

```sh
# 1) 动态链接（glibc）：快，适合在目标机直接跑
cargo build --release
# 产物：target/release/obs-mount

# 2) 全静态（musl）：拷到任意 x86_64 Linux 都能跑，无需 glibc/libfuse
sudo apt-get install -y musl-tools            # Debian 13 (trixie) 自带 1.2.5
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
# 产物：target/x86_64-unknown-linux-musl/release/obs-mount
```

**不需要 zig。** fuser 0.18 默认不链接 libfuse（直接读写 `/dev/fuse`），
所以 FUSE 层不阻碍静态化；整棵树里唯一的 C 依赖是 rustls 拉进来的
`aws-lc-sys`，Debian 13 的 `musl-tools` 就够。实测产物 9.3 MB，
`file` 显示 `static-pie linked`、`ldd` 显示 `statically linked`。

CI（`.github/workflows/ci.yml`）会在 `debian:trixie-slim` 容器里跑这条路，
所以上面的命令和 GitHub Actions 用的是同一套；推 tag 时两种二进制
会自动附加到 release。

运行：

```sh
obs-mount --config /etc/obs/obs-mount.yaml   # 推荐：挂载位置、AK/SK、桶、endpoint 全在配置文件里
obs-mount /mnt/obs          # 也可以只给挂载点，其余参数走环境变量或配置文件
obs-mount --help            # 查看全部参数
```

配置优先级：命令行参数 > 环境变量 > 配置文件。配置文件只支持一种格式：YAML，
默认位置为 /etc/obs/obs-mount.yaml，也可用 --config 指定；模板见
obs-mount.yaml.example，含 AK/SK 的文件务必 0600（权限放宽时启动会警告）。
二进制与配置文件统一放在 /etc/obs/ 目录：`/etc/obs/obs-mount` 与
`/etc/obs/obs-mount.yaml`（见“部署”）。

**挂载需要 fuse3 包提供的 `fusermount` 助手**（Debian/Ubuntu:
`apt-get install fuse3`）。缺了它程序仍可挂载，只是没有 `auto_unmount`，
启动时会给出安装提示；以 root 直接走 `/dev/fuse` 时通常感觉不到差别。

## 部署（systemd）

```sh
# 运行期依赖只有一个：fusermount 助手（提供 auto_unmount 与普通用户挂载）
sudo apt-get install -y fuse3

mkdir -p /etc/obs
install -m 0755 target/release/obs-mount /etc/obs/obs-mount
install -m 0644 obs-mount.service /etc/systemd/system/obs-mount.service
install -m 0600 obs-mount.yaml.example /etc/obs/obs-mount.yaml   # 填入真实 AK/SK、桶、endpoint、挂载位置
mkdir -p /mnt/obs
systemctl daemon-reload && systemctl enable --now obs-mount
journalctl -u obs-mount -f
```

卸载：`systemctl stop obs-mount`（或 `fusermount -u /mnt/obs`）。
staging 目录在系统临时目录下自动创建，无需手动建；allow_root 恒开。
装了 `fuse3` 时会自动启用 `auto_unmount`，服务退出即懒卸载；
没装也能挂载，但需要手动 `umount`。`ExecStop` 里的 `/bin/fusermount`
按 `fuse3` 的安装路径写的，若发行版把它放在别处（如 `/usr/bin/fusermount3`），
改一下这一行即可。

## 验证状态

### 已做到的

- `cargo build --release`、`cargo test`（13 个用例）、`cargo clippy -D warnings`、
  `cargo fmt --check` 全部通过。
- **真实挂载 + 端到端读写已验证**（2026-11-03）：容器内有 `/dev/fuse`，
  用本仓库搭的 OBS 协议模拟服务（严格校验 HMAC-SHA1 签名，签名不符直接 403）
  挂上 `/mnt/obs` 后实测通过：
    - 建目录（含多级）、`readdir`/`lookup`/`getattr`，`find` 与 `os.walk` 结果一致
    - 小文件写读、重复覆盖同名文件、追加写、`truncate`、Range 读
    - 20 MiB 文件走分段上传（4 路并行），md5 与本地一致；8 MiB 阈值边界判定正确
    - `unlink`、`rmdir`（含非空返回 `ENOTEMPTY`）、文件与目录 `rename`
    - 空格、中文、`+`/`%` 等特殊字符 key，同一文件多句柄并发
- 静态 musl 构建实测 `statically linked`（见“构建”）。

### 仍未做到的（上生产前务必补）

- **没有对真实华为云 OBS 桶跑过**：签名与协议只在本地模拟服务上验证，
  模拟服务按文档实现，但不保证覆盖真实服务的所有行为差异。
  上生产前请先在测试桶做一轮只读验证（List / Head / Range Get）。
- 未做长时间稳定性与断网重连测试；失败重试目前只有 5xx 退避，没有断点续传。
- `statfs` 仍是 fuser 默认值，`df` 显示的数字无意义。

### 本轮修掉的缺陷

以下都是上面那套端到端测试暴露出来的，此前单元测试无法发现：

1. **分段上传失败**（P0）：XML 解析遇到 `<?xml ?>` 声明就提前退出，
   `UploadId` 永远解析不到 → 所有 ≥8 MiB 的上传报 `no UploadId in response`。
2. **覆盖已有文件失败**（P0）：`setattr(size=0)` 在上传后删掉 staging 文件，
   但同一句柄仍在用它，后续 `write` 报 ENOENT；表现为 `echo x > file` 第二次起失败。
3. **`rename` 后新名字不可见**（P0）：成功路径把新路径的 inode 映射一起删了，
   内核还握着那个 inode，`mv a b && cat b` 报 ENOENT 且不发任何请求，
   直到元数据 TTL 过期。现在改成保留 inode 号、只重指向新路径，打开中的句柄一并改 key。
4. **缺 `fusermount` 时报裸 ENOENT**：现在会检测助手是否存在，缺了就降级挂载并
   提示安装 `fuse3`，而不是抛一句 `No such file or directory`。
5. 同一 inode 的第二个只读句柄读不到刚写入的内容（staging 未被只读句柄复用）。

## 依赖版本（Cargo.lock 实际锁定，直接依赖）

| 依赖 | 版本 | 备注 |
|---|---|---|
| fuser | 0.18.0 | 纯 Rust FUSE，无 libfuse 链接 |
| reqwest | 0.13.1 | blocking + rustls + webpki-roots + system-proxy |
| base64 | 0.23.1 | （另有 0.22.1 为传递依赖） |
| hmac | 0.13.0 | |
| sha1 | 0.11.0 | |
| md-5 | 0.11.0 | |
| quick-xml | 0.42.0 | 事件流解析 ListBucket XML |
| clap | 4.6.7 | derive + env |
| serde | 1.0.229 | derive |
| thiserror | 2.0.21 | （另有 1.0.69 为传递依赖） |
| anyhow | 1.0.104 | |
| chrono | 0.4.45 | RFC 1123 Date |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | 日志到 stderr；非 TTY 时自动关 ANSI |
| urlencoding | 2.1.3 | |
| libc | 0.2.191 | |

## 已知限制（不是 bug，是对象存储的物理特性）

- 每次 `ls` / `stat` 都要远端请求（元数据缓存仅 5 秒）；`ls -R`、`find` 会很慢。
- 多机同挂一桶、无锁、无合并：最后写赢，业务层规避。
- 每次 `fsync` / 关闭都全量重传：不要把数据库、虚拟机镜像跑在挂载盘上。
- `rename` 非原子；大文件 `truncate` 等于一次全量重传。
- 公网挂载走公网流量；同区域 ECS 优先用内网 endpoint。
