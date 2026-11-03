# obs-mount

把华为云 OBS **对象桶**挂成本地目录的 FUSE 程序（Rust edition 2024）。

**只走 OBS 原生 REST 签名**（HMAC-SHA1，`Authorization: OBS <AK>:<签名>`，
`x-obs-*` 头），不含任何 S3/SigV4 代码路径。签名与接口细节以
`~/workspace/your_files/Huawei-OBS-Rust-Native-Mount.md` 为准。

## 项目结构

```text
obs-mount/
  Cargo.toml / Cargo.lock
  src/
    main.rs   # CLI（clap）：mountpoint、bucket/endpoint/AK/SK（环境变量）、
              #   分段阈值（可选，默认 8 MiB，学 AWS CLI/boto3）；staging 固定在系统临时目录，
              #   allow_root 恒开；启动先做桶可达自检，不过不挂载；
              #   日志到 stderr（systemd journal 直接收）
    obs.rs    # OBS 原生客户端：签名（HMAC-SHA1 + 规范头/规范资源/子资源白名单）、
              #   ListObjects（含翻页）、HeadObject、GetObject Range 读、
              #   PutObject、DeleteObject、CopyObject（rename 用）、
              #   分段上传（初始化/传段/合并/取消）+ XML 解析 + 单测
    fs.rs     # FUSE 文件系统（fuser 0.18）：inode↔key 映射、元数据缓存（5 秒 TTL）、
              #   写 staging、关闭时整文件上传
  obs-mount.service       # systemd 单元（见“部署”）
  obs-mount.yaml.example  # 配置模板（YAML，唯一格式；占位符，无真实凭据）
```

## 已实现的 FUSE 操作

| 操作 | OBS 实现 |
|---|---|
| `lookup` / `getattr` | `HEAD /<key>`；目录先查 `<dir>/` 占位对象，再用 `prefix=<dir/>&delimiter=/&max-keys=1` 探查 |
| `readdir` | `GET ?prefix=<dir/>&delimiter=/` 翻页聚合（`CommonPrefixes` + `Contents`），含 `.` / `..` |
| `open` / `read` | 读模式直接 Range GET（先 HEAD 定长，越过 EOF 返回空）；写模式把远端内容（如有）下载到 staging 做 read-modify-write |
| `create` / `write` | 只写本地 staging 文件，不逐次 PUT |
| `flush` / `fsync` / `release` | 关闭/刷盘时上传：小于阈值单 PUT，大于等于阈值分段上传（默认 8 MiB，学 AWS CLI/boto3），分片 8 MiB（超 80 GiB 的文件自动放大分片以不超 10000 片上限）、4 路并行上传，失败先等齐在途分片再 abort 整个分段上传 |
| `mkdir` / `rmdir` | PUT `<dir>/` 零字节占位对象 / 非空检查后删占位对象 |
| `unlink` | `DELETE /<key>` |
| `rename` | **Copy + Delete，非原子**（目录递归逐 key；中途失败不回滚） |
| `setattr` | 仅截断（下载→本地截断→重传）；mode/uid/gid/atime 等忽略（OBS 不存 Unix 权限），以免 `cp -p` 类工具失败 |
| `statfs` | 未重写，用 fuser 默认固定值（`df` 数字是假的，以控制台为准） |

未实现（默认返回 `ENOSYS` 或内核默认）：`symlink` / `hardlink`（OBS 无此语义）、
`chmod` / `chown` / `xattr`（无存储位置）、`mknod`。`forget` 未重写，
inode 映射在进程生命周期内只增不减（备份场景可接受，长期挂载会缓慢增长）。

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

## 构建（当前默认：动态链接）

```sh
# 动态链接版（glibc），当前默认做法；Debian 13 上直接这样编即可
cargo build --release
# 产物：target/release/obs-mount
```

全静态版（musl）为可选项，不再是默认：此前已验证可行，见下节“静态编译”
（本机曾用 zig 0.15.1 交叉编译出 7.5MB 全静态二进制）。你说会在 Debian 13
上手动编译，那就直接用上面动态版，不用走 musl 路线。

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

## 静态编译结论（已验证）

**全静态构建成功。** 关键点：fuser 0.18 默认不链接 libfuse
（直接走 `/dev/fuse`），所以 FUSE 层不是静态化的障碍；
真正的卡点在 TLS 的 C 依赖（reqwest 0.13 → rustls → aws-lc-sys），
它需要一个 musl C 工具链，而本沙箱里：

1. `apt-get install musl-tools` 不可用（apt 源不可达，`apt-get update` 无响应）；
2. musl.cc 的 `x86_64-linux-musl-cross`（GCC 11.2.1）二进制在本容器里
   直接段错误（连 `--version` 都跑不起来）；
3. 改用 zig 0.15.1 的 `zig cc` 后又遇到两处需要手工处理：
   cc-rs 传的 `--target=x86_64-unknown-linux-musl`（Rust triple）被 zig
   拒绝（`UnknownOperatingSystem`），以及 rustc 自带的 musl CRT 对象
   （rcrt1.o）与 zig 的 crt1.o 的 `_start` 重定义冲突。
   解决：包装脚本过滤掉 Rust triple 参数（`tools/zig-musl-cc.sh`），
   并以 `RUSTFLAGS="-C link-self-contained=no"` 让 zig 的 CRT 接管。

`ldd` 证据（2026-11-03 实测）：

```text
$ ldd target/x86_64-unknown-linux-musl/release/obs-mount
        not a dynamic executable

$ ldd target/release/obs-mount
        linux-vdso.so.1 (0x00007a9d83461000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
        /lib64/ld-linux-x86-64.so.2
```

**退路**（如果在目标机上不想用 zig）：在目标机装好 musl-tools 后，
`CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc` 走标准 musl 交叉编译
即可，不需要 zig；或直接用动态链接版（glibc + libgcc_s 即可，无 libfuse 依赖）。

## 部署（systemd）

```sh
mkdir -p /etc/obs
install -m 0755 target/release/obs-mount /etc/obs/obs-mount
install -m 0644 obs-mount.service /etc/systemd/system/obs-mount.service
install -m 0600 obs-mount.yaml.example /etc/obs/obs-mount.yaml   # 填入真实 AK/SK、桶、endpoint、挂载位置
mkdir -p /mnt/obs
systemctl daemon-reload && systemctl enable --now obs-mount
journalctl -u obs-mount -f
```

卸载：`systemctl stop obs-mount`（或 `fusermount -u /mnt/obs`）。
staging 目录在系统临时目录下自动创建，无需手动建；allow_root 恒开，
挂载同时设了 `auto_unmount`，服务退出时自动卸载。

## 验证状态（2026-11-03，诚实记录）

- `cargo build --release` 成功；`cargo test --release` 3/3 通过
  （签名确定性、子资源过滤、ListBucket XML 解析）。
- `--help` / `--version` 正常；无配置启动时 clap 明确报缺失参数；
  挂载点不存在时报 `mountpoint ... is not a directory`；
  占位凭据启动时桶自检失败、拒绝挂载并给出排查提示（AK/SK、区域、时钟）。
- **未做真实 OBS 联调**：没有真实凭据，签名只在本地单测层面验证，
  未对真实桶跑过 List/Get/Put；上生产桶前务必先在测试桶做 P0 只读验证。
- **未做真实挂载测试**：本容器无 `/dev/fuse`，无法实际 mount；
  FUSE 操作的正确性目前只到“按 fuser 0.18 trait 签名编译通过”这一层。
- reqwest 锁定在 0.13.1：`cargo search` 显示 crates.io 最新是 0.13.5，
  但本地索引解析不到 0.13.5（`--precise 0.13.5` 冲突），故用本地可解析的
  最新稳定版 0.13.1；其余直接依赖均为本地可解析的最新正式版
  （libc 0.2 系：1.0 还是 alpha，按要求排除）。

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
