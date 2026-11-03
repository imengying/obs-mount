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
              #   分段阈值（可选，默认 25 MB / 10 MB，与华为 obsfs 一致）；staging 固定在系统临时目录，
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
| `flush` / `fsync` / `release` | 关闭/刷盘时上传：小于阈值单 PUT，大于等于阈值分段上传。阈值与分片可配（默认 25 MB / 10 MB，与 obsfs 一致），分片低于 5 MiB 会被抬到 OBS 下限，超过 10000 片时自动放大分片；4 路并行，失败先等齐在途分片再 abort |
| `mkdir` / `rmdir` | PUT `<dir>/` 零字节占位对象 / 非空检查后删占位对象 |
| `unlink` | `DELETE /<key>` |
| `rename` | **Copy + Delete，非原子**（目录递归逐 key；中途失败不回滚，已在日志中明示）。成功后 inode 号不变、只把映射指向新 key，打开中的句柄同样改 key |
| `setattr` | `chmod` / `chown` / `utimes` 写入对象元数据（`x-obs-meta-*`），靠一次自拷贝 `x-obs-metadata-directive: REPLACE` 完成，不重传数据；截断仍是下载→本地截断→重传 |
| `statfs` | `GET /?quota` 取配额（真实上限）+ `GET /?storageinfo` 取已用量，60 秒缓存；无配额时上报与 obsfs 相同的 16 TiB 合成容量，见下文“容量显示” |
| `symlink` / `readlink` | 零字节对象 + `x-obs-meta-symlink-target`，mode 记 `S_IFLNK` |
| `getxattr` / `setxattr` / `listxattr` / `removexattr` | 存成 `x-obs-meta-xdg.<base64(name)>`，值同样 base64（元数据必须是 header 安全的 ASCII） |

未实现（默认返回 `ENOSYS` 或内核默认）：`hardlink` / `mknod`（OBS 无此语义）。
`forget` 未重写，
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
OBS_MULTIPART_THRESHOLD=26214400              # 可选，不配就默认 25 MB（与华为 obsfs 一致）
OBS_MULTIPART_PART_SIZE=10485760              # 可选，分片大小；obsfs 用 10 MiB，OBS 下限 5 MiB
```

配置只有一种格式：YAML（`/etc/obs/obs-mount.yaml`），只含 mountpoint、
bucket、endpoint、ak、sk，以及可选的 multipart_threshold。staging 固定用
系统临时目录下的 `obs-mount-staging`（`$TMPDIR/obs-mount-staging`，未设
`TMPDIR` 时为 `/tmp/obs-mount-staging`，启动时自动创建并清理上次残留），
allow_root 恒开（root 与挂载用户均可见），不支持临时 AK 与 allow_other。
**不兼容旧版本**：配置文件出现未知字段时启动直接报错，不静默忽略；旧的
env 文件（`/etc/obs/obs-mount.env`）不再被 systemd 单元加载，旧配置请按
obs-mount.yaml.example 重写一份。

`endpoint` 两种写法都支持，程序按 host 自动选择寻址方式：

| 写法 | 寻址 | 说明 |
|---|---|---|
| `https://<bucket>.obs.<region>.myhuaweicloud.com` | 虚拟主机式 | 推荐，OBS 惯例 |
| `https://obs.<region>.myhuaweicloud.com` + `bucket:` | 路径式 `/bucket/key` | 与华为 obsfs 的配置习惯一致 |
| `http://10.0.0.1:9000` 之类 IP 端点 | 路径式 | IP 不能做 `bucket.10.0.0.1` 解析 |

判定逻辑与 obsfs 的 `pathrequeststyle` 一致：host 不以 `<bucket>.` 开头、
或 host 是 IP 地址时，自动切路径式——否则这类端点根本无法挂载。
不要跨区域挂载。服务器时钟必须 NTP 对时（签名 Date 偏差超 15 分钟即 403）。

启动时会用 `HEAD /` 检查桶类型（与 obsfs 的 `DetectBucketTypeFromHeaders` 相同）：
如果返回 `x-obs-bucket-type: POSIX` 或 `x-obs-fs-file-interface: Enabled`，
说明这是 OBS 的 **POSIX/文件桶**，本程序会直接拒绝——文件桶本身已是 POSIX 语义，
再套一层 FUSE 翻译只会变错（占位对象当目录、rename 非原子）。

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
    - 30 MiB 文件走分段上传（4 路并行），md5 与本地一致；25 MB 阈值边界判定正确
    - `unlink`、`rmdir`（含非空返回 `ENOTEMPTY`）、文件与目录 `rename`
    - 空格、中文、`+`/`%` 等特殊字符 key，同一文件多句柄并发
    - `statfs`：无配额时报 16 TiB（与 obsfs 一致）、有配额时报真实值
    - 路径式寻址（服务级 endpoint / IP 端点）、POSIX 文件桶被正确拒绝
    - `chmod` / `chown` / `touch -d` 落进对象元数据并跨进程可见
    - `ln -s` + `readlink`、30 MiB 分段上传带上元数据
    - 扩展属性：写入 / 读取 / 列举 / 删除 / 多属性共存 / 跨进程可见
- 静态 musl 构建实测 `statically linked`（见“构建”）。

### 仍未做到的（上生产前务必补）

- **没有对真实华为云 OBS 桶跑过**：签名与协议只在本地模拟服务上验证，
  模拟服务按文档实现，但不保证覆盖真实服务的所有行为差异。
  上生产前请先在测试桶做一轮只读验证（List / Head / Range Get）。
- 未做长时间稳定性与断网重连测试；失败重试目前只有 5xx 退避，没有断点续传。
- `statfs` 已实现（见“容量显示”），但没有在**设了配额**的真实桶上验证过；
  `storageinfo` 的统计延迟量级也只在文档层面了解，未实测。
- 扩展属性已实测（`setfattr` / `getfattr`：写入、读取、列举、删除、
  多属性共存、ENODATA），需要 `attr` 包，e2e 缺该包时会自动跳过。

### 已从 obsfs 对齐的三项

1. **`statfs` 合成容量 16 TiB**，与 obsfs 的 `0xFFFFFFFF × 4096` 逐字节一致。
2. **路径式寻址**（`pathrequeststyle`）：服务级 endpoint、IP 端点自动走
   `/bucket/key`，不再要求必须配桶虚拟主机域名。
3. **桶类型检测**：挂载前 `HEAD /`，识别出 POSIX/文件桶就拒绝，
   避免用对象桶语义去操作文件桶。

### 与 obsfs 的元数据方案

OBS 没有原生权限，但对象元数据是自由格式的，obsfs 就是靠这一点把 Unix 属性存下来的。
本项目用同样的思路，只是走 **OBS 原生前缀 `x-obs-meta-`**（obsfs 用 S3 风格
`x-amz-meta-`，因为它也服务通用 S3 端点；原生前缀见官方 SDK 的
`HEADER_PREFIX_META_OBS = "x-obs-meta-"`）。

| 属性 | 元数据键 | 说明 |
|---|---|---|
| 权限 | `x-obs-meta-mode` | 完整 `st_mode`，含 `S_IFLNK`/`S_IFDIR` 类型位 |
| 属主 | `x-obs-meta-uid` / `x-obs-meta-gid` | |
| 修改时间 | `x-obs-meta-mtime` | Unix 秒 |
| 符号链接 | `x-obs-meta-symlink-target` | 对象为 0 字节，mode 标记 `S_IFLNK` |
| 扩展属性 | `x-obs-meta-xdg.<base64url(名字)>` | 名字用 **base64url 无 padding**：`=` 不是合法的 HTTP header 名字符，带 `=` 会让请求根本发不出去 |

改属性**不重传数据**：用 `PUT` + `x-obs-copy-source: /<bucket>/<key>` +
`x-obs-metadata-directive: REPLACE` 把对象拷回自己，只换元数据。改一个
100 GiB 对象的权限位是瞬间完成的。这与 obsfs 的 `s3fs_setxattr_s3` 一致。

**没有元数据的对象**（别的工具上传、或本程序早期版本写的）读出来时回退到固定
默认值（目录 0755、文件 0644、属主取请求方 uid/gid），而不是当成"无权限"——
否则 `ls` 会看到 `----------`，工具容易误判。

### readdir 的元数据取舍

obsfs 有个 `accurate_readdir` 开关，解决的是这个矛盾：`readdir` 时对每个条目补元数据，
如果逐条 `HEAD` 会很慢（1000 个文件 = 1000 次请求），于是它默认**合成**一份假元数据
（uid/gid 取当前进程、mode 固定 0640）塞进缓存，代价是对象上真实的
`x-amz-meta-uid` 会被显示错，直到缓存过期。打开该开关就不合成、退回逐条 `HEAD`。

本项目的做法是取中间值：`readdir` 只使用列表响应里**真实存在**的字段
（`Size`），不编造 uid/gid/mode；`getattr` 拿到缓存缺失的属性时再补一次 `HEAD`。
因此 `ls` 里的大小是准的、属主权限可能延迟一个 TTL，但**不会显示一个假的属主**。

### 其余对齐项

| 项 | obsfs | 本项目 |
|---|---|---|
| 重试 | 固定 3 次 | 5 次，指数退避 0.5→1→2→4s（上限 8s），403 不重试 |
| 分段阈值/分片 | 25 MB / 10 MB（写死） | 默认 **25 MB / 10 MB（同 obsfs）**，仍可配；分片低于 5 MiB 抬到 OBS 下限，超 10000 片自动放大 |
| 并发上传 | 顺序 | 4 路并行 |
| 临时文件 | `use_cache`/`stat_cache` 落地到本地 | staging 在 `$TMPDIR`，退出时清理 |

仍存在的差距：`hardlink` / `mknod`（OBS 无此语义）、断点续传（重试仍是整段重来）。

### 本轮修掉的缺陷

以下都是上面那套端到端测试暴露出来的，此前单元测试无法发现：

1. **分段上传失败**（P0）：XML 解析遇到 `<?xml ?>` 声明就提前退出，
   `UploadId` 永远解析不到 → 所有走分段上传的文件都报 `no UploadId in response`。
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

## 容量显示（statfs / df）

fuser 的默认 `statfs` 回调把所有字段填 0，于是 `df -h` 显示 `Size 0 / Avail 0 / Use% -`，
后果比"数字不准"严重：

- 监控脚本的"剩余空间不足"阈值会把这个挂载点判定为**已写满**，天天告警；
- 一些程序写文件前会用 `statvfs(2)` 预检剩余空间，看到 `f_bavail = 0` 直接报
  `ENOSPC`/“空间不足”，**根本不尝试写入**。备份脚本最容易踩到。

OBS 确实提供了两个可用于此的原生子资源（见华为云官方 SDK
`huaweicloud-sdk-go-obs` 的 `obs/type.go`、`obs/const.go`、`obs/model_bucket.go`）：

| 请求 | 返回 | 含义 |
|---|---|---|
| `GET /?storageinfo` | `GetBucketStorageInfoResult`：`Size`、`ObjectNumber`，另有 Standard/Warm/Cold 分档 | 桶**已用**字节数与对象数 |
| `GET /?quota` | `Quota/StorageQuota` | 桶的**字节配额**；为 `0` 表示**未设配额（不限量）**，不是“没有空间” |

两者都是签名子资源（`const.go` 里 `"storageinfo": true`、`"quota": true`），
必须计入 `CanonicalizedResource`。

因此本项目的 `statfs` 按如下规则回答：

| 情况 | `df` 显示 | 说明 |
|---|---|---|
| 桶设了配额 | 真实容量 / 真实已用 / 真实剩余 | 唯一 `df` 有实际意义的场景 |
| 桶**没设**配额（quota=0） | `Size 1.0P`，`Used` 为真实已用量 | 1 PiB 是**合成上限**，不是真实限制；只为避免被误判为写满 |
| 查询失败 | 用上次成功的结果；从未成功则用合成上限 + used=0 | 不让 `df` 卡住挂载 |

补充说明：

- 已用量来自 `storageinfo`，**OBS 对它的统计有延迟**（通常几分钟），所以 `df` 的
  `Used` 不会即时反映刚写入的文件。要精确核对以控制台为准。
- 结果缓存 60 秒，`df` 被监控高频轮询时不会每次都打两个请求。
- 用已用 > 配额时（桶可以被写超配额，此后写入开始失败而不是数据缩水），
  `Used` 会被夹到等于 `Size`，避免 `df` 出现负数剩余。
- `df -i` 的 inode 数固定上报 `u64::MAX`（表示“无限制”），不虚构可计数的 inode 上限。

### 与华为官方 obsfs 的对照

华为官方开源了 FUSE 客户端 [`huaweicloud/huaweicloud-obs-obsfs`](https://github.com/huaweicloud/huaweicloud-obs-obsfs)（C++）。
它的 `statfs` 实现（`src/s3fs_operations.cpp:3109`）完全不查询服务端：

```c
// Return fake filesystem stats for S3
// S3 doesn't have a real concept of filesystem size/limits
stbuf->f_bsize  = 4096;
stbuf->f_blocks = 0xFFFFFFFF;   // ≈16 TiB
stbuf->f_bfree  = 0xFFFFFFFF;
stbuf->f_bavail = 0xFFFFFFFF;
stbuf->f_files  = 0xFFFFFFFF;
stbuf->f_ffree  = 0xFFFFFFFF;
stbuf->f_namemax = NAME_MAX;    // 255
```

结论一致：**必须给大值，不能给 0**。本项目的差异是：

| | 官方 obsfs | 本项目 |
|---|---|---|
| 无配额 | 固定 16 TiB | 固定 16 TiB（与 obsfs 完全一致） |
| 有配额 | 不区分 | 查 `GET /?quota`，显示真实容量 |
| 已用量 | 不查询 | 查 `GET /?storageinfo`，`df` 的 `Used` 是真的 |
| inode | `0xFFFFFFFF` | `0xFFFFFFFF`（同 obsfs） |
| 文件名长度 | `NAME_MAX`(255) | 1023（OBS 的实际 key 上限） |

### 与 OpenList 的对照

OpenList（原 Alist）的 S3 驱动**没有**实现容量查询——`GetDetails` 属于可选的
`WithDetails` 接口，S3 驱动只断言了 `driver.Driver`，上层拿到 `errs.NotImplement`，
等于“不知道”。对 Web UI 够用，对 FUSE 挂载不行：上报 0 会主动引发上面两个故障。

## 已知限制（不是 bug，是对象存储的物理特性）

- 每次 `ls` / `stat` 都要远端请求（元数据缓存仅 5 秒）；`ls -R`、`find` 会很慢。
- 多机同挂一桶、无锁、无合并：最后写赢，业务层规避。
- 每次 `fsync` / 关闭都全量重传：不要把数据库、虚拟机镜像跑在挂载盘上。
- `rename` 非原子；大文件 `truncate` 等于一次全量重传。
- 公网挂载走公网流量；同区域 ECS 优先用内网 endpoint。
