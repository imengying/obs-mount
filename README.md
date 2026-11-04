# obs-mount

把华为云 OBS **对象桶**挂成本地目录的 FUSE 程序。

只走 OBS 原生 REST 签名（HMAC-SHA1，`Authorization: OBS <AK>:<签名>`，`x-obs-*` 头），
不含 S3/SigV4 代码路径。签名规则见
[OBS API 参考](https://support.huaweicloud.com/api-obs/obs_04_0011.html)。

```sh
# 包内是 obs 和 obs-mount.yaml.example，解压即可执行
tar -xzf obs-mount-x86_64-linux-musl.tar.gz
sudo install -m 0755 obs /etc/obs/obs
sudo install -m 0600 obs-mount.yaml.example /etc/obs/obs.yaml   # 填 AK/SK、桶、endpoint
sudo apt-get install -y fuse3                                   # fusermount
/etc/obs/obs -c /etc/obs/obs.yaml
```

源码构建：`cargo build --release`，产物是 `target/release/obs-mount`（这个需要 `chmod +x`，
tar 包里的 `obs` 已经是 0755）。

## 配置

YAML，默认 `/etc/obs/obs.yaml`，可用 `-c` 指定。优先级：命令行 > 环境变量 > 文件。
未知字段启动即报错。模板见 `obs-mount.yaml.example`，含凭据的文件用 0600。

| 字段 | 环境变量 | 说明 |
|---|---|---|
| `mountpoint` | — | 挂载点，需已存在 |
| `bucket` | `OBS_BUCKET` | 桶名 |
| `endpoint` | `OBS_ENDPOINT` | 见下 |
| `ak` / `sk` | `OBS_AK` / `OBS_SK` | 建议 IAM 子账号，仅该桶权限 |
| `multipart_threshold` | `OBS_MULTIPART_THRESHOLD` | 默认 25 MB |
| `multipart_part_size` | `OBS_MULTIPART_PART_SIZE` | 默认 10 MB，下限 5 MiB |

`endpoint` 按 host 自动选择寻址方式：

| 写法 | 寻址 |
|---|---|
| `https://<bucket>.obs.<region>.myhuaweicloud.com` | 虚拟主机式 |
| `https://obs.<region>.myhuaweicloud.com` + `bucket:` | 自动补成 `<bucket>.obs...` |
| `http://10.0.0.1:9000` 之类 IP 端点 | 路径式 |
| 自有域名（如 `https://s3.example.com`） | 路径式 |

华为云 OBS 服务端点只接受虚拟主机式，用路径式会被拒（`VirtualHostDomainRequired`），
所以 `obs.<region>.myhuaweicloud.com` 会自动补成 `<bucket>.obs.<region>...`。
只有 IP 端点和自有域名走路径式。不要跨区域挂载；服务器时钟须 NTP 对时
（Date 偏差超 15 分钟即 403）。

启动时用 `HEAD /` 检查桶类型，返回 `x-obs-bucket-type: POSIX` 或
`x-obs-fs-file-interface: Enabled` 的是 **POSIX/文件桶**，程序会拒绝——
文件桶本身已是 POSIX 语义，再套一层 FUSE 翻译只会变错。

## 已实现的 FUSE 操作

| 操作 | OBS 实现 |
|---|---|
| `lookup` / `getattr` | `HEAD /<key>`；目录先查 `<dir>/` 占位对象，再用 `prefix=<dir/>` 探查 |
| `readdir` | `GET ?prefix=<dir/>&delimiter=/` 翻页聚合，含 `.` / `..` |
| `open` / `read` | Range GET，1 MiB 预取窗口；写模式把远端内容下载到 staging |
| `create` / `write` | 只写本地 staging，不逐次 PUT |
| `flush` / `fsync` / `release` | 关闭时上传：低于阈值单 PUT，否则分段（4 路并行） |
| `mkdir` / `rmdir` | PUT `<dir>/` 占位对象 / 非空检查后删除 |
| `unlink` | `DELETE /<key>` |
| `rename` | **Copy + Delete，非原子**；inode 号保持不变，打开中的句柄改 key |
| `setattr` | `chmod`/`chown`/`utimes` 写对象元数据，不重传数据；截断走下载→截断→重传 |
| `statfs` | 见「容量显示」 |
| `symlink` / `readlink` | 零字节对象 + `x-obs-meta-symlink-target` |
| `getxattr` / `setxattr` / `listxattr` / `removexattr` | 见「元数据」 |

未实现：`hardlink` / `mknod`（OBS 无此语义）。

**并发模型**：全部可变状态在一把 `Mutex` 后，请求串行；读路径不持锁跨网络往返。
备份场景够用，高并发需改分片锁。

## 暂存与上传失败

暂存文件仍放在**系统临时目录**（`$TMPDIR`，默认 `/tmp`），每个挂载独立创建
`obs-mount-staging-<uid>-<会话标识>` 子目录，权限 0700。启动时在日志中列出当前用户已存在的
暂存目录，提醒检查；其中可能有仍在使用的挂载，因此启动时不删除目录或文件。
挂载正常释放时删除自身的空目录。有数据的目录不按天数自动清理，以免误删未上传的唯一副本。

写打开会先把远端对象流式下载到暂存文件；HEAD/GET 失败、对象在下载前发生变化或
下载长度不完整都会返回错误，不会把空文件当作原内容继续写入。
小文件 PUT 和大文件分段上传均从磁盘读取，不再把整个备份读进内存；分段最多 4 路并行，
内存开销取决于分段大小和并发数。暂存磁盘仍需容纳正在写入的完整文件。

上传失败时保留数据文件 `ino-<编号>` 及同名 `.yaml` 记录（桶、对象 key、元数据，不含凭据），
日志会输出所在路径。当前会话重新打开文件后可通过 `fsync`/关闭重试；重启后保留旧会话目录，
供人工按记录中的 key 恢复，不自动覆盖远端对象。成功上传且最后一个句柄关闭后删除暂存文件。
系统临时目录仍受操作系统清理策略影响，请及时处理失败文件。

**日志**：默认只输出 `error`，正常运行完全静默。排查时用
`RUST_LOG=info`（启动、上传进度）或 `RUST_LOG=debug`（逐请求、逐文件上传）。

## 元数据

OBS 无原生权限，但对象元数据可自由填写，Unix 属性就存在这里：

| 属性 | 键 |
|---|---|
| 权限 | `x-obs-meta-mode`（完整 `st_mode`，含类型位） |
| 属主 | `x-obs-meta-uid` / `x-obs-meta-gid` |
| 修改时间 | `x-obs-meta-mtime`（Unix 秒） |
| 符号链接 | `x-obs-meta-symlink-target` |
| 扩展属性 | `x-obs-meta-xdg.<小写十六进制(名字)>`，值 base64 |

`xattr` 名字用小写十六进制，避免 HTTP 头名称转小写破坏 Base64 的大小写。
改属性用 `PUT` + `x-obs-copy-source` + `x-obs-metadata-directive: REPLACE`
把对象拷回自己，只换元数据，不重传数据。

没有元数据的对象（别的工具上传的）回退到 0755/0644、属主取请求方，
而不是报「无权限」。

`readdir` 只用列表响应里真实存在的字段，不编造 uid/gid/mode；
`getattr` 缺属性时补一次 `HEAD`。宁可晚一个 TTL，也不显示假属主。

## 容量显示

fuser 默认的 `statfs` 各项填 0，`df` 会显示 `Size 0 / Avail 0`。这不只是数字不准：
监控会判定磁盘已满，写前的 `statvfs` 预检会直接报 `ENOSPC` 而拒绝写入。

OBS 提供两个原生子资源，statfs 由此回答：

| 请求 | 含义 |
|---|---|
| `GET /?storageinfo` | 桶已用字节数与对象数 |
| `GET /?quota` | 字节配额；`0` 表示**未设配额（不限量）**，不是没有空间 |

| 情况 | `df` 显示 |
|---|---|
| 设了配额 | 真实容量 / 已用 / 剩余 |
| 未设配额 | 16 TiB 合成容量 + 真实已用量 |
| 查询失败 | 上次成功值，否则合成容量 + 0 |

16 TiB 与华为 obsfs 的 `0xFFFFFFFF × 4096` 一致。结果缓存 60 秒。
`storageinfo` 的统计有延迟（通常几分钟），`df` 的 `Used` 不会即时反映刚写入的文件。

## 与官方 obsfs 的对比

华为官方的 FUSE 客户端是
[`huaweicloud-obs-obsfs`](https://github.com/huaweicloud/huaweicloud-obs-obsfs)（C++）。

| | obs-mount | obsfs |
|---|---|---|
| 体积 | 9.9 MB（静态 9.8 MB） | 15.6 MB |
| 动态依赖 | libc / libgcc_s，静态版无 | libfuse、libcurl、libxml2、libcrypto、libstdc++ 等 8 个 |
| 顺序读 20 MiB | 33.1 MiB/s | 97.9 MiB/s（有本地磁盘缓存） |
| 顺序写 20 MiB | 28.9 MiB/s | 32.6 MiB/s |
| 小文件创建 | 19.7 ops/s | 157 ops/s（延迟上传，一致性模型不同） |
| `stat` / `mkdir` / `rename` | 持平 | 持平 |

测法：同一台机器、同一个模拟端点、两个客户端同时挂载。读吞吐的差距来自架构——
obsfs 把文件内容缓存到本地磁盘，第二遍读完全不联网；备份挂载不能把整个桶在本地再存一份。

## 构建

需要 Rust stable（edition 2024，MSRV 1.85）。发布产物是全静态 musl 构建，
不依赖目标机的 glibc：

```sh
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
# 产物：target/x86_64-unknown-linux-musl/release/obs-mount
```

fuser 不链接 libfuse（直接读写 `/dev/fuse`），树里唯一的 C 依赖是 rustls 的
`aws-lc-sys`，`musl-tools` 足够，不需要 zig。`cargo build --release` 的动态
版本仅供开发调试，不发布。

## 发布

推 `v*` tag 触发，版本号取自 tag：

```sh
git tag v0.2.0 && git push origin v0.2.0
```

产物：`obs-mount-x86_64-linux-musl`，全静态，拷到任意 x86_64 Linux 即可运行。

CI 在 `debian:trixie-slim` 里完成构建、单元测试和端到端测试，
发布的就是这一个静态二进制。

## 部署

```sh
sudo apt-get install -y fuse3
tar -xzf obs-mount-x86_64-linux-musl.tar.gz
sudo install -m 0755 obs /etc/obs/obs
sudo install -m 0600 obs-mount.yaml.example /etc/obs/obs.yaml
sudo install -m 0644 obs-mount.service /etc/systemd/system/obs.service
sudo mkdir -p /mnt/obs
sudo systemctl daemon-reload && sudo systemctl enable --now obs
```

卸载：`systemctl stop obs`。进程退出时由 fusermount 自动摘除挂载，
所以 unit 文件里不需要写挂载点，`systemctl stop` 对任何配置路径都成立。

**访问权限**：挂载对所有本地用户开放（`allow_other`），便于 OpenList、nginx、rsync
这类以别的用户运行的服务读取同一个桶。以 root 挂载不需要额外配置；普通用户挂载需要
在 `/etc/fuse.conf` 里加一行 `user_allow_other`，否则 fusermount 会拒绝。

因为所有对象都归挂载用户所有，内核级的权限检查被有意关闭（未启用
`DefaultPermissions`）。`chmod` 属性能保存、`ls -l` 也会显示，但**不用于限制访问**——
能到达挂载点的用户都能读写。需要访问控制请用文件系统外的机制（如给服务单独建用户并
限制挂载点父目录权限）。

## 验证状态

**已有挂载测试覆盖**：`tests/e2e.sh` 对严格校验签名的模拟 OBS 服务测试——
目录、读写、覆盖、追加、截断、Range、分段上传、rename、特殊字符 key、
`chmod`/`chown`/`touch`、`symlink`、xattr、路径式寻址、桶类型拒绝、`statfs`。
挂载测试需要可用的 `/dev/fuse`；缺少时会明确输出 `SKIP`，不能视为挂载验证通过。
另有 44 个自动化测试（`cargo test`，需 Python 3），包括无需 FUSE 的 HTTP 测试：
读取失败、上传失败保留与重试、分段失败清理、独立原件校验、元数据重新 HEAD 及暂存隔离。

**未验证**：

- 没有对真实 OBS 桶跑过。上生产前请在测试桶做一轮只读验证（List / Head / Range Get）。
- 没有长时间稳定性和断网重连测试；重试是整段重来，没有断点续传。
- `statfs` 没有在设了配额的真实桶上验证过。

## 已知限制

- 每次 `ls` / `stat` 都要远端请求（元数据缓存 5 秒），`ls -R`、`find` 会很慢。
- 多机同挂一桶无锁无合并，最后写赢。
- 每次 `fsync` / 关闭都全量重传。不要跑数据库或虚拟机镜像。
- `rename` 非原子；大文件 `truncate` 等于一次全量重传。
- 公网挂载走公网流量，同区域 ECS 优先用内网 endpoint。
