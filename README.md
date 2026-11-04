# obs-mount

把华为云 OBS **对象桶**挂成本地目录的 FUSE 程序。

只走 OBS 原生 REST 签名（HMAC-SHA1，`Authorization: OBS <AK>:<签名>`，`x-obs-*` 头），
不含 S3/SigV4 代码路径。签名规则见
[OBS API 参考](https://support.huaweicloud.com/api-obs/obs_04_0011.html)。

```sh
sudo apt-get install -y fuse3 attr        # fusermount、setfattr/getfattr
cargo build --release
sudo install -m 0755 target/release/obs-mount /etc/obs/obs-mount
sudo install -m 0600 obs-mount.yaml.example /etc/obs/obs-mount.yaml   # 填 AK/SK、桶、endpoint
obs-mount -c /etc/obs/obs-mount.yaml
```

## 配置

YAML，默认 `/etc/obs/obs-mount.yaml`，可用 `-c` 指定。优先级：命令行 > 环境变量 > 文件。
未知字段启动即报错。模板见 `obs-mount.yaml.example`，含凭据的文件用 0600。

| 字段 | 环境变量 | 说明 |
|---|---|---|
| `mountpoint` | — | 挂载点，需已存在 |
| `bucket` | `OBS_BUCKET` | 桶名 |
| `endpoint` | `OBS_ENDPOINT` | 见下 |
| `ak` / `sk` | `OBS_AK` / `OBS_SK` | 建议 IAM 子账号，仅该桶权限 |
| `multipart_threshold` | `OBS_MULTIPART_THRESHOLD` | 默认 25 MB |
| `multipart_part_size` | `OBS_MULTIPART_PART_SIZE` | 默认 10 MB，下限 5 MiB |

`endpoint` 支持两种写法，按 host 自动选择寻址方式：

| 写法 | 寻址 |
|---|---|
| `https://<bucket>.obs.<region>.myhuaweicloud.com` | 虚拟主机式 |
| `https://obs.<region>.myhuaweicloud.com` + `bucket:` | 路径式 |
| `http://10.0.0.1:9000` 之类 IP 端点 | 路径式 |

host 不以 `<bucket>.` 开头或为 IP 时自动走路径式。不要跨区域挂载；服务器时钟须 NTP 对时
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

## 元数据

OBS 无原生权限，但对象元数据可自由填写，Unix 属性就存在这里：

| 属性 | 键 |
|---|---|
| 权限 | `x-obs-meta-mode`（完整 `st_mode`，含类型位） |
| 属主 | `x-obs-meta-uid` / `x-obs-meta-gid` |
| 修改时间 | `x-obs-meta-mtime`（Unix 秒） |
| 符号链接 | `x-obs-meta-symlink-target` |
| 扩展属性 | `x-obs-meta-xdg.<base64url(名字)>`，值 base64 |

`xattr` 名字用 **base64url 无 padding**：`=` 不是合法的 HTTP header 名字符。
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
sudo install -m 0755 target/release/obs-mount /etc/obs/obs-mount
sudo install -m 0644 obs-mount.service /etc/systemd/system/obs-mount.service
sudo install -m 0600 obs-mount.yaml.example /etc/obs/obs-mount.yaml
sudo mkdir -p /mnt/obs
sudo systemctl daemon-reload && sudo systemctl enable --now obs-mount
```

卸载：`systemctl stop obs-mount`。进程退出时由 fusermount 自动摘除挂载，
所以 unit 文件里不需要写挂载点，`systemctl stop` 对任何配置路径都成立。

**访问权限**：只有挂载者本人能访问，与 obsfs 一致（它的 `allow_other` 也默认关闭）。

## 验证状态

**已验证**：挂载与端到端读写（`tests/e2e.sh`，对严格校验签名的模拟 OBS 服务）——
目录、读写、覆盖、追加、截断、Range、分段上传、rename、特殊字符 key、
`chmod`/`chown`/`touch`、`symlink`、xattr、路径式寻址、桶类型拒绝、`statfs`。
另有 31 个单元测试。

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
