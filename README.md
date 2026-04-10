# SSH Proxy Core

高性能、可扩展的 SSH 协议代理平台。C 数据面 (libssh, ~14,700 行) + Go 控制面 (REST API / Web UI / 自动化 / 网关 / 洞察)。

<!-- badges -->
<!-- ![Build](https://img.shields.io/github/actions/workflow/status/your-org/ssh-proxy-core/ci.yml?branch=main) -->
<!-- ![License](https://img.shields.io/badge/license-GPL--3.0--only-blue) -->
<!-- ![Version](https://img.shields.io/badge/version-0.3.0-green) -->

[English](README_EN.md)

---

## 目录

- [特性](#特性)
- [快速上手](#快速上手)
- [配置参考](#配置参考)
- [日志与审计](#日志与审计)
- [运维](#运维)
- [架构](#架构)
- [项目结构](#项目结构)
- [构建](#构建)
- [Terraform Bridge](#terraform-bridge)
- [API 参考](#api-参考)
- [开发](#开发)
- [部署](#部署)
- [文档索引](#文档索引)
- [许可证](#许可证)

---

## 特性

### 核心能力

- **代理转发** — 透明代理和显式代理，支持多后端路由
- **Envoy 风格过滤器链** — 可扩展的链式过滤器架构，8 个回调点覆盖连接全生命周期
  - Auth Filter — 用户认证 (Password / PublicKey / SSH Certificate / LDAP / TOTP-MFA)
  - IP ACL Filter — IP 白名单/黑名单 (CIDR)
  - RBAC Filter — 基于角色的访问控制
  - Policy Filter — 细粒度功能策略 (30+ 功能标识)
  - Audit Filter — 会话审计、终端录像 (asciicast v2)、命令审计
  - Rate Limit Filter — 连接速率、并发限制、Per-User 会话上限
  - MFA Filter — TOTP 双因素认证
- **会话管理** — 完整的 SSH 会话生命周期管理，支持分布式会话存储
- **路由与负载均衡** — Round-Robin / Random / 最少连接 / Hash 四种策略
- **上游连接池** — SSH 连接复用，减少握手开销
- **上游连接重试** — 指数退避重试策略
- **健康检查** — 自动检测后端服务器健康状态

### v0.3.0 新增特性

| # | 特性 | 分类 | 说明 |
|---|------|------|------|
| 1 | [IP 白名单/黑名单](#ip_acl-ip-访问控制) | 安全 | CIDR 支持，白名单/黑名单模式 |
| 2 | [Per-User 并发会话限制](#limits-连接限制) | 安全 | 每用户最大会话数 |
| 3 | [上游连接重试与指数退避](#router-路由与连接池) | 可靠性 | 可配置重试次数、退避因子 |
| 4 | [配置文件校验模式](#配置校验) | 运维 | `--check` / `-t` 类 nginx 语法检查 |
| 5 | [命令审计日志](#命令审计日志) | 安全 | 记录 Shell 命令到独立日志文件 |
| 6 | [结构化 JSON 日志](#结构化-json-日志) | 可观测 | NDJSON 格式运行日志输出 |
| 7 | [登录 Banner/MOTD](#server-服务器) | 运维 | 认证前 Banner 和认证后 MOTD，支持变量展开 |
| 8 | [管理 REST API](#管理-rest-api) | 运维 | 会话管理、上游控制、热重载、配置查看 |
| 9 | [Webhook 事件通知](#webhook-事件通知) | 可观测 | 异步 HTTP POST 通知，9 种事件类型 |
| 10 | [上游连接池](#router-路由与连接池) | 性能 | SSH 连接复用与空闲回收 |
| 11 | [LDAP 认证后端](#auth-认证后端) | 安全 | 原生 TCP BER 编码，无 libldap 依赖 |
| 12 | [TOTP/MFA 双因素认证](#mfa-双因素认证) | 安全 | 自实现 SHA1/HMAC-SHA1 TOTP |
| 13 | [分布式会话存储](#session_store-会话存储) | 扩展 | 内存或文件 (NDJSON + flock) 后端 |

### 设计理念

- **零外部依赖** — LDAP 通过原生 Socket BER 编码实现；TOTP 自实现 SHA1/HMAC-SHA1；Webhook 使用原生 HTTP。唯一外部依赖为 libssh
- **C11 标准** — 编译选项 `-Wall -Wextra -Wpedantic -Werror`
- **线程安全** — 关键路径使用 pthread mutex 和原子操作
- **全部向后兼容** — 所有新特性默认禁用，可按需开启

### 控制面能力 (Go)

| # | 模块 | 说明 |
|---|------|------|
| 1 | 管理 Web UI | 仪表盘、会话列表、用户管理、服务器管理、审计查看器 |
| 2 | REST API | 完整 CRUD，OpenAPI/Swagger 文档 (`/api/docs`) |
| 3 | OIDC / SAML SSO | 企业单点登录集成 |
| 4 | SSH CA | 短期证书签发、自动轮转 |
| 5 | JIT 访问 | 即时访问请求与多级审批 |
| 6 | 集群管理 | 多节点集群，支持 DNS / K8s / Consul 发现 |
| 7 | 资产发现 | 自动导入 AWS / Azure / GCP / CMDB / Ansible 主机 |
| 8 | 命令控制 | 高危命令实时拦截与审批 |
| 9 | 会话协作 | 多人共享会话、控制权转移、会话内聊天 |
| 10 | 合规检查 | 合规策略引擎与报告 |
| 11 | SIEM 集成 | Splunk / Elasticsearch / Syslog 日志导出 |
| 12 | 威胁检测 | 基于规则的异常行为告警 |
| 13 | **工作流自动化** | 脚本库、批量 SSH 作业、Cron 调度、CI/CD 触发 |
| 14 | **协议网关** | SOCKS5 / RDP / VNC / MySQL / PostgreSQL / Redis / K8s / HTTP(S) / X11 隧道 |
| 15 | **智能洞察** | 命令意图分类、异常检测、最小权限推荐、自然语言策略预览、审计摘要 |

> 详见 [API 参考](docs/api-reference.md) 和 [架构设计](docs/DESIGN.md)。

---

## 快速上手

### 1. 安装与构建

```bash
# 安装依赖 (Ubuntu/Debian)
sudo apt update && sudo apt install -y build-essential libssh-dev

# 构建
make

# 生成主机密钥 (首次运行)
ssh-keygen -t ed25519 -f /tmp/ssh_proxy_host_key -N ""
```

### 2. 最小配置

创建 `/etc/ssh-proxy/config.ini`（或使用项目根目录的 `config.ini`）：

```ini
[server]
bind_addr = 0.0.0.0
port = 2222
host_key = /etc/ssh-proxy/host_key

[logging]
level = info
audit_dir = /var/log/ssh-proxy/audit

[limits]
max_sessions = 1000
session_timeout = 3600
auth_timeout = 60

# 用户 — 密码使用 openssl passwd -6 生成
[user:admin]
password_hash = $6$saltsalt$...
pubkey = ssh-rsa AAAA... user@host
enabled = true

# 路由
[route:admin]
upstream = prod.example.com
port = 22
user = root
privkey = /etc/ssh-proxy/keys/admin.key

[route:*]
upstream = bastion.example.com
user = guest
```

### 3. 启动

```bash
# 校验配置 (类似 nginx -t)
./build/bin/ssh-proxy-core -t -c /etc/ssh-proxy/config.ini

# 启动服务
./build/bin/ssh-proxy-core -c /etc/ssh-proxy/config.ini

# 调试模式
./build/bin/ssh-proxy-core -d

# 查看帮助
./build/bin/ssh-proxy-core --help
```

### 4. 连接测试

```bash
# 密码认证
ssh -p 2222 admin@proxy-server

# 透明代理
ssh -p 2222 admin@target-server -o ProxyJump=proxy-server
```

---

## 配置参考

SSH Proxy Core 使用 INI 格式配置文件。完整示例见 `docs/config.example.ini`。

### `[server]` 服务器

```ini
[server]
bind_addr = 0.0.0.0               # 监听地址
port = 2222                        # 监听端口
host_key = /etc/ssh-proxy/host_key # 主机密钥路径
banner = /etc/ssh-proxy/banner.txt # 认证前 Banner 文件路径 (可选)
motd = Welcome {username} from {client_ip}!  # 认证后 MOTD (可选)
```

**Banner/MOTD 变量展开**:

| 变量 | 说明 |
|------|------|
| `{username}` | 认证用户名 |
| `{client_ip}` | 客户端 IP 地址 |
| `{datetime}` | 当前日期时间 |
| `{hostname}` | 代理服务器主机名 |
| `{version}` | ssh-proxy-core 版本号 |

Banner 在认证前显示（如法律声明），MOTD 在认证成功后显示。

### `[logging]` 日志

```ini
[logging]
level = info                          # 日志级别: trace, debug, info, warn, error, fatal
audit_dir = /var/log/ssh-proxy/audit  # 审计日志目录
audit_encryption_key = 001122...eeff  # 可选: 64 位十六进制 AES-256-GCM 密钥
format = text                         # 日志格式: text (默认) | json
```

`format = json` 时，运行日志以 NDJSON (每行一个 JSON 对象) 格式输出，方便 ELK、Loki 等日志系统采集：

```json
{"ts":"2025-01-05T12:00:00Z","level":"info","file":"ssh_server.c","line":142,"msg":"Server listening on 0.0.0.0:2222"}
```

配置 `audit_encryption_key` 或 `audit_encryption_key_file` 后，事件日志和命令日志会按行使用
AES-256-GCM 加密，并保留现有的轮转/归档行为。

### `[limits]` 连接限制

```ini
[limits]
max_sessions = 1000            # 全局最大并发会话数
session_timeout = 3600         # 会话空闲超时 (秒)
auth_timeout = 60              # 认证超时 (秒)
per_user_max_sessions = 10     # 每用户最大并发会话数 (0 = 不限)
```

### `[user:*]` 用户

```ini
# 格式: [user:用户名]
[user:admin]
password_hash = $6$saltsalt$...        # openssl passwd -6 -salt saltsalt 'password'
pubkey = ssh-rsa AAAA... admin@host    # OpenSSH 格式公钥 (可选)
enabled = true                         # 是否启用
totp_secret = JBSWY3DPEHPK3PXP        # Base32 TOTP 密钥 (MFA 启用时需要)
mfa_enabled = true                     # 该用户是否启用 MFA
```

当前 data plane 配置中的敏感字段支持三种来源：

1. 明文（兼容旧配置）
2. `${env:NAME}` / `${file:/path/to/value}`
3. `enc:v1:<nonce_hex>:<ciphertext_hex>:<tag_hex>`，配合 `[security]` 中的 `master_key` 或 `master_key_file`

目前已接入加密存储的字段包括 `password_hash`、`[admin].auth_token`、
`[webhook].hmac_secret` 和 `[logging].audit_encryption_key`。

如需启用 SSH 证书认证，请在 `[security]` 中配置 `trusted_user_ca_key` 或
`trusted_user_ca_keys_file`。启用后，用户可以仅依赖 CA 签发的短期证书登录；代理会强制校验
`source-address` critical option，并拒绝未知 critical options。若需下发撤销列表，可通过
`/api/v2/ca/crl` 导出已撤销序列号，并在 data plane 的 `[security]` 中配置
`revoked_user_cert_serial` 或 `revoked_user_cert_serials_file` 以拒绝已撤销证书。

```ini
[security]
master_key = ${env:SSH_PROXY_MASTER_KEY}      # 64 hex chars (AES-256)
# master_key_file = /etc/ssh-proxy/master_key.hex
```

密码哈希生成：

```bash
openssl passwd -6 -salt saltsalt 'yourpassword'
```

### `[route:*]` 路由

```ini
# 格式: [route:代理用户模式]  支持 glob 通配符 (*, ?)
[route:admin]
upstream = prod.example.com    # 上游服务器地址
port = 22                      # 上游端口 (默认 22)
user = root                    # 上游用户名
privkey = /etc/ssh-proxy/keys/admin.key  # 上游认证私钥

[route:dev-*]                  # 匹配 dev-alice, dev-bob 等
upstream = dev.example.com
user = developer

[route:*]                      # 默认路由 (catch-all)
upstream = bastion.example.com
user = guest
```

### `[policy:*]` 功能策略

策略通过 `[policy:用户名模式]` 或 `[policy:用户名模式@上游服务器模式]` 段配置。

```ini
# 管理员 — 允许所有
[policy:admin]
allow = all

# 开发者 — 允许 shell、git、下载
[policy:dev-*]
allow = shell, exec, git, download, sftp_list
deny = upload, port_forward

# 只读用户
[policy:readonly-*]
allow = shell, download, sftp_list
deny = upload, scp_upload, sftp_upload, rsync_upload, git_push, exec

# 特定上游策略
[policy:*@prod.example.com]
allow = shell, download, sftp_list
deny = upload, exec, git_push, sftp_delete

[policy:admin@prod.example.com]
allow = all
```

**匹配优先级**（从高到低）：

1. 精确用户 + 精确上游服务器
2. 精确用户 + 通配符上游服务器
3. 精确用户（无上游限制）
4. 通配符用户 + 精确上游服务器
5. 通配符用户 + 通配符上游服务器
6. 通配符用户（无上游限制）

**功能标识列表**:

| 功能标识 | 说明 |
|----------|------|
| `shell` | 交互式 Shell |
| `exec` | 远程命令执行 |
| `scp` / `scp_upload` / `scp_download` | SCP 全部 / 上传 / 下载 |
| `sftp` / `sftp_upload` / `sftp_download` / `sftp_list` / `sftp_delete` | SFTP 全部 / 上传 / 下载 / 列目录 / 删除 |
| `rsync` / `rsync_upload` / `rsync_download` | rsync 全部 / 上传 / 下载 |
| `port_forward` / `local-forward` / `remote-forward` / `dynamic-forward` | 端口转发 全部 / -L / -R / -D |
| `x11` | X11 转发 |
| `agent` | SSH Agent 转发 |
| `git` / `git_push` / `git_pull` | Git 全部 / push / pull+fetch+clone |
| `upload` / `download` | 所有上传 / 所有下载 (scp/sftp/rsync) |
| `all` / `none` | 全部允许 / 全部禁止 |

### `[rbac:*]` 基于角色的访问控制

```ini
[rbac:ops-team]
roles = admin, operator
allowed_targets = prod-*, staging-*
```

### `[ip_acl]` IP 访问控制

```ini
[ip_acl]
mode = whitelist                  # whitelist | blacklist
rules = 10.0.0.0/8, 192.168.1.0/24, 172.16.0.0/12  # CIDR 规则 (逗号分隔)
log_rejections = true             # 记录被拒绝的连接
```

- **whitelist 模式** — 仅允许列出的 IP/CIDR 连接
- **blacklist 模式** — 拒绝列出的 IP/CIDR，允许其余

IP ACL 过滤器在过滤器链中最早执行（`on_connect` 阶段），可以在认证前快速拒绝连接。

### `[auth]` 认证后端

```ini
[auth]
backend = config                  # config (默认) | ldap

# LDAP 后端配置 (backend=ldap 时生效)
ldap_uri = ldap://ldap-a.example.com:389,ldap://ldap-b.example.com:389
ldap_base_dn = ou=users,dc=example,dc=com
ldap_bind_dn = cn=proxy,dc=example,dc=com   # 可选：用于后续属性查询
ldap_bind_pw = ${env:LDAP_BIND_PASSWORD}
ldap_user_filter = (uid={username})    # {username} 会被替换为实际用户名
ldap_timeout = 5                       # 连接超时 (秒)
ldap_group_attr = memberOf             # 组成员属性
ldap_email_attr = mail
ldap_department_attr = department
ldap_manager_attr = manager
```

LDAP 认证使用原生 TCP Socket 和 BER/ASN.1 编码实现 Simple Bind，不依赖 libldap。`ldap_uri`
支持逗号分隔多个节点，认证时会在节点不可用时自动故障转移，并优先尝试最近一次成功的节点。
认证成功后还会查询用户条目的 `memberOf/mail/department/manager`（可配置属性名），并写入 session
metadata，供后续角色映射或审计链路消费。

### `[mfa]` 双因素认证

```ini
[mfa]
enabled = true                    # 全局 MFA 开关
issuer = SSH-Proxy                # TOTP 发行者名称
time_step = 30                    # 时间步长 (秒，默认 30)
digits = 6                        # TOTP 位数 (默认 6)
window = 1                        # 时间窗口容差 (±N 步，默认 1)
```

Per-user MFA 在 `[user:xxx]` 中配置 `totp_secret` 和 `mfa_enabled`。TOTP 实现遵循 RFC 6238，自实现 SHA1 和 HMAC-SHA1，无外部加密库依赖。

### `[webhook]` 事件通知

```ini
[webhook]
url = https://hooks.example.com/ssh-events
auth_header = Bearer my-secret-token     # 可选: Authorization 头
events = auth.success, auth.failure, session.start, session.end  # 订阅事件
retry_max = 3                            # 最大重试次数 (默认 3)
retry_delay_ms = 1000                    # 重试间隔 (毫秒，默认 1000)
timeout_ms = 5000                        # HTTP 超时 (毫秒，默认 5000)
```

**支持的事件类型**:

| 事件 | 触发时机 |
|------|----------|
| `auth.success` | 认证成功 |
| `auth.failure` | 认证失败 |
| `session.start` | 会话建立 |
| `session.end` | 会话结束 |
| `rate_limit.triggered` | 触发速率限制 |
| `ip_acl.denied` | IP ACL 拒绝连接 |
| `upstream.unhealthy` | 上游服务器变为不健康 |
| `upstream.healthy` | 上游服务器恢复健康 |
| `config.reloaded` | 配置热重载完成 |

Webhook 使用异步队列和专用工作线程发送，不阻塞 SSH 连接处理。HTTP 请求通过原生 Socket 实现，无 libcurl 依赖。

### `[admin]` 管理 API

```ini
[admin]
auth_token = my-admin-secret     # Bearer Token 认证 (空 = 无需认证，也支持 enc:v1:...)
```

管理 API 复用健康检查 HTTP 服务器（默认端口 9090），详见 [管理 REST API](#管理-rest-api)。

### `[router]` 路由与连接池

```ini
[router]
lb_policy = round_robin           # round_robin | random | least_conn | hash
connect_timeout_ms = 10000        # 单次连接超时 (毫秒)
health_check_enabled = true       # 启用健康检查
health_check_interval = 30        # 健康检查间隔 (秒)

# 连接重试 (指数退避)
retry_max = 3                     # 最大重试次数 (0 = 不重试)
retry_initial_delay_ms = 100      # 初始重试延迟 (毫秒)
retry_max_delay_ms = 5000         # 最大重试延迟 (毫秒)
retry_backoff_factor = 2.0        # 退避因子

# 熔断器
circuit_breaker_enabled = true    # 连续失败后临时摘除该 route
circuit_breaker_failure_threshold = 3
circuit_breaker_open_seconds = 30

# 连接池
pool_enabled = false              # 启用连接池
pool_max_idle = 10                # 最大空闲连接数
pool_max_idle_time = 300          # 空闲连接最大存活时间 (秒)
```

连接重试使用指数退避算法：`delay = min(initial_delay × factor^attempt, max_delay)`。每次重试会重新进行路由解析，自动跳过熔断器仍处于 open 状态的上游 route；冷却时间到期后，只允许一个 half-open 探测请求去验证该 route 是否恢复。

### `[session_store]` 会话存储

```ini
[session_store]
type = local                      # local (内存，默认) | file (文件共享)
path = /var/lib/ssh-proxy/sessions.json  # 文件后端路径 (type=file 时)
sync_interval = 5                 # 同步间隔 (秒)
instance_id = proxy-01            # 实例标识 (多实例部署时区分来源)
```

- **local** — 内存存储，单进程使用
- **file** — NDJSON 文件 + flock 文件锁，支持多进程共享会话信息

启用共享后端后，管理 API 的会话列表会合并本地与远端实例的活跃会话，并透出
`instance_id`；同时 `per_user_max_sessions` 会基于共享视图做集群级并发会话限制。

---

## 日志与审计

### 日志位置

| 类型 | 默认路径 | 说明 |
|------|----------|------|
| 运行日志 | stdout/stderr | 服务运行时日志 (支持 JSON 格式) |
| 审计事件日志 | `{audit_dir}/audit_YYYYMMDD.log` | JSON 格式连接/认证/断开事件 |
| 命令审计日志 | `{audit_dir}/commands_YYYYMMDD.log` | Shell 命令记录 |
| 会话录像 | `{audit_dir}/session_{id}_{datetime}.cast` | asciicast v2 终端录像 |
| 文件传输日志 | `{audit_dir}/transfers_YYYYMMDD.log` | SCP/SFTP/rsync 传输记录 |
| 端口转发日志 | `{audit_dir}/port_forwards_YYYYMMDD.log` | 端口转发请求记录 |

默认 `audit_dir` 为 `/tmp/ssh_proxy_audit`，可在 `[logging]` 段的 `audit_dir` 中修改。

### 结构化 JSON 日志

启用 `[logging] format = json` 后，运行日志以 NDJSON 格式输出：

```json
{"ts":"2025-01-05T12:00:00Z","level":"info","file":"ssh_server.c","line":142,"msg":"Server listening on 0.0.0.0:2222"}
{"ts":"2025-01-05T12:00:01Z","level":"warn","file":"ip_acl_filter.c","line":87,"msg":"Connection rejected by IP ACL","client":"203.0.113.50"}
```

### 审计事件日志

审计事件日志为 JSON 格式，每行一个事件：

```json
{"timestamp":1704412800,"type":"AUTH_SUCCESS","session_id":12345,"username":"admin","client_addr":"192.168.1.100"}
{"timestamp":1704412801,"type":"SESSION_START","session_id":12345,"username":"admin","target":"prod.example.com"}
{"timestamp":1704413400,"type":"SESSION_END","session_id":12345,"username":"admin"}
```

### 命令审计日志

启用 `[audit] record_commands = true` 后，审计过滤器在 `on_data_upstream` 回调中解析并记录 Shell 命令：

```json
{"timestamp":1704412900,"session_id":12345,"username":"admin","upstream":"prod.example.com","command":"ls -la /etc/"}
{"timestamp":1704412910,"session_id":12345,"username":"admin","upstream":"prod.example.com","command":"cat /etc/passwd"}
```

日志文件路径：`{audit_dir}/commands_YYYYMMDD.log`。

### 文件传输日志

```json
{"timestamp":1704412900,"session":12345,"user":"admin","event":"start","direction":"upload","protocol":"scp","path":"/home/user/file.txt","size":1024,"transferred":0}
{"timestamp":1704412901,"session":12345,"user":"admin","event":"complete","direction":"upload","protocol":"scp","path":"/home/user/file.txt","size":1024,"transferred":1024,"checksum":"a1b2c3..."}
{"timestamp":1704412950,"session":12346,"user":"dev","event":"denied","direction":"upload","protocol":"sftp","path":"/etc/passwd","size":0,"transferred":0}
```

| 字段 | 说明 |
|------|------|
| `event` | `start` / `complete` / `failed` / `denied` |
| `direction` | `upload` / `download` |
| `protocol` | `scp` / `sftp` / `rsync` / `git` |
| `path` | 远程文件路径 |
| `size` | 文件大小 (字节) |
| `transferred` | 已传输字节数 |
| `checksum` | 文件 SHA-256 校验和 (完成时) |

### 端口转发日志

```json
{"timestamp":1704413000,"session":12345,"user":"admin","type":"local","bind":"localhost:8080","target":"db.internal:3306","allowed":true}
{"timestamp":1704413010,"session":12346,"user":"guest","type":"remote","bind":"0.0.0.0:9000","target":"localhost:22","allowed":false}
```

### 查看会话录像 (.cast 文件)

会话录像使用 [asciicast v2](https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md) 格式：

#### 方法 1: asciinema 播放

```bash
# 安装
sudo apt install asciinema  # 或 pip install asciinema

# 播放
asciinema play /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast

# 2 倍速 + 限制空闲
asciinema play -s 2 -i 2 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast
```

#### 方法 2: asciinema-player (Web)

```bash
cd /tmp/ssh_proxy_audit && python3 -m http.server 8000
```

```html
<html>
<head>
  <link rel="stylesheet" href="https://unpkg.com/asciinema-player@3.0.1/dist/bundle/asciinema-player.css" />
</head>
<body>
  <div id="player"></div>
  <script src="https://unpkg.com/asciinema-player@3.0.1/dist/bundle/asciinema-player.min.js"></script>
  <script>
    AsciinemaPlayer.create('http://localhost:8000/session_12345_20250105_120000.cast',
                           document.getElementById('player'));
  </script>
</body>
</html>
```

#### 方法 3: 查看原始内容

```bash
head -1 session_*.cast | jq    # JSON 头部
cat session_*.cast             # 全部帧
```

`.cast` 文件格式：第一行为 JSON 头部（版本、终端尺寸、时间戳），后续每行为 `[时间偏移, "o"|"i", "数据"]` 事件帧（`"o"` = 输出，`"i"` = 输入）。

---

## 运维

### 配置校验

使用 `--check`（或 `-t`）标志校验配置文件，类似 `nginx -t`：

```bash
$ ./build/bin/ssh-proxy-core -t -c /etc/ssh-proxy/config.ini
Configuration OK: /etc/ssh-proxy/config.ini

$ ./build/bin/ssh-proxy-core -t -c bad-config.ini
Configuration ERROR: bad-config.ini
  [ERROR] host_key file not found: /nonexistent/key
  [WARN]  no routes defined — all connections will be rejected
```

配置校验不启动服务，仅检查配置语法和语义（文件存在性、值范围、依赖关系等），适合 CI/CD 流程和部署前检查。

### 健康检查

健康检查 HTTP 服务器默认监听 `127.0.0.1:9090`：

```bash
# 健康状态
curl http://localhost:9090/health
# {"status":"healthy","version":"0.3.0","uptime":3600,"active_sessions":42}

# Prometheus 指标
curl http://localhost:9090/metrics
```

**Prometheus 指标**（`/metrics` 端点）:

```
ssh_proxy_connections_total 12345
ssh_proxy_connections_active 42
ssh_proxy_auth_success_total 10000
ssh_proxy_auth_failure_total 500
ssh_proxy_bytes_upstream 1048576
ssh_proxy_bytes_downstream 2097152
ssh_proxy_sessions_rejected 100
ssh_proxy_config_reloads 5
ssh_proxy_upstream_retries_total 30
ssh_proxy_upstream_retries_success 25
ssh_proxy_upstream_retries_exhausted 5
```

### 管理 REST API

管理 API 复用健康检查 HTTP 服务器，需在 `[admin]` 中配置 `auth_token` 启用认证。

```bash
# 认证方式
curl -H "Authorization: Bearer my-admin-secret" http://localhost:9090/api/v1/sessions
```

**API 端点**:

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/sessions` | 列出所有活跃会话 |
| DELETE | `/api/v1/sessions/{id}` | 强制终止指定会话 |
| GET | `/api/v1/upstreams` | 列出上游服务器状态 |
| POST | `/api/v1/upstreams/{id}/enable` | 启用上游服务器 |
| POST | `/api/v1/upstreams/{id}/disable` | 禁用上游服务器 |
| POST | `/api/v1/reload` | 热重载配置 |
| GET | `/api/v1/config` | 查看当前运行配置 (脱敏) |

**示例**:

```bash
# 查看活跃会话
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/v1/sessions | jq

# 踢出会话
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/v1/sessions/12345

# 禁用故障上游
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/v1/upstreams/2/disable

# 热重载配置
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/v1/reload
```

### 热重载配置

两种方式触发：

```bash
# 方式 1: 发送 SIGHUP
kill -HUP $(pidof ssh-proxy-core)

# 方式 2: REST API
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/v1/reload
```

热重载会重新加载配置文件中的用户、路由、策略、ACL 等，已建立的会话不受影响。

### `sshproxy` 控制平面 CLI

`cmd/sshproxy` 提供了面向控制平面的命令行工具，可用于 OIDC 登录、SSH 证书获取、会话查询与通过代理发起 `ssh` / `scp`：

```bash
go build ./cmd/sshproxy

# 首次配置控制平面地址
./sshproxy config set server https://proxy.example.com
./sshproxy config set ssh_addr proxy.example.com:2222

# 浏览器 OIDC 登录并自动获取短期 SSH 证书
./sshproxy login

# 常用命令
./sshproxy ls servers
./sshproxy ls sessions
./sshproxy ssh alice@db-prod
./sshproxy scp ./backup.tgz alice@db-prod:/tmp/
./sshproxy completion bash
```

`sshproxy login` 会将控制平面会话保存到 `~/.sshproxy/config.json`，生成或复用 `~/.sshproxy/id_ed25519`，并向内置 SSH CA 申请短期用户证书。后续 `sshproxy ssh` / `scp` 会自动注入该身份文件。若需对控制平面 HTTPS 做证书固定，可在该配置文件中设置 `pinned_server_pubkey_sha256`（格式为 `sha256/<base64-spki-hash>`）。

### Web SSO（OIDC / SAML）

控制平面登录页同时支持 OIDC 与 SAML 2.0 Web SSO。SAML 集成采用
metadata-driven 方式：配置 `saml_root_url`、`saml_idp_metadata_url`
（或 `saml_idp_metadata_file`）、`saml_sp_cert`、`saml_sp_key` 后，
服务端会暴露 `/auth/saml/login`（SP-Initiated）、`/auth/saml/acs`
（ACS / IdP-Initiated）与 `/auth/saml/metadata`（SP metadata），并基于
Assertion Attribute 将 IdP 组/角色映射到本地 `admin` / `operator` /
`viewer` 角色。该路径面向 ADFS、Shibboleth、OneLogin 等企业 IdP。

---

## 架构

```
                           ┌──────────────────────────────────────────────────────┐
                           │                  SSH Proxy Core                      │
┌──────────┐               │                                                      │               ┌──────────────┐
│          │   TCP / SSH   │  ┌──────────────────────────────────────────────┐    │   SSH / TCP   │              │
│  Client  │──────────────▶│  │              Filter Chain                    │    │──────────────▶│   Upstream   │
│          │               │  │  ┌────────┬──────┬──────┬────────┬───────┐  │    │               │   Server(s)  │
└──────────┘               │  │  │IP ACL  │ Auth │ MFA  │  RBAC  │ Audit │  │    │               └──────────────┘
                           │  │  │Filter  │Filter│Filter│ Filter │Filter │  │    │
                           │  │  └────────┴──────┴──────┴────────┴───────┘  │    │
                           │  │  ┌────────┬──────────┐                      │    │
                           │  │  │ Rate   │ Policy   │                      │    │
                           │  │  │ Limit  │ Filter   │                      │    │
                           │  │  └────────┴──────────┘                      │    │
                           │  └──────────────────────────────────────────────┘    │
                           │                                                      │
                           │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │
                           │  │   Session    │  │    Router     │  │  Webhook   │  │
                           │  │   Manager    │  │  + Conn Pool  │  │  Manager   │  │
                           │  └──────┬──────┘  │  + LB + Retry │  └────────────┘  │
                           │         │         └──────────────┘                    │
                           │  ┌──────▼──────┐  ┌──────────────┐  ┌────────────┐  │
                           │  │   Session    │  │   Health     │  │   Admin    │  │
                           │  │   Store      │  │   Check      │  │   API      │  │
                           │  │ (local/file) │  │  + Metrics   │  │  (HTTP)    │  │
                           │  └─────────────┘  └──────────────┘  └────────────┘  │
                           └──────────────────────────────────────────────────────┘
```

### 过滤器链执行顺序

```
on_connect:        IP ACL → Rate Limit → Audit
on_auth:           Auth (Password/PublicKey/LDAP) → Audit
on_authenticated:  MFA → RBAC → Audit
on_route:          Policy → Audit
on_data_upstream:  Policy → Audit (命令解析)
on_data_downstream: Policy → Audit (asciicast 录像)
on_close:          Rate Limit → Audit → Webhook
```

---

## 项目结构

```
ssh-proxy-core/
├── src/                      # 源文件 (20 个 .c 文件)
│   ├── main.c                    # 主入口、CLI 参数解析
│   ├── ssh_server.c              # SSH 服务器核心
│   ├── session.c                 # 会话管理器
│   ├── session_store.c           # 分布式会话存储
│   ├── filter.c                  # 过滤器链框架
│   ├── auth_filter.c             # 认证过滤器 (Password/PublicKey)
│   ├── ldap_auth.c               # LDAP 认证后端 (原生 BER)
│   ├── mfa_filter.c              # TOTP/MFA 过滤器 (自实现 SHA1)
│   ├── ip_acl_filter.c           # IP 白名单/黑名单过滤器
│   ├── rbac_filter.c             # RBAC 过滤器
│   ├── policy_filter.c           # 功能策略过滤器
│   ├── audit_filter.c            # 审计过滤器 (事件/命令/录像)
│   ├── rate_limit_filter.c       # 速率限制过滤器
│   ├── router.c                  # 路由器、连接池、重试
│   ├── proxy_handler.c           # 代理数据处理
│   ├── config.c                  # 配置文件加载与校验
│   ├── logger.c                  # 日志系统 (Text/JSON)
│   ├── metrics.c                 # 运行时指标 (原子计数器)
│   ├── health_check.c            # HTTP 健康检查 + Admin API
│   └── webhook.c                 # Webhook 事件通知
├── include/                  # 头文件 (19 个 .h 文件)
│   ├── version.h                 # 版本定义 (0.3.0)
│   └── ...                       # 与 src/ 一一对应
├── tests/                    # 测试文件 (11 个 .c 文件)
│   ├── test_config.c
│   ├── test_filter.c
│   ├── test_integration.c
│   ├── test_ip_acl_filter.c
│   ├── test_logger.c
│   ├── test_mfa_filter.c
│   ├── test_router.c
│   ├── test_session.c
│   ├── test_session_store.c
│   ├── test_ssh_server.c
│   └── test_webhook.c
├── docs/                     # 文档
│   ├── DESIGN.md                 # 设计文档
│   ├── DEPLOYMENT.md             # 部署指南
│   ├── TESTING.md                # 测试指南
│   └── config.example.ini        # 完整配置示例
├── deploy/                   # 部署文件
│   └── ssh-proxy.service         # systemd 服务单元
├── scripts/                  # 脚本
│   ├── install-libssh.sh         # libssh 源码安装
│   └── setup-and-verify.sh       # 环境验证
├── lib/                      # 第三方库
├── build/                    # 构建输出目录
├── Dockerfile                # 多阶段 Docker 构建
├── Makefile                  # 构建系统
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE                   # GPL-3.0-only
```

---

## 构建

### 依赖

| 依赖 | 类型 | 说明 |
|------|------|------|
| GCC / Clang (C11) | 必选 | 编译器 |
| GNU Make | 必选 | 构建系统 |
| libssh (>= 0.9.0) | 必选 | SSH 协议库 |
| pthread | 必选 | POSIX 线程 |
| crypt | 必选 | 密码哈希 |
| clang-format | 可选 | 代码格式化 |
| cppcheck | 可选 | 静态分析 |

### 安装依赖 (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libssh-dev
```

### 从源码安装 libssh

```bash
./scripts/install-libssh.sh
```

### 构建命令

```bash
make                  # 调试构建 (默认)
make release          # 发布构建 (优化)
make lib              # 构建静态库
make test             # 运行测试
make clean            # 清理构建
```

### Make 目标

| 目标 | 说明 |
|------|------|
| `all` | 构建项目 (默认) |
| `debug` | 调试构建 |
| `release` | 发布构建 |
| `lib` | 构建静态库 |
| `test` | 构建并运行测试 |
| `run` | 构建并运行 |
| `clean` | 清理构建产物 |
| `install` | 安装到系统 (PREFIX=/usr/local) |
| `uninstall` | 从系统卸载 |
| `format` | 格式化代码 (clang-format) |
| `check` | 静态分析 (cppcheck) |
| `check-deps` | 验证依赖 |
| `compile_commands.json` | 生成编译数据库 (用于 LSP) |
| `json-gen` | 生成 JSON 序列化代码 |
| `help` | 显示帮助 |

---

## Terraform Bridge

控制面附带了一个轻量 Terraform bridge：`cmd/terraform-provider`。它适合搭配
`external` data source、`local-exec` 或自定义 wrapper 使用，直接复用现有
REST API，而不要求完整 Terraform plugin runtime。

### 环境变量

- `SSHPROXY_SERVER` — 控制面地址，例如 `https://proxy.example.com:8443`
- `SSHPROXY_TOKEN` — API Bearer Token

### 支持动作

- 读取：`read-users`、`read-user <username>`、`read-servers`、`read-server <id>`、`read-config`
- 变更：`create-user`、`update-user`、`delete-user`、`create-server`、`update-server`、`delete-server`、`apply-config`

### 示例

```bash
# 读取当前配置
SSHPROXY_SERVER=https://proxy.example.com:8443 \
SSHPROXY_TOKEN=$TOKEN \
go run ./cmd/terraform-provider read-config

# “导入”已有用户 / 服务器（按标识读取，供 Terraform state 对齐）
go run ./cmd/terraform-provider read-user alice
go run ./cmd/terraform-provider read-server srv-1

# 创建用户
printf '{"username":"alice","password":"Str0ngPass!","role":"operator"}' \
  | go run ./cmd/terraform-provider create-user
```

---

## API 参考

### 会话管理器 (`session.h`)

```c
session_manager_t *session_manager_create(const session_manager_config_t *config);
void              session_manager_destroy(session_manager_t *manager);
session_t        *session_manager_create_session(session_manager_t *manager, ssh_session client);
void              session_manager_remove_session(session_manager_t *manager, session_t *session);
session_t        *session_manager_find(session_manager_t *manager, uint64_t session_id);
size_t            session_manager_get_count(const session_manager_t *manager);
size_t            session_manager_cleanup(session_manager_t *manager);
```

### 过滤器链 (`filter.h`)

```c
filter_chain_t  *filter_chain_create(void);
void             filter_chain_destroy(filter_chain_t *chain);
int              filter_chain_add(filter_chain_t *chain, filter_t *filter);
int              filter_chain_remove(filter_chain_t *chain, const char *name);
filter_t        *filter_chain_get(filter_chain_t *chain, const char *name);
size_t           filter_chain_count(const filter_chain_t *chain);
filter_status_t  filter_chain_on_connect(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t  filter_chain_on_auth(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t  filter_chain_on_authenticated(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t  filter_chain_on_route(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t  filter_chain_on_data_upstream(filter_chain_t *chain, filter_context_t *ctx, const uint8_t *data, size_t len);
filter_status_t  filter_chain_on_data_downstream(filter_chain_t *chain, filter_context_t *ctx, const uint8_t *data, size_t len);
void             filter_chain_on_close(filter_chain_t *chain, filter_context_t *ctx);
```

### 路由器 (`router.h`)

```c
router_t    *router_create(const router_config_t *config);
void         router_destroy(router_t *router);
int          router_add_upstream(router_t *router, const upstream_config_t *config);
int          router_remove_upstream(router_t *router, int index);
int          router_resolve(router_t *router, const char *username, const char *target, route_result_t *result);
ssh_session  router_connect(router_t *router, route_result_t *result, uint32_t timeout_ms);
ssh_session  router_connect_with_retry(router_t *router, const char *username, const char *target, route_result_t *result, uint32_t timeout_ms);
void         router_health_check(router_t *router);
```

### 连接池 (`router.h`)

```c
int          connection_pool_init(connection_pool_t *pool, size_t max_idle, uint32_t max_idle_time);
ssh_session  connection_pool_get(connection_pool_t *pool, const char *host, uint16_t port);
int          connection_pool_put(connection_pool_t *pool, ssh_session session, const char *host, uint16_t port, const char *username);
int          connection_pool_cleanup(connection_pool_t *pool);
void         connection_pool_destroy(connection_pool_t *pool);
```

### IP ACL (`ip_acl_filter.h`)

```c
filter_t *ip_acl_filter_create(const ip_acl_filter_config_t *config);
int       ip_acl_add_entry(ip_acl_filter_config_t *config, const char *cidr, ip_acl_action_t action);
bool      ip_acl_check(filter_t *filter, const char *ip_addr);
void      ip_acl_clear_entries(ip_acl_filter_config_t *config);
```

### MFA/TOTP (`mfa_filter.h`)

```c
filter_t *mfa_filter_create(const mfa_filter_config_t *config);
int       base32_decode(const char *encoded, uint8_t *decoded, size_t decoded_size);
void      hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output);
int       totp_generate(const char *secret_base32, int time_step, int digits, int time_offset);
bool      totp_validate(const char *secret_base32, int code, int time_step, int digits, int window);
```

### Webhook (`webhook.h`)

```c
webhook_manager_t *webhook_manager_create(const webhook_config_t *config);
void               webhook_manager_destroy(webhook_manager_t *mgr);
int                webhook_send(webhook_manager_t *mgr, webhook_event_type_t event, const char *payload_fmt, ...);
```

### 会话存储 (`session_store.h`)

```c
session_store_t *session_store_create(const session_store_config_t *config);
void             session_store_destroy(session_store_t *store);
int              session_store_put(session_store_t *store, const session_record_t *record);
int              session_store_remove(session_store_t *store, uint64_t session_id);
int              session_store_list(session_store_t *store, session_record_t *records, size_t max_records, size_t *count);
```

### 配置 (`config.h`)

```c
proxy_config_t        *config_create(void);
proxy_config_t        *config_load(const char *path);
void                   config_destroy(proxy_config_t *config);
int                    config_reload(proxy_config_t *config, const char *path);
config_user_t         *config_find_user(const proxy_config_t *config, const char *username);
config_route_t        *config_find_route(const proxy_config_t *config, const char *proxy_user);
config_policy_t       *config_find_policy(const proxy_config_t *config, const char *username, const char *upstream);
config_valid_result_t *config_validate(const proxy_config_t *config, const char *config_path);
void                   config_valid_free(config_valid_result_t *results);
```

---

## 开发

### 添加自定义过滤器

```c
#include "filter.h"

static filter_status_t my_on_connect(filter_t *filter, filter_context_t *ctx) {
    LOG_INFO("Custom filter: new connection from %s",
             session_get_metadata(ctx->session)->client_addr);
    return FILTER_CONTINUE;  // FILTER_REJECT 拒绝连接
}

static filter_status_t my_on_data_upstream(filter_t *filter, filter_context_t *ctx,
                                            const uint8_t *data, size_t len) {
    // 检查/修改上行数据
    return FILTER_CONTINUE;
}

filter_callbacks_t callbacks = {
    .on_connect = my_on_connect,
    .on_data_upstream = my_on_data_upstream,
};
filter_t *my_filter = filter_create("my_filter", FILTER_TYPE_CUSTOM, &callbacks, NULL);
filter_chain_add(chain, my_filter);
```

### 嵌入式使用

```c
#include "session.h"
#include "filter.h"
#include "router.h"

// 会话管理器
session_manager_config_t sm_cfg = {
    .max_sessions = 1000,
    .session_timeout = 3600,
    .auth_timeout = 60
};
session_manager_t *sm = session_manager_create(&sm_cfg);

// 路由器 (带连接池和重试)
router_config_t rt_cfg = {
    .lb_policy = LB_POLICY_ROUND_ROBIN,
    .connect_timeout_ms = 10000,
    .max_retries = 3,
    .retry_initial_delay_ms = 100,
    .retry_backoff_factor = 2.0,
    .pool_enabled = true,
    .pool_max_idle = 10,
};
router_t *router = router_create(&rt_cfg);
```

### 调试

```bash
make debug                          # 调试构建
gdb ./build/bin/ssh-proxy-core      # GDB 调试

make compile_commands.json          # 生成 LSP 编译数据库
```

### 代码质量

```bash
make format    # clang-format 格式化
make check     # cppcheck 静态分析
make test      # 运行全部测试
```

---

## 部署

### systemd

```bash
# 安装
sudo make install
sudo cp deploy/ssh-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload

# 创建用户和目录
sudo useradd -r -s /usr/sbin/nologin ssh-proxy
sudo mkdir -p /etc/ssh-proxy /var/log/ssh-proxy/audit
sudo chown ssh-proxy:ssh-proxy /var/log/ssh-proxy /var/log/ssh-proxy/audit

# 生成密钥并放置配置
sudo ssh-keygen -t ed25519 -f /etc/ssh-proxy/host_key -N ""
sudo chown ssh-proxy:ssh-proxy /etc/ssh-proxy/host_key*
sudo cp docs/config.example.ini /etc/ssh-proxy/config.ini
sudo vi /etc/ssh-proxy/config.ini  # 编辑配置

# 启动
sudo systemctl enable --now ssh-proxy

# 查看状态
sudo systemctl status ssh-proxy
sudo journalctl -u ssh-proxy -f
```

systemd 服务文件 (`deploy/ssh-proxy.service`) 已包含安全加固：`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome`、`PrivateTmp`。资源限制：65536 文件描述符、4096 进程。

热重载配置：

```bash
sudo systemctl reload ssh-proxy   # 发送 SIGHUP
```

### Docker

```bash
# 构建镜像
docker build -t ssh-proxy-core .

# 运行
docker run -d \
  --name ssh-proxy \
  -p 2222:2222 \
  -p 9090:9090 \
  -v /path/to/config.ini:/etc/ssh-proxy/config.ini:ro \
  -v /path/to/audit:/var/log/ssh-proxy/audit \
  ssh-proxy-core

# 查看日志
docker logs -f ssh-proxy
```

Dockerfile 使用多阶段构建（builder + runtime），运行时镜像仅包含 libssh 运行时库。默认使用 `ssh-proxy` 非 root 用户运行，暴露端口 2222 (SSH) 和 9090 (Admin API + Health Check)。

---

## 文档索引

| 文档 | 说明 |
|------|------|
| [快速上手指南](docs/quickstart.md) | 从安装到首次使用的完整流程 |
| [API 参考](docs/api-reference.md) | 全部 REST API 端点、请求/响应示例 |
| [架构设计](docs/DESIGN.md) | 双平面架构、模块设计、数据流 |
| [部署指南](docs/DEPLOYMENT.md) | 生产环境部署、systemd、Docker、Kubernetes |
| [测试文档](docs/TESTING.md) | C 和 Go 双套件测试流程、覆盖矩阵 |
| [配置示例](docs/config.example.ini) | 完整配置文件模板 |
| [贡献指南](CONTRIBUTING.md) | 开发规范、C 与 Go 两端贡献指引 |
| [安全政策](SECURITY.md) | 漏洞报告流程 |
| [变更日志](CHANGELOG.md) | 版本发布记录 |

---

## 许可证

本项目采用 [GNU GPL v3.0 only](LICENSE) 许可证。详见 [LICENSE](LICENSE) 文件。
