# SSH Proxy Core — 架构设计文档

## 概述

SSH Proxy Core 是一个高性能、可扩展的 SSH 协议代理平台。类似于 HTTP 领域的 Nginx / Envoy，它位于 SSH 客户端与后端服务器之间，提供流量转发、访问控制、会话审计和协议网关等功能。

项目采用 **双平面架构**：

| 平面 | 语言 | 职责 |
|------|------|------|
| **数据面 (Data Plane)** | C (libssh) | SSH 协议代理、过滤器链、终端录像、连接池、路由 |
| **控制面 (Control Plane)** | Go | REST API、Web UI、集群管理、自动化、网关、洞察 |

```
┌──────────────────────────────────────────────────────────────────────┐
│                          客户端 (SSH / Browser)                       │
└────────────────┬──────────────────────────┬──────────────────────────┘
                 │ SSH (TCP 2222)           │ HTTPS (TCP 8443)
                 ▼                          ▼
┌────────────────────────────┐  ┌──────────────────────────────────────┐
│     C 数据面               │  │         Go 控制面                     │
│                            │  │                                      │
│  Listener ─► Filter Chain  │  │  REST API (/api/v2/*)                │
│    ├─ Auth Filter          │  │    ├─ Sessions / Users / Servers     │
│    ├─ IP ACL Filter        │  │    ├─ Audit / Compliance / SIEM     │
│    ├─ RBAC Filter          │  │    ├─ SSH CA / JIT Access            │
│    ├─ Policy Filter        │  │    ├─ Cluster / Discovery            │
│    ├─ Rate Limit Filter    │  │    ├─ Command Control                │
│    ├─ MFA Filter           │  │    ├─ Automation (P7.3)              │
│    └─ Audit Filter         │  │    ├─ Gateway    (P7.4/P7.5)        │
│  Router ─► Upstream Pool   │  │    └─ Insights   (P7.6)             │
│  Health Check HTTP Server  │  │  Web UI (会话列表/审计/自动化/仪表盘) │
│  /health  /metrics  /api   │  │  Scheduler (cron 自动化调度)          │
└────────────────────────────┘  └──────────────────────────────────────┘
```

## 核心设计目标

1. **代理 (Proxy)** — 透明代理和显式代理，多后端路由与负载均衡
2. **审计 (Audit)** — 命令审计、终端录像 (asciicast v2)、文件传输日志、结构化事件流
3. **安全 (Security)** — MFA、RBAC、细粒度策略、IP ACL、SSH CA 证书签发、JIT 访问
4. **可扩展 (Extensibility)** — Envoy 风格过滤器链 + Go 控制面 Set/Register 插件模式
5. **运维 (Operations)** — 自动化运维工作流、协议网关、智能洞察

---

## 数据面架构 (C)

### 目录结构

```
src/           # C 源文件 (~14,700 行)
include/       # 公共头文件
tests/         # C 单元 / 集成测试 (188+ 测试)
```

### 核心组件

#### 1. 监听器 (Listener)
监听 SSH 端口 (默认 2222)，接受客户端连接。每个连接分配到线程并创建 Session。

#### 2. 过滤器链 (Filter Chain)
参考 Envoy 设计，8 个回调点覆盖连接全生命周期：

| 回调 | 时机 |
|------|------|
| `on_connect` | 新连接到达 |
| `on_auth` | 认证请求 |
| `on_authenticated` | 认证成功后 |
| `on_channel_open` | 通道打开 |
| `on_data_client` | 客户端 → 上游数据 |
| `on_data_upstream` | 上游 → 客户端数据 |
| `on_request` | SSH 请求 (exec/subsystem) |
| `on_close` | 连接关闭 |

内置过滤器：Auth、IP ACL、RBAC、Policy (30+ 功能标识)、Rate Limit、MFA、Audit。

#### 3. 路由与连接池 (Router & Upstream Pool)
- Round-Robin / Random / 最少连接 / Hash 四种负载均衡策略
- SSH 连接复用池，空闲回收与 keepalive
- 指数退避重试 (可配置次数与退避因子)
- 健康检查自动摘除不可用后端

#### 4. 审计系统
- **终端录像**: asciicast v2 格式，支持 asciinema 回放
- **命令审计**: 从 upstream 数据流提取命令，独立日志文件
- **事件日志**: JSON 结构化连接/认证/断开事件
- **文件传输**: SCP / SFTP / rsync 操作日志含校验和

### 数据流

```
Client ──SSH──► Listener ──► Session 创建
                               │
                     Filter Chain (ordered)
                       on_connect → on_auth → on_authenticated
                               │
                            Router ──► Upstream Pool ──► Backend SSH Server
                               │
                     双向数据管道 (on_data_client / on_data_upstream)
                       Audit Filter 实时捕获命令与终端输出
                               │
                          连接终止 → on_close → 审计归档
```

---

## 控制面架构 (Go)

### 目录结构

```
cmd/               # CLI 入口 (sshproxy, terraform-provider)
internal/
  api/             # REST API 处理器 (核心业务逻辑)
  server/          # HTTP 服务器、TLS、路由注册
  config/          # 控制面配置解析
  cluster/         # 集群发现 (static / dns:// / k8s:// / consul://)
  models/          # 共享数据模型
  openapi/         # OpenAPI 路由注册
web/
  templates/       # Go HTML 模板 (页面 + 局部模板)
  static/          # CSS / JS / 图标
sdk/               # Go SDK + Python SDK
api/proto/         # gRPC proto 定义
```

### 可选功能接入模式

控制面使用 **Set / Register 模式** 避免循环依赖：

```go
// 1. 在 api.New() 中初始化组件
api.automation = newAutomationState(api)

// 2. 在 RegisterRoutes() 中注册路由
api.registerAutomationRoutes(mux)
```

每个功能模块遵循相同模式：创建状态 → Set 到 API → Register 路由到 mux。

### 核心 API 模块

| 模块 | 端点前缀 | 功能 |
|------|---------|------|
| Authentication | `/login`, `/logout`, `/auth/*` | OIDC, SAML, 本地认证 |
| Dashboard | `/api/v2/dashboard/*` | 统计概览、活动流 |
| Sessions | `/api/v2/sessions/*` | 会话列表/详情/终止/录像下载 |
| Users | `/api/v2/users/*` | 用户 CRUD、密码、MFA |
| Servers | `/api/v2/servers/*` | 服务器 CRUD、健康、维护 |
| Audit | `/api/v2/audit/*` | 审计事件查询 |
| Configuration | `/api/v2/config/*` | 配置查看/修改/导入导出 |
| SSH CA | `/api/v2/ca/*` | 证书签发与轮转 |
| JIT Access | `/api/v2/jit/*` | 即时访问请求与审批 |
| Cluster | `/api/v2/cluster/*` | 节点管理、成员列表 |
| Discovery | `/api/v2/discovery/*` | 资产发现 (AWS/Azure/GCP/CMDB/Ansible) |
| Command Control | `/api/v2/cmdctrl/*` | 命令拦截与审批 |
| Collaboration | `/api/v2/collab/*` | 会话协作、控制权转移、聊天 |
| Compliance | `/api/v2/compliance/*` | 合规检查 |
| SIEM | `/api/v2/siem/*` | SIEM 集成导出 |
| Threat Detection | `/api/v2/threats/*` | 威胁检测规则与告警 |
| **Automation** | `/api/v2/automation/*` | 脚本库、批量作业、定时调度、CI 触发 |
| **Gateway** | `/api/v2/gateway/*` | 协议网关 (SOCKS5/RDP/VNC/DB/K8s/HTTP) |
| **Insights** | `/api/v2/insights/*` | 命令意图、异常检测、策略预览、审计摘要 |

### Automation 子系统 (P7.3)

```
automationState
  ├─ scriptStore   (JSON 持久化脚本库)
  ├─ jobStore      (JSON 持久化批量作业)
  ├─ runStore      (JSON 持久化运行记录)
  └─ scheduler     (后台 goroutine, 每分钟检查 cron)

执行流程:
  Job → resolveTargets(serverIDs / tags / "all")
      → 对每个 target 并行:
           sshClientConnector.Connect(jumpChain + target)
           → 构建 env prefix + shell 命令
           → session.Run(cmd)
           → 捕获 stdout/stderr (截断 64KB)
      → 汇总 summary → 存储 run
```

### Gateway 子系统 (P7.4 / P7.5)

```
gatewayState
  ├─ proxies map[string]*gatewayRuntime
  └─ mu sync.RWMutex

协议预设:
  socks5(dynamic) | rdp(3389) | vnc(5900) | mysql(3306)
  postgresql(5432) | redis(6379) | kubernetes(6443)
  http(80) | https(443) | x11(6000) | tcp(custom)

SOCKS5 流程 (RFC 1928):
  Client → local listener → 握手 (0x05 no-auth)
         → CONNECT 请求 (解析 IPv4/IPv6/FQDN)
         → sshClientConnector.Connect(jumpChain)
         → ssh.Dial("tcp", target) → 双向 io.Copy

TCP Forward 流程:
  Client → local listener → Accept
         → sshClientConnector.Connect(jumpChain)
         → ssh.Dial("tcp", remoteHost:remotePort)
         → 双向 io.Copy
```

### Insights 子系统 (P7.6)

```
五个分析端点 (基于审计日志的确定性分析):

1. command-intents    — 正则匹配命令 → 分类 + 风险评分
2. anomalies          — 建立用户基线 → 检测偏差 (罕见目标/意图/时段/高危命令)
3. recommendations    — 从使用模式推导最小权限角色与操作集
4. policy-preview     — 自然语言 → 结构化策略规则 (关键词抽取)
5. audit-summary      — 时间范围内审计摘要 (总数/高危/Top 用户/Top 目标)
```

### 共享 SSH 传输层

`ssh_transport.go` 提供复用的 `sshClientConnector`：

- 支持多跳 jump chain (逐跳拨号)
- Password / PrivateKey 认证
- `${env:VAR}` / `${file:/path}` 秘密解析
- known_hosts 校验 (`knownhosts.New`)
- 被 Automation 和 Gateway 共同使用

---

## 持久化

| 数据 | 存储方式 | 路径 |
|------|---------|------|
| 会话元数据 | SQLite | `data_dir/sessions.db` |
| 配置快照 | JSON | `data_dir/config_store.json` |
| 自动化脚本 | JSON | `data_dir/automation_scripts.json` |
| 自动化作业 | JSON | `data_dir/automation_jobs.json` |
| 运行记录 | JSON | `data_dir/automation_runs.json` |
| 终端录像 | asciicast v2 | `recording_dir/session_<id>_*.cast` |
| 审计日志 | NDJSON | `audit_dir/*.log` |
| 命令审计 | NDJSON | `audit_dir/commands_YYYYMMDD.log` |
| 网关代理 | 仅内存 | (进程重启后消失) |

---

## 集群与高可用

- 集群种子支持 `host:port`、`dns://`、`k8s://`、`consul://` 发现
- 隔离节点自动重试加入
- 滚动升级: 数据面 `/drain` + `/health` 503；控制面 `/api/v2/system/upgrade` 就绪闸门
- 会话存储: 共享文件 NDJSON + flock，带 owner 心跳和过期清理

---

## 类似项目对比

| 项目 | 定位 | 与本项目区别 |
|------|------|------------|
| **Teleport** | 全功能堡垒机 | 较重；本项目侧重轻量核心 + 可嵌入 |
| **OpenSSH** | 标准 SSH 实现 | 缺乏代理、审计、RBAC 的可编程性 |
| **Boundary** | 零信任访问代理 | 不含 SSH 协议级审计与过滤 |
| **sshpiper** | SSH 路由器 | 无过滤器链、无控制面、无网关 |

