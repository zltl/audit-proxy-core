# SSH Proxy Core — 商业化产品路线图

> 从 Demo 到行业领先的 SSH 访问管控平台

---

## 一、现状评估

### 1.1 已实现能力 (v0.3.0)

| 模块 | 能力 | 成熟度 |
|------|------|--------|
| SSH 代理核心 | libssh 服务端、双向数据转发、会话生命周期管理 | ✅ 生产就绪 |
| 认证 | Password (crypt) / PublicKey / LDAP (原生 BER) / TOTP-MFA | ✅ 完整 |
| 授权 | RBAC 角色访问控制、IP ACL (CIDR)、Policy Filter (30+ 功能标识) | ✅ 完整 |
| 审计 | 会话录像 (asciicast v2)、命令审计、文件传输日志、端口转发日志 | ✅ 完整 |
| 路由 & 负载均衡 | Round-Robin / Random / Least-Conn / Hash、健康检查、连接池、指数退避重试 | ✅ 完整 |
| 速率限制 | 全局连接速率、Per-IP 限流、Per-User 并发会话限制 | ✅ 完整 |
| 配置管理 | INI 配置、`--check` 校验、SIGHUP 热重载 | ✅ 完整 |
| 可观测性 | `/health` 健康检查、`/metrics` Prometheus 指标、NDJSON 结构化日志 | ✅ 完整 |
| 管理 API | REST API (会话/上游/配置/重载)、Bearer Token 认证 | ⚠️ 基本可用 |
| Webhook | 9 种事件类型、异步队列、重试机制 | ✅ 完整 |
| 会话存储 | 内存 / 文件 (NDJSON + flock) | ⚠️ 仅单机 |
| 部署 | Docker 多阶段构建、systemd 服务、CI/CD (GitHub Actions) | ✅ 完整 |

**代码规模**: ~14,700 行 C 代码，20 个源文件，11 个测试套件 (86+ 单元测试)

### 1.2 关键差距

| 差距 | 严重性 | 说明 |
|------|--------|------|
| 无 Web 管理界面 | 🔴 致命 | 竞品 (Teleport/StrongDM) 全部提供 Web UI |
| 无高可用集群 | 🔴 致命 | 仅支持单节点，无法满足企业 SLA |
| Admin API 无 TLS | 🔴 严重 | HTTP 明文传输管理凭证 |
| LDAP 无 TLS | 🔴 严重 | 明文传输 LDAP 绑定密码 |
| 审计日志无加密/签名 | 🔴 严重 | 日志可被篡改，无法满足合规要求 |
| 无 OIDC/SAML/OAuth | 🟠 高 | 无法对接企业 IdP (Okta/Azure AD/Keycloak) |
| 无 SSH 证书认证 | 🟠 高 | 缺少零信任架构的基础能力 |
| 无密钥/凭证管理 | 🟠 高 | 密码哈希明文存储在配置文件中 |
| 无多租户 | 🟠 高 | 无法作为 SaaS 或 MSP 平台 |
| 无合规报告 | 🟡 中 | 无 SOC2/HIPAA/等保 审计报告生成 |
| 无威胁检测 | 🟡 中 | 无异常行为分析 |

---

## 二、竞品分析摘要

### 2.1 竞品对标

| 产品 | 定位 | 核心优势 | 典型定价 |
|------|------|----------|----------|
| **Teleport** | 统一访问平台 (SSH/K8s/DB/RDP) | 可搜索录像回放、证书认证、K8s 原生 | $29/节点/月 |
| **StrongDM** | 零信任基础设施访问 | 凭证令牌化、JIT 审批、全协议支持 | $80-150/用户/月 |
| **Boundary** (HashiCorp) | 身份驱动的访问管理 | 凭证注入、Vault 集成、HCP 托管 | $5/Worker/月 |
| **CyberArk** | 企业特权账号管理 (PAM) | 合规认证齐全、金融/政府首选 | $100K+ 起 |
| **BeyondTrust** | 远程特权访问 | 合规引擎、会话锁定、密码轮换 | 企业报价 |
| **AWS Session Manager** | 云原生 SSH 替代 | 免费、IAM 集成、无需开端口 | 免费 (AWS Only) |
| **Azure Bastion** | Azure 原生堡垒机 | 无代理、Portal 集成 | $0.019/小时 |
| **Smallstep** | OIDC→SSH 证书 | 短期证书、开源核心 | 开源 + 商业版 |

### 2.2 我们的差异化定位

```
"SSH Proxy Core: 最快、最轻量的 SSH 访问管控平台"

vs Teleport:  10x 更轻量 (14.7K LOC vs 500K+)，纯 SSH 专注，真正开源
vs StrongDM:  1/10 成本，自托管，无供应商锁定
vs Boundary:  标准 SSH 工作流，无需改变运维习惯
vs CyberArk:  80% 功能，1/10 价格，中小企业友好
vs 云厂商方案: 多云/混合云兼容，完全掌控数据主权
```

---

## 三、产品架构目标

### 3.1 目标架构

```
                    ┌──────────────────────────────────────────────────────────────┐
                    │                     Control Plane (Go stdlib)                  │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
                    │  │ Web UI   │  │ REST API │  │ Config   │  │ Certificate │  │
                    │  │(html/    │  │(net/http │  │ Manager  │  │ Authority   │  │
                    │  │template) │  │+ JSON)   │  │          │  │ (SSH CA)    │  │
                    │  └──────────┘  └──────────┘  └──────────┘  └─────────────┘  │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
                    │  │ User &   │  │ Audit    │  │ Policy   │  │ Compliance  │  │
                    │  │ IdP Mgmt │  │ Center   │  │ Engine   │  │ Reporter    │  │
                    │  └──────────┘  └──────────┘  └──────────┘  └─────────────┘  │
                    └───────────────────────┬──────────────────────────────────────┘
                                            │ gRPC / Internal API
                    ┌───────────────────────▼──────────────────────────────────────┐
                    │                    Data Plane (C Core)                        │
                    │  ┌────────────────────────────────────────────────────────┐  │
                    │  │                   SSH Proxy Core                       │  │
                    │  │  Filter Chain: IP ACL → Auth → MFA → RBAC → Policy    │  │
                    │  │  → Audit → Rate Limit → DLP → Threat Detection        │  │
                    │  └────────────────────────────────────────────────────────┘  │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
                    │  │ Session  │  │ Router   │  │ Conn     │  │ Health      │  │
                    │  │ Manager  │  │ + LB     │  │ Pool     │  │ Check       │  │
                    │  └──────────┘  └──────────┘  └──────────┘  └─────────────┘  │
                    └──────────────────────────────────────────────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              ▼                             ▼                             ▼
    ┌──────────────────┐     ┌──────────────────┐          ┌──────────────────┐
    │  State Store     │     │  Audit Storage   │          │  Secret Vault    │
    │  (Redis/etcd/    │     │  (S3/ES/DB/      │          │  (Vault/KMS/     │
    │   PostgreSQL)    │     │   Local File)    │          │   Native)        │
    └──────────────────┘     └──────────────────┘          └──────────────────┘
```

### 3.2 核心设计原则

1. **Control Plane / Data Plane 分离** — C 核心处理 SSH 数据面 (极致性能)，Go/Rust 控制面负责管理、UI、策略分发
2. **零信任架构** — 默认拒绝，所有访问需验证身份 + 授权 + 审计
3. **可插拔后端** — 认证、存储、审计、密钥管理均支持多后端
4. **标准 SSH 兼容** — 不改变用户 SSH 工作流，无需安装客户端
5. **审计不可篡改** — 加密签名 + 追加写入 + 外部归档

---

## 四、功能路线图 — 分阶段详细设计

---

### Phase 1: 安全加固 & 企业基础 (MVP)

> 目标: 修补安全致命短板，达到企业可用最低标准

#### P1.1 TLS/HTTPS 支持

- [ ] Admin REST API 强制 HTTPS (TLS 1.2+)
- [ ] 支持自签名证书和 Let's Encrypt 自动续期
- [ ] mTLS 双向认证 (用于节点间通信)
- [ ] HSTS、证书固定支持

#### P1.2 LDAP 安全增强

- [ ] LDAPS (ldaps://) 支持
- [ ] StartTLS 升级支持
- [ ] LDAP 连接池与故障转移
- [ ] LDAP Group 成员查询 (用于自动角色映射)
- [ ] LDAP Attribute 提取 (部门、邮箱、manager 等)

#### P1.3 审计日志安全

- [ ] 审计日志 AES-256-GCM 加密
- [ ] HMAC-SHA256 日志完整性签名
- [ ] 追加写入保护 (append-only)
- [ ] 日志链式哈希 (blockchain-style，防止中间删除)
- [ ] 自动日志轮转与归档策略

#### P1.4 密钥与凭证安全

- [ ] 敏感字段加密存储 (密码哈希、TOTP secret、LDAP 密码)
- [ ] 运行时配置内存擦除
- [ ] 主密钥 (Master Key) 机制
- [ ] 环境变量 / 文件引用替代明文配置: `password_hash = ${env:ADMIN_PW_HASH}`
- [ ] 配置文件加密支持

#### P1.5 认证增强

- [ ] SSH 证书认证 (SSH CA 签名的短期证书)
- [ ] 密码复杂度策略 (长度、字符类别、历史密码检查)
- [ ] 账户锁定策略 (N 次失败后锁定 M 分钟)
- [ ] 密码过期与强制轮换
- [ ] 认证尝试暴力破解检测

#### P1.6 Admin API Token 安全

- [ ] 实际 Token 验证逻辑 (当前为 stub)
- [ ] JWT Token 签发与验证
- [ ] Token 作用域 (read-only / admin / super-admin)
- [ ] Token 过期与轮换
- [ ] API 审计日志 (谁在什么时间调用了什么 API)

---

### Phase 2: Web 管理界面 & 配置平台

> 目标: 提供可视化管理能力，降低运维门槛，对标 Teleport/StrongDM

#### P2.1 Web Dashboard (前端)

- [ ] **技术选型**: Vanilla HTML/CSS/JS — 零框架，Go html/template 服务端渲染 + 原生 JS 动态交互
- [ ] **实时仪表盘**
  - 活跃会话数、连接趋势图 (实时 WebSocket 推送)
  - 上游服务器健康状态拓扑图
  - 认证成功/失败统计、告警概览
  - 系统资源监控 (CPU/内存/连接数)
- [ ] **会话管理页面**
  - 活跃会话列表 (用户、来源IP、目标、时长、流量)
  - 实时会话监控 (Live View — 管理员实时观看用户终端)
  - 会话录像回放 (内嵌 asciinema-player)
  - 一键踢出会话
  - 会话搜索与过滤 (按用户/时间/IP/目标)
- [ ] **用户管理页面**
  - 用户 CRUD (创建/编辑/禁用/删除)
  - 角色分配与权限矩阵可视化
  - MFA 二维码生成与绑定
  - 用户登录历史与活动时间线
  - 批量导入/导出 (CSV/LDAP 同步)
- [ ] **上游服务器管理页面**
  - 服务器注册/编辑/删除
  - 健康状态实时指示灯
  - 连接池状态与统计
  - 一键启用/禁用/维护模式
  - 服务器标签与分组
- [ ] **路由与策略配置页面**
  - 可视化路由规则编辑器 (拖拽优先级排序)
  - 策略模板库 (只读用户/开发者/管理员/审计员)
  - 策略模拟器 (输入用户+目标，预览匹配结果)
  - 策略变更 Diff 对比与审批流
- [ ] **审计中心页面**
  - 审计事件时间线 (认证/连接/命令/传输)
  - 全文搜索 (命令内容搜索)
  - 录像回放播放器 (支持快进/搜索/标记)
  - 审计报告生成与导出 (PDF/CSV)
  - 合规仪表盘 (合规评分、未覆盖资源)

#### P2.2 Web API Gateway (后端)

- [ ] **技术选型**: Go 标准库 (net/http + html/template)，不引入 Gin/Echo 等框架
- [ ] html/template 服务端渲染页面 (SSR)，原生 JS fetch() 调用 API 实现动态交互
- [ ] RESTful API v2 (覆盖所有管理功能，JSON 响应)
- [ ] gRPC 内部通信接口 (Control Plane ↔ Data Plane)
- [ ] WebSocket 端点 (实时会话推送、Live View)
- [ ] OpenAPI 3.0 文档自动生成
- [ ] API 版本控制 (v1/v2/v3)
- [ ] 请求限流与防滥用
- [ ] 静态资源嵌入 (go:embed 打包 HTML/CSS/JS 为单二进制)

#### P2.3 配置管理平台

- [ ] Web 可视化配置编辑器 (替代手动编辑 INI)
- [ ] 配置版本控制 (每次变更自动保存历史)
- [ ] 配置 Diff 对比 (修改前 vs 修改后)
- [ ] 配置回滚 (一键恢复任意历史版本)
- [ ] 配置审批工作流 (变更需审批人确认)
- [ ] 配置同步 (多节点自动分发)
- [ ] 配置模板 (预设生产/测试/开发环境模板)
- [ ] 配置导入/导出 (INI/YAML/JSON 格式互转)

#### P2.4 Web Terminal (浏览器 SSH)

- [ ] 基于 xterm.js 的 Web 终端
- [ ] 通过 WebSocket 连接到 SSH Proxy
- [ ] 支持窗口大小自适应
- [ ] 复制粘贴支持
- [ ] 文件上传/下载 (Web 拖拽)
- [ ] 会话共享 (多人协作同一终端)
- [ ] 审计录像与 Web 终端同步

---

### Phase 3: 企业身份集成 & 零信任

> 目标: 对接企业 IdP 生态，实现零信任访问控制

#### P3.1 OIDC / OAuth 2.0 集成

- [ ] OIDC Discovery (/.well-known/openid-configuration)
- [ ] Authorization Code Flow + PKCE
- [ ] Token 验证 (JWT RS256/ES256)
- [ ] 支持 IdP: Okta, Azure AD, Google Workspace, Keycloak, Auth0
- [ ] 用户属性映射 (IdP claims → SSH Proxy 角色)
- [ ] Group 同步 (IdP Group → SSH 角色自动映射)
- [ ] SSO 登录 Web UI

#### P3.2 SAML 2.0 集成

- [ ] SP-Initiated SSO
- [ ] IdP-Initiated SSO
- [ ] SAML Assertion 解析与验证
- [ ] Attribute Statement → 角色映射
- [ ] 与 ADFS / Shibboleth / OneLogin 对接

#### P3.3 SSH Certificate Authority (SSH CA)

- [ ] 内置 SSH CA (签发短期用户证书)
- [ ] 证书签发 API
- [ ] 证书有效期策略 (例如 8 小时工作证书)
- [ ] 证书扩展字段 (force-command, source-address, permit-*)
- [ ] 主机证书签发 (零信任主机身份)
- [ ] 证书轮换与撤销列表 (CRL)
- [ ] 与 OIDC 联动: IdP 登录 → 自动签发 SSH 证书

#### P3.4 Just-In-Time (JIT) 访问

- [ ] 按需申请访问 (申请 → 审批 → 临时授权)
- [ ] 时间窗口授权 (例如允许 2 小时访问)
- [ ] 审批人通知 (邮件/Slack/钉钉/企业微信)
- [ ] 审批工作流 (多级审批、自动审批规则)
- [ ] 访问自动过期回收
- [ ] 紧急访问 (break-glass) 流程

#### P3.5 设备信任 & 上下文感知

- [ ] 客户端设备指纹采集 (SSH client 版本、OS 信息)
- [ ] 地理位置感知 (GeoIP → 异常登录地点告警)
- [ ] 时间窗口策略 (仅允许工作时间登录)
- [ ] 网络来源策略 (VPN/办公网络/公网 不同策略)
- [ ] 风险评分引擎 (多因子动态评估)

---

### Phase 4: 高可用 & 可扩展

> 目标: 支撑企业级大规模部署，满足 99.99% SLA

#### P4.1 集群模式

- [ ] 多节点部署 (Active-Active)
- [ ] 会话状态共享 (Redis / etcd / PostgreSQL 后端)
- [ ] 集群节点发现 (DNS / K8s Service / Consul)
- [ ] 配置中心化存储与自动分发
- [ ] 节点健康心跳与自动摘除
- [ ] 滚动升级 (零停机更新)

#### P4.2 会话持久化 & 故障转移

- [ ] 会话元数据持久化到数据库
- [ ] 会话录像实时写入对象存储 (S3/MinIO/OSS)
- [ ] 节点故障时活跃会话列表恢复
- [ ] 审计数据不丢失保证
- [ ] 跨 AZ / 跨 Region 部署

#### P4.3 负载均衡增强

- [ ] 一致性哈希 (Consistent Hashing) 负载均衡
- [ ] 加权路由 (按服务器容量)
- [ ] 地理就近路由 (Geo-routing)
- [ ] 连接亲和性 (同用户粘连同节点)
- [ ] 熔断器 (Circuit Breaker) 模式

#### P4.4 数据库存储层

- [ ] PostgreSQL 作为配置/用户/策略存储
- [ ] 审计数据存储 (PostgreSQL / ClickHouse / TimescaleDB)
- [ ] 数据库连接池与读写分离
- [ ] 数据迁移工具 (INI → DB、版本升级迁移)
- [ ] 数据备份与恢复策略

#### P4.5 Kubernetes 原生

- [ ] Helm Chart
- [ ] Operator (CRD 管理 Proxy 实例)
- [ ] K8s Service Account 认证
- [ ] 自动扩缩容 (HPA 基于连接数)
- [ ] 日志集成 (stdout/stderr → K8s logging)
- [ ] ConfigMap/Secret 自动挂载
- [ ] Pod 亲和性与拓扑分布

---

### Phase 5: 审计合规 & 安全增强

> 目标: 满足 SOC2/HIPAA/等保/PCI-DSS 合规审计要求

#### P5.1 合规报告引擎

- [ ] SOC 2 Type II 审计报告模板
- [ ] HIPAA 访问控制审计报告
- [ ] PCI-DSS 特权访问报告
- [ ] 等保 2.0 / 等保 3.0 审计报告
- [ ] GDPR 数据访问与删除报告
- [ ] 自定义报告模板 (SQL 查询 → PDF/CSV)
- [ ] 定时生成与邮件发送

#### P5.2 审计日志增强

- [ ] Syslog 转发 (RFC 5424 / CEF 格式)
- [ ] S3/MinIO/OSS 归档
- [ ] Elasticsearch / OpenSearch 索引
- [ ] Kafka / RabbitMQ 消息队列转发
- [ ] 审计日志保留策略 (时间/大小/合规要求)
- [ ] 审计日志搜索 API (全文检索)

#### P5.3 SIEM 集成

- [ ] Splunk HEC (HTTP Event Collector) 输出
- [ ] Datadog Logs 输出
- [ ] ELK Stack (Filebeat/Logstash) 输出
- [ ] Sumo Logic 输出
- [ ] QRadar SIEM 输出
- [ ] Wazuh 集成
- [ ] 通用 SIEM 输出 (CEF/LEEF 格式)

#### P5.4 威胁检测 & 异常分析

- [ ] 暴力破解检测 (N 次失败 → 自动封禁 IP)
- [ ] 异常登录时间检测
- [ ] 异常地理位置登录检测 (不可能旅行)
- [ ] 敏感命令检测 (rm -rf, chmod 777, cat /etc/shadow 等)
- [ ] 数据泄露检测 (大量下载、异常传输模式)
- [ ] 横向移动检测 (SSH 跳板行为分析)
- [ ] 自定义规则引擎 (DSL 或 Lua 脚本)
- [ ] 威胁评分与告警分级
- [ ] 自动响应 (封禁 IP、终止会话、通知管理员)

#### P5.5 数据防泄漏 (DLP)

- [ ] 文件传输白名单/黑名单 (按文件名、扩展名、路径)
- [ ] 文件大小限制
- [ ] 敏感内容检测 (正则匹配: 信用卡号、身份证、API Key)
- [ ] 传输审批流程 (敏感文件需审批)
- [ ] 剪贴板内容审计 (检测粘贴的敏感数据)

---

### Phase 6: 集成生态 & 开发者体验

> 目标: 构建开放的集成生态，提升开发者采用率

#### P6.1 Webhook 增强

- [ ] 事件种类扩展 (用户变更、策略变更、证书签发等)
- [ ] Webhook 签名验证 (HMAC-SHA256)
- [ ] 死信队列 (Dead Letter Queue)
- [ ] Webhook 调试控制台 (查看历史推送与重试)

#### P6.2 Terraform Provider

- [ ] SSH Proxy 资源管理 (用户/路由/策略/上游)
- [ ] 数据源 (读取当前配置)
- [ ] Import 支持 (导入已有资源)
- [ ] 完整文档与示例

#### P6.3 CLI 工具

- [ ] `sshproxy` CLI (Go 实现)
  - `sshproxy login` — OIDC 登录并获取 SSH 证书
  - `sshproxy ssh <target>` — 通过代理 SSH
  - `sshproxy scp <src> <dst>` — 通过代理 SCP
  - `sshproxy ls sessions` — 列出会话
  - `sshproxy ls servers` — 列出可访问服务器
  - `sshproxy play <session-id>` — 回放录像
  - `sshproxy config` — 查看/编辑配置
- [ ] SSH ProxyCommand 模式 (`~/.ssh/config` 无缝集成)
- [ ] Tab 自动补全 (Bash/Zsh/Fish)

#### P6.4 SDK & API

- [ ] Go SDK
- [ ] Python SDK
- [ ] REST API OpenAPI 3.0 规范
- [ ] gRPC Proto 文件发布
- [ ] API Playground (Swagger UI)
- [ ] Webhook 事件 JSON Schema

#### P6.5 ChatOps 集成

- [ ] Slack 通知与审批机器人
- [ ] 钉钉 / 企业微信 通知
- [ ] Microsoft Teams 集成
- [ ] PagerDuty / Opsgenie 告警
- [ ] 自定义通知模板

#### P6.6 资产发现 & 同步

- [ ] 云资产自动发现
  - AWS EC2 (Tag-based 过滤)
  - Azure VM
  - GCP Compute Engine
  - 阿里云 ECS
  - 腾讯云 CVM
- [ ] CMDB 集成 (ServiceNow / 自定义 API)
- [ ] Ansible Inventory 同步
- [ ] 定时同步与增量更新
- [ ] 自动注册/注销上游服务器

---

### Phase 7: 高级功能 & 差异化

> 目标: 构建竞品不具备的差异化能力

#### P7.1 智能命令控制

- [ ] 命令白名单/黑名单 (正则表达式)
- [ ] 危险命令拦截与二次确认
- [ ] 命令审批 (高危命令需管理员实时审批)
- [ ] 命令改写/替换 (自动添加 audit flag)
- [ ] 交互式命令授权 (管理员实时允许/拒绝)

#### P7.2 会话协作

- [ ] 多人会话共享 (管理员协助用户)
- [ ] 会话接管 (管理员接管用户终端)
- [ ] 会话聊天 (会话内文字交流)
- [ ] 四眼原则 (Four-Eyes: 操作需两人在场)
- [ ] 会话实时审计 (管理员实时监控所有终端)

#### P7.3 工作流自动化

- [ ] 定时任务 (Scheduled Jobs — 通过 SSH 执行)
- [ ] 批量命令执行 (选中多台服务器批量操作)
- [ ] 自动化脚本运行 (预定义脚本库)
- [ ] 执行结果收集与汇总
- [ ] 与 CI/CD 集成 (GitHub Actions / GitLab CI / Jenkins)

#### P7.4 SSH 网关高级能力

- [ ] SSH 跳板链 (Multi-hop Proxy)
- [ ] TCP 端口转发审计 (L/R/D 转发完整记录)
- [ ] SOCKS5 代理模式
- [ ] 自定义 SSH Subsystem
- [ ] SCP/SFTP 完整代理 (非 passthrough)
- [ ] X11 转发代理

#### P7.5 多协议扩展 (长期)

- [ ] RDP 代理 (远程桌面)
- [ ] VNC 代理
- [ ] 数据库代理 (MySQL/PostgreSQL/Redis)
- [ ] Kubernetes API 代理
- [ ] HTTP/HTTPS 代理

#### P7.6 AI / 智能运维

- [ ] 命令意图识别 (NLP 分析命令语义)
- [ ] 异常行为基线 (用户画像 → 偏差检测)
- [ ] 智能推荐 (推荐最小权限策略)
- [ ] 自然语言策略配置 ("允许运维团队在工作时间访问生产服务器")
- [ ] 审计日志智能摘要

---

## 五、非功能需求

### 5.1 性能指标

| 指标 | 目标值 |
|------|--------|
| 单节点并发会话 | ≥ 10,000 |
| 连接建立延迟 (P99) | ≤ 50ms |
| 数据转发吞吐量 | ≥ 1 Gbps |
| 认证延迟 (密码) | ≤ 100ms |
| 认证延迟 (LDAP) | ≤ 500ms |
| API 响应延迟 (P99) | ≤ 200ms |
| 内存占用 (空闲) | ≤ 50 MB |
| 内存占用 (万连接) | ≤ 2 GB |

### 5.2 可靠性指标

| 指标 | 目标值 |
|------|--------|
| 服务可用性 | 99.99% (集群模式) |
| 故障切换时间 | ≤ 5 秒 |
| 数据持久化 | 零丢失 (审计数据) |
| 配置热重载 | 零停机 |
| 滚动升级 | 零停机 |

### 5.3 安全指标

| 指标 | 目标值 |
|------|--------|
| 密码存储 | bcrypt/scrypt/argon2 |
| 传输加密 | TLS 1.2+ (Admin API)、SSH (数据面) |
| 审计日志完整性 | HMAC-SHA256 签名 |
| 密钥最小长度 | RSA-4096 / Ed25519 |
| 会话录像加密 | AES-256-GCM |
| TOTP 算法 | HMAC-SHA1/SHA256 (RFC 6238) |

### 5.4 兼容性

| 类别 | 支持范围 |
|------|----------|
| SSH 协议版本 | SSH 2.0 |
| 操作系统 | Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS Stream 8+, Alpine 3.16+ |
| 容器 | Docker, Podman, containerd |
| 编排 | Kubernetes 1.24+, Docker Compose, Nomad |
| CPU 架构 | x86_64, aarch64 (ARM64) |
| SSH 客户端 | OpenSSH 7.4+, PuTTY 0.78+, Bitvise, MobaXterm |

---

## 六、技术选型建议

| 组件 | 推荐技术 | 理由 |
|------|----------|------|
| **Data Plane (核心代理)** | C (现有) | 极致性能，已有成熟实现 |
| **Control Plane (管理服务)** | Go 标准库 (net/http + html/template) | 零框架、单二进制、go:embed 打包前端资源 |
| **Web 前端** | Vanilla HTML/CSS/JS + Go html/template (SSR) | 零框架依赖、单二进制部署 (go:embed)、无 Node.js 构建链 |
| **Web 终端** | xterm.js + WebSocket (唯一 JS 依赖，CDN 或 vendor) | 业界标准、Teleport/Boundary 同款 |
| **录像回放** | asciinema-player (vendor 嵌入) | 已有 asciicast 格式兼容 |
| **数据库** | PostgreSQL | 可靠性、JSON 支持、扩展性 |
| **缓存/状态** | Redis | 会话共享、分布式锁、Pub/Sub |
| **消息队列** | NATS / Redis Streams | 轻量、嵌入式友好 |
| **对象存储** | S3 / MinIO | 录像/日志归档 |
| **配置分发** | etcd | 强一致、Watch 机制 |
| **Kubernetes** | Helm + Operator SDK | 标准化部署 |
| **CI/CD** | GitHub Actions | 已有基础 |
| **API 文档** | OpenAPI 3.0 + Swagger UI | 行业标准 |
| **IaC** | Terraform Provider (Go) | 基础设施即代码 |

---

## 七、商业模式 & 版本规划

### 7.1 版本矩阵

| 功能 | Community (开源) | Professional | Enterprise |
|------|-------------------|-------------|------------|
| SSH 代理核心 | ✅ | ✅ | ✅ |
| Filter Chain 全部过滤器 | ✅ | ✅ | ✅ |
| CLI 工具 | ✅ | ✅ | ✅ |
| 本地审计日志 | ✅ | ✅ | ✅ |
| Prometheus 指标 | ✅ | ✅ | ✅ |
| Web UI 管理界面 | ❌ | ✅ | ✅ |
| Web Terminal (浏览器 SSH) | ❌ | ✅ | ✅ |
| 录像回放 (Web) | ❌ | ✅ | ✅ |
| OIDC/SAML 集成 | ❌ | ✅ | ✅ |
| SSH 证书认证 (CA) | ❌ | ✅ | ✅ |
| SIEM 集成 | ❌ | ✅ | ✅ |
| 合规报告 | ❌ | ❌ | ✅ |
| 多节点集群 (HA) | ❌ | ❌ | ✅ |
| JIT 访问审批 | ❌ | ❌ | ✅ |
| 威胁检测 & DLP | ❌ | ❌ | ✅ |
| 多租户 | ❌ | ❌ | ✅ |
| 会话协作 & 接管 | ❌ | ❌ | ✅ |
| 资产自动发现 | ❌ | ❌ | ✅ |
| Terraform Provider | ❌ | ❌ | ✅ |
| SLA 保障 | ❌ | Email | 24/7 + SLA |
| 并发会话上限 | 50 | 1,000 | 无限制 |
| 代理节点数 | 1 | 3 | 无限制 |

### 7.2 定价参考

| 版本 | 月费 | 年费 |
|------|------|------|
| **Community** | 免费 (GPL-3.0) | 免费 |
| **Professional** | ¥3,000 / 部署 | ¥30,000 / 部署 |
| **Enterprise** | ¥15,000 / 部署 | ¥150,000 / 部署 |
| **SaaS 托管版** | ¥8,000 / 月 | ¥80,000 / 年 |

---

## 八、里程碑时间线

```
Phase 1: 安全加固 & 企业基础          ████████░░░░░░░░░░░░░░░░
Phase 2: Web 管理界面 & 配置平台      ░░░░████████████░░░░░░░░
Phase 3: 企业身份集成 & 零信任        ░░░░░░░░████████░░░░░░░░
Phase 4: 高可用 & 可扩展              ░░░░░░░░░░░░████████░░░░
Phase 5: 审计合规 & 安全增强          ░░░░░░░░░░░░░░░░████████
Phase 6: 集成生态 & 开发者体验        ░░░░░░░░░░░░░░░░░░░░████
Phase 7: 高级功能 & 差异化            ░░░░░░░░░░░░░░░░░░░░████
```

| 里程碑 | 版本 | 关键交付物 |
|--------|------|-----------|
| **M1** | v0.4.0 | TLS 支持、LDAPS、审计加密、认证加固、Token 验证 |
| **M2** | v0.5.0 | Web Dashboard MVP、实时会话管理、录像回放 |
| **M3** | v1.0.0 | OIDC/SAML、SSH CA、JIT 访问、**商业版首发** |
| **M4** | v1.1.0 | 集群模式、PostgreSQL 后端、K8s Helm Chart |
| **M5** | v1.2.0 | 合规报告、SIEM 集成、威胁检测 |
| **M6** | v1.3.0 | Terraform Provider、CLI 工具、资产发现 |
| **M7** | v2.0.0 | 多协议扩展、AI 分析、会话协作 |

---

## 九、关键成功因素

1. **Web UI 是第一优先级** — 这是与开源方案的最大差异化，也是客户愿意付费的核心原因
2. **标准 SSH 兼容** — 不改变用户习惯是关键优势，不要为了功能牺牲兼容性
3. **开源核心 + 商业增强** — 借助开源社区获取用户，商业版提供企业功能
4. **合规是付费门槛** — SOC2/等保报告是企业客户的硬性需求，也是高利润来源
5. **集成能力决定壁垒** — IdP、SIEM、Cloud、IaC 集成越多，替换成本越高
6. **性能是核心差异** — C 核心的性能优势是对标 Go/Rust 竞品的护城河

---

## 十、风险与缓解

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| Control Plane (Go) 与 Data Plane (C) 集成复杂度 | 高 | 高 | 定义清晰 gRPC 接口、充分集成测试 |
| Web UI 开发周期超预期 | 高 | 中 | 使用成熟 UI 框架、优先实现核心页面 |
| 开源竞品 (Teleport) 功能追赶 | 中 | 高 | 保持轻量差异化、聚焦性能与易用性 |
| GPL-3.0 许可证限制商业化 | 中 | 高 | 考虑 AGPL 或双许可 (GPL + 商业) |
| C 代码安全漏洞 | 中 | 高 | AddressSanitizer、模糊测试、安全审计 |
| 单人/小团队开发瓶颈 | 高 | 中 | 优先 Phase 1-2、招募开源贡献者 |

---

> **文档版本**: v1.0
> **最后更新**: 2026-04-07
> **适用范围**: SSH Proxy Core 从 Demo 到商业产品的完整路线图
