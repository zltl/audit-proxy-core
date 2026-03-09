# SSH Proxy Core

高性能、可扩展的 SSH 协议代理服务器核心库，纯 C 语言实现。

[English](README_EN.md)

## 特性

- **代理转发**: 透明代理和显式代理，支持多后端路由
- **过滤器链**: Envoy 风格的可扩展过滤器架构
  - Auth Filter: 用户认证 (Password, PublicKey)
  - RBAC Filter: 基于角色的访问控制
  - Audit Filter: 会话审计和录像 (asciicast 格式)
  - Rate Limit Filter: 连接速率和并发限制
- **会话管理**: 完整的 SSH 会话生命周期管理
- **路由与负载均衡**: 支持 Round-Robin、Random、最少连接、Hash 策略
- **健康检查**: 自动检测后端服务器健康状态

## 快速上手

### 1. 安装与构建

```bash
# 安装依赖
sudo apt update && sudo apt install -y build-essential libssh-dev

# 构建
make

# 生成主机密钥 (首次运行需要)
ssh-keygen -t rsa -f /tmp/ssh_proxy_host_key -N ""
```

### 2. 配置文件

创建配置文件 `/etc/ssh-proxy/config.ini`（或使用项目根目录的 `config.ini`）：

```ini
[server]
bind_addr = 0.0.0.0          # 监听地址
port = 2222                   # 监听端口
host_key = /etc/ssh-proxy/host_key   # 主机密钥路径

[logging]
level = info                  # 日志级别: debug, info, warn, error
audit_dir = /var/log/ssh-proxy/audit # 审计日志和录像目录

[limits]
max_sessions = 1000           # 最大并发会话数
session_timeout = 3600        # 会话超时 (秒)
auth_timeout = 60             # 认证超时 (秒)

# 添加用户 - 密码使用 openssl passwd -6 生成
[user:admin]
password_hash = $6$saltsalt$...      # openssl passwd -6 -salt saltsalt 'yourpassword'
pubkey = ssh-rsa AAAA... user@host   # 可选：公钥认证
enabled = true

# 路由配置 - 将代理用户映射到上游服务器
[route:admin]
upstream = prod.example.com   # 上游服务器地址
port = 22                     # 上游端口
user = root                   # 上游用户名
privkey = /etc/ssh-proxy/keys/admin.key  # 连接上游的私钥

# 通配符路由
[route:dev-*]                 # 匹配 dev-alice, dev-bob 等
upstream = dev.example.com
user = developer

# 默认路由
[route:*]
upstream = bastion.example.com
user = guest

# ============ 功能策略控制 ============
# 控制用户可以使用的 SSH 功能
# 格式: [policy:用户名] 或 [policy:用户名@上游服务器]

# 管理员 - 允许所有功能
[policy:admin]
allow = all

# 开发者 - 允许 shell、git、下载，禁止上传和端口转发
[policy:dev-*]
allow = shell, exec, git, download, sftp_list
deny = upload, port_forward

# 只读用户 - 只能下载，不能上传
[policy:readonly-*]
allow = shell, download, sftp_list
deny = upload, scp_upload, sftp_upload, rsync_upload, git_push, exec

# Git 用户 - 只能 git 操作
[policy:git-*]
allow = git_pull, git_push
deny = shell, exec, scp, sftp, rsync, port_forward

# 受限用户 - 只能 shell，禁止所有文件传输和端口转发
[policy:restricted-*]
allow = shell
deny = scp, sftp, rsync, port_forward, git, exec

# ============ 针对特定上游服务器的策略 ============
# 格式: [policy:用户名@上游服务器模式]

# 任何用户访问生产服务器 - 只读
[policy:*@prod.example.com]
allow = shell, download, sftp_list
deny = upload, exec, git_push, sftp_delete

# 管理员访问生产服务器 - 允许所有 (覆盖上面的通用规则)
[policy:admin@prod.example.com]
allow = all

# 开发者访问开发服务器 - 允许上传
[policy:dev-*@dev.example.com]
allow = shell, exec, scp, sftp, git
deny = port_forward

# 任何用户访问数据库服务器 - 禁止端口转发
[policy:*@*db*]
allow = shell, exec
deny = scp, sftp, rsync, port_forward, git
```

### 功能策略说明

策略通过 `[policy:用户名模式]` 或 `[policy:用户名模式@上游服务器模式]` 段配置。

**匹配优先级**（从高到低）：
1. 精确用户 + 精确上游服务器
2. 精确用户 + 通配符上游服务器
3. 精确用户（无上游限制）
4. 通配符用户 + 精确上游服务器
5. 通配符用户 + 通配符上游服务器
6. 通配符用户（无上游限制）

支持以下功能标识：

| 功能标识 | 说明 |
|----------|------|
| `shell` | 交互式 Shell |
| `exec` | 远程命令执行 |
| `scp` | SCP 上传和下载 |
| `scp_upload` | SCP 上传 |
| `scp_download` | SCP 下载 |
| `sftp` | SFTP 所有操作 |
| `sftp_upload` | SFTP 上传 |
| `sftp_download` | SFTP 下载 |
| `sftp_list` | SFTP 目录列表 |
| `sftp_delete` | SFTP 删除/重命名 |
| `rsync` | rsync 上传和下载 |
| `rsync_upload` | rsync 上传 |
| `rsync_download` | rsync 下载 |
| `port_forward` | 所有端口转发 |
| `local-forward` | 本地端口转发 (-L) |
| `remote-forward` | 远程端口转发 (-R) |
| `dynamic-forward` | 动态端口转发 (-D) |
| `x11` | X11 转发 |
| `agent` | SSH Agent 转发 |
| `git` | 所有 Git 操作 |
| `git_push` | git push |
| `git_pull` | git pull/fetch/clone |
| `upload` | 所有上传 (scp/sftp/rsync) |
| `download` | 所有下载 (scp/sftp/rsync) |
| `all` | 所有功能 |
| `none` | 禁止所有 |

### 3. 启动服务

```bash
# 使用默认配置启动
./build/bin/ssh-proxy-core

# 指定配置文件
./build/bin/ssh-proxy-core -c /etc/ssh-proxy/config.ini

# 调试模式 (详细日志输出)
./build/bin/ssh-proxy-core -d

# 查看所有选项
./build/bin/ssh-proxy-core --help
```

### 4. 连接测试

```bash
# 通过代理连接
ssh -p 2222 admin@proxy-server

# 指定目标服务器 (透明代理模式)
ssh -p 2222 admin@target-server -o ProxyJump=proxy-server
```

## 日志与审计

### 日志位置

| 类型 | 默认路径 | 说明 |
|------|----------|------|
| 审计事件日志 | `{audit_dir}/audit_YYYYMMDD.log` | JSON 格式的连接/认证/断开事件 |
| 会话录像 | `{audit_dir}/session_{id}_{datetime}.cast` | asciicast v2 格式的终端录像 |
| 文件传输日志 | `{audit_dir}/transfers_YYYYMMDD.log` | 文件传输记录 (SCP/SFTP/rsync) |
| 端口转发日志 | `{audit_dir}/port_forwards_YYYYMMDD.log` | 端口转发请求记录 |
| 运行日志 | stdout/stderr | 服务运行时日志 |

默认 `audit_dir` 为 `/tmp/ssh_proxy_audit`，可在配置文件 `[logging]` 段的 `audit_dir` 中修改。

### 审计日志格式

审计事件日志为 JSON 格式，每行一个事件：

```json
{"timestamp":1704412800,"type":"AUTH_SUCCESS","session_id":12345,"username":"admin","client_addr":"192.168.1.100"}
{"timestamp":1704412801,"type":"SESSION_START","session_id":12345,"username":"admin","target":"prod.example.com"}
{"timestamp":1704413400,"type":"SESSION_END","session_id":12345,"username":"admin"}
```

### 文件传输日志

文件传输日志记录所有通过代理的文件传输操作：

```json
{"timestamp":1704412900,"session":12345,"user":"admin","event":"start","direction":"upload","protocol":"scp","path":"/home/user/file.txt","size":1024,"transferred":0}
{"timestamp":1704412901,"session":12345,"user":"admin","event":"complete","direction":"upload","protocol":"scp","path":"/home/user/file.txt","size":1024,"transferred":1024,"checksum":"a1b2c3..."}
{"timestamp":1704412950,"session":12346,"user":"dev","event":"denied","direction":"upload","protocol":"sftp","path":"/etc/passwd","size":0,"transferred":0}
```

| 字段 | 说明 |
|------|------|
| `event` | `start`/`complete`/`failed`/`denied` |
| `direction` | `upload`/`download` |
| `protocol` | `scp`/`sftp`/`rsync`/`git` |
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

会话录像使用 [asciicast v2](https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md) 格式，可以用以下方式播放：

#### 方法 1: 使用 asciinema 播放

```bash
# 安装 asciinema
sudo apt install asciinema
# 或
pip install asciinema

# 播放录像
asciinema play /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast

# 以 2 倍速播放
asciinema play -s 2 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast

# 限制空闲时间 (最多暂停 2 秒)
asciinema play -i 2 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast
```

#### 方法 2: 使用 asciinema-player (Web)

```bash
# 启动简单 HTTP 服务器
cd /tmp/ssh_proxy_audit
python3 -m http.server 8000
```

然后创建 HTML 页面嵌入播放器：

```html
<html>
<head>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/asciinema-player@3.0.1/dist/bundle/asciinema-player.css" />
</head>
<body>
  <div id="player"></div>
  <script src="https://unpkg.com/asciinema-player@3.0.1/dist/bundle/asciinema-player.min.js"></script>
  <script>
    AsciinemaPlayer.create('http://localhost:8000/session_12345_20250105_120000.cast', document.getElementById('player'));
  </script>
</body>
</html>
```

#### 方法 3: 直接查看原始内容

```bash
# 查看录像头部信息
head -1 /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast | jq

# 查看所有帧
cat /tmp/ssh_proxy_audit/session_12345_20250105_120000.cast
```

`.cast` 文件格式：
- 第一行：JSON 头部（版本、终端尺寸、时间戳等）
- 后续行：`[时间偏移, "o"或"i", "数据"]` 格式的事件帧
  - `"o"` = 输出 (从服务器到客户端)
  - `"i"` = 输入 (从客户端到服务器)

## 架构

```
┌─────────────┐     ┌─────────────────────────────────────┐     ┌──────────────┐
│   Client    │────▶│           SSH Proxy Core            │────▶│   Upstream   │
└─────────────┘     │  ┌─────────────────────────────┐    │     └──────────────┘
                    │  │       Filter Chain          │    │
                    │  │ ┌────────┬────────┬───────┐ │    │
                    │  │ │  Auth  │  RBAC  │ Audit │ │    │
                    │  │ └────────┴────────┴───────┘ │    │
                    │  └─────────────────────────────┘    │
                    │  ┌────────────┐  ┌──────────────┐   │
                    │  │  Session   │  │    Router    │   │
                    │  │  Manager   │  │ (Load Balancer)│ │
                    │  └────────────┘  └──────────────┘   │
                    └─────────────────────────────────────┘
```

## 项目结构

```
ssh-proxy-core/
├── src/              # 源文件 (.c)
│   ├── main.c            # 主入口
│   ├── ssh_server.c      # SSH 服务器
│   ├── session.c         # 会话管理器
│   ├── filter.c          # 过滤器链
│   ├── router.c          # 路由器
│   ├── config.c          # 配置文件加载
│   ├── auth_filter.c     # 认证过滤器
│   ├── rbac_filter.c     # RBAC 过滤器
│   ├── audit_filter.c    # 审计过滤器
│   └── rate_limit_filter.c # 速率限制
├── include/          # 头文件 (.h)
├── tests/            # 测试文件 (.c)
├── lib/              # 第三方库
├── docs/             # 文档
│   ├── DESIGN.md         # 设计文档
│   └── config.example.ini # 配置文件示例
├── scripts/          # 构建和工具脚本
├── build/            # 构建输出目录
├── Makefile          # 构建配置
└── README.md         # 本文件
```

## 构建

### 依赖

- GCC (支持 C11)
- Make
- libssh (>= 0.9.0) - SSH 协议库
- pthread - 线程支持
- crypt - 密码哈希
- (可选) clang-format - 代码格式化
- (可选) cppcheck - 静态分析

### 安装依赖 (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libssh-dev
```

### 从源码安装 libssh

如果系统包管理器中没有 libssh 或版本过旧，可以从源码安装：

```bash
./scripts/install-libssh.sh
```

### 构建命令

```bash
# 调试构建 (默认)
make

# 发布构建
make release

# 构建静态库
make lib

# 清理
make clean
```

### 运行测试

```bash
make test
```

### 配置文件

SSH Proxy Core 支持通过 INI 格式的配置文件管理用户认证和路由映射。

配置文件示例见 `docs/config.example.ini`。

#### 配置文件格式

```ini
# 服务器配置
[server]
bind_addr = 0.0.0.0
port = 2222
host_key = /etc/ssh-proxy/host_key

# 日志配置
[logging]
level = info
audit_dir = /var/log/ssh-proxy/audit

# 连接限制
[limits]
max_sessions = 1000
session_timeout = 3600
auth_timeout = 60

# 用户配置 (用户名在冒号后)
[user:admin]
password_hash = $6$saltsalt$...  # 使用 openssl passwd -6 生成
pubkey = ssh-rsa AAAA... admin@example.com
enabled = true

# 用户到上游服务器的路由映射
# 格式: [route:proxy_user_pattern]  支持 glob 模式 (*, ?)
[route:admin]
upstream = prod.example.com
port = 22
user = root                      # 上游服务器的用户名
privkey = /etc/ssh-proxy/keys/admin.key

[route:dev-*]
upstream = dev.example.com
user = developer
privkey = /etc/ssh-proxy/keys/dev.key

# 默认路由 (catch-all)
[route:*]
upstream = bastion.example.com
user = guest
```

#### 编程方式使用配置

```c
#include "config.h"

// 从文件加载配置
proxy_config_t *config = config_load("/etc/ssh-proxy/config.ini");

// 查找用户认证信息
config_user_t *user = config_find_user(config, "admin");
if (user != NULL) {
    // 使用 user->password_hash 或 user->pubkeys 进行认证
}

// 查找用户路由 (用于确定上游服务器和认证方式)
config_route_t *route = config_find_route(config, "dev-alice");
if (route != NULL) {
    // route->upstream_host  - 上游服务器地址
    // route->upstream_port  - 上游服务器端口
    // route->upstream_user  - 上游服务器用户名
    // route->privkey_path   - 连接上游的私钥路径
}

// 重载配置
config_reload(config, "/etc/ssh-proxy/config.ini");

// 清理
config_destroy(config);
```

## 使用

### 运行代理服务器

```bash
# 运行 (默认端口 2222)
./build/bin/ssh-proxy-core

# 指定端口
./build/bin/ssh-proxy-core -p 2223

# 调试模式
./build/bin/ssh-proxy-core -d

# 指定主机密钥
./build/bin/ssh-proxy-core -k /path/to/host_key

# 查看帮助
./build/bin/ssh-proxy-core --help
```

### 嵌入式使用

```c
#include "session.h"
#include "filter.h"
#include "router.h"

// 创建会话管理器
session_manager_config_t sm_cfg = {
    .max_sessions = 1000,
    .session_timeout = 3600,
    .auth_timeout = 60
};
session_manager_t *session_mgr = session_manager_create(&sm_cfg);

// 创建过滤器链
filter_chain_t *filters = filter_chain_create();

// 添加认证过滤器
auth_filter_config_t auth_cfg = {
    .backend = AUTH_BACKEND_CALLBACK,
    .allow_password = true,
    .password_cb = my_auth_callback,
    .cb_user_data = my_context
};
filter_chain_add(filters, auth_filter_create(&auth_cfg));

// 创建路由器
router_config_t router_cfg = {
    .lb_policy = LB_POLICY_ROUND_ROBIN,
    .connect_timeout_ms = 10000
};
router_t *router = router_create(&router_cfg);

// 添加上游服务器
upstream_config_t upstream = { .port = 22, .enabled = true };
strcpy(upstream.host, "backend.example.com");
router_add_upstream(router, &upstream);
```

## API 参考

### 会话管理器 (session.h)

```c
session_manager_t *session_manager_create(const session_manager_config_t *config);
void session_manager_destroy(session_manager_t *manager);
session_t *session_manager_create_session(session_manager_t *manager, ssh_session client);
void session_manager_remove_session(session_manager_t *manager, session_t *session);
size_t session_manager_cleanup(session_manager_t *manager);
```

### 过滤器链 (filter.h)

```c
filter_chain_t *filter_chain_create(void);
void filter_chain_destroy(filter_chain_t *chain);
int filter_chain_add(filter_chain_t *chain, filter_t *filter);
filter_status_t filter_chain_on_connect(filter_chain_t *chain, filter_context_t *ctx);
filter_status_t filter_chain_on_auth(filter_chain_t *chain, filter_context_t *ctx);
```

### 路由器 (router.h)

```c
router_t *router_create(const router_config_t *config);
void router_destroy(router_t *router);
int router_add_upstream(router_t *router, const upstream_config_t *config);
int router_resolve(router_t *router, const char *username, const char *target, route_result_t *result);
ssh_session router_connect(router_t *router, route_result_t *result, uint32_t timeout_ms);
```

## 开发

### 添加自定义过滤器

```c
// 定义回调函数
static filter_status_t my_on_connect(filter_t *filter, filter_context_t *ctx) {
    LOG_INFO("Custom filter: new connection");
    return FILTER_CONTINUE;  // 或 FILTER_REJECT
}

// 创建过滤器
filter_callbacks_t callbacks = {
    .on_connect = my_on_connect,
    .on_auth = my_on_auth,
    .on_close = my_on_close
};
filter_t *my_filter = filter_create("my_filter", FILTER_TYPE_CUSTOM, &callbacks, config);

// 添加到链
filter_chain_add(chain, my_filter);
```

### 调试

```bash
# 调试构建
make debug

# 使用 GDB
gdb ./build/bin/ssh-proxy-core
```

### 代码质量

```bash
# 格式化代码
make format

# 静态分析
make check
```

### Make 目标

| 目标 | 说明 |
|------|------|
| `all` | 构建项目 (默认) |
| `debug` | 调试构建 |
| `release` | 发布构建 |
| `lib` | 构建静态库 |
| `test` | 运行测试 |
| `run` | 构建并运行 |
| `clean` | 清理构建 |
| `install` | 安装到系统 |
| `format` | 格式化代码 |
| `check` | 静态分析 |
| `help` | 显示帮助 |

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可证。详见 [LICENSE](LICENSE) 文件。
