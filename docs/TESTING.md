# SSH Proxy Core - 测试流程文档

## 概述

本文档描述了 SSH Proxy Core 项目的完整测试流程。项目包含两个测试套件：

| 测试套件 | 语言 | 测试数量 | 运行命令 |
|---------|------|---------|---------|
| C 数据面单元测试 | C | 188+ | `make test` |
| Go 控制面单元测试 | Go | 466+ | `go test ./... -count=1` |

## 快速测试

```bash
# C 数据面 — 运行全部测试 (188+)
make test

# C 数据面 — TLS 变体
make clean && make TLS_ENABLED=1 test

# Go 控制面 — 运行全部测试 (466+)
go test ./... -count=1

# 只运行 C 集成测试
./build/bin/test_integration
```

## 测试套件

### 1. 单元测试

| 测试文件 | 测试内容 |
|---------|---------|
| `test_logger.c` | 日志系统初始化、级别过滤、格式化输出 |
| `test_ssh_proxy.c` | 代理核心 API（创建、启动、停止） |
| `test_ssh_server.c` | SSH 服务器（创建、密钥生成） |
| `test_session.c` | 会话管理器（创建、状态转换、超时） |
| `test_filter.c` | 过滤器链（添加、处理、回调） |
| `test_router.c` | 路由器（上游管理、规则匹配、负载均衡） |

### 2. 集成测试

`test_integration.c` 包含以下测试场景：

#### 核心工作流测试
- **test_complete_workflow**: 验证完整的组件集成
  - 创建会话管理器
  - 创建过滤器链
  - 创建路由器并添加上游
  - 路由解析

#### 过滤器链测试
- **test_filter_chain_workflow**: 验证多过滤器处理
  - 添加 3 个过滤器
  - 验证 on_connect 调用 3 次
  - 验证 on_auth 调用 3 次
  - 验证 on_close 调用 3 次

- **test_filter_rejection**: 验证拒绝流程
  - 过滤器返回 FILTER_REJECT
  - 连接被正确拒绝

#### 认证测试
- **test_auth_filter_workflow**: 验证认证回调
  - 正确密码：AUTH SUCCESS
  - 错误密码：AUTH FAILED

#### RBAC 测试
- **test_rbac_workflow**: 验证角色访问控制
  - 创建角色（admin, developer）
  - 添加权限规则
  - 分配用户角色
  - 验证访问控制：
    - admin-john → prod-server1: ALLOW
    - dev-alice → dev-server1: ALLOW
    - dev-alice → prod-server1: DENY
    - unknown-user → any-server: DENY

#### 速率限制测试
- **test_rate_limit_workflow**: 验证连接限制
  - 配置：max_conn=5, rate=3/s
  - 前 3 个连接：ALLOW
  - 第 4 个连接：THROTTLE（超过速率）
  - 等待 2 秒后：ALLOW（速率重置）

#### 路由器测试
- **test_router_load_balancing**: 验证负载均衡
  - Round-Robin 轮询：A → B → C → A → B

- **test_router_with_rules**: 验证路由规则
  - admin-john → prod-cluster（匹配规则）
  - qa-alice → staging-cluster（匹配规则）
  - dev-bob → dev-cluster（匹配规则）
  - guest → LB 回退

- **test_glob_patterns**: 验证模式匹配
  - IP 模式：192.168.*.*
  - 用户名模式：admin*
  - 主机模式：*.example.com

## 测试输出示例

```
╔═══════════════════════════════════════════════════════════════╗
║           SSH Proxy Core - Integration Tests                   ║
╚═══════════════════════════════════════════════════════════════╝

▶ Core Workflow Tests
─────────────────────────────────────────────────────────────────
Running test_complete_workflow...
    [1] Session Manager created
    [2] Filter Chain created
    [3] Router created with 2 upstreams
    [4] Route resolved to: server1.example.com
  PASS

▶ Filter Chain Tests
─────────────────────────────────────────────────────────────────
Running test_filter_chain_workflow...
    Added 3 filters to chain
    on_connect: called 3 times
    on_auth: called 3 times
    on_close: called 3 times
  PASS

▶ RBAC Tests
─────────────────────────────────────────────────────────────────
Running test_rbac_workflow...
    Added roles: admin, developer
    admin-john -> prod-server1: ALLOW (correct)
    dev-alice -> dev-server1: ALLOW (correct)
    dev-alice -> prod-server1: DENY (correct)
  PASS

═════════════════════════════════════════════════════════════════
✓ All integration tests passed!
═════════════════════════════════════════════════════════════════
```

## 手动测试

### 1. 启动代理服务器

```bash
# 编译
make

# 调试模式启动（端口 2222）
./build/bin/ssh-proxy-core -d

# 指定端口
./build/bin/ssh-proxy-core -p 2223 -d
```

### 2. 测试连接

```bash
# 从另一个终端连接代理
ssh -p 2222 testuser@localhost

# 查看审计日志
cat /tmp/ssh_proxy_audit/audit_*.log
```

### 3. 验证过滤器

当前实现中，连接后会进行完整的 SSH 握手和认证。认证成功后，代理会将连接转发到上游服务器。日志输出会显示：

```
INFO  main.c: New connection accepted
DEBUG proxy_handler.c: SSH handshake completed
INFO  auth_filter.c: Auth success for user 'test'
DEBUG proxy_handler.c: Connected to upstream 127.0.0.1:22
```

## 测试覆盖矩阵

| 组件 | 创建/销毁 | 基本功能 | 边界条件 | NULL 处理 | 并发安全 |
|------|----------|---------|---------|----------|---------|
| Session Manager | ✓ | ✓ | ✓ | ✓ | ✓ |
| Filter Chain | ✓ | ✓ | ✓ | ✓ | - |
| Auth Filter | ✓ | ✓ | ✓ | ✓ | - |
| RBAC Filter | ✓ | ✓ | ✓ | ✓ | - |
| Audit Filter | ✓ | ✓ | - | ✓ | - |
| Rate Limit | ✓ | ✓ | ✓ | ✓ | ✓ |
| Router | ✓ | ✓ | ✓ | ✓ | - |

## 添加新测试

### 添加 C 单元测试

1. 在 `tests/` 创建 `test_<component>.c`
2. 包含 `test_utils.h`
3. 使用 `TEST_START()`, `ASSERT_*`, `TEST_PASS()` 宏
4. 运行 `make test`

示例：

```c
#include "test_utils.h"
#include "my_component.h"

static int test_my_feature(void)
{
    TEST_START();

    my_component_t *c = my_component_create();
    ASSERT_NOT_NULL(c);
    ASSERT_EQ(my_component_do_something(c), 0);

    my_component_destroy(c);
    TEST_PASS();
}

int main(void)
{
    int failed = 0;
    failed += test_my_feature();
    return failed;
}
```

### 添加 Go 控制面测试

1. 在对应源文件同目录创建 `<module>_test.go`
2. 使用标准 `testing` 包
3. 使用 `httptest.NewServer` 测试 HTTP 处理器
4. 运行 `go test ./... -count=1`

示例：

```go
package api

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestMyHandler(t *testing.T) {
    api := &API{} // 初始化所需的最小 API 状态
    mux := http.NewServeMux()
    api.registerMyRoutes(mux)

    srv := httptest.NewServer(mux)
    defer srv.Close()

    resp, err := http.Get(srv.URL + "/api/v2/my-resource")
    if err != nil {
        t.Fatal(err)
    }
    if resp.StatusCode != http.StatusOK {
        t.Fatalf("expected 200, got %d", resp.StatusCode)
    }
}
```

### 添加集成测试

在 `test_integration.c` 中添加测试函数，并在 `main()` 中调用。

---

## Go 控制面测试套件

Go 控制面测试覆盖 466+ 个测试用例，分布在以下包中：

| 包 | 测试范围 |
|----|---------|
| `internal/api` | 所有 REST API 处理器、自动化、网关、洞察 |
| `internal/server` | 服务器启动、路由注册、页面渲染 |
| `internal/config` | 配置解析与校验 |
| `internal/cluster` | 集群发现与成员管理 |

### 运行 Go 测试

```bash
# 运行全部 Go 测试
go test ./... -count=1

# 运行特定包的测试
go test ./internal/api/... -count=1

# 详细输出
go test ./internal/api/... -count=1 -v

# 运行匹配模式的测试
go test ./internal/api/... -count=1 -run TestAutomation
```

### Go 控制面测试覆盖矩阵

| 模块 | CRUD | 业务逻辑 | 错误处理 | 端到端 |
|------|------|---------|---------|--------|
| Automation (脚本/作业/运行) | ✓ | ✓ | ✓ | ✓ |
| Gateway (TCP/SOCKS5) | ✓ | ✓ | ✓ | ✓ |
| Insights (意图/异常/策略) | ✓ | ✓ | ✓ | ✓ |
| Sessions | ✓ | ✓ | ✓ | ✓ |
| Users | ✓ | ✓ | ✓ | ✓ |
| Servers | ✓ | ✓ | ✓ | ✓ |
| Cluster | ✓ | ✓ | ✓ | - |
| Discovery | ✓ | ✓ | ✓ | ✓ |
| SSH CA | ✓ | ✓ | ✓ | ✓ |

## CI/CD 集成

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]

jobs:
  test-c:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: sudo apt-get install -y libssh-dev
      - name: Build
        run: make
      - name: Test
        run: make test

  test-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - name: Build
        run: go build ./...
      - name: Test
        run: go test ./... -count=1
```

## 故障排除

### 测试失败

1. 检查 libssh 是否正确安装：`pkg-config --modversion libssh`
2. 清理并重新编译：`make clean && make`
3. 运行调试构建：`make debug && make test`

### 内存问题

使用 Valgrind 检查内存泄漏：

```bash
valgrind --leak-check=full ./build/bin/test_integration
```

### 性能测试

```bash
# 简单压力测试
for i in {1..100}; do
    ssh -p 2222 -o ConnectTimeout=1 test@localhost &
done
wait
```
