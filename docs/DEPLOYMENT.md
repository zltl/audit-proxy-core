# SSH Proxy Core - 实际环境配置与验证指南

## 快速开始

```bash
# 一键配置和验证
chmod +x scripts/setup-and-verify.sh
./scripts/setup-and-verify.sh
```

## 手动配置步骤

### 1. 安装依赖

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential libssh-dev

# CentOS/RHEL
sudo yum install -y gcc make libssh-devel

# 验证 libssh
pkg-config --modversion libssh
```

### 2. 编译项目

```bash
cd /path/to/ssh-proxy-core
make clean && make

# 验证编译成功
./build/bin/ssh-proxy-core --version
```

### 3. 创建配置目录

```bash
# 生产环境
sudo mkdir -p /etc/ssh-proxy
sudo mkdir -p /var/log/ssh-proxy/audit
sudo mkdir -p /var/run

# 设置权限
sudo chown $USER:$USER /etc/ssh-proxy
sudo chown $USER:$USER /var/log/ssh-proxy
```

### 4. 生成主机密钥

```bash
# RSA 密钥 (推荐 4096 位)
ssh-keygen -t rsa -b 4096 -f /etc/ssh-proxy/host_key_rsa -N ""

# ECDSA 密钥
ssh-keygen -t ecdsa -b 521 -f /etc/ssh-proxy/host_key_ecdsa -N ""

# Ed25519 密钥 (最快)
ssh-keygen -t ed25519 -f /etc/ssh-proxy/host_key_ed25519 -N ""
```

### 5. 启动代理服务器

```bash
# 基本启动
./build/bin/ssh-proxy-core -p 2222 -k /etc/ssh-proxy/host_key_rsa

# 调试模式
./build/bin/ssh-proxy-core -p 2222 -k /etc/ssh-proxy/host_key_rsa -d

# 后台运行
nohup ./build/bin/ssh-proxy-core -p 2222 -k /etc/ssh-proxy/host_key_rsa > /var/log/ssh-proxy/proxy.log 2>&1 &
```

## 验证测试

### 1. 端口验证

```bash
# 检查端口监听
ss -tuln | grep 2222
netstat -tuln | grep 2222

# 预期输出:
# tcp    LISTEN  0  128  0.0.0.0:2222  0.0.0.0:*
```

### 2. 连接测试

```bash
# 使用 nc 测试端口
nc -zv localhost 2222

# SSH 连接测试 (当前版本会断开)
ssh -p 2222 -v testuser@localhost
```

### 3. 日志检查

```bash
# 查看代理日志
tail -f /var/log/ssh-proxy/proxy.log

# 查看审计日志
ls -la /var/log/ssh-proxy/audit/
cat /var/log/ssh-proxy/audit/audit_*.log
```

## Systemd 服务配置

创建 `/etc/systemd/system/ssh-proxy.service`:

```ini
[Unit]
Description=SSH Proxy Core Server
After=network.target

[Service]
Type=simple
User=ssh-proxy
Group=ssh-proxy
ExecStart=/opt/ssh-proxy-core/build/bin/ssh-proxy-core \
    -p 2222 \
    -k /etc/ssh-proxy/host_key_rsa
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# 安全设置
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/ssh-proxy

[Install]
WantedBy=multi-user.target
```

启用服务:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-proxy
sudo systemctl start ssh-proxy
sudo systemctl status ssh-proxy
```

## Docker 部署

### Dockerfile

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    libssh-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN make clean && make

RUN mkdir -p /etc/ssh-proxy /var/log/ssh-proxy/audit
RUN ssh-keygen -t rsa -b 2048 -f /etc/ssh-proxy/host_key -N ""

EXPOSE 2222

CMD ["./build/bin/ssh-proxy-core", "-p", "2222", "-k", "/etc/ssh-proxy/host_key"]
```

### 构建和运行

```bash
# 构建镜像
docker build -t ssh-proxy-core .

# 运行容器
docker run -d \
    -p 2222:2222 \
    -v /var/log/ssh-proxy:/var/log/ssh-proxy \
    --name ssh-proxy \
    ssh-proxy-core

# 查看日志
docker logs -f ssh-proxy
```

## 集成测试场景

### 场景 1: 过滤器链验证

```bash
# 运行集成测试
./build/bin/test_integration

# 预期输出:
# ✓ All integration tests passed!
```

### 场景 2: 负载均衡验证

```c
// 在代码中配置多个上游
upstream_config_t u1 = { .host = "backend1", .port = 22, .enabled = true };
upstream_config_t u2 = { .host = "backend2", .port = 22, .enabled = true };
router_add_upstream(router, &u1);
router_add_upstream(router, &u2);

// 验证 Round-Robin
for (int i = 0; i < 10; i++) {
    route_result_t result;
    router_resolve(router, "user", "target", &result);
    printf("Request %d -> %s\n", i, result.upstream->config.host);
}
```

### 场景 3: RBAC 验证

```c
// 配置角色
rbac_add_role(&cfg, "admin");
rbac_add_role(&cfg, "developer");

// 配置权限
rbac_add_permission(&cfg, "admin", "*", RBAC_ACTION_ALLOW);
rbac_add_permission(&cfg, "developer", "dev-*", RBAC_ACTION_ALLOW);
rbac_add_permission(&cfg, "developer", "prod-*", RBAC_ACTION_DENY);

// 分配角色
rbac_assign_role(&cfg, "admin-*", "admin");
rbac_assign_role(&cfg, "dev-*", "developer");

// 验证访问
printf("admin-john -> prod: %s\n", 
    rbac_check_access(&cfg, "admin-john", "prod-server") == RBAC_ACTION_ALLOW ? "ALLOW" : "DENY");
printf("dev-alice -> prod: %s\n", 
    rbac_check_access(&cfg, "dev-alice", "prod-server") == RBAC_ACTION_ALLOW ? "ALLOW" : "DENY");
```

### 场景 4: 速率限制验证

```bash
# 快速发起多个连接
for i in {1..10}; do
    ssh -p 2222 -o ConnectTimeout=1 test@localhost &
done
wait

# 检查日志中的限制消息
grep "Rate limit" /var/log/ssh-proxy/proxy.log
```

## 性能测试

### 连接吞吐量

```bash
# 安装测试工具
sudo apt install -y apache2-utils

# 简单压力测试脚本
cat > /tmp/stress_test.sh << 'EOF'
#!/bin/bash
for i in {1..100}; do
    (echo | nc -w 1 localhost 2222) &
done
wait
EOF
chmod +x /tmp/stress_test.sh

# 运行测试
time /tmp/stress_test.sh
```

### 内存检查

```bash
# 使用 Valgrind
valgrind --leak-check=full ./build/bin/test_integration

# 使用 AddressSanitizer (需重新编译)
make clean
CFLAGS="-fsanitize=address" make
./build/bin/test_integration
```

## 监控

### 健康检查端点

```bash
# 检查服务健康状态 (默认监听 127.0.0.1:9090)
curl http://localhost:9090/health

# 获取 Prometheus 格式指标
curl http://localhost:9090/metrics
```

### 指标收集

```bash
# 使用内置 Prometheus 指标端点
curl -s http://localhost:9090/metrics | grep ssh_proxy

# 查看当前连接数
ss -s | grep -E "TCP|ESTAB"

# 查看进程资源
ps aux | grep ssh-proxy
top -p $(pgrep ssh-proxy)
```

## 故障排除

### 问题: 端口被占用

```bash
# 查找占用进程
sudo lsof -i :2222
sudo fuser 2222/tcp

# 终止进程
sudo kill $(sudo fuser 2222/tcp 2>/dev/null | awk '{print $1}')
```

### 问题: 权限不足

```bash
# 检查密钥权限
chmod 600 /etc/ssh-proxy/host_key*

# 检查目录权限
chmod 755 /etc/ssh-proxy
chmod 755 /var/log/ssh-proxy
```

### 问题: libssh 找不到

```bash
# 添加库路径
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
sudo ldconfig

# 或重新链接
sudo ln -sf /usr/local/lib/libssh.so.4 /usr/lib/
```

## 下一步

1. **TLS 终结** - 支持 TLS 层加密
2. **集群部署** - 多实例水平扩展与状态同步
3. **Vault 集成** - 外部密钥管理系统集成
4. **审计日志外发** - 支持将审计日志发送到 SIEM 系统
