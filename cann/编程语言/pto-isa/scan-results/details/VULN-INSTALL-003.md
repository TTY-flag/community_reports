# VULN-INSTALL-003: Download of Code Without Integrity Check

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **ID** | VULN-INSTALL-003 |
| **CWE** | CWE-494: Download of Code Without Integrity Check |
| **严重等级** | Critical |
| **置信度** | 85 |
| **文件** | scripts/install_pto.sh |
| **行号** | 96-147 |
| **函数** | download_pto_isa_run / install_pto_isa_run |

## 漏洞描述

脚本通过 HTTP 协议（非 HTTPS）下载可执行的 `.run` 安装包，下载后**未进行任何完整性校验**（无 checksum、签名或 hash 验证），直接通过 `chmod +x` 赋予执行权限并运行。

## 可达性分析

### 攻击入口

```
main() → download_pto_isa_run() → wget 下载 → install_pto_isa_run() → chmod +x → 执行
```

**触发条件**:
1. 用户执行 `scripts/install_pto.sh <install_path>` 
2. 目标安装路径未检测到已安装的 toolkit
3. 脚本自动尝试下载 PTO ISA 包

**环境可达性**: 高
- 安装脚本为用户必经步骤
- 无需特殊权限或配置
- 目标 URL 使用 HTTP 明文协议

### 攻击面暴露

```bash
# 漏洞代码位置 (lines 96-147)

download_pto_isa_run() {
  local arch="$1"
  # 漏洞点 1: HTTP 协议，无 TLS 加密
  local base_url="http://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com/package/cann/pto-isa/version_compile/master/${CURRENT_YEAR}${CURRENT_MONTH}"
  
  # ... 日期回溯逻辑 ...
  
  local filename="cann-pto-isa_8.5.0_linux-${arch}.run"
  PTO_ISA_PKG="${DOWNLOAD_DIR}/${filename}"
  
  for date in "${try_dates[@]}"; do
    local url="${base_url}/${date}/ubuntu_${arch}/${filename}"
    
    # 漏洞点 2: --no-check-certificate 禁用证书验证
    if wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q; then
      info "download successful!"
      return 0
    fi
  done
}

install_pto_isa_run() {
  local toolkit_path="$1"
  local install_path="${toolkit_path}"
  
  # 漏洞点 3: 无校验直接执行
  chmod +x "$PTO_ISA_PKG"
  "$PTO_ISA_PKG" --full --quiet --install-path="$install_path"
}
```

## 攻击链构建

### 完整攻击链

```
┌─────────────────────────────────────────────────────────────────────┐
│ Phase 1: MITM 定位                                                  │
├─────────────────────────────────────────────────────────────────────┤
│ 攻击者位于用户与 obs.cn-north-4.myhuaweicloud.com 之间的网络路径    │
│ 可能位置:                                                           │
│ • 企业网络出口网关                                                  │
│ • ISP 网络                                                          │
│ • 公共 WiFi 接入点                                                  │
│ • BGP 劫持场景                                                      │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Phase 2: 请求拦截                                                   │
├─────────────────────────────────────────────────────────────────────┤
│ HTTP 明文请求:                                                      │
│ GET /package/cann/pto-isa/version_compile/master/202604/...        │
│ Host: container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com   │
│                                                                     │
│ 攻击者可以:                                                         │
│ • 完全查看请求内容                                                  │
│ • 修改请求参数                                                      │
│ • 返回任意响应内容                                                  │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Phase 3: 恶意载荷投递                                               │
├─────────────────────────────────────────────────────────────────────┤
│ 攻击者返回恶意 .run 文件:                                           │
│ • 伪造的 Makeself 安装包                                            │
│ • 包含后门/恶意代码                                                 │
│ • 可定向投递（针对特定目标）                                        │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Phase 4: 无校验执行                                                 │
├─────────────────────────────────────────────────────────────────────┤
│ chmod +x "$PTO_ISA_PKG"          # 赋予执行权限                     │
│ "$PTO_ISA_PKG" --full --quiet    # 静默安装，无用户交互              │
│                                                                     │
│ 恶意代码以当前用户权限执行，可:                                     │
│ • 安装持久化后门                                                    │
│ • 窃取凭证/密钥                                                     │
│ • 横向移动                                                          │
│ • 部署挖矿程序                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 攻击复杂度分析

| 因素 | 评估 | 说明 |
|------|------|------|
| 网络位置要求 | 中等 | 需要位于 MITM 位置，但公网 HTTP 流量易被劫持 |
| 技术难度 | 低 | 无需破解加密，直接替换响应即可 |
| 检测难度 | 高 | HTTP 明文传输，`--no-check-certificate` 绕过证书检查 |
| 持久性 | 高 | 恶意代码可建立持久化后门 |

## 实际影响评估

### 直接影响

1. **任意代码执行**: 攻击者可在受害者机器上执行任意代码
2. **供应链攻击**: CANN 是华为 AI 计算框架，影响面广泛
3. **权限继承**: 脚本以执行用户权限运行，可能获得 root（若用户使用 sudo）

### 潜在危害场景

```
┌──────────────────────────────────────────────────────────────────┐
│ 场景 1: 企业内网渗透                                            │
├──────────────────────────────────────────────────────────────────┤
│ 攻击者位置: 企业网络边界                                         │
│ 目标: 开发者工作站                                               │
│ 效果: 安装后门 → 窃取代码/凭证 → 横向移动到代码仓库/服务器       │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ 场景 2: CI/CD 流水线投毒                                        │
├──────────────────────────────────────────────────────────────────┤
│ 攻击者位置: CI/CD 运行环境网络                                   │
│ 目标: 自动化构建服务器                                           │
│ 效果: 污染构建产物 → 影响下游所有用户                             │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ 场景 3: 针对性 APT 攻击                                          │
├──────────────────────────────────────────────────────────────────┤
│ 攻击者: 国家级 APT 组织                                           │
│ 目标: 特定企业/机构的 AI 开发人员                                 │
│ 效果: 窃取 AI 模型/数据、植入后门                                 │
└──────────────────────────────────────────────────────────────────┘
```

### 影响范围

- **受影响版本**: 所有使用此安装脚本的用户
- **影响平台**: aarch64 (ARM64), x86_64 (AMD64)
- **信任链断裂**: 用户信任 CANN 官方安装脚本，但攻击者可劫持下载

## PoC 可行性判断

### 技术可行性: **高**

PoC 构造步骤:

```bash
# 1. 创建恶意 .run 文件 (Makeself 格式)
mkdir -p /tmp/malicious_payload
cat > /tmp/malicious_payload/install.sh << 'EOF'
#!/bin/bash
# 恶意代码示例
echo "[!] Malicious code executed as: $(whoami)"
echo "[!] Running from: $(pwd)"
# 实际攻击中可包含: 反弹 shell、窃取文件、持久化等
EOF
chmod +x /tmp/malicious_payload/install.sh

# 2. 打包为 .run 文件
makeself /tmp/malicious_payload malicious.run "Malicious PTO ISA" ./install.sh

# 3. 模拟 MITM 攻击
# 在实际攻击中，攻击者会在网络层面劫持 HTTP 响应
# 返回 malicious.run 而非合法的 PTO ISA 包
```

### 演示环境搭建

```bash
# 环境要求:
# - 可控的 HTTP 服务器
# - DNS 劫持或 hosts 文件修改

# 搭建恶意服务器
python3 -m http.server 80

# 受害者机器 /etc/hosts 修改
# 127.0.0.1 container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com
```

### 验证指标

| 指标 | 结果 |
|------|------|
| 是否需要认证绕过 | 否 |
| 是否需要漏洞利用链 | 否，直接替换响应即可 |
| 是否可远程触发 | 是，需网络位置 |
| 是否需要用户交互 | 是，需用户运行安装脚本 |

## 修复建议

### 短期修复 (优先级: Critical)

```bash
# 1. 使用 HTTPS 协议
-local base_url="http://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com/..."
+local base_url="https://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com/..."

# 2. 移除 --no-check-certificate 标志
-if wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q; then
+if wget -O "$PTO_ISA_PKG" "$url" -q; then
```

### 中期修复 (推荐)

```bash
# 添加完整性校验
EXPECTED_SHA256="<发布时计算的正确 hash>"

download_pto_isa_run() {
  # ... 下载逻辑 ...
  
  # 验证 hash
  ACTUAL_SHA256=$(sha256sum "$PTO_ISA_PKG" | awk '{print $1}')
  if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    error "Integrity check failed! Package may be corrupted or tampered."
    rm -f "$PTO_ISA_PKG"
    exit 1
  fi
  
  info "Integrity check passed"
}
```

### 长期修复 (最佳实践)

1. **签名验证**: 使用 GPG 签名验证下载包
2. **固定 URL**: 避免动态日期拼接，使用固定版本 URL
3. **内部镜像**: 使用内部受信任的镜像源
4. **审计日志**: 记录所有下载和安装操作

## 判定结论

| 项目 | 结果 |
|------|------|
| 是否为真实漏洞 | **是** |
| 漏洞类型 | CWE-494: Download of Code Without Integrity Check |
| 可利用性 | 高 (MITM 场景下无需高级技术) |
| 影响 | Critical (任意代码执行) |
| PoC 可行性 | 高 (可轻松构造演示) |

---

**报告生成时间**: 2026-04-22
**分析者**: details-analyzer