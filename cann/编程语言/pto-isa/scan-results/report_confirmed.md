# 漏洞扫描报告 — 已确认漏洞

**项目**: pto-isa
**扫描时间**: 2026-04-22T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 pto-isa 项目（华为 CANN 工具链中的 PTO ISA 组件）进行了代码审计，发现了 **2 个已确认的安全漏洞**，均为 Critical 或 High 级别。所有漏洞集中在 `install_scripts` 模块的安装脚本中，涉及网络下载过程中的安全校验缺失问题。

**核心风险**: 安装脚本通过 HTTP 协议下载可执行安装包并直接执行，且禁用了 SSL/TLS 证书校验。这使得中间人攻击者可以替换下载的软件包，注入恶意代码，在目标系统上获得完全控制权。

**影响范围**: 
- 执行安装脚本的开发者或运维人员
- 目标 Ascend 服务器环境
- 使用该工具链的 AI 应用

**整体评估**: 该项目在运行时代码逻辑方面未见明显漏洞，但安装部署流程存在严重安全隐患，建议优先修复后再用于生产环境。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 10 | 71.4% |
| LIKELY | 2 | 14.3% |
| CONFIRMED | 2 | 14.3% |
| **总计** | **14** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 50.0% |
| High | 1 | 50.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 10 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-INSTALL-003]** Download of Code Without Integrity Check (Critical) - `scripts/install_pto.sh:96` @ `download_pto_isa_run/install_pto_isa_run` | 置信度: 85
2. **[VULN-INSTALL-001]** Certificate Validation Bypass (High) - `scripts/install_pto.sh:123` @ `download_pto_isa_run` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `run_command@tests/run_cpu.py` | cmdline | semi_trusted | Python 测试脚本入口，接收命令行参数并执行 subprocess.run | 测试框架主入口，执行 cmake 编译和 gtest 运行 |
| `run_command@tests/run_costmodel.py` | cmdline | semi_trusted | CostModel 测试脚本入口，接收命令行参数并执行 subprocess.run | CostModel 测试框架主入口 |
| `download_pto_isa_run@scripts/install_pto.sh` | network | untrusted_network | 从远程服务器下载软件包，使用 wget --no-check-certificate | 网络下载入口点，下载 PTO ISA 安装包 |
| `install_gtest@scripts/install_pto.sh` | network | untrusted_network | 使用 git clone 从 GitHub 下载 googletest | 网络下载入口点，克隆 googletest 源码 |
| `generate_golden@tests/run_cpu.py` | file | semi_trusted | 复制和执行 gen_data.py 脚本，读取测试数据文件 | 测试数据生成入口点 |

**其他攻击面**:
- Command Line Arguments: tests/run_cpu.py, tests/run_costmodel.py 接收命令行参数
- Network Downloads: scripts/install_pto.sh 从远程服务器下载软件包
- Git Clone: scripts/install_pto.sh 从 GitHub 克隆代码
- Subprocess Execution: Python 测试脚本执行外部命令（cmake, gtest）
- File I/O: 测试数据文件读写（numpy 二进制格式）

---

## 3. Critical 漏洞 (1)

### [VULN-INSTALL-003] Download of Code Without Integrity Check - download_pto_isa_run/install_pto_isa_run

**严重性**: Critical | **CWE**: CWE-494 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner

**位置**: `scripts/install_pto.sh:96-147` @ `download_pto_isa_run/install_pto_isa_run`
**模块**: install_scripts

**描述**: Downloads .run executable package via HTTP (not HTTPS) and executes it without any integrity verification (no checksum, signature, or hash validation). The downloaded file is immediately executed via chmod +x and direct execution

**漏洞代码** (`scripts/install_pto.sh:96-147`)

```bash
wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q
...
chmod +x "$PTO_ISA_PKG"
"$PTO_ISA_PKG" --full --quiet --install-path="$install_path"
```

**达成路径**

http_url(no_tls) -> wget_download(no_integrity_check) -> chmod_exec -> direct_execution

**验证说明**: HTTP download (line 98: http://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com) with --no-check-certificate (line 123) + immediate chmod+x execution (lines 139-140). No integrity verification (checksum/signature/hash). MITM attacker can intercept and replace the .run package with malicious content, gaining full control over the installed software.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

#### 深度分析

**攻击链完整还原**:

1. **初始触发**: 用户执行 `scripts/install_pto.sh <toolkit_path>`，脚本进入 `main()` 函数
2. **下载阶段**: 调用 `download_pto_isa_run()` (第 96 行)，使用 HTTP 协议从华为 OBS 存储下载 `.run` 安装包
3. **TLS 禁用**: wget 使用 `--no-check-certificate` 参数 (第 123 行)，完全跳过证书校验
4. **完整性缺失**: 下载后未计算 SHA256/MD5，未比对签名，直接赋予权限
5. **代码执行**: `chmod +x "$PTO_ISA_PKG"` (第 139 行) 后直接执行 (第 140 行)

**真实攻击场景**:

攻击者可在以下位置实施中间人攻击:
- 用户所在局域网（ARP 欺骗 + DNS 劫持）
- 企业网络边界（SSL stripping）
- 公共 WiFi 环境
- ISP 层级（BGP 路由劫持）

攻击者可替换 `.run` 安装包为任意恶意代码，包括:
- 后门程序，持久化驻留系统
- 密钥窃取模块，获取 Ascend NPU 相关凭证
- 供应链攻击载荷，污染后续编译产物
- 勒索软件或挖矿程序

**证据代码片段**:

```bash
# 第 98 行 - 使用 HTTP 协议而非 HTTPS
local base_url="http://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com/package/cann/pto-isa/version_compile/master/${CURRENT_YEAR}${CURRENT_MONTH}"

# 第 123 行 - 禁用证书校验
wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q

# 第 139-140 行 - 直接赋予执行权限并运行
chmod +x "$PTO_ISA_PKG"
"$PTO_ISA_PKG" --full --quiet --install-path="$install_path"
```

---

## 4. High 漏洞 (1)

### [VULN-INSTALL-001] Certificate Validation Bypass - download_pto_isa_run

**严重性**: High | **CWE**: CWE-295 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner

**位置**: `scripts/install_pto.sh:123` @ `download_pto_isa_run`
**模块**: install_scripts

**描述**: wget command uses --no-check-certificate flag which disables SSL/TLS certificate verification, allowing man-in-the-middle attacks to intercept or modify downloaded packages

**漏洞代码** (`scripts/install_pto.sh:123`)

```bash
wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q
```

**达成路径**

untrusted_network -> wget(no_cert_verify) -> file_download -> execution

**验证说明**: wget --no-check-certificate (line 123) disables TLS certificate verification. This allows MITM attacker to intercept the download and serve malicious content. Note: CWE-295 is typically in specialized crypto audit scope but is valid security issue in this deployment context.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

#### 深度分析

**与 VULN-INSTALL-003 的关联性**:

此漏洞是 VULN-INSTALL-003 的组成部分。`--no-check-certificate` 参数在 wget 下载命令中禁用了 TLS 证书校验，这使得即使下载 URL 使用 HTTPS，攻击者仍可:
- 使用自签名证书伪装服务器
- 使用过期或无效证书
- 完全绕过 TLS 提供的身份验证保护

**代码位置与上下文**:

```bash
# 第 121-123 行 - 完整的下载命令
info "downloading $url"

if wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q; then
  info "download successful!"
```

`--no-check-certificate` 参数的存在表明开发者可能遇到证书问题后采用了"绕过而非修复"的方式，这是不安全的临时解决方案。

**攻击者视角**:

攻击者可搭建与目标服务器相似的域名，使用自签名证书，诱导流量后:
- wget 会跳过证书错误提示
- 静默下载恶意内容（`-q` 参数抑制输出）
- 用户无感知，继续安装流程

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| install_scripts | 1 | 1 | 0 | 0 | 2 |
| **合计** | **1** | **1** | **0** | **0** | **2** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-494 | 1 | 50.0% |
| CWE-295 | 1 | 50.0% |

---

## 7. 修复建议

### 7.1 VULN-INSTALL-003 (CWE-494) 修复方案

**优先级**: P0 — 立即修复

**具体措施**:

1. **使用 HTTPS 协议**
   ```bash
   # 将 HTTP URL 改为 HTTPS
   local base_url="https://container-obsfs-filesystem.obs.cn-north-4.myhuaweicloud.com/..."
   ```

2. **添加完整性校验**
   - 在发布 `.run` 安装包时，同时发布 SHA256 校验值
   - 下载后比对校验值：
   ```bash
   # 下载校验文件
   wget -O "${PTO_ISA_PKG}.sha256" "${url}.sha256"
   
   # 计算并比对
   actual_hash=$(sha256sum "$PTO_ISA_PKG" | cut -d' ' -f1)
   expected_hash=$(cat "${PTO_ISA_PKG}.sha256")
   if [[ "$actual_hash" != "$expected_hash" ]]; then
     error "Integrity check failed! File may be corrupted or tampered."
     exit 1
   fi
   ```

3. **使用签名验证**
   - 对 `.run` 包进行 GPG 签名
   - 安装脚本验证签名后才执行
   ```bash
   gpg --verify "${PTO_ISA_PKG}.sig" "$PTO_ISA_PKG"
   ```

4. **移除 `--no-check-certificate` 参数**
   ```bash
   wget -O "$PTO_ISA_PKG" "$url" -q
   ```

### 7.2 VULN-INSTALL-001 (CWE-295) 修复方案

**优先级**: P0 — 立即修复

**具体措施**:

1. **移除证书校验禁用参数**
   ```bash
   # 修改前
   wget -O "$PTO_ISA_PKG" "$url" --no-check-certificate -q
   
   # 修改后
   wget -O "$PTO_ISA_PKG" "$url" -q
   ```

2. **解决根因而非绕过**
   - 如果服务器证书问题导致下载失败，应修复服务器证书配置
   - 联系华为 OBS 存储团队确保证书链完整有效
   - 如需使用内部 CA，将 CA 证书导入系统信任库：
   ```bash
   cp internal-ca.crt /usr/local/share/ca-certificates/
   update-ca-certificates
   ```

3. **添加证书错误处理**
   ```bash
   if ! wget -O "$PTO_ISA_PKG" "$url" -q; then
     error "Download failed. Check network connectivity and server certificate."
     error "If using internal CA, ensure it is imported to system trust store."
     exit 1
   fi
   ```

### 7.3 综合建议

1. **最小权限原则**: 安装脚本不应以 root 执行，避免 `sudo make install`
2. **依赖隔离**: googletest 等依赖应从可信源获取，而非直接从 GitHub clone
3. **审计日志**: 记录下载 URL、校验值、执行时间，便于事后审计
4. **测试环境验证**: 修改后应在隔离环境中测试，确认安装流程安全可控

---

## 8. 附录

### 8.1 扫描方法说明

本次扫描采用多 Agent 协作架构:
- **Architecture Agent**: 分析项目结构，识别攻击面
- **DataFlow Scanner**: 追踪数据流，发现污点传播漏洞
- **Security Auditor**: 识别常见安全编码缺陷
- **Verification Agent**: 验证候选漏洞，计算置信度评分

### 8.2 置信度评分方法

置信度评分采用多维度加法模型:
- **Base (30分)**: 基础漏洞类型分值
- **Reachability (0-30分)**: 入口点可达性
- **Controllability (0-25分)**: 输入可控程度
- **Mitigations (-10-0分)**: 缓解措施发现情况
- **Context (0-10分)**: 上下文风险加分
- **Cross-file (0-10分)**: 跨文件传播加分

总分 0-100，≥80 为 CONFIRMED，60-79 为 LIKELY，40-59 为 POSSIBLE，<40 为 FALSE_POSITIVE。