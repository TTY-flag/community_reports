# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Ops-Generator  
**扫描时间**: 2026-04-21T04:30:00Z  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次扫描共发现 **19 个待确认漏洞**，其中：
- **LIKELY (8个)**：漏洞机制明确，但需要特定攻击条件
- **POSSIBLE (11个)**：漏洞模式存在，但攻击可行性较低

### 关键发现

| 漏洞类型 | 数量 | 主要模块 | 严重性分布 |
|----------|------|----------|------------|
| **路径遍历/文件操作** | 8 | msopst/template, msopst/st/interface | High/Medium |
| **代码/命令执行** | 5 | msopgen, msopst/st/interface | High/Medium |
| **供应链风险** | 4 | build_scripts | Medium/Low |
| **环境变量操作** | 1 | msopst | Medium |

### 高优先级关注漏洞

按置信度和严重性排序的 Top 5 待确认漏洞：

| 漏洞编号 | 严重性 | 置信度 | 漏洞类型 | 状态 |
|----------|--------|--------|----------|------|
| VULN-DF-PY-STI-002 | High | 70% | 代码执行 (JSON 配置) | LIKELY |
| VULN-DF-PY-BLD-003 | High | 70% | Zip Slip (解压) | LIKELY |
| VULN-DF-PY-BLD-004 | High | 70% | TLS 证书绕过 | LIKELY |
| VULN-DF-CMD-001 | High | 60% | 命令执行 (build.sh) | LIKELY |
| VULN-DF-CPP-001 | High | 55% | TOCTOU (文件读取) | POSSIBLE |

### 影响评估

**LIKELY 状态漏洞**：
- 漏洞机制真实存在，代码路径可达
- 需要特定前提条件（如控制配置文件、项目目录）
- 在 CI/CD 或共享环境场景风险较高

**POSSIBLE 状态漏洞**：
- 漏洞模式存在（如 TOCTOU、路径遍历）
- 但攻击者可控性较低（开发工具上下文）
- 需结合其他漏洞或特定环境才能利用

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 12 | 36.4% |
| POSSIBLE | 11 | 33.3% |
| LIKELY | 8 | 24.2% |
| CONFIRMED | 2 | 6.1% |
| **总计** | **33** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 6 | 31.6% |
| Medium | 11 | 57.9% |
| Low | 2 | 10.5% |
| **有效漏洞总计** | **19** | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-PY-STI-002]** Arbitrary Code Execution (High) - `data_generator.py:397` | 置信度: 70
2. **[VULN-DF-PY-BLD-003]** Path Traversal/Zip Slip (High) - `download_dependencies.py:112` | 置信度: 70
3. **[VULN-DF-PY-BLD-004]** Insecure TLS (High) - `download_dependencies.py:104` | 置信度: 70
4. **[VULN-DF-CMD-001]** Command Injection (High) - `op_file_compile.py:73` | 置信度: 60
5. **[VULN-DF-CPP-001]** TOCTOU Race Condition (High) - `op_execute.cpp:74` | 置信度: 55
6. **[VULN-DF-CPP-002]** TOCTOU Race Condition (High) - `op_execute.cpp:110` | 置信度: 55
7. **[VULN-DF-PY-BLD-001]** SSRF (Medium) - `download_dependencies.py:104` | 置信度: 70
8. **[VULN-DF-PY-ST-001]** Env Variable Manipulation (Medium) - `acl_op_runner.py:219` | 置信度: 68
9. **[VULN-DF-PY-INT-001]** Script Execution (Medium) - `op_file_compile.py:73` | 置信度: 65
10. **[VULN-DF-PY-STI-005]** Arbitrary File Read (Medium) - `data_generator.py:175` | 置信度: 65

---

## 2. 攻击面分析

待确认漏洞主要集中在以下攻击面：

| 攻击面 | 漏洞数量 | 主要风险 |
|--------|----------|----------|
| **构建脚本** | 6 | SSRF, Zip Slip, TLS 绕过, 供应链 |
| **测试框架** | 5 | 代码执行, 文件读取, 环境变量 |
| **C++ 测试模板** | 5 | TOCTOU, 路径验证缺失 |
| **算子编译** | 3 | 命令执行, 脚本执行 |

---

## 3. High 漏洞详细分析

### [VULN-DF-PY-STI-002] Arbitrary Code Execution via JSON

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY

**位置**: `tools/msopst/st/interface/data_generator.py:397` @ `generate`

#### 漏洞分析

与已确认的 VULN-DF-CODE-001 相似，但置信度较低的原因：
- JSON 测试用例文件通常由开发者控制
- 需要攻击者能够修改或替换 JSON 文件内容

**修复建议**：与 VULN-DF-CODE-001 采用相同的白名单机制。

---

### [VULN-DF-PY-BLD-003] Zip Slip via Archive Extraction

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY

**位置**: `download_dependencies.py:112-116` @ `proc_artifact`

#### 漏洞分析

构建脚本使用 `tar` 和 `shutil.unpack_archive` 解压下载的归档文件，未验证文件路径：

```python
# 解压未验证路径
tar -xf str(archive_path) -C str(extract_path)
# 或
shutil.unpack_archive(archive_path, extract_path)
```

**攻击场景**：
1. 攻击者控制 `dependencies.json` 中的 URL
2. 恶意归档包含 `../../../etc/cron.d/malicious` 路径
3. 解压后覆盖系统文件

**修复建议**：
```python
def safe_unpack_archive(archive_path, extract_path):
    """安全解压归档文件"""
    with tarfile.open(archive_path, 'r:*') as tar:
        for member in tar.getmembers():
            # 验证路径不包含遍历序列
            member_path = os.path.join(extract_path, member.name)
            if not os.path.realpath(member_path).startswith(
                os.path.realpath(extract_path)
            ):
                raise SecurityException(f"Path traversal detected: {member.name}")
            tar.extract(member, extract_path)
```

---

### [VULN-DF-PY-BLD-004] Insecure TLS Certificate Verification

**严重性**: High | **CWE**: CWE-295 | **置信度**: 70/100 | **状态**: LIKELY

**位置**: `download_dependencies.py:104-105` @ `proc_artifact`

#### 漏洞分析

curl 命令使用 `-k` 标志禁用 TLS 证书验证：

```python
cmd = ['curl', '-Lfk', '--retry', '5', '-o', str(archive_path), url]
```

**影响**：
- 与 SSRF 漏洞结合可实施 MITM 攻击
- 下载的 artifact 无来源验证

**修复建议**：
```python
# 移除 -k 标志，强制 TLS 验证
cmd = ['curl', '-Lf', '--retry', '5', '-o', str(archive_path), url]

# 或使用 Python requests 库（默认验证证书）
import requests
response = requests.get(url, verify=True)
```

---

### [VULN-DF-CMD-001] Command Execution via build.sh

**严重性**: High | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY

**位置**: `msopgen/interface/op_file_compile.py:73-108` @ `compile`

#### 漏洞分析

用户通过 CLI 参数指定项目目录，其中的 `build.sh` 脚本被执行：

```python
def compile(self):
    build_path = os.path.join(self.input_path, 'build.sh')
    execute_cmd = [build_path]
    subprocess.Popen(cmd, shell=False)  # shell=False 阻止 shell 注入
```

**缓解措施**：
- `shell=False` 阻止 shell 元字符注入
- `check_execute_file` 检查文件权限

**剩余风险**：
- 恶意脚本内容仍可执行
- 供应链攻击：恶意项目分发

**修复建议**：
```python
def check_script_safe(script_path):
    """检查脚本内容安全性"""
    # 检查脚本哈希是否在预注册列表中
    registered_hashes = load_registered_scripts()
    actual_hash = compute_sha256(script_path)
    return actual_hash in registered_hashes

def compile(self):
    build_path = os.path.join(self.input_path, 'build.sh')
    if not check_script_safe(build_path):
        raise SecurityException("Script not in trusted registry")
```

---

### [VULN-DF-CPP-001 & 002] TOCTOU Race Conditions

**严重性**: High | **CWE**: CWE-367 | **置信度**: 55/100 | **状态**: POSSIBLE

**位置**: `tools/msopst/template/acl_op_src/src/op_execute.cpp`

#### 漏洞分析

C++ 测试框架中存在 TOCTOU（Time-of-check to Time-of-use）漏洞：

```cpp
// VULN-001: 文件读取 TOCTOU
ReadFile(filePath, ...);     // 先读取文件
realpath(filePath, realPath); // 后验证路径 - 太晚了

// VULN-002: 文件写入 TOCTOU
WriteFile(filePath, ...);    // 先写入文件
realpath(filePath, realPath); // 后验证路径 - 太晚了
```

**攻击窗口**：
- 在 ReadFile/WriteFile 和 realpath 之间可替换符号链接
- 攻击者可读取/写入任意文件

**置信度较低原因**：
- 测试框架上下文，路径通常由开发者配置
- 需要本地并发攻击者

**修复建议**：
```cpp
// 先规范化路径，再操作文件
char realPath[PATH_MAX];
if (realpath(filePath.c_str(), realPath) == NULL) {
    return false;  // 路径验证失败
}

// 使用验证后的路径
std::string validatedPath(realPath);
ReadFile(validatedPath, ...);  // 使用安全路径
```

---

## 4. Medium 漏洞摘要

| 漏洞编号 | 类型 | 模块 | 置信度 | 状态 |
|----------|------|------|--------|------|
| VULN-DF-PY-BLD-001 | SSRF | build_scripts | 70% | LIKELY |
| VULN-DF-PY-ST-001 | Env Variable | msopst | 68% | LIKELY |
| VULN-DF-PY-INT-001 | Script Exec | msopgen/interface | 65% | LIKELY |
| VULN-DF-PY-STI-005 | File Read | msopst/st/interface | 65% | LIKELY |
| VULN-DF-CPP-003/004/005 | Path Validation | msopst/template | 55% | POSSIBLE |
| VULN-DF-PY-BLD-006 | Integrity | build_scripts | 55% | POSSIBLE |
| VULN-DF-PY-STI-006 | File Read | msopst/st/interface | 50% | POSSIBLE |
| VULN-DF-PY-STI-003 | Code Exec | msopst/st/interface | 45% | POSSIBLE |
| VULN-DF-CMD-002 | Command Exec | msopgen-simulator | 40% | POSSIBLE |

---

## 5. Low 漏洞摘要

| 漏洞编号 | 类型 | 模块 | 置信度 | 状态 |
|----------|------|------|--------|------|
| VULN-DF-PY-BLD-005 | Supply Chain | build_scripts | 50% | POSSIBLE |
| VULN-DF-PY-BLD-007 | Dep Confusion | build_scripts | 45% | POSSIBLE |

**说明**：这两类漏洞属于供应链风险，需要结合其他漏洞或攻击者修改项目源码才能利用，直接攻击可行性较低。

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| build_scripts | 0 | 3 | 2 | 2 | 7 |
| msopst/template | 0 | 2 | 3 | 0 | 5 |
| msopst/st/interface | 0 | 1 | 4 | 0 | 5 |
| msopgen | 0 | 1 | 0 | 0 | 1 |
| msopgen/interface | 0 | 0 | 1 | 0 | 1 |
| msopgen-simulator | 0 | 0 | 1 | 0 | 1 |
| msopst | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **6** | **11** | **2** | **19** |

---

## 7. CWE 分布

| CWE | 数量 | 占比 | 说明 |
|-----|------|------|------|
| CWE-22 | 6 | 31.6% | Path Traversal (路径遍历) |
| CWE-78 | 3 | 15.8% | OS Command Injection (命令注入) |
| CWE-94 | 2 | 10.5% | Code Injection (代码注入) |
| CWE-367 | 2 | 10.5% | TOCTOU Race Condition (时间检查) |
| CWE-918 | 1 | 5.3% | SSRF (服务器端请求伪造) |
| CWE-295 | 1 | 5.3% | Improper Certificate Validation |
| CWE-453 | 1 | 5.3% | Insecure Environmental Variable |
| CWE-353 | 1 | 5.3% | Missing Integrity Check |
| CWE-494 | 1 | 5.3% | Download of Code Without Integrity Check |
| CWE-426 | 1 | 5.3% | Untrusted Search Path |

---

## 8. 综合修复建议

### 8.1 构建脚本安全加固（build_scripts）

**高优先级修复**：

| 漏洞 | 修复方案 |
|------|----------|
| Zip Slip | 使用 `safe_unpack_archive` 验证解压路径 |
| TLS 绕过 | 移除 curl `-k` 标志，使用 Python requests |
| SSRF | URL 白名单验证，禁止内部 IP |
| Integrity | 强制 SHA256 验证 |

```python
# 构建脚本安全配置
ALLOWED_URL_DOMAINS = ['repo.huawei.com', 'secure.mindstudio.cn']
FORBIDDEN_IP_RANGES = ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']

def validate_download_url(url):
    """验证下载 URL 安全性"""
    # 域名白名单
    hostname = urlparse(url).hostname
    if hostname not in ALLOWED_URL_DOMAINS:
        raise SecurityException(f"URL domain not allowed: {hostname}")
    
    # 禁止内部 IP
    try:
        ip = socket.gethostbyname(hostname)
        if is_private_ip(ip):
            raise SecurityException(f"Internal IP not allowed: {ip}")
    except socket.gaierror:
        pass
```

### 8.2 C++ 测试框架安全加固（msopst/template）

**修复 TOCTOU 和路径验证漏洞**：

```cpp
// 安全文件读取函数
bool SafeReadFile(const std::string& filePath, std::vector<char>& buffer) {
    // 1. 先规范化路径
    char realPath[PATH_MAX];
    if (realpath(filePath.c_str(), realPath) == NULL) {
        return false;
    }
    
    // 2. 验证路径不遍历
    if (strstr(realPath, "/etc/") != NULL ||
        strstr(realPath, "/root/") != NULL) {
        return false;  // 禁止敏感路径
    }
    
    // 3. 使用验证后的路径
    std::ifstream file(realPath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // 4. 使用 O_NOFOLLOW 防止符号链接
    int fd = open(realPath, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        return false;
    }
    
    // ...读取内容
    close(fd);
    return true;
}

// 安全文件写入函数
bool SafeWriteFile(const std::string& filePath, const std::vector<char>& buffer) {
    char realPath[PATH_MAX];
    if (realpath(filePath.c_str(), realPath) == NULL) {
        return false;
    }
    
    // 使用 O_NOFOLLOW | O_EXCL 防止符号链接攻击
    int fd = open(realPath, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW | O_EXCL,
                  S_IRUSR | S_IWUSR);
    if (fd == -1) {
        return false;
    }
    
    // ...写入内容
    close(fd);
    return true;
}
```

### 8.3 测试框架输入验证（msopst/st/interface）

**修复文件读取和代码执行漏洞**：

```python
def validate_json_input_path(path, allowed_dirs):
    """验证 JSON 输入中的文件路径"""
    real_path = os.path.realpath(path)
    
    # 白名单目录验证
    for allowed_dir in allowed_dirs:
        if real_path.startswith(os.path.realpath(allowed_dir) + os.sep):
            return real_path
    
    raise SecurityException(f"Path not in allowed directories: {path}")

def safe_np_fromfile(value, allowed_dirs):
    """安全的 np.fromfile 调用"""
    if isinstance(value, str):
        validated_path = validate_json_input_path(value, allowed_dirs)
        return np.fromfile(validated_path, dtype)
    return value
```

---

## 9. 修复优先级矩阵

| 优先级 | 漏洞范围 | 建议时间 | 修复难度 |
|--------|----------|----------|----------|
| **P0** | VULN-DF-PY-BLD-003, 004 (构建脚本) | 立即 | Low |
| **P1** | VULN-DF-CPP-001, 002 (TOCTOU) | 1 周 | Medium |
| **P1** | VULN-DF-CMD-001 (命令执行) | 1 周 | Medium |
| **P2** | VULN-DF-PY-STI-002, 005 (测试框架) | 2 周 | Medium |
| **P3** | C++ 路径验证漏洞 (003-005) | 长期 | High |
| **P3** | 供应链风险 (Low 级别) | 长期 | Medium |

---

## 10. 验证测试建议

### 10.1 构建脚本测试

```
测试用例：
- URL 白名单验证 → 非 allow 域名应拒绝
- 内部 IP SSRF → 192.168.x.x 应拒绝
- Zip Slip → 包含 ../ 的归档应拒绝
- TLS 验证 → 无效证书应拒绝下载
```

### 10.2 C++ 测试框架测试

```
测试用例：
- TOCTOU 符号链接 → 应拒绝或使用规范化路径
- 路径遍历 → ../../../etc/passwd 应拒绝
- O_NOFOLLOW → 符号链接文件应拒绝
```

### 10.3 Python 测试框架测试

```
测试用例：
- JSON 路径注入 → 非 allow 目录路径应拒绝
- np.fromfile 路径 → 验证路径合法性
- importlib 导入 → 与已确认漏洞使用相同白名单
```

---

## 11. 参考资料

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [OWASP Zip Slip Prevention](https://owasp.org/www-community/vulnerabilities/Zip_Slip)
- [Secure File Handling in C/C++](https://wiki.sei.cmu.edu/confluence/display/c/FIO21-C.+Do+not+open+a+file+that+already+exists)
- [CURL TLS Best Practices](https://curl.se/docs/sslcerts.html)