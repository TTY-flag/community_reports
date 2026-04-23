# 漏洞扫描报告 — 待确认漏洞

**项目**: pto-isa
**扫描时间**: 2026-04-22T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Medium | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 10 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-INSTALL-004]** Inclusion of Functionality from Untrusted Control Sphere (Medium) - `scripts/install_pto.sh:149` @ `install_gtest` | 置信度: 65
2. **[VULN-INSTALL-002]** Certificate Validation Bypass (Medium) - `scripts/install_pto.sh:150` @ `install_gtest` | 置信度: 65

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

## 3. Medium 漏洞 (2)

### [VULN-INSTALL-004] Inclusion of Functionality from Untrusted Control Sphere - install_gtest

**严重性**: Medium | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `scripts/install_pto.sh:149-170` @ `install_gtest`
**模块**: install_scripts

**描述**: Clones code from external GitHub repository and executes it via cmake/make without verifying the integrity or authenticity of the downloaded code. While URL is hardcoded, the code is downloaded over network and executed with system privileges

**漏洞代码** (`scripts/install_pto.sh:149-170`)

```c
git clone https://github.com/google/googletest.git -b v1.14.x\n...\ncmake .. && make -j$(nproc) && sudo make install
```

**达成路径**

github_clone(no_integrity_check) -> cmake_build -> sudo_make_install

**验证说明**: git clone https://github.com/google/googletest.git (line 151) + cmake/make/sudo make install (lines 155-164). No integrity verification of downloaded code. URL is hardcoded (partial control), but network download is untrusted and executed with sudo. MITM via sslverify=false could inject malicious code.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-INSTALL-002] Certificate Validation Bypass - install_gtest

**严重性**: Medium | **CWE**: CWE-295 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `scripts/install_pto.sh:150` @ `install_gtest`
**模块**: install_scripts

**描述**: git config disables SSL verification globally with http.sslverify false, allowing MITM attacks on all git operations including code downloads

**漏洞代码** (`scripts/install_pto.sh:150`)

```c
git config --global http.sslverify false
```

**达成路径**

git_config -> ssl_disabled -> git_clone -> untrusted_code

**验证说明**: git config --global http.sslverify false (line 150) disables SSL verification for ALL git operations globally. This affects the googletest clone (line 151). MITM can intercept and modify the cloned repository. Less severe than INSTALL-001 because googletest URL is hardcoded (partial control).

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| install_scripts | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **0** | **2** | **0** | **2** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-829 | 1 | 50.0% |
| CWE-295 | 1 | 50.0% |
