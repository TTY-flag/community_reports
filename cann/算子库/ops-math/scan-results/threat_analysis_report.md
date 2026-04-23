# Threat Analysis Report - 华为 CANN ops-math 算子库

## 执行摘要

**项目**: 华为 CANN (Compute Architecture for Neural Networks) 数学运算算子库
**语言**: C/C++ (3544个cpp文件, 2279个头文件) + Python (47个文件)
**分析日期**: 2026-04-21
**风险等级**: **中高** (存在关键Python脚本漏洞和PRNG安全性问题)

### 关键发现

| 类别 | 发现数 | 严重程度 | 风险等级 |
|------|--------|----------|----------|
| Python代码执行漏洞 | 1 | Critical | 高 |
| Shell注入漏洞 | 4 | Critical | 高 |
| 弱PRNG种子生成 | 1 | High | 中 |
| 动态内存操作 | 多处 | Medium | 低 |
| 不安全getattr调用 | 1 | Medium | 低 |
| 配置文件解析无验证 | 多处 | Low | 低 |

**总体评估**: 该项目在Python构建脚本中存在严重的代码执行和命令注入漏洞，在生产环境使用这些脚本可能导致系统被完全控制。PRNG实现使用时间戳熵源，对安全敏感应用可能存在预测风险。C++算子实现相对安全，但缺少值范围验证。

---

## 1. 项目架构概述

### 1.1 模块分布

```
ops-math/
├── math/           (2294文件) - 数学运算算子，178个算子
├── conversion/     (966文件)  - 数据转换和形状操作
├── experimental/   (1267文件) - 实验性算子
├── random/         (230文件)  - 随机数生成算子，22个算子
├── common/         (59文件)   - 公共基础设施
└── scripts/        (47文件)   - Python构建脚本
```

### 1.2 入口点分析

- **API入口**: 300个aclnn函数 (`aclnnXXXGetWorkspaceSize` + `aclnnXXX` 两段式API)
- **Python入口**: 47个Python脚本，涉及代码生成、配置解析、构建流程
- **配置入口**: 多个.ini配置文件控制算子行为

### 1.3 数据流架构

```
用户API调用
    ↓
[op_api] aclnnXXXGetWorkspaceSize
    ↓ 参数验证 (OP_CHECK_*宏)
    ↓ Contiguous/Cast预处理
    ↓
[op_host] Tiling计算
    ↓ 形状分解、种子初始化
    ↓
[op_kernel] NPU内核执行
    ↓ AscendC模板执行
    ↓
[op_api] ViewCopy输出
    ↓ 返回用户
```

---

## 2. 关键漏洞详情

### 2.1 CRITICAL: Python eval() 代码执行漏洞

**漏洞ID**: VULN-001
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
**文件**: `conversion/fill_diagonal_v2/tests/ut/op_kernel/fill_diagonal_v2_data/gen_data.py`
**行号**: 21

**漏洞代码**:
```python
shape = eval(sys.argv[1])  # 直接执行用户输入
```

**攻击向量**:
```bash
python gen_data.py "__import__('os').system('id')" value wrap dtype
# 执行任意Python代码
```

**影响**: 完全系统控制，攻击者可执行任意命令、读取文件、建立反向连接

**修复建议**:
```python
# 方案1: 使用ast.literal_eval (安全)
import ast
shape = ast.literal_eval(sys.argv[1])

# 方案2: 使用JSON解析
import json
shape = json.loads(sys.argv[1])
```

---

### 2.2 CRITICAL: Shell注入漏洞 (多文件)

**漏洞ID**: VULN-002
**CWE**: CWE-78 (Improper Neutralization of Special Elements in Command Execution)

#### 文件1: scripts/util/modify_gen_aclnn_static.py
**行号**: 20, 45-50
```python
cmd = f"cd {aclnn_cpp} && ..."
subprocess.Popen(cmd, shell=True)  # shell=True + f-string = 注入
```

#### 文件2: scripts/util/build_opp_kernel_static.py
**行号**: 38, 94-107, 132-136
```python
subprocess.Popen(cmd, shell=True)  # 多处shell=True调用
```

#### 文件3: scripts/package/common/py/packer.py
**行号**: 215
```python
subprocess.run(cmd, shell=True)  # 处理用户提供的delivery_dir
```

**攻击向量**:
```bash
# 如果路径参数包含shell元字符
aclnn_cpp = "/path; rm -rf /"
# 或
aclnn_cpp = "/path && cat /etc/passwd > /tmp/out"
```

**影响**: 命令执行，可读取敏感文件、删除数据、执行任意命令

**修复建议**:
```python
# 方案: 使用列表参数，禁用shell=True
subprocess.run(["cd", dir_path, "&&", "some", "command"], shell=False)

# 或验证路径不包含特殊字符
import re
if re.search(r'[;&|`$]', dir_path):
    raise ValueError("Invalid path characters")
```

---

### 2.3 HIGH: 弱PRNG种子生成

**漏洞ID**: VULN-003
**CWE**: CWE-338 (Use of Cryptographically Weak PRNG)
**文件**: `random/random_common/op_host/arch35/random_tiling_base.h`
**行号**: 26-42

**漏洞代码**:
```cpp
static inline std::mt19937_64& GetGlobalRng() {
    static std::mt19937_64 rng([]() -> uint64_t {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()
        ).count();
        seed ^= std::hash<std::thread::id>()(std::this_thread::get_id());
        return seed;
    }());
    return rng;
}

inline uint64_t New64() {
    return GetGlobalRng()();
}
```

**熵源分析**:
- 主熵源: `std::chrono::high_resolution_clock::now()` (纳秒时间戳)
- 辅助熵源: `std::hash<std::thread::id>()` (线程ID哈希)
- RNG引擎: `std::mt19937_64` (Mersenne Twister，非密码学安全)

**攻击向量**:
1. 如果攻击者能估计程序启动时间，可预测初始种子
2. 如果攻击者能控制线程调度，可影响线程ID哈希
3. Mersenne Twister输出可被逆向分析恢复内部状态

**影响算子** (当seed=0时调用New64()):
- `random_uniform_v2`
- `random_uniform_int_v2`
- `random_standard_normal_v2`
- `truncated_normal_v2`

**安全影响**: 
- 非密码学应用: 风险较低
- 密码学/安全应用: **高风险** - 可预测的随机数可能导致密钥泄露、会话劫持

**修复建议**:
```cpp
// 方案1: 使用操作系统安全熵源
#include <random>
#include <unistd.h>
#include <fcntl.h>

uint64_t SecureNew64() {
    uint64_t seed;
    // Linux: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &seed, sizeof(seed));
    close(fd);
    return seed;
}

// 方案2: 使用C++11 random_device (如果实现安全)
std::random_device rd;
uint64_t seed = rd();
```

---

### 2.4 MEDIUM: 不安全getattr动态属性访问

**漏洞ID**: VULN-004
**CWE**: CWE-669 (Incorrect Use of Privileged API)
**文件**: `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py`
**行号**: 17, 20

**漏洞代码**:
```python
x1_type = sys.argv[2]
getattr(torch, x1_type)  # 从CLI输入访问torch模块属性
```

**攻击向量**:
```bash
python gen_data.py shape "__dict__" ...
# 可访问torch.__dict__，暴露内部结构
```

**影响**: 信息泄露，可能访问敏感模块属性

**修复建议**:
```python
# 方案: 使用白名单验证
ALLOWED_TYPES = {'float32', 'float16', 'int32', 'int64', ...}
if x1_type not in ALLOWED_TYPES:
    raise ValueError(f"Invalid dtype: {x1_type}")
dtype = getattr(torch, x1_type)
```

---

### 2.5 MEDIUM: 动态模块加载风险

**漏洞ID**: VULN-005
**CWE**: CWE-669
**文件**: `scripts/torch_extension/torch_extension_ut_runner.py`
**行号**: 43-44

**漏洞代码**:
```python
import importlib.util
spec = importlib.util.spec_from_file_location("module", file_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
```

**风险**: 如果file_path指向恶意Python文件，将被加载并执行

**修复建议**: 验证文件路径来源，仅允许可信目录下的模块加载

---

### 2.6 LOW: 配置文件解析无验证

**漏洞ID**: VULN-006
**CWE**: CWE-20 (Improper Input Validation)
**涉及文件**:
- `scripts/kernel/binary_script/parser_ini.py` (52-73行)
- `scripts/util/parse_ini_to_json.py` (85-115行)
- 多个`json.load()`调用

**风险**: 
- 配置文件无大小限制，可能导致内存耗尽
- 无schema验证，可能解析恶意配置

---

### 2.7 LOW: 动态内存操作风险

**漏洞ID**: VULN-007
**CWE**: CWE-120 (Buffer Copy without Size Check)
**文件**: `tests/ut/common/tiling_case_executor.cpp`
**行号**: 302

**漏洞代码**:
```cpp
std::memcpy(tiling, tilingInfo.tilingData.get(), tilingInfo.tilingDataSize);
```

**风险**: 如果allocated buffer小于tilingDataSize，可能缓冲区溢出

**注**: 该问题存在于测试代码，生产kernel代码未发现memcpy/memset

---

## 3. 攻击面分析

### 3.1 外部输入攻击面

| 入口类型 | 数据来源 | 验证状态 | 风险 |
|----------|----------|----------|------|
| aclnn API | aclTensor参数 | OP_CHECK_*宏 | 中 |
| Python sys.argv | 命令行 | **无验证** | 高 |
| ConfigParser | .ini文件 | 无验证 | 低 |
| json.load | JSON文件 | 无大小限制 | 低 |
| importlib | 文件路径 | 无验证 | 中 |

### 3.2 PRNG攻击面

```
Philox RNG架构:
┌─────────────────────────────────────────────┐
│ 用户种子 (int64_t)                          │
│     ↓                                       │
│ GetKeyAndCounter: key[2], counter[4]        │
│     ↓ (如果seed=0)                          │
│ New64: 时间戳 + 线程ID -> mt19937_64        │
│     ↓                                       │
│ PhiloxAlgParsInit: 初始化密钥               │
│     ↓                                       │
│ PhiloxRandomSimt: 10轮加密                  │
│     ↓                                       │
│ 随机数输出                                  │
└─────────────────────────────────────────────┘
```

**安全属性**:
- Philox本身是确定性PRNG，种子已知则输出完全可预测
- 安全性依赖种子熵源质量
- 当前实现: 时间戳熵源 = 可预测风险

### 3.3 算子API安全检查

**现有检查宏** (`common/inc/op_api/aclnn_check.h`):
- `OP_CHECK_NULL` - 空指针检查 ✓
- `OP_CHECK_DTYPE_NOT_SUPPORT` - 数据类型验证 ✓
- `OP_CHECK_SHAPE_NOT_EQUAL` - 形状验证 ✓
- `OP_CHECK_MAX_DIM` - 维度上限检查 ✓

**缺失检查**:
- ❌ 张量数据值范围验证
- ❌ 内存大小上限验证
- ❌ 整数溢出检查
- ❌ 并发访问保护

---

## 4. 安全调用链分析

### 链1: RNG自动种子攻击链

```
1. aclnnRandomUniformGetWorkspaceSize
   ↓
2. RandomUniformV2Tiling
   ↓
3. GetKeyAndCounter (seed=0触发)
   ↓
4. New64
   ↓
5. GetGlobalRng (时间戳+线程ID)
   ↓ 可预测种子
```

### 链2: Python Shell注入攻击链

```
1. build_opp_kernel_static.py
   ↓
2. subprocess.Popen(cmd, shell=True)
   ↓
3. f-string路径插值: f"cd {dir_path} && ..."
   ↓ shell元字符解析
4. 命令注入执行
```

### 链3: Python eval代码执行链

```
1. gen_data.py CLI调用
   ↓
2. sys.argv[1] -> shape
   ↓
3. eval(shape)
   ↓ 任意Python代码执行
```

---

## 5. 修复优先级矩阵

| 漏洞ID | 严重程度 | 利用难度 | 影面范围 | 修复优先级 |
|--------|----------|----------|----------|------------|
| VULN-001 | Critical | 低 | 测试脚本 | P1 |
| VULN-002 | Critical | 低 | 构建脚本 | P1 |
| VULN-003 | High | 中 | 生产算子 | P2 |
| VULN-004 | Medium | 中 | 测试脚本 | P3 |
| VULN-005 | Medium | 中 | 测试脚本 | P3 |
| VULN-006 | Low | 高 | 配置解析 | P4 |
| VULN-007 | Low | 高 | 测试代码 | P4 |

---

## 6. 建议措施

### 6.1 立即修复 (P1)

1. **禁用eval()**: 将`eval(sys.argv[1])`替换为`ast.literal_eval()`或JSON解析
2. **禁用shell=True**: 所有subprocess调用使用列表参数

### 6.2 高优先级修复 (P2)

1. **PRNG种子改进**: 使用`/dev/urandom`或`std::random_device`作为熵源
2. **文档警告**: 明确标注哪些算子不适合密码学应用

### 6.3 中优先级修复 (P3)

1. **getattr白名单**: 限制可访问的torch属性类型
2. **路径验证**: importlib加载前验证文件路径来源

### 6.4 低优先级修复 (P4)

1. **配置解析增强**: 添加大小限制和schema验证
2. **测试代码边界检查**: memcpy前验证buffer大小

---

## 7. 附录

### 7.1 Philox算法常数

```cpp
// golden ratio-derived constants
PHILOX_W32_A = 0x9E3779B9  // 2^32 / φ
PHILOX_W32_B = 0xBB67AE85  // 2^32 / (φ-1)

// multiplication constants
PHILOX_M4X32_A = 0xD2511F53
PHILOX_M4X32_B = 0xCD9E8D57
```

### 7.2 高风险文件列表

| 文件路径 | 漏洞类型 | 行号 |
|----------|----------|------|
| conversion/fill_diagonal_v2/tests/.../gen_data.py | eval() | 21 |
| scripts/util/modify_gen_aclnn_static.py | shell注入 | 20,45-50 |
| scripts/util/build_opp_kernel_static.py | shell注入 | 38,94-107,132-136 |
| scripts/package/common/py/packer.py | shell注入 | 215 |
| random/random_common/op_host/arch35/random_tiling_base.h | 弱熵源 | 26-42 |

### 7.3 RNG算子完整列表

- random_uniform_v2, random_uniform_int_v2
- random_standard_normal_v2
- stateless_random_uniform_v2, stateless_random_uniform_v3
- stateless_random_normal_v2, stateless_random_normal_v3
- stateless_randperm, stateless_bernoulli
- stateless_drop_out_gen_mask
- multinomial_with_replacement
- truncated_normal_v2
- drop_out_v3, drop_out_do_mask
- dsa_random_uniform, dsa_random_normal
- sim_thread_exponential

---

**报告生成**: OpenCode Vulnerability Scanner Architecture Agent
**数据库路径**: `/home/pwn20tty/Desktop/opencode_project/cann/1/ops-math/scan-results/.context/scan.db`