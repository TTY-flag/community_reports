# VULN-RNG-002：时间戳种子熵不足漏洞

## 漏洞摘要

**判定**：**TRUE POSITIVE - 真实漏洞**

该漏洞识别了PRNG种子生成机制中特定弱点，主要熵源是纳秒时间戳。虽然时间戳提供高分辨率时间，但对于能观察或估计执行时机的攻击者仍根本可预测。

---

## 漏洞详情

| 属性 | 值 |
|-----------|-------|
| **ID** | VULN-RNG-002 |
| **类型** | Timestamp-Based Seed Entropy |
| **CWE** | CWE-337: Predictable Seed in PRNG |
| **严重性** | HIGH |
| **置信度** | 90% |
| **状态** | 已确认 |
| **文件** | `random/random_common/op_host/arch35/random_tiling_base.h` |
| **行号** | 28-31 |
| **函数** | `GetGlobalRng()` |

---

## 技术分析

### 漏洞代码

```cpp
static inline std::mt19937_64& GetGlobalRng() {
    static std::mt19937_64 rng([]() -> uint64_t {
        auto now = std::chrono::high_resolution_clock::now();           // 第28行
        uint64_t seed = std::chrono::duration_cast<std::chrono::nanoseconds>(  // 第29行
            now.time_since_epoch()                                       // 第30行
        ).count();                                                        // 第31行

        seed ^= std::hash<std::thread::id>()(std::this_thread::get_id()); // 第33行
        return seed;
    }());
    return rng;
}
```

### 熵源分解

| 熵源 | 位数 | 可预测性 | 攻击面 |
|----------------|------|----------------|----------------|
| `high_resolution_clock::now()` | ~64位（纳秒epoch） | **可预测** - 攻击者可估计执行窗口 | HIGH |
| `thread::id`哈希 | 可变 | **可猜测** - 受控环境中通常为小整数 | MEDIUM |

### 为什么时间戳种子是脆弱的

1. **时间可观察**：系统时钟非秘密。攻击者可：
   - 观察进程启动时间
   - 从日志估计执行时机
   - 使用侧信道时间攻击
   - 在共享环境中控制执行调度

2. **纳秒精度不足够**：
   - 即使纳秒精度，时间可被缩小
   - 1微秒窗口 = 约1,000候选
   - 1毫秒窗口 = 约1,000,000候选（可暴力破解）
   - 输出的统计分析进一步减少候选

3. **静态初始化 = 单一种子**：
   - RNG用lambda初始化一次（`[]() -> uint64_t {...}()`）
   - 该种子持续整个进程生命周期
   - 种子妥协 = 所有输出的完整预测

---

## 数据流分析

```
┌─────────────────────────────────────────────────────────────────────┐
│                    种子生成链                            │
└─────────────────────────────────────────────────────────────────────┘

high_resolution_clock::now()    ◄── 可预测熵源
        │
        ▼
epoch以来的纳秒（64位）  ◄── 可被攻击者估计
        │
        ▼
与thread::id哈希XOR          ◄── 添加有限熵
        │
        ▼
std::mt19937_64初始化    ◄── Mersenne Twister（非密码安全）
        │
        ▼
静态rng实例               ◄── 单实例，持续进程生命周期
        │
        ▼
New64() → GetGlobalRng()()        ◄── 当seed=0, seed2=0时调用
        │
        ▼
GetKeyAndCounter()                ◄── Philox密钥/计数器派生
        │
        ▼
PhiloxRandomSimt（10轮）      ◄── 给定密钥时确定性的
        │
        ▼
随机输出（均匀、正态等）
```

---

## 攻击向量分析

### 攻击场景 1：时间侧信道

**前提条件**：
- 攻击者有带时间戳的系统日志访问
- 攻击者知道算子被调用无显式种子

**攻击步骤**：
1. 从日志识别目标算子调用时间戳
2. 估计执行窗口（日志通常毫秒精度）
3. 在窗口内暴力破解纳秒候选
4. 通过比较预测与实际随机输出过滤候选
5. 恢复精确种子值

**可行性**：
- 毫秒日志精度 → 约10^6候选
- 用少量观察输出 → 统计过滤到唯一种子
- **攻击时间**：分钟到小时，取决于并行化

### 攻击场景 2：受控环境执行

**前提条件**：
- 攻击者可触发目标算子执行
- 攻击者观察或控制进程调度

**攻击步骤**：
1. 以受控时机触发多次执行
2. 记录精确执行时间戳
3. 对每次执行计算精确种子
4. 预测每次执行的所有随机输出

**可行性**：
- **攻击时间**：实时（完美种子预测）

### 攻击场景 3：云/容器环境

**前提条件**：
- 目标运行在共享云基础设施
- 攻击者有同租户访问

**攻击步骤**：
1. 使用共享基础设施时间侧信道
2.估计邻居ML工作负载执行时机
3. 缩小种子候选
4. 若使用了seed=0则预测随机输出

**可行性**：
- 中等复杂度但文献中有记录
- **攻击时间**：小时到天

---

## 利用影响评估

### 受影响算子

| 算子 | 种子触发 | 下游影响 |
|----------|--------------|-------------------|
| `random_uniform_v2` | `seed=0, seed2=0` | 均匀分布完全可预测 |
| `random_standard_normal_v2` | `seed=0, seed2=0` | 正态分布完全可预测 |
| `random_uniform_int_v2` | `seed=0, seed2=0` | 整数随机值可预测 |
| `truncated_normal_v2` | `seed=0, offset=0` | 截断正态可预测 |

### 安全影响矩阵

| 用例 | 影响级别 | 描述 |
|----------|--------------|-------------|
| **ML模型训练** | MEDIUM-HIGH | 可预测dropout模式、权重初始化 |
| **差分隐私** | CRITICAL | 若种子可预测则隐私保证违反 |
| **密码采样** | CRITICAL | 密钥派生破坏可能 |
| **对抗鲁棒性** | HIGH | 可预测随机分量降低鲁棒性 |
| **模型水印** | HIGH | 水印方案可能被绕过 |

---

## 攻击复杂度分析

### 复杂度因素

| 因素 | 评估 |
|--------|------------|
| **所需知识** | 执行时机、线程行为 |
| **所需访问** | 系统级或侧信道 |
| **计算成本** | 中等（暴力破解候选搜索） |
| **检测风险** | 低（被动攻击） |

### CVSS v3.1 评分估算

| 指标 | 值 | 理由 |
|--------|-------|---------------|
| 攻击向量 | Local/Network | 取决于攻击向量 |
| 攻击复杂度 | Low/Medium | 需时间估计 |
| 所需权限 | Low | 系统观察访问 |
| 用户交互 | None | 自动利用 |
| 范围 | Changed | 影响下游系统 |
| 机密性影响 | High | 可预测随机 = 信息泄露 |
| 完整性影响 | High | 可预测输出 |
| 可用性影响 | Low | 无直接可用性影响 |

**估算CVSS**：7.1-8.2 (HIGH)

---

## 与相关漏洞对比 (VULN-RNG-001)

| 方面 | VULN-RNG-001 | VULN-RNG-002 |
|--------|--------------|--------------|
| **焦点** | PRNG弱点（CWE-338） | 种子熵（CWE-337） |
| **范围** | 整个GetGlobalRng函数 | 时间戳熵源 |
| **根因** | 使用Mersenne Twister | 可预测熵源 |
| **缓解优先级** | 替换PRNG | 改进熵源 |

**注**：VULN-RNG-002是VULN-RNG-001识别的更广泛弱点的**具体表现**。两者应一起解决。

---

## 缓解建议

### 立即行动

1. **添加硬件熵源**：
```cpp
#include <random>

static inline uint64_t GetSecureSeed() {
    std::random_device rd;  // 硬件熵源
    uint64_t seed = 0;
    seed |= static_cast<uint64_t>(rd()) << 32;
    seed |= static_cast<uint64_t>(rd());
    return seed;
}
```

2. **组合多熵源**：
```cpp
static inline std::mt19937_64& GetGlobalRng() {
    static std::mt19937_64 rng([]() -> uint64_t {
        // 硬件熵（主要）
        uint64_t seed = GetSecureSeed();
        
        // 混入时间戳（次要）
        auto now = std::chrono::high_resolution_clock::now();
        seed ^= std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()
        ).count();
        
        // 混入线程ID（第三）
        seed ^= std::hash<std::thread::id>()(std::this_thread::get_id());
        
        // 混入进程ID
        seed ^= static_cast<uint64_t>(getpid()) << 32;
        
        // 混入内存地址（ASLR熵）
        seed ^= reinterpret_cast<uint64_t>(&seed);
        
        return seed;
    }());
    return rng;
}
```

### 长期解决方案

1. **API分离**：为可复现与安全随机提供不同API
2. **CSPRNG迁移**：用密码安全PRNG替换Mersenne Twister
3. **文档**：清晰文档当前实现不适用于安全上下文
4. **熵监控**：添加熵质量的运行时检查

---

## 概念验证

### 种子恢复攻击（概念性）

```python
#!/usr/bin/env python3
"""
时间戳种子恢复的概念演示。
展示攻击者如何给定时间信息恢复种子。
"""

import hashlib
from datetime import datetime, timedelta

def estimate_seed_candidates(estimated_time: datetime, window_ms: int = 1000):
    """
    给定估计执行时间，生成候选种子。
    
    参数：
        estimated_time：RNG初始化的近似时间
        window_ms：搜索窗口毫秒（默认1秒）
    
    返回：
        候选种子值列表
    """
    # 转换为epoch以来的纳秒
    base_ns = int(estimated_time.timestamp() * 1_000_000_000)
    window_ns = window_ms * 1_000_000  # 毫秒转纳秒
    
    candidates = []
    for offset in range(-window_ns, window_ns + 1):
        timestamp_ns = base_ns + offset
        
        # 尝试常见线程ID（通常小整数）
        for thread_id in range(1, 50):
            # 简化线程ID哈希（实现各异）
            thread_hash = hash(thread_id) & 0xFFFFFFFFFFFFFFFF
            seed = timestamp_ns ^ thread_hash
            candidates.append(seed)
    
    return candidates

def filter_candidates_by_output(candidates: list, observed_value: int):
    """
    通过匹配观察到的随机输出过滤种子候选。
    
    参数：
        candidates：候选种子列表
        observed_value：RNG已知输出
    
    返回：
        产生观察输出的种子列表
    """
    import random
    matching = []
    
    for seed in candidates:
        rng = random.Random(seed)
        if rng.getrandbits(64) == observed_value:
            matching.append(seed)
    
    return matching

# 示例使用：
# candidates = estimate_seed_candidates(datetime(2026, 4, 21, 10, 30, 0), window_ms=100)
# matching = filter_candidates_by_output(candidates, observed_first_output)
# print(f"找到{len(matching)}个匹配种子")
```

### 攻击复杂度计算

对于**1毫秒时间窗口**：
- 纳秒候选：1,000,000
- 线程ID候选：约50（典型范围）
- 总候选：约50,000,000

用**统计过滤**使用2-3个观察输出：
- 通常减少到1-10个候选
- **攻击时间**：现代硬件上分钟级

---

## 参考文献

- **CWE-337**：Predictable Seed in Pseudo-Random Number Generator (PRNG)
- **NIST SP 800-90B**：Recommendation for the Entropy Sources Used for Random Bit Generation
- **RFC 4086**：Randomness Requirements for Security
- **Kim et al. (2012)**："Predicting the Seeds of Pseudo-Random Number Generators"

---

## 结论

**VULN-RNG-002是TRUE POSITIVE漏洞。**

时间戳种子生成代表熵源的根本弱点。虽然纳秒精度比秒级时间戳提供更多熵，但核心问题依然：**时间不是秘密**。能估计或观察执行时机的攻击者可显著缩小种子搜索空间。

该漏洞：
- **与VULN-RNG-001共存**（更广泛PRNG弱点）
- **在时间可观察环境有实际利用潜力**
- **影响依赖不可预测随机性的安全敏感应用**
- **需要架构修复**（硬件熵源）

**建议**：实现缓解建议中描述的硬件支持的熵混合。标记当前实现为密码或安全敏感用例不安全。

---

*分析日期：2026-04-21*
*扫描器：dataflow-module-scanner*
*置信度：90%*