# VULN-RNG-004：自动种子生成条件漏洞

## 漏洞摘要

**判定**：**真实漏洞**（已确认）
**分类**：CWE-339 - Use of Random Seed derived from Previous Seed in Pseudo-Random Number Generator
**严重性**：High
**攻击复杂度**：Medium
**实际影响**：中等到高，取决于使用上下文

---

## 1. 漏洞概述

### 1.1 技术描述

该漏洞存在于CANN ops-math库中多个RNG算子使用的自动种子生成机制。当提供`seed=0`和`seed2=0`（**默认值**）时，系统使用`New64()`函数自动生成种子：

```cpp
// 位置：random/random_common/op_host/arch35/random_tiling_base.h:87-90
if (seed == 0 && seed2 == 0) {
    seed = static_cast<int64_t>(New64());
    seed2 = static_cast<int64_t>(New64());
}
```

### 1.2 根因分析

`New64()`函数从**可预测熵源**派生种子：

```cpp
// 位置：random/random_common/op_host/arch35/random_tiling_base.h:26-43
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

**熵源分解**：
- 主要：`high_resolution_clock::now()` - epoch以来纳秒时间戳
- 次要：`std::hash<std::thread::id>()` - 线程ID哈希
- RNG引擎：`std::mt19937_64` - Mersenne Twister（非密码安全）

---

## 2. 攻击向量分析

### 2.1 主要攻击向量：基于时间的种子预测

**攻击场景**：
```
时间线：
┌─────────────────────────────────────────────────────────────────────┐
│ T0：进程启动（种子初始化）                             │
│     seed_global = nanoseconds(T0) XOR hash(thread_id)               │
│     mt19937_64以此值播种                                │
├─────────────────────────────────────────────────────────────────────┤
│ T1：算子调用1（seed=0, seed2=0）                               │
│     auto_seed1 = mt19937_64.output[0]                               │
│     auto_seed2 = mt19937_64.output[1]                               │
├─────────────────────────────────────────────────────────────────────┤
│ T2：算子调用2（seed=0, seed2=0）                               │
│     auto_seed3 = mt19937_64.output[2]                               │
│     auto_seed4 = mt19937_64.output[3]                               │
├─────────────────────────────────────────────────────────────────────┤
│ 攻击者知道：近似T0 + 可观察输出                 │
│ 攻击者可：预测auto_seed序列                            │
└─────────────────────────────────────────────────────────────────────┘
```

**利用要求**：
1. 近似进程启动时间知识（日志中通常可用）
2. 观察一些随机输出能力（如模型初始化值）
3. 统计分析能力

### 2.2 次要攻击向量：Mersenne Twister状态恢复

**技术细节**：
Mersenne Twister（MT19937_64）有已知漏洞：**624连续64位输出可完整恢复内部状态**。

```
攻击流程：
1. 收集624连续New64()输出
2. 应用MT19937状态恢复算法
3. 重构完整内部状态
4. 以完美精度预测所有未来输出
```

**恢复算法参考**：
MT19937去扭曲算法可逆向输出变换：
- 逆向扭曲变换（位移和XOR）
- 恢复312个64位内部状态字
- 继续预测未来输出

### 2.3 多算子关联攻击

**受影响算子**（都使用相同全局PRNG）：

| 算子 | 触发条件 | 种子生成 |
|----------|-------------------|-----------------|
| `random_uniform_v2` | seed=0, seed2=0 | New64() × 2 |
| `random_uniform_int_v2` | seed=0, seed2=0 | New64() × 2 |
| `random_standard_normal_v2` | seed=0, seed2=0 | New64() × 2 |
| `truncated_normal_v2` | seed=0, offset=0 | New64() × 2 |

**关联风险**：
多个算子以默认种子调用将从同一全局PRNG接收**连续种子**，在其输出间创建确定性关联。

---

## 3. 攻击路径分析

### 3.1 完整攻击链

```
阶段1：情报收集
┌──────────────────────────────────────────────────────────────────────┐
│ 1. 识别使用CANN RNG算子的目标应用              │
│ 2. 确定算子是否使用默认种子（seed=0, seed2=0）        │
│ 3. 从以下收集时间信息：                                   │
│    - 进程日志（启动时间戳）                                 │
│    - 系统监控                                               │
│    - 训练作业元数据                                           │
└──────────────────────────────────────────────────────────────────────┘
                                     ↓
阶段2：种子空间缩小
┌──────────────────────────────────────────────────────────────────────┐
│ 1. 基于时间窗口估计初始种子范围               │
│    示例：若时间窗口为±1秒                            │
│    → 种子范围：约10^9可能值（1秒内纳秒）    │
│ 2. 应用线程ID哈希约束                                  │
│    → 进一步减少种子空间                                      │
└──────────────────────────────────────────────────────────────────────┘
                                     ↓
阶段3：输出关联分析
┌──────────────────────────────────────────────────────────────────────┐
│ 1. 观察目标算子RNG输出                         │
│ 2. 使用Philox密钥/计数器派生公式：                        │
│    key[0] = seed & 0xFFFFFFFF                                        │
│    key[1] = (seed >> 32) & 0xFFFFFFFF                                │
│ 3. 关联输出与候选种子                           │
└──────────────────────────────────────────────────────────────────────┘
                                     ↓
阶段4：种子恢复与预测
┌──────────────────────────────────────────────────────────────────────┐
│ 1. 通过统计关联识别正确种子            │
│ 2. 重构完整PRNG状态                                      │
│ 3. 预测未来RNG输出                                       │
│ 4. 在下游应用利用                                 │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Philox密钥/计数器推导

种子生成后，Philox计数器RNG初始化：

```cpp
// 位置：random_tiling_base.h:91-97
constexpr uint32_t SHIFT_BITS = 32;
key[0] = static_cast<uint32_t>(seed);
key[1] = static_cast<uint32_t>(seed >> SHIFT_BITS);
counter[0] = 0;
counter[1] = 0;
counter[2] = static_cast<uint32_t>(seed2);
counter[3] = static_cast<uint32_t>(seed2 >> SHIFT_BITS);
```

**安全影响**：
- Philox是**确定性PRNG**：相同密钥/计数器 → 相同输出
- 若种子被预测，所有输出完美可预测
- 10轮Philox变换密码强度高，但种子安全是瓶颈

---

## 4. 实际利用场景

### 4.1 ML训练可复现性攻击

**场景**：可复现性重要的竞争ML挑战

```
攻击步骤：
1. 定位竞争对手训练作业
2. 从作业调度器日志记录训练开始时间
3. 观察初始模型输出（为可复现性发布）
4. 反向工程自动生成种子
5. 重现竞争对手确切训练轨迹
6. 获得竞争优势
```

**影响**：可复现性保证丧失，潜在不公平优势

### 4.2 安全敏感应用攻击

**场景**：应用使用RNG用于安全目的

```
潜在用途：
- 随机密钥生成
- 会话标识符创建  
- 密码nonce生成
- 随机化算法初始化

风险：
若开发者使用CANN RNG算子以默认种子用于安全目的，
可预测种子生成可导致：
- 弱密码密钥
- 可预测会话令牌
- 会话劫持漏洞
```

**影响**：高 - 密码破坏可能

### 4.3 模型初始化操纵

**场景**：利用可预测模型初始化

```
攻击步骤：
1. 识别使用默认种子RNG进行权重初始化的目标ML模型
2. 确定训练启动窗口
3. 预测初始化种子序列
4. 基于已知初始化模式构造对抗样本
5. 利用模型漏洞
```

**影响**：模型鲁棒性退化，对抗漏洞

---

## 5. 攻击复杂度评估

| 因素 | 评级 | 详情 |
|--------|--------|---------|
| 时间信息访问 | Medium | 通常在日志、作业元数据中可用 |
| 输出观察 | Variable | 取决于应用架构 |
| 统计分析 | Medium | 标准PRNG分析技术 |
| 实现努力 | Low | 已知MT19937恢复算法存在 |
| **整体复杂度** | **Medium** | 需时间+观察能力 |

---

## 6. 影响评估

### 6.1 严重性分解

| 影响类别 | 评级 | 理由 |
|-----------------|--------|---------------|
| ML应用 | Moderate | 影响可复现性，非灾难性 |
| 密码使用 | High | 违反安全假设 |
| 竞争ML | High | 潜在不公平优势 |
| 系统完整性 | Low | 无直接系统妥协 |
| 数据暴露 | Low | RNG本身无数据泄露 |

### 6.2 受影响算子总结

**确认受影响**（通过代码分析验证）：

1. `random_uniform_v2` - 通过`GetKeyAndCounter<SEED_INDEX, SEED_INDEX2>`
2. `random_uniform_int_v2` - 通过直接New64()调用
3. `random_standard_normal_v2` - 通过`GetKeyAndCounter<1, 2>`
4. `truncated_normal_v2` - 通过`config.getSeedAndOffset` lambda

**潜在受影响**（相同模式可能存在）：
- `stateless_random_uniform_v3`
- `stateless_random_normal_v3`
- 其他使用默认种子行为的RNG算子

---

## 7. 概念验证（概念性）

### 7.1 基于时间的攻击演示

```python
# 概念攻击演示
import numpy as np
from datetime import datetime

# 假设攻击者知道近似启动时间
estimated_start_window = 1.0  # 秒

# 计算种子搜索空间
nanoseconds_per_second = 1e9
seed_search_space = int(nanoseconds_per_second * estimated_start_window)

# 对每个候选种子：
for candidate_seed in range(seed_search_space):
    # 用候选初始化MT19937
    rng_state = recover_mt19937_state(candidate_seed)
    
    # 生成预测输出
    predicted_outputs = generate_mt19937_outputs(rng_state, 10)
    
    # 与观察输出关联
    correlation = compute_correlation(predicted_outputs, observed_outputs)
    
    if correlation > threshold:
        print(f"种子恢复：{candidate_seed}")
        break
```

### 7.2 状态恢复攻击参考

```python
# MT19937状态恢复算法（参考）
def untemper(y):
    y ^= y >> 29
    y ^= (y << 17) & 0xEFB71D5BD5B5E5B
    y ^= (y << 37) & 0xECFFD9FFF9F3F
    y ^= y >> 43
    return y

def recover_state(outputs):
    """从624连续输出恢复MT19937状态"""
    state = [untemper(o) for o in outputs[:312]]
    return state
```

---

## 8. 缓解建议

### 8.1 主要建议

**1. 替换熵源**：

```cpp
// 推荐：使用密码熵源
#include <unistd.h>
#include <fcntl.h>

inline uint64_t SecureNew64() {
    uint64_t seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &seed, sizeof(seed));
        close(fd);
        return seed;
    }
    // 回退到random_device
    std::random_device rd;
    return rd();
}
```

**2. 每算子种子独立**：

```cpp
// 每个算子应有独立播种
// 避免共享全局PRNG状态
inline uint64_t OperatorSpecificNew64() {
    std::random_device rd;
    std::mt19937_64 local_rng(rd());
    return local_rng();
}
```

**3. 文档警告**：

在算子文档中添加显式警告：
```
"警告：当使用seed=0和seed2=0（默认行为）时，
自动生成种子从系统时间派生，
不适用于密码或安全敏感应用。
为可复现结果，显式提供非零种子值。"
```

### 8.2 次要建议

- 为生成种子添加熵质量测试
- 实现每会话种子唯一性跟踪
- 为安全敏感应用提供安全RNG API变体

---

## 9. 结论

### 9.1 漏洞分类

**VULN-RNG-004是真实漏洞**，因为：

1. **可预测熵源**：时间戳+线程ID提供有限熵
2. **全局PRNG状态共享**：多算子通过共享状态关联
3. **符合CWE-339**：种子从之前可预测PRNG输出派生
4. **真实攻击潜力**：基于时间预测+MT状态恢复可行

### 9.2 风险评估

| 指标 | 值 |
|--------|-------|
| 严重性 | High |
| 置信度 | 95% |
| 可利用性 | Medium |
| 业务影响 | Moderate-High |
| 补丁优先级 | P2 |

### 9.3 最终建议

**所需行动**：在安全敏感环境生产部署前，为自动种子生成实现安全熵源。对于仅ML应用，显式文档可预测性限制。

---

## 10. 技术参考文献

- CWE-339：https://cwe.mitre.org/data/definitions/339.html
- MT19937状态恢复：https://github.com/kmyk/mersenne-twister-recover
- Philox RNG论文："Parallel Random Numbers: As Easy as 1, 2, 3" (Salmon et al.)
- CANN文档：Seed/seed2默认行为规范

---

**分析日期**：2026-04-21
**分析者**：OpenCode漏洞扫描器 - Details Worker Agent
**数据库记录**：VULN-RNG-004 | 已验证 | dataflow-module-scanner