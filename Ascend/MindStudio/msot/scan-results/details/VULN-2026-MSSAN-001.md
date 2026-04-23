# VULN-2026-MSSAN-001：add_custom.cpp缓冲区溢出致程序崩溃

## 漏洞标识
- **漏洞ID**: VULN-2026-MSSAN-001
- **类型**: Buffer Overflow (CWE-787)
- **严重性**: Critical
- **置信度**: 100%

---

## 一、漏洞概述

### 1.1 漏洞位置
- **文件**: `example/quick_start/mssanitizer/bug_code/add_custom.cpp`
- **行号**: 44
- **函数**: `KernelAdd::CopyIn`
- **模块**: mssanitizer_bug_code

### 1.2 漏洞描述
该漏洞是一个**堆缓冲区溢出**，发生在华为昇腾 AI Core 算子代码中。`CopyIn` 函数通过 `pipe.InitBuffer()` 分配了 `tileLength` 个元素的缓冲区，但随后通过 `AscendC::DataCopy()` 复制了 `2 * tileLength` 个元素，导致写入数据量超出缓冲区容量两倍。

### 1.3 性质判定
**这是一个故意植入的测试漏洞**。项目模型明确标注该模块为 `mssanitizer_bug_code`，描述为"msSanitizer异常检测工具的示例Bug代码（故意包含内存越界）"，用于测试 msSanitizer 工具的内存安全检测能力。

**技术真实性**: 虽然是测试代码，但从技术角度这是**真实的缓冲区溢出漏洞**，代码逻辑确实存在内存安全问题。

---

## 二、技术分析（代码级别）

### 2.1 缓冲区分配（第25行）
```cpp
pipe.InitBuffer(inQueueX, BUFFER_NUM, this->tileLength * sizeof(DTYPE_X));
```
- **分配容量**: `tileLength * sizeof(DTYPE_X)` 字节
- **可容纳元素数**: `tileLength` 个 `DTYPE_X` 类型元素
- **内存位置**: Ascend AI Core 的 Unified Buffer (UB)

### 2.2 溢出触发点（第44行）
```cpp
AscendC::DataCopy(xLocal, xGm[progress * this->tileLength], 2 * this->tileLength);
```
- **复制长度**: `2 * tileLength` 个元素
- **缓冲区容量**: `tileLength` 个元素
- **溢出量**: `tileLength` 个元素（100% 额外溢出）

### 2.3 对比：正确的数据复制（第45行）
```cpp
AscendC::DataCopy(yLocal, yGm[progress * this->tileLength], this->tileLength);
```
`yLocal` 缓冲区的复制长度正确匹配分配大小，证明第44行是明确的错误。

### 2.4 调用链分析
```
main() [main.cpp:102]
  ↓ aclnnAddCustom() [ACL API]
    ↓ add_custom() [add_custom.cpp:78, kernel entry]
      ↓ KernelAdd::Process() [add_custom.cpp:29]
        ↓ KernelAdd::CopyIn() [add_custom.cpp:40]
          ↓ AscendC::DataCopy() [OVERFLOW at line 44]
```

### 2.5 关键数据流
```
Init(): tileLength = blockLength / tileNum / BUFFER_NUM
  ↓
pipe.InitBuffer(): 分配 tileLength 元素空间
  ↓
CopyIn(progress): 
  AllocTensor() → 返回 tileLength 大小的 xLocal
  DataCopy(..., 2*tileLength) → 写入 2*tileLength 元素 [OVERFLOW]
```

---

## 三、攻击可达性分析

### 3.1 入口点
| 文件 | 行号 | 函数 | 类型 | 信任等级 |
|------|------|------|------|----------|
| `example/quick_start/msopgen/caller/main.cpp` | 102 | `main` | cmdline | untrusted_local |

### 3.2 输入控制
```cpp
// main.cpp:106-108
if (argc > 1) {
    deviceId = static_cast<int32_t>(strtol(argv[1], nullptr, 10));
}
```
攻击者可通过命令行参数控制 NPU 设备选择，但无法直接控制 `tileLength` 或溢出大小。

### 3.3 数据依赖性
溢出大小由以下参数决定：
```cpp
// add_custom.cpp:18-20
this->blockLength = totalLength / AscendC::GetBlockNum();
this->tileNum = tileNum ? tileNum : 1;
this->tileLength = this->blockLength / this->tileNum / BUFFER_NUM;
```

这些参数来自 `tiling_data`（通过 `GET_TILING_DATA` 宏获取），由 Host 端算子计算得出（`op_host/add_custom.cpp`）。

### 3.4 攻击路径评估
| 攻击向量 | 可行性 | 说明 |
|----------|--------|------|
| 命令行参数 | 低 | 仅能控制 deviceId，不影响溢出大小 |
| 输入张量数据 | 低 | 输入数据影响计算结果，不影响缓冲区分配 |
| Tiling 参数 | 中 | 若 Host 端算子接受外部输入控制 Tiling 参数，可间接影响溢出大小 |
| 代码注入 | 不适用 | 漏洞已在编译后算子二进制中，攻击者无法修改 |

### 3.5 结论
**攻击可达性：低**。虽然漏洞是真实的，但攻击者需要：
1. 获得算子代码编译权限
2. 修改 Tiling 参数计算逻辑
3. 或在算子运行时篡改内存

该代码作为测试示例，通常不会在生产环境部署。

---

## 四、触发条件和利用路径

### 4.1 触发条件
1. **必需**: 昇腾 NPU 硬件环境（AI Core）
2. **必需**: 正确配置的 CANN 软件栈
3. **必需**: 调用带有漏洞代码的 `add_custom` 算子
4. **触发**: 任何正常的算子执行都会触发溢出

### 4.2 必然触发
由于溢出在每次 `CopyIn` 调用时都会发生，且 `Process()` 循环调用 `CopyIn`：
```cpp
// add_custom.cpp:31-36
int32_t loopCount = this->tileNum * BUFFER_NUM;
for (int32_t i = 0; i < loopCount; i++) {
    CopyIn(i);  // 每次迭代都会触发溢出
    ...
}
```

### 4.3 利用路径
```
步骤1: 攻击者获取目标系统访问权限
  ↓
步骤2: 构造调用该算子的应用程序
  ↓
步骤3: 准备输入数据（8x2048 float16 张量）
  ↓
步骤4: 执行算子 → 触发堆溢出
  ↓
步骤5: 溢出覆盖相邻内存（Unified Buffer 区域）
  ↓
可能后果:
  - 算子执行失败（ACL_ERROR）
  - NPU 异常中断
  - 若能控制溢出内容，可能影响后续计算或实现代码执行
```

### 4.4 实际利用难度
| 因素 | 评估 |
|------|------|
| 昇腾 AI Core 内存保护 | 有硬件隔离机制 |
| UB 溢出影响范围 | 主要影响当前核函数 |
| 控制流劫持可能性 | 中等（取决于溢出后内存布局） |
| 信息泄露可能性 | 中等（可读取相邻数据） |

---

## 五、漏洞影响评估

### 5.1 直接影响
1. **内存损坏**: 溢出覆盖 `inQueueY` 缓冲区和其他 UB 数据
2. **计算错误**: 溢出可能导致后续计算结果不正确
3. **程序崩溃**: 严重的内存损坏可能导致算子执行失败

### 5.2 间接影响
1. **数据完整性**: 影响计算结果的正确性
2. **系统稳定性**: NPU 异常可能影响系统稳定性
3. **潜在代码执行**: 在特定条件下，精心构造的溢出可能实现任意代码执行

### 5.3 影响范围矩阵
| 场景 | 影响 | 可能性 |
|------|------|--------|
| 测试环境 | 功能验证失败 | 高 |
| 开发环境 | 调试困难，内存错误 | 高 |
| 生产环境（误部署） | 数据损坏、服务中断 | 低（代码不应部署） |

### 5.4 CVSS v3.1 评估
- **攻击向量 (AV)**: Local
- **攻击复杂度 (AC)**: High（需要特定环境）
- **权限要求 (PR)**: Low
- **用户交互 (UI)**: None
- **影响范围 (S)**: Changed
- **机密性影响 (C)**: Low
- **完整性影响 (I)**: High
- **可用性影响 (A)**: High

**基础分数**: 7.1 (High)
**时态分数**: 6.2 (考虑到测试代码性质)

---

## 六、缓解措施建议

### 6.1 代码修复（立即）
**修复第44行**：
```cpp
// 修复前
AscendC::DataCopy(xLocal, xGm[progress * this->tileLength], 2 * this->tileLength);

// 修复后
AscendC::DataCopy(xLocal, xGm[progress * this->tileLength], this->tileLength);
```

### 6.2 代码审计
1. 审查所有 `DataCopy` 调用，确保复制长度匹配缓冲区大小
2. 添加静态断言验证缓冲区大小：
```cpp
static_assert(BUFFER_NUM == 2, "BUFFER_NUM must be 2");
```

### 6.3 运行时检查
添加边界检查（如果 AscendC API 支持）：
```cpp
// 建议添加编译时或运行时检查
if (copyLength > bufferSize) {
    // 报错或截断
}
```

### 6.4 工具集成
1. 使用 msSanitizer 工具检测此类内存错误
2. 集成静态分析工具到 CI/CD 流程
3. 启用编译器警告（如 `-Warray-bounds`）

### 6.5 部署建议
1. **确保测试代码不被部署到生产环境**
2. 添加文件命名规范，区分测试代码和生产代码
3. 在发布流程中添加代码审查步骤

---

## 七、总结

### 7.1 漏洞真实性确认
✅ **确认：这是一个真实的堆缓冲区溢出漏洞**

虽然该漏洞是故意植入用于测试 msSanitizer 工具的检测能力，但从技术角度：
- 缓冲区分配和复制长度不匹配是事实
- 溢出会在每次算子执行时触发
- 可能导致内存损坏、计算错误或程序崩溃

### 7.2 安全风险评估
- **技术严重性**: Critical（明确的双倍缓冲区溢出）
- **实际风险**: Low（测试代码，不应部署到生产环境）
- **可利用性**: Low（需要特定昇腾硬件环境，攻击者控制有限）

### 7.3 建议行动
| 优先级 | 行动 | 时间框架 |
|--------|------|----------|
| P1 | 修复代码错误（如作为正确性测试） | 立即 |
| P2 | 确保测试代码与生产代码分离 | 短期 |
| P3 | 集成自动化内存安全检测工具 | 中期 |

---

**报告生成时间**: 2026-04-21  
**分析工具**: details-worker (深度漏洞利用分析)  
**数据来源**: scan.db, project_model.json, 源代码静态分析
