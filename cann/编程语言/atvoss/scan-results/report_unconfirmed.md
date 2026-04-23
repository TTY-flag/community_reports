# 漏洞扫描报告 — 待确认漏洞

**项目**: ATVOSS
**扫描时间**: 2026-04-22T02:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 9 | 47.4% |
| LIKELY | 5 | 26.3% |
| POSSIBLE | 4 | 21.1% |
| CONFIRMED | 1 | 5.3% |
| **总计** | **19** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 14.3% |
| Medium | 5 | 71.4% |
| Low | 1 | 14.3% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 9 | - |

### 1.3 Top 10 关键漏洞

1. **[DF-011]** NULL Pointer Dereference (High) - `include/utils/tensor.h:26` @ `Tensor -> DeviceTensor -> TransformArgs -> KernelCustom` | 置信度: 55
2. **[VULN-SEC-MEM-002]** buffer_overflow (Medium) - `include/elewise/device/device_tensor.h:28` @ `DeviceTensor::operator[]` | 置信度: 65
3. **[VULN-SEC-TYPE-001]** type_conversion_issue (Medium) - `include/evaluator/eval_base.h:63` @ `Evaluator<Param>::operator()` | 置信度: 65
4. **[DF-002]** Buffer Overflow (Medium) - `include/elewise/device/device_tensor.h:28` @ `DeviceTensor::operator[]` | 置信度: 65
5. **[DF-012]** Buffer Overflow (Medium) - `include/elewise/device/device_tensor.h:28` @ `DeviceTensor::operator[] -> evaluator.Assign` | 置信度: 45
6. **[VULN-SEC-XMOD-002]** error_propagation_chain (Medium) - `include/elewise/device/device_adapter.h:21` @ `CHECK_ACL` | 置信度: 40
7. **[DF-010]** Integer Overflow (Low) - `include/operators/math_expression.h:188` @ `Cast -> OpCast -> Evaluator` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `DeviceAdapter::Run@include/elewise/device/device_adapter.h` | rpc | semi_trusted | 作为库的主要入口点，由调用方应用程序控制。调用方需要提供 tensor 数据和参数，如果调用方处理不当可能导致安全问题，但攻击者无法直接触达此入口。 | Device 层主入口，完成 kernel 启动、ACL 资源管理、数据传输 |
| `PyInit__C@examples/python_extension/csrc/extension.cpp` | decorator | semi_trusted | Python C 扩展初始化入口，由 Python runtime 调用。攻击者需要能够控制 Python 环境才能触达，属于本地攻击场景。 | Python C 扩展模块初始化函数 |
| `CMakeBuildCommand.run@examples/python_extension/setup.py` | cmdline | trusted_admin | 构建脚本入口，由开发者/部署人员执行。环境变量（NPU_ARCH）由管理员控制，不属于运行时攻击面。 | Python 扩展构建命令，使用环境变量配置编译 |

**其他攻击面**:
- Python C Extension API: PyInit__C() - 本地攻击场景
- DeviceAdapter Run Interface - 由调用方应用程序控制
- Environment Variable Injection: NPU_ARCH, TORCH_NPU_PATH - 构建时风险
- Expression Template Processing - 编译期数据流处理

---

## 3. High 漏洞 (1)

### [DF-011] NULL Pointer Dereference - Tensor -> DeviceTensor -> TransformArgs -> KernelCustom

**严重性**: High | **CWE**: CWE-476 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `include/utils/tensor.h:26-48` @ `Tensor -> DeviceTensor -> TransformArgs -> KernelCustom`
**模块**: cross_module
**跨模块**: utils → elewise → device

**描述**: Cross-module null pointer chain: Tensor accepts null dataPtr, DeviceTensor wraps it, TransformArgs passes pointer to kernel, kernel may dereference null on device.

**达成路径**

utils.Tensor.dataPtr -> elewise.DeviceTensor.ptr_ -> device_adapter.TransformArgs -> KernelCustom kernel args

**验证说明**: 跨模块空指针链完整：Tensor(utils)接受nullptr->DeviceTensor(elewise)包装->TransformArgs传递->kernel参数。调用方(semi_trusted)可传入空指针，设备端可能空指针解引用。DeviceTensor::operator[]和GetPtr()都有空指针检查，但TransformArgs未检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (5)

### [VULN-SEC-MEM-002] buffer_overflow - DeviceTensor::operator[]

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-119 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `include/elewise/device/device_tensor.h:28-35` @ `DeviceTensor::operator[]`
**模块**: elewise

**描述**: DeviceTensor::operator[] 无边界检查直接访问设备内存指针。operator[] 直接返回 ptr_[pos]，没有检查 pos 是否在有效范围内。如果调用方传入超出有效范围的 pos 值，可能导致缓冲区越界读取或写入。

**漏洞代码** (`include/elewise/device/device_tensor.h:28-35`)

```c
T& operator[](std::size_t pos) { return ptr_[pos]; }
const T& operator[](std::size_t pos) const { return ptr_[pos]; }
```

**达成路径**

调用方传入 pos -> DeviceTensor::operator[] -> ptr_[pos] (无边界检查)

**验证说明**: 1. operator[] 无边界检查确实存在\n2. 数据流可达：arguments -> DeviceAdapter::Run -> PrepareParams -> DeviceTensor -> operator[]\n3. 但 tiling 系统控制 tile 大小，pos 值由编译期模板和 tiling 计算决定\n4. 调用方控制 shape，有部分可控性\n5. 入口点信任等级 semi_trusted（调用方应用程序控制）

**评分明细**: base_score: 30 | reachability: indirect_external | reachability_score: 20 | controllability: partial | controllability_score: 15 | mitigations:  | mitigation_score: 0 | context:  | context_score: 0 | cross_file: chain_complete | cross_file_score: 0 | final_score: 65

---

### [VULN-SEC-TYPE-001] type_conversion_issue - Evaluator<Param>::operator()

**严重性**: Medium | **CWE**: CWE-681 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `include/evaluator/eval_base.h:63-69` @ `Evaluator<Param>::operator()`
**模块**: evaluator
**跨模块**: device,kernel,block,tile,evaluator

**描述**: 表达式评估器中对 IN 参数进行 static_cast 强制类型转换。对于 IN 参数，如果不是相同类型，直接使用 static_cast<T> 进行类型转换。可能导致数据精度问题、数值溢出或意外的行为。

**漏洞代码** (`include/evaluator/eval_base.h:63-69`)

```c
if constexpr (std::is_same_v<T, NthType> || ...) {
    return AscendC::Std::get<index>(context.argsTensors);
} else {
    static_assert(U == ParamUsage::IN, "...");
    return static_cast<T>(AscendC::Std::get<index>(context.argsTensors));
}
```

**达成路径**

context.argsTensors -> static_cast<T> -> 返回转换后的值

**验证说明**: Verified: static_cast implicit type conversion for IN parameters. Compile-time static_assert restricts to IN params only. No runtime validation. Risk: precision loss, integer overflow, sign conversion issues. Call chain: DeviceAdapter::Run -> TileEvaluate::Run -> Evaluator::operator()

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: _ | 30: e | 31: x | 32: t | 33: e | 34: r | 35: n | 36: a | 37: l | 38: ) | 39: : | 40: 3 | 41: 0 | 42:   | 43: + | 44:   | 45: c | 46: o | 47: n | 48: t | 49: r | 50: o | 51: l | 52: l | 53: a | 54: b | 55: i | 56: l | 57: i | 58: t | 59: y | 60: ( | 61: p | 62: a | 63: r | 64: t | 65: i | 66: a | 67: l | 68: ) | 69: : | 70: 1 | 71: 5 | 72:   | 73: - | 74:   | 75: m | 76: i | 77: t | 78: i | 79: g | 80: a | 81: t | 82: i | 83: o | 84: n | 85: ( | 86: t | 87: y | 88: p | 89: e | 90: _ | 91: c | 92: h | 93: e | 94: c | 95: k | 96: ) | 97: : | 98: 1 | 99: 0 | 100:   | 101: = | 102:   | 103: 6 | 104: 5

---

### [DF-002] Buffer Overflow - DeviceTensor::operator[]

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-119 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `include/elewise/device/device_tensor.h:28-35` @ `DeviceTensor::operator[]`
**模块**: elewise

**描述**: DeviceTensor::operator[] lacks bounds checking. Accessing position pos beyond tensor size causes buffer overflow.

**验证说明**: operator[] 无边界检查，tiling 系统控制访问范围，部分可控

**评分明细**: base_score: 30 | reachability: indirect_external | reachability_score: 20 | controllability: partial | controllability_score: 15 | final_score: 65

---

### [DF-012] Buffer Overflow - DeviceTensor::operator[] -> evaluator.Assign

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-119 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `include/elewise/device/device_tensor.h:28-35` @ `DeviceTensor::operator[] -> evaluator.Assign`
**模块**: cross_module
**跨模块**: elewise → tile → evaluator → common

**描述**: Cross-module buffer overflow chain: DeviceTensor operator[] lacks bounds check, called by evaluator during tile execution, may overflow based on elementNum from ContextData.

**达成路径**

elewise.DeviceTensor.operator[] -> tile.TileEvaluate -> evaluator.Evaluator -> ContextData.elementNum

**验证说明**: 跨模块缓冲区溢出链：DeviceTensor::operator[]无边界检查，被evaluator调用。elementNum来自内部tiling计算而非直接外部输入，攻击者控制程度有限。DeviceTensor有空指针检查但无边界检查。降级为Medium。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-XMOD-002] error_propagation_chain - CHECK_ACL

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-252 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `include/elewise/device/device_adapter.h:21-27` @ `CHECK_ACL`
**模块**: cross_module
**跨模块**: elewise → kernel → block → tile → evaluator

**描述**: 跨模块错误传播链断裂：CHECK_ACL 宏在 elewise 模块中只打印错误不中断执行，导致 ACL 错误被静默忽略。后续的 Kernel 启动（kernel/builder.h）、Block 分解（block/builder.h）、Tile 计算（tile/tile_evaluate.h）和 Evaluator 执行（evaluator/eval_base.h）都在错误状态继续执行，可能导致数据损坏或计算结果错误。错误从 elewise 模块传播到 kernel/block/tile/evaluator 模块但未被正确处理。

**漏洞代码** (`include/elewise/device/device_adapter.h:21-27`)

```c
#define CHECK_ACL(x) do { aclError __ret = x; if (__ret != ACL_ERROR_NONE) { std::cerr << ...; } } while (0)
// 错误后继续执行，传播到 kernel/block/tile/evaluator
```

**达成路径**

[ERROR_FLOW] DeviceAdapter::Run -> CHECK_ACL 打印错误 -> LaunchKernelWithDataTuple -> KernelCustom -> KernelBuilder::Run -> BlockBuilder::Run -> TileEvaluate::Run -> Evaluator (错误状态继续执行)

**验证说明**: 错误传播链完整：CHECK_ACL在elewise只打印错误不中断，错误传播到kernel/block/tile/evaluator。但这是设计决策而非漏洞，ACL错误后继续执行可能导致数据损坏但不会直接崩溃。降级为Medium。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [DF-010] Integer Overflow - Cast -> OpCast -> Evaluator

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `include/operators/math_expression.h:188-198` @ `Cast -> OpCast -> Evaluator`
**模块**: cross_module
**跨模块**: operators → expression → graph → evaluator

**描述**: Cross-module Cast overflow chain: operators Cast creates OpCast expression, passes through graph linearizer, evaluator executes static_cast at runtime. Precision loss may propagate across modules.

**达成路径**

operators.Cast -> expression.OpCast -> graph.ExprLinearizer -> evaluator.static_cast

**验证说明**: 跨模块Cast溢出链完整：operators.Cast->OpCast->ExprLinearizer->Evaluator.static_cast。static_cast在编译期确定，运行时只执行类型转换。精度损失属于语义问题而非安全漏洞，不会导致内存损坏。降级为Low。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 1 | 2 | 1 | 4 |
| elewise | 0 | 0 | 2 | 0 | 2 |
| evaluator | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **1** | **5** | **1** | **7** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-119 | 3 | 42.9% |
| CWE-681 | 1 | 14.3% |
| CWE-476 | 1 | 14.3% |
| CWE-252 | 1 | 14.3% |
| CWE-190 | 1 | 14.3% |
