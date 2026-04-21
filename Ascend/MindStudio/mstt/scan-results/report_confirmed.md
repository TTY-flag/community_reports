# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio Training Tools (mstt)  
**扫描时间**: 2026-04-21T12:00:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞  

---

## 执行摘要

本次漏洞扫描对 MindStudio Training Tools (mstt) 项目进行了全面的安全审计。该项目是一个 AI 模型训练调试工具集，包含 Python CLI 工具、TensorBoard 可视化插件和 C++ 扩展模块。

### 关键发现

本次扫描共发现 **27 个候选漏洞**，经验证后确认 **1 个真实漏洞**：

| 分类 | 数量 | 说明 |
|------|------|------|
| **CONFIRMED** | 1 | 已确认的真实漏洞，需要立即修复 |
| LIKELY | 6 | 存在缓解措施，需评估风险 |
| POSSIBLE | 6 | 需进一步调查 |
| FALSE_POSITIVE | 14 | 已确认为误报或已缓解 |

### 已确认漏洞概要

| 漏洞ID | 类型 | 严重性 | 模块 | CWE | 状态 |
|--------|------|--------|------|-----|------|
| VULN-DF-CPP-msprobe_ccsrc-004 | 越界读取 | **High** | msprobe_ccsrc | CWE-125 | CONFIRMED |

### 主要风险点

1. **NPU 硬件交互边界缺乏验证**: C++ 扩展模块在处理来自 Ascend NPU 硬件的数据时，未进行边界检查，可能导致越界内存读取和信息泄露

2. **TensorBoard 网络暴露风险**: 当使用 `--bind_all` 参数时，19 个 REST API 端点无认证机制暴露到网络

3. **代码注入风险点**: 多处使用 `eval()` 执行动态代码，虽有白名单缓解，但配置文件篡改可绕过

### 建议优先级

| 优先级 | 漏洞 | 建议 |
|--------|------|------|
| **立即修复** | VULN-DF-CPP-msprobe_ccsrc-004 | 在 `DumpOpDebugDataToDisk()` 添加边界检查 |
| 高优先级 | LIKELY 类别 | 评估 TensorBoard 端点和 eval() 风险 |
| 中优先级 | POSSIBLE 类别 | 审查命令注入和库加载路径 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 51.9% |
| POSSIBLE | 6 | 22.2% |
| LIKELY | 6 | 22.2% |
| CONFIRMED | 1 | 3.7% |
| **总计** | **27** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CPP-msprobe_ccsrc-004]** out_of_bounds_read (High) - `debug/accuracy_tools/msprobe/ccsrc/core/AclDumpDataProcessor.cpp:452` @ `DumpOpDebugDataToDisk` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@debug/accuracy_tools/msprobe/msprobe.py` | cmdline | untrusted_local | 命令行入口，接收用户提供的框架参数、路径参数等，通过sys.argv直接索引解析 | msprobe CLI主入口，支持compare/run_ut/api_precision_compare等子命令 |
| `msprof_analyze_cli@profiler/msprof_analyze/cli/entrance.py` | cmdline | untrusted_local | Click框架CLI入口，接收profiling路径、输出路径等参数，可被本地用户控制 | msprof-analyze CLI主入口，支持advisor/compare/cluster子命令 |
| `__parse_command@msfmktransplt/src/ms_fmk_transplt/ms_fmk_transplt.py` | cmdline | untrusted_local | argparse CLI入口，接收input/output路径和version参数 | PyTorch GPU到NPU迁移工具CLI入口 |
| `args_parse@profiler/affinity_cpu_bind/bind_core.py` | cmdline | untrusted_local | argparse CLI，接收--application参数直接执行用户命令，存在命令注入风险 | CPU绑核工具CLI，可通过--application参数启动任意进程 |
| `main@profiler/tinker/tinker_auto_parallel.py` | cmdline | untrusted_local | argparse CLI入口，接收模型配置和profiling路径 | Tinker自动并行策略寻优工具入口 |
| `get_plugin_apps@plugins/tensorboard-plugins/tb_graph_ascend/server/plugin.py` | web_route | untrusted_network | TensorBoard HTTP插件，创建19个REST API端点，默认绑定localhost但可通过--bind_all暴露到网络 | 模型可视化TensorBoard插件HTTP端点 |
| `load_meta_dir@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | GET端点，扫描logdir目录返回.vis文件列表 | HTTP GET端点 - 加载元数据目录 |
| `load_graph_data@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | GET端点，接收run/tag/type查询参数加载图数据 | HTTP GET端点 - 加载图可视化数据 |
| `load_graph_config_info@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | POST端点，接收JSON payload解析metaData | HTTP POST端点 - 加载图配置信息 |
| `save_data@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | POST端点，可写入数据到服务器文件系统 | HTTP POST端点 - 保存图数据（文件写入操作） |
| `forward@debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py` | decorator | semi_trusted | eval()执行动态PyTorch算子，self.op来自YAML配置文件 | 动态算子执行 - eval代码注入风险点 |
| `generate_code@debug/accuracy_tools/msprobe/mindspore/api_accuracy_checker/generate_op_script/operator_replication.template` | file | semi_trusted | eval(data_dtype)从配置数据中解析dtype字符串 | 模板代码生成中的eval()调用 |
| `get_rank_id@debug/accuracy_tools/msprobe/ccsrc/base/Environment.cpp` | env | untrusted_local | 读取RANK_ID环境变量 | C++环境变量读取 - RANK_ID |
| `get_log_level@debug/accuracy_tools/msprobe/ccsrc/base/ErrorInfosManager.cpp` | env | untrusted_local | 读取MSPROBE_LOG_LEVEL环境变量 | C++环境变量读取 - MSPROBE_LOG_LEVEL |
| `load_acl_library@debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp` | file | semi_trusted | dlopen加载libascendcl.so等动态库 | 动态库加载 - ACL API |
| `parse_config@debug/accuracy_tools/msprobe/ccsrc/base/DebuggerConfig.cpp` | file | semi_trusted | 解析外部JSON配置文件，使用re2正则表达式 | JSON配置文件解析 |
| `requeue_job@msfmktransplt/test/msFmkTransplt/resources/net/barlowtwins_amp/main.py` | env | untrusted_local | os.system()执行包含环境变量SLURM_JOB_ID的shell命令 | os.system命令注入 - SLURM环境变量 |

**其他攻击面**:
- CLI接口: msprobe/mprof-analyze/msfmktransplt/tinker/bind_core (命令行参数注入风险)
- HTTP接口: TensorBoard插件graph_ascend (19个REST端点，无认证)
- 文件输入: JSON/YAML配置文件解析、NPY数据加载
- 环境变量: RANK_ID/MSPROBE_LOG_LEVEL/SLURM_JOB_ID
- 动态库加载: dlopen加载libascendcl.so/libmindspore_ascend.so
- Python C扩展: ccsrc模块与Python交互边界
- 代码注入: eval()在wrap_aten.py和operator_replication.template
- 进程执行: subprocess.Popen/run在bind_core.py/profile_space.py

---

## 3. High 漏洞详细分析 (1)

### [VULN-DF-CPP-msprobe_ccsrc-004] Out-of-Bounds Read - DumpOpDebugDataToDisk

#### 基本信息

| 属性 | 值 |
|------|-----|
| **严重性** | High |
| **CWE** | CWE-125 (Out-of-bounds Read) |
| **置信度** | 80/100 |
| **状态** | CONFIRMED |
| **来源** | dataflow-scanner |
| **位置** | `debug/accuracy_tools/msprobe/ccsrc/core/AclDumpDataProcessor.cpp:452-471` |
| **模块** | msprobe_ccsrc |

#### 漏洞描述

`DumpOpDebugDataToDisk()` 函数处理来自 Ascend NPU 硬件的溢出调试数据时，使用固定偏移量常量读取数据缓冲区，但**完全忽略了传入的 `dataLen` 参数**，未进行任何边界检查。当 NPU 返回的数据量小于预期时，会导致越界内存读取。

#### 根因分析

**函数签名**:
```cpp
static DebuggerErrno DumpOpDebugDataToDisk(
    const std::string& dumpPath, 
    AclDumpMsg::DumpData& dumpData,
    const uint8_t* data, 
    size_t dataLen  // ⚠️ 此参数从未被使用
)
```

**问题代码片段 (L452-471)**:
```cpp
uint32_t num = static_cast<uint32_t>(dumpData.output().size());
for (uint32_t slot = 0; slot < num; slot++) {
    uint32_t offset = 0;
    // ❌ 无边界检查：直接从 offset=0 读取
    nlohmann::json dhaAtomicAddInfo = ParseOverflowInfo(data + offset);  // L452
    offset += DHA_ATOMIC_ADD_INFO_SIZE;  // += 128
    
    nlohmann::json l2AtomicAddInfo = ParseOverflowInfo(data + offset);   // L455
    offset += L2_ATOMIC_ADD_INFO_SIZE;  // += 128
    
    nlohmann::json aiCoreInfo = ParseOverflowInfo(data + offset);        // L458
    offset += AICORE_INFO_SIZE;  // += 256
    
    // ... 继续累积偏移至 1048 bytes
}
```

**固定偏移量常量**:
| 常量 | 值 | 说明 |
|------|-----|------|
| DHA_ATOMIC_ADD_INFO_SIZE | 128 | DHA 原子加信息 |
| L2_ATOMIC_ADD_INFO_SIZE | 128 | L2 原子加信息 |
| AICORE_INFO_SIZE | 256 | AI Core 信息 |
| DHA_ATOMIC_ADD_STATUS_SIZE | 256 | DHA 状态 |
| L2_ATOMIC_ADD_STATUS_SIZE | 256 | L2 状态 |
| UINT64_SIZE | 8 | 单个 uint64 |

**每个输出槽位最小数据需求**: `128 + 128 + 256 + 256 + 256 + 8 + 8 + 8 = 1048 bytes`

#### 数据流追踪

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TRUST BOUNDARY                                    │
│  Ascend NPU Hardware → 硬件/固件层 (数据来源)                         │
│         ↓ ACL Runtime Callback                                      │
│  AclDumpCallBack(chunk, len)                                        │
│         ↓                                                           │
│  AclDumper::OnAclDumpCallBack()                                     │
│         ↓                                                           │
│  AclDumpDataProcessor::PushData(chunk)                              │
│    - chunk->bufLen → totalLen                                       │
│    - chunk->dataBuf → buffer                                        │
│         ↓                                                           │
│  DumpOpDebugDataToDisk(data, dataLen)                               │
│    - ❌ dataLen 被忽略                                               │
│    - ❌ 无边界检查直接读取                                            │
│    - ⚠️ 越界读取风险                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

#### 对比分析

同文件中的安全函数 `DumpTensorDataToDisk()` (L803-861) **已实现边界检查**:

```cpp
// ✅ 安全实现示例
if (offset > dataLen) {
    LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW, 
              dumpPath + ": offset overflow " + std::to_string(offset) + 
              "/" + std::to_string(dataLen) + ".");
    return DebuggerErrno::ERROR_VALUE_OVERFLOW;
}
```

**对比结论**: `DumpOpDebugDataToDisk()` 缺失了同文件其他函数已有的安全机制。

#### 影响评估

| 影响类型 | 风险等级 | 说明 |
|----------|----------|------|
| **信息泄露** | Medium-High | 越界读取可泄露相邻内存中的敏感数据（tensor 参数、配置信息） |
| **拒绝服务** | Medium | 读取未映射内存页可触发 SIGSEGV 崩溃，中断调试流程 |
| **程序稳定性** | Medium | 未定义行为可能导致不可预测的程序状态 |

#### 触发条件

1. 启用溢出检查配置 (`OverflowCheckCfg`)
2. 调试级别设置为 L2 (`DebuggerLevel::L2`)
3. NPU 执行溢出检测并返回调试数据
4. 返回数据量小于 1048 bytes/槽位

#### 深度分析报告

完整的利用分析和修复方案详见: `scan-results/details/VULN-DF-CPP-msprobe_ccsrc-004.md`

---

## 4. 修复建议

### 针对 VULN-DF-CPP-msprobe_ccsrc-004 的修复方案

#### 方案1: 函数入口添加总长度检查（推荐）

```cpp
static DebuggerErrno DumpOpDebugDataToDisk(
    const std::string& dumpPath, 
    AclDumpMsg::DumpData& dumpData,
    const uint8_t* data, 
    size_t dataLen)
{
    DEBUG_FUNC_TRACE();
    
    // ✅ 新增：计算最小需求长度
    constexpr size_t MIN_SLOT_SIZE = 
        DHA_ATOMIC_ADD_INFO_SIZE +      // 128
        L2_ATOMIC_ADD_INFO_SIZE +       // 128
        AICORE_INFO_SIZE +              // 256
        DHA_ATOMIC_ADD_STATUS_SIZE +    // 256
        L2_ATOMIC_ADD_STATUS_SIZE +     // 256
        3 * UINT64_SIZE;                // 24
    
    uint32_t num = static_cast<uint32_t>(dumpData.output().size());
    
    // ✅ 新增：总长度验证
    size_t requiredSize = num * MIN_SLOT_SIZE;
    if (dataLen < requiredSize) {
        LOG_ERROR(DebuggerErrno::ERROR_INVALID_FORMAT, 
                  dumpPath + ": debug data too short. Required " + 
                  std::to_string(requiredSize) + " bytes, got " + 
                  std::to_string(dataLen) + " bytes.");
        return DebuggerErrno::ERROR_INVALID_FORMAT;
    }
    
    // ... 继续原有处理
}
```

#### 方案2: 每次读取前验证偏移

```cpp
#define CHECK_OFFSET(required) \
    if (offset + required > dataLen) { \
        LOG_ERROR(DebuggerErrno::ERROR_INVALID_FORMAT, \
                  dumpPath + ": buffer overflow at slot " + std::to_string(slot)); \
        return DebuggerErrno::ERROR_INVALID_FORMAT; \
    }

CHECK_OFFSET(48);  // ParseOverflowInfo 需要 48 字节
nlohmann::json dhaAtomicAddInfo = ParseOverflowInfo(data + offset);
offset += DHA_ATOMIC_ADD_INFO_SIZE;
// ... 对所有读取点应用相同检查
```

#### 方案3: 修改 ParseOverflowInfo 接口

为 `ParseOverflowInfo()` 增加 `availableLen` 参数，在解析前验证长度：

```cpp
static nlohmann::json ParseOverflowInfo(const uint8_t* data, size_t availableLen)
{
    constexpr size_t REQUIRED_SIZE = 6 * UINT64_SIZE;  // 48 bytes
    if (availableLen < REQUIRED_SIZE) {
        return nlohmann::json();  // 返回空 JSON
    }
    // ... 原有解析逻辑
}
```

### 其他建议

#### TensorBoard 端点安全（针对 LIKELY 漏洞）

1. **添加认证机制**: 为 `/saveData` 等敏感端点实现 API Token 或 Session 认证
2. **默认禁用网络绑定**: `--bind_all` 参数应警告用户安全风险
3. **路径写入限制**: 增强已有的路径验证，添加写入目录白名单

#### eval() 代码注入缓解（针对 LIKELY 漏洞）

1. **强化白名单**: `white_aten_ops` 配置应使用签名验证而非简单字符串匹配
2. **配置文件完整性**: YAML/JSON 配置文件应添加 checksum 验证
3. **替代方案**: 考虑使用 `getattr()` 或函数映射表替代 `eval()`

#### 优先级排序

| 优先级 | 漏洞/风险 | 时间建议 |
|--------|-----------|----------|
| P0 | VULN-DF-CPP-msprobe_ccsrc-004 | 立即修复（1-2 天） |
| P1 | TensorBoard 网络暴露 | 下一迭代（1 周） |
| P2 | eval() 白名单强化 | 下一迭代（1 周） |
| P3 | POSSIBLE 类别审查 | 2 周内评估 |

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| msprobe_ccsrc | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-125 | 1 | 100.0% |
