# msProbe 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析基于项目源码扫描，未发现 threat.md 约束文件，识别范围为完整攻击面。

## 项目架构概览

### 项目基本信息
- **项目名称**: MindStudio Probe (msProbe)
- **项目类型**: Python CLI 工具
- **语言组成**: C/C++ 60 文件 (约 5,000 行) / Python 443 文件 (约 85,000 行)
- **主要功能**: AI 模型精度调试工具，支持 PyTorch/MindSpore 框架的精度数据采集、比对、预检和溢出检测

### 架构分层

```
┌─────────────────────────────────────────────────────────────┐
│                     Python CLI Entry                         │
│                   (msprobe/msprobe.py)                       │
├─────────────────────────────────────────────────────────────┤
│  Core Modules                                                │
│  ├── compare (数据比对)                                      │
│  ├── dump (数据采集)                                         │
│  ├── config_check (配置检查)                                 │
│  ├── overflow_check (溢出检测)                               │
│  ├── visualization (可视化)                                  │
│  └──────────────────────────────────────────────────────────┤
│  Framework Adapters                                          │
│  ├── pytorch/ (PyTorch 适配)                                 │
│  ├── mindspore/ (MindSpore 适配)                             │
│  └──────────────────────────────────────────────────────────┤
│  Cross-Language Boundary                                     │
│  ├── PrecisionDebuggerIfPython.cpp (Python C API 接口)       │
│  └──────────────────────────────────────────────────────────┤
│  C/C++ Extension (adump)                                     │
│  ├── core (AclDumpDataProcessor, PrecisionDebugger)          │
│  ├── base (DebuggerConfig)                                   │
│  ├── utils (FileUtils, FileOperation, CPythonUtils)          │
│  └──────────────────────────────────────────────────────────┘
```

### 数据流概览

1. **用户输入 → CLI 解析 → 子命令执行**
2. **配置文件 → JSON/YAML 解析 → DebuggerConfig**
3. **数据文件 → load_json/load_npy → 数据处理**
4. **ACL dump 数据 → Protobuf 解析 → 文件写入**

## 模块风险评估

| 模块 | 语言 | 文件数 | 风险等级 | 主要风险类型 |
|------|------|--------|----------|--------------|
| adump_base | c_cpp | 4 | **Critical** | 配置解析、路径处理 |
| adump_core | c_cpp | 5 | **Critical** | Protobuf 解析、数据处理 |
| adump_utils | c_cpp | 6 | **Critical** | 文件操作、Python C API |
| core_file_utils | python | 14 | **Critical** | 文件读写、JSON/YAML 解析 |
| core_dump | python | 5 | **High** | 数据导入、JSON 解析 |
| core_compare | python | 10 | **High** | 数据比对、文件处理 |
| infer_offline | python | 15 | **High** | 离线模型处理 |
| adump_if_python | c_cpp | 4 | **High** | 跨语言接口 |
| cli_entry | python | 2 | **Medium** | 命令行参数解析 |
| visualization | python | 8 | **Medium** | 数据可视化 |

## 攻击面分析

### 1. CLI 命令行入口 (Medium Risk)

**入口点**: `main()` @ msprobe.py:34

**分析**:
- 用户通过命令行参数控制工具行为
- 支持多个子命令：compare、acc_check、overflow_check、config_check、graph_visualize、data2db、offline_dump
- 参数包括文件路径、配置路径等敏感输入

**攻击向量**:
- 命令行参数注入（路径遍历）
- 参数类型混淆

**信任等级**: `untrusted_local` - 本地用户可控制

### 2. 配置文件解析 (Critical Risk)

**入口点**: 
- C++: `DebuggerConfig::LoadConfig()` @ DebuggerConfig.cpp:462
- Python: `load_json()` @ file_utils.py:525, `load_yaml()` @ file_utils.py:503

**分析**:
- 配置文件路径由用户 CLI 参数传入
- 使用 nlohmann::json (C++) 和 json.load/yaml.safe_load (Python) 解析
- 配置内容影响 dump 路径、任务类型等关键参数

**攻击向量**:
- JSON/YAML 解析漏洞（格式错误导致崩溃）
- 配置文件注入（恶意配置触发异常行为）
- 路径遍历（配置路径指向敏感文件）

**信任等级**: `untrusted_local` - 用户可控制配置文件内容

### 3. 数据文件解析 (High Risk)

**入口点**:
- `load_npy()` @ file_utils.py:515
- `_process_dump_file()` @ dump2db.py:322
- `np.load()` with allow_pickle=False

**分析**:
- 读取用户提供的 numpy 文件和 dump.json 文件
- dump.json 包含大量 tensor 统计数据，结构复杂
- numpy 文件可能包含恶意构造的数组

**攻击向量**:
- numpy 文件格式漏洞
- JSON 文件结构混淆
- 大文件导致内存耗尽

**信任等级**: `untrusted_local` - 用户可控制数据文件内容

### 4. Protobuf 数据解析 (Critical Risk)

**入口点**: `AclDumpDataProcessor::DumpToDisk()` @ AclDumpDataProcessor.cpp:886

**分析**:
- 解析 ACL API 返回的 dump 数据
- 使用 `dumpData.ParseFromArray()` 解析 protobuf 格式
- 数据来源为硬件层，但路径配置来自用户

**攻击向量**:
- Protobuf 解析漏洞
- 数据长度溢出（已有 size 检查）

**信任等级**: `semi_trusted` - 数据来自 ACL API，路径来自用户

### 5. 文件操作 (Critical Risk)

**入口点**:
- `FileUtils::GetAbsPath()` @ FileUtils.cpp:88
- `FileUtils::OpenFile()` @ FileUtils.cpp:430
- `FileOpen.__enter__()` @ file_utils.py:131

**分析**:
- 路径处理使用 GetAbsPath() 规范化
- 存在路径长度检查、字符检查、软链接检查
- 文件大小存在上限检查

**防护措施**:
- `IsPathLengthLegal()` - 路径长度限制
- `IsPathCharactersValid()` - 字符白名单
- `IsFileSymbolLink()` - 软链接检测
- `check_path_no_others_write()` - 权限检查

**剩余风险**:
- 路径规范化后可能仍有绕过
- 符号链接检查可能遗漏某些场景

### 6. 跨语言接口 (High Risk)

**入口点**: `InitPrecisionDebugger()` @ PrecisionDebuggerIfPython.cpp:42

**分析**:
- Python C API 接口，接收 Python 传入的 framework 和 config_path
- 使用 CPythonUtils 进行类型转换
- 接口参数来自用户 CLI 输入

**攻击向量**:
- Python C API 类型混淆
- 参数验证不足导致的内存问题

**信任等级**: `semi_trusted` - 参数来自 Python 层用户输入

## STRIDE 威胁建模

### Spoofing (欺骗)
| 威胁 | 影响 | 风险等级 |
|------|------|----------|
| 配置文件身份伪装 | 恶意配置覆盖合法配置 | Low |
| CLI 参数伪装 | 错误参数导致意外行为 | Low |

### Tampering (篡改)
| 威胁 | 影响 | 风险等级 |
|------|------|----------|
| 配置文件篡改 | 修改 dump 路径、任务配置 | **High** |
| 数据文件篡改 | 修改 tensor 数据影响分析结果 | **High** |
| 输出文件篡改 | 修改比对结果影响诊断 | Medium |

### Repudiation (抵赖)
| 威胁 | 影响 | 风险等级 |
|------|------|----------|
| 无操作日志 | 无法追溯谁执行了什么操作 | Low |

### Information Disclosure (信息泄露)
| 娅害 | 影响 | 风险等级 |
|------|------|----------|
| 配置文件泄露 | 暴露模型结构、训练参数 | Medium |
| dump 数据泄露 | 暴露模型权重、梯度信息 | **High** |
| 路径信息泄露 | 通过错误信息暴露路径结构 | Low |

### Denial of Service (拒绝服务)
| 威胁 | 影响 | 风险等级 |
|------|------|----------|
| 大文件解析耗尽内存 | 工具崩溃，无法继续分析 | **High** |
| 无限循环数据结构 | 解析卡死 | Medium |
| 目录深度过大 | 递归创建目录失败 | Low |

### Elevation of Privilege (权限提升)
| 威胁 | 影响 | 风险等级 |
|------|------|----------|
| 通过软链接访问其他用户文件 | 读取敏感文件 | **High** |
| 通过路径遍历写入系统目录 | 写入恶意文件 | **High** |
| Python C API 内存问题 | 代码执行 | Medium |

## 安全加固建议

### 架构层面

1. **输入验证增强**
   - 在所有文件路径输入点增加二次验证
   - 对 JSON/YAML 配置内容进行 schema 校验
   - 对 numpy 文件头进行更严格的格式检查

2. **路径安全强化**
   - 增加路径前缀白名单机制（只允许写入特定目录）
   - 强化软链接检查（检查整个路径链）
   - 增加文件属主一致性检查

3. **资源限制**
   - 增加全局内存使用限制
   - 增加单个文件处理时间限制
   - 增加递归深度限制

4. **跨语言接口加固**
   - 增加参数类型严格验证
   - 增加异常捕获和转换机制
   - 减少跨边界的数据传递量

### 代码层面

1. **配置解析模块 (DebuggerConfig.cpp)**
   - 增加 JSON schema 校验
   - 限制解析深度
   - 增加 unknown field 检测

2. **文件操作模块 (FileUtils.cpp)**
   - 增强 GetAbsPath() 的规范化逻辑
   - 增加路径组件检查（防止 `..` 组件过多）
   - 增加并发访问保护

3. **数据解析模块 (file_utils.py)**
   - 增加 JSON 解析深度限制
   - 增加 numpy 文件头验证
   - 增加 CSV/Excel 注入检测

4. **Protobuf 解析模块 (AclDumpDataProcessor.cpp)**
   - 增加解析前大小验证
   - 增加解析失败的安全回退
   - 增加数据完整性校验

## 总结

msProbe 作为 AI 模型精度调试工具，主要风险集中在：
1. **配置文件解析** - 用户可控的 JSON/YAML 输入
2. **数据文件解析** - 用户可控的 dump.json/npy 文件
3. **文件操作** - 路径处理和文件读写
4. **跨语言接口** - Python C API 边界

项目已实现多项安全措施（路径检查、软链接检测、文件大小限制），但仍存在以下潜在改进空间：
- JSON/YAML schema 校验
- 路径前缀白名单
- 资源使用限制
- 跨语言接口参数验证

建议后续安全扫描重点关注：
- `DebuggerConfig::LoadConfig()` - 配置解析
- `load_json()` / `load_yaml()` - Python 文件解析
- `FileUtils::GetAbsPath()` - 路径处理
- `AclDumpDataProcessor::DumpToDisk()` - Protobuf 解析