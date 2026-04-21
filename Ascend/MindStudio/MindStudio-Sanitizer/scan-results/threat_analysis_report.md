# MindStudio-Sanitizer 威胁分析报告

## 1. 项目概况

**项目名称**: MindStudio-Sanitizer  
**项目类型**: CLI 工具 (NPU 算子内存安全检测工具)  
**分析时间**: 2026-04-21  
**分析范围**: csrc 目录（排除 test 目录）

### 项目定位
MindStudio-Sanitizer 是华为 MindStudio 工具链的一部分，用于检测 NPU (昇腾) 算子程序的内存安全和并发问题。该工具通过 LD_PRELOAD 钩子机制劫持用户算子程序的 Ascend Runtime/ACL/HAL API 调用，并通过 Unix Domain Socket IPC 与主进程通信进行检测分析。

### 核心功能
- **memcheck**: 内存安全检测（越界访问、未初始化读取、内存泄漏）
- **racecheck**: 竞态条件检测（核内/核间/流水线竞态）
- **initcheck**: 同步问题检测
- **synccheck**: 同步指令检测
- **registercheck**: 寄存器检测

---

## 2. 模块架构分析

### 2.1 模块层次结构

```
                    ┌─────────────────────┐
                    │   User Application  │  (不可信)
                    │   (算子程序)         │
                    └─────────────────────┘
                              │
                              │ LD_PRELOAD 钩子
                              ▼
        ┌─────────────────────────────────────────────┐
        │                Hooks Layer                   │
        │  ┌─────────────┬─────────────┬─────────────┐ │
        │  │ runtime_    │ hal_        │ acl_        │ │
        │  │ hooks       │ hooks       │ hooks       │ │
        │  │ (RT API)    │ (HAL API)   │ (ACL API)   │ │
        │  └─────────────┴─────────────┴─────────────┘ │
        │              ascendc_hooks                   │
        │            (AscendC 内核钩子)                 │
        │              hooks_verify                    │
        │            (参数验证防护)                     │
        └─────────────────────────────────────────────┘
                              │
                              │ Unix Domain Socket IPC
                              ▼
        ┌─────────────────────────────────────────────┐
        │            Core Framework                    │
        │  ┌─────────────┬─────────────┬─────────────┐ │
        │  │ communication│ protocol   │ checker     │ │
        │  │ (IPC)       │ (解析)      │ (调度)      │ │
        │  └─────────────┴─────────────┴─────────────┘ │
        │  thread_manager  device_manager  command    │
        └─────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────────┐
        │              Sanitizer Modules               │
        │  ┌─────────────┬─────────────┬─────────────┐ │
        │  │ address_    │ race_       │ sync_       │ │
        │  │ sanitizer   │ sanitizer   │ sanitizer   │ │
        │  │ (内存检测)  │ (竞态检测)  │ (同步检测)  │ │
        │  └─────────────┴─────────────┴─────────────┘ │
        │            register_sanitizer                │
        │  ┌─────────────────────────────────────────┐ │
        │  │ shadow_memory  bounds_check  heap_block │ │
        │  │ (Shadow内存)  (边界检查)    (堆管理)    │ │
        │  └─────────────────────────────────────────┘ │
        └─────────────────────────────────────────────┘
```

### 2.2 模块依赖关系

| 模块 | 依赖模块 | 外部依赖 |
|------|----------|----------|
| hooks | hook_report, hooks_verify, communication | libruntime.so, libascendcl.so, libascend_hal.so |
| hook_report | communication, protocol, serializer | 无 |
| communication | domain_socket | 无 |
| protocol | serializer, record_format | 无 |
| checker | address_sanitizer, race_sanitizer, sync_sanitizer, record_pre_process | 无 |
| address_sanitizer | shadow_memory, bounds_check, heap_block_manager, asan_action | 无 |
| race_sanitizer | race_alg_factory, vector_clock, sync_event_data_base | 无 |
| command | checker, thread_manager, process, protocol, device_manager | 无 |
| cli_parser | command, file_system, path | 无 |

---

## 3. 攻击面分析

### 3.1 攻击入口点

#### 3.1.1 Hooks Layer（高风险）

Hooks 层是主要的攻击入口点，通过 LD_PRELOAD 机制劫持用户算子程序的 API 调用：

| 入口函数 | 文件 | 信任等级 | 风险描述 |
|----------|------|----------|----------|
| `rtMalloc` | runtime_hooks.cpp:592 | semi_trusted | 接收用户传入的 devPtr 指针和 size 参数，存在整数溢出风险 |
| `rtFree` | runtime_hooks.cpp:613 | semi_trusted | 接收用户传入的 devPtr 参数，可能包含恶意地址 |
| `rtMemcpy` | runtime_hooks.cpp:646 | semi_trusted | 接收 dst、src、cnt 参数，存在缓冲区溢出风险 |
| `rtMemset` | runtime_hooks.cpp:628 | semi_trusted | 接收 devPtr、cnt 参数，内存操作风险 |
| `rtKernelLaunch` | runtime_hooks.cpp:805 | semi_trusted | 接收 args 缓冲区，可能包含恶意内核参数 |
| `rtKernelLaunchWithHandleV2` | runtime_hooks.cpp:847 | semi_trusted | 接收 argsInfo 结构体，复杂的参数解析 |
| `rtDevBinaryRegister` | runtime_hooks.cpp:704 | semi_trusted | 接收二进制数据，存在大小校验（MAX_BINARY_SIZE） |
| `halMemAlloc` | hal_hooks.cpp:37 | semi_trusted | 接收 size 和 flag 参数 |
| `drvMemcpy` | hal_hooks.cpp:90 | semi_trusted | 接收 byteCount 参数 |
| `halMemcpy2D` | hal_hooks.cpp:133 | semi_trusted | 接收 MEMCPY2D 结构体，存在 height * pitch 溢出风险 |
| `aclrtMalloc` | acl_hooks.cpp:45 | semi_trusted | 接收 size 参数 |
| `aclrtMemcpy` | acl_hooks.cpp:70 | semi_trusted | 接收 count 参数 |
| `KERNEL_LAUNCH_INIT` | ascendc_hooks.cpp:437 | semi_trusted | 接收 blockDim 参数 |
| `KERNEL_LAUNCH_FINALIZE` | ascendc_hooks.cpp:374 | semi_trusted | 接收 memInfo 指针，来自 Device 内存 |

#### 3.1.2 Core Framework（中等风险）

| 入口函数 | 文件 | 信任等级 | 风险描述 |
|----------|------|----------|----------|
| `DomainSocketServer::Read` | domain_socket.cpp:168 | semi_trusted | 从 Socket 读取数据，已做 UID/GID 验证 |
| `MemCheckProtocol::GetPacket` | protocol.cpp:196 | internal | 解析数据包，需关注缓冲区溢出 |
| `MemCheckProtocol::Feed` | protocol.cpp:189 | internal | 填充数据流，已有 MAX_STREAM_LEN 限制 |

#### 3.1.3 CLI 入口（低风险）

| 入口函数 | 文件 | 信任等级 | 风险描述 |
|----------|------|----------|----------|
| `CliParser::Parse` | cli_parser.cpp:775 | trusted_admin | 命令行参数解析，已做白名单校验 |
| `IsLogFileSafe` | cli_parser.cpp:144 | trusted_admin | 日志文件安全检查 |

### 3.2 信任边界

```
┌─────────────────────────────────────────────────────────────────┐
│                        信任边界图                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [不可信] User Application                                       │
│      │                                                          │
│      │ 信任边界 1: LD_PRELOAD 钩子                               │
│      │ (Medium Risk - 参数验证防护)                              │
│      ▼                                                          │
│  [半可信] Hooks Layer                                           │
│      │                                                          │
│      │ 信任边界 2: Unix Domain Socket IPC                        │
│      │ (Low Risk - UID/GID 验证)                                │
│      ▼                                                          │
│  [内部可信] Core Framework                                       │
│      │                                                          │
│      │ 内部通信                                                  │
│      ▼                                                          │
│  [内部可信] Sanitizer Modules                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. 高风险文件清单

### 4.1 Critical 级别文件

| 文件 | 模块 | 风险原因 | 行数 |
|------|------|----------|------|
| runtime_hooks.cpp | hooks | 处理内存分配/拷贝/内核启动，接收用户参数 | 971 |
| hal_hooks.cpp | hooks | HAL 层内存操作，接收用户参数 | 172 |
| acl_hooks.cpp | hooks | ACL API 钩子，接收用户参数 | 389 |

### 4.2 High 级别文件

| 文件 | 模块 | 风险原因 | 行数 |
|------|------|----------|------|
| ascendc_hooks.cpp | hooks | AscendC 内核钩子，处理 Device 内存数据 | 484 |
| hook_report.cpp | hooks | 钩子报告，序列化用户数据 | 403 |
| protocol.cpp | core_framework | 协议解析，处理 IPC 数据包 | 215 |
| command.cpp | core_framework | 命令执行，协调各模块 | 523 |
| shadow_memory.cpp | address_sanitizer | Shadow Memory 管理，内存状态跟踪 | 381 |
| bounds_check.cpp | address_sanitizer | 边界检查核心逻辑 | 200 |
| heap_block_manager.cpp | address_sanitizer | Heap 块管理 | 250 |

### 4.3 Medium 级别文件

| 文件 | 模块 | 风险原因 | 行数 |
|------|------|----------|------|
| hooks_verify.cpp | hooks | 参数验证（防护措施） | 95 |
| communication.cpp | core_framework | IPC 通信管理 | 181 |
| domain_socket.cpp | utility | Unix Domain Socket 实现（已有 UID/GID 验证） | 298 |
| checker.cpp | core_framework | 检测器调度 | 464 |
| cli_parser.cpp | cli_parser | CLI 参数解析（已有白名单校验） | 836 |
| address_sanitizer.cpp | address_sanitizer | 内存检测主逻辑 | 724 |

---

## 5. 安全防护措施分析

### 5.1 已存在的防护措施

#### 5.1.1 Hooks Layer 防护

**参数验证** (`hooks_verify.cpp`):
- `IsValidHalMemcpy2DArg`: 验证 MEMCPY2D 结构体参数，防止 height * pitch 溢出
- `IsValidRtMemcpy2dAsyncArg`: 验证 memcpy2d 参数

**大小限制** (`runtime_hooks.cpp`):
- `MAX_BINARY_SIZE = 32GB`: 限制内核二进制大小
- `MAX_FILE_MAPPING_BUFF_SIZE = 1GB`: 限制文件映射大小
- `MAX_MEMORY_RECORD_HEIGHT = 60*1024^3`: 限制 2D 拷贝高度

**参数校验** (`runtime_hooks.cpp`):
- `VerifyArginfo`: 校验 rtArgsEx_t 参数合法性
- `CheckBlockDimValid`: 验证 blockDim 范围

#### 5.1.2 IPC 通信防护

**Unix Domain Socket 安全** (`domain_socket.cpp`):
```cpp
// SO_PEERCRED 验证
if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == -1) {
    return error;
}
if (getuid() != cred.uid || getgid() != cred.gid) {
    return error; // 拒绝不同用户的连接
}
```
- 通过 `SO_PEERCRED` 验证连接进程的 UID/GID
- 仅允许相同用户进程连接
- Socket 文件使用 umask 0177 创建

#### 5.1.3 Protocol 解析防护

**流大小限制** (`protocol.cpp`):
```cpp
static constexpr uint64_t MAX_STREAM_LEN = 100UL * 1024UL * 1024UL * 1024UL; // 100TB
if (bytes_.size() + msg.size() < MAX_STREAM_LEN) {
    bytes_ += msg;
}
```

#### 5.1.4 CLI 参数防护

**白名单校验** (`cli_parser.cpp`):
- `IsInWhiteList`: 参数字符白名单验证
- `IsLogFileSafe`: 日志文件安全检查
- `MAX_FILE_PATH_LEN = 4096`: 路径长度限制
- `KERNEL_NAME_MAX`: 内核名长度限制

### 5.2 安全建议

#### 5.2.1 建议增强的防护

1. **整数溢出检测**:
   - `rtMemcpy` 的 cnt 参数建议增加溢出检查
   - `rtMemset` 的 cnt 参数建议增加溢出检查
   - `aclrtMemcpy2d` 的 width * height 溢出检查

2. **边界检查增强**:
   - `KERNEL_LAUNCH_FINALIZE` 的 memInfo 指针建议增加大小验证
   - `ReportSanitizerRecords` 建议增加 recordCount 溢出检查

3. **日志安全增强**:
   - `hook_logger.h` 的日志建议增加更严格的字符过滤

---

## 6. STRIDE 威胁建模

### 6.1 Spoofing (身份伪造)

| 威胁 | 风险等级 | 缓解措施 |
|------|----------|----------|
| 恶意进程尝试连接 Unix Domain Socket | Low | SO_PEERCRED UID/GID 验证 |
| 恶意用户尝试伪造 CLI 调用 | Low | 命令行由管理员执行，参数已校验 |

### 6.2 Tampering (数据篡改)

| 威胁 | 风险等级 | 缓解措施 |
|------|----------|----------|
| 用户程序篡改 args 参数 | Medium | hooks_verify 参数验证 |
| 用户程序篡改内核二进制 | Low | MAX_BINARY_SIZE 大小限制 |
| IPC 数据篡改 | Low | 仅限同用户进程，协议头校验 |

### 6.3 Repudiation (抵赖)

| 威胁 | 风险等级 | 缓解措施 |
|------|----------|----------|
| 无审计日志 | Medium | 建议增加审计日志功能 |

### 6.4 Information Disclosure (信息泄露)

| 威胁 | 飯险等级 | 缓解措施 |
|------|----------|----------|
| Socket 文件权限泄露 | Low | umask 0177 创建 |
| 日志文件权限泄露 | Low | umask 0177 创建 |
| 内存地址泄露到日志 | Medium | 日志已做字符替换处理 |

### 6.5 Denial of Service (拒绝服务)

| 娃胁 | 飯险等级 | 缓解措施 |
|------|----------|----------|
| 大参数导致内存耗尽 | Medium | MAX_BINARY_SIZE 等大小限制 |
| 无限循环请求 | Low | MAX_MEMORY_RECORD_HEIGHT 循环限制 |
| Socket 连接超时 | Low | 已设置 SO_RCVTIMEO |

### 6.6 Elevation of Privilege (权限提升)

| 威胁 | 飯险等级 | 缓解措施 |
|------|----------|----------|
| 恶意代码注入 | Medium | LD_PRELOAD 由用户配置，需信任用户环境 |
| 通过恶意参数触发漏洞 | Medium | hooks_verify 参数验证 |

---

## 7. 总结

### 7.1 风险评估

| 风险等级 | 文件数量 | 主要风险类型 |
|----------|----------|----------|
| Critical | 3 | Hooks 层内存操作 API |
| High | 7 | 协议解析、内核处理、Shadow Memory |
| Medium | 6 | IPC 通信、CLI 解析、检测器 |
| Low | 4 | Python 脚本、头文件 |

### 7.2 关键发现

1. **主要攻击面**: Hooks Layer 是主要的攻击入口，接收用户程序的内存参数
2. **防护措施**: 已存在多项安全防护（UID/GID 验证、参数校验、大小限制）
3. **信任边界**: User Application → Hooks Layer → Core Framework，风险逐层降低
4. **潜在风险**: 部分参数可能存在整数溢出风险，建议增强验证

### 7.3 下一步建议

1. **重点扫描文件**:
   - `csrc/hooks/runtime_hooks.cpp`
   - `csrc/hooks/hal_hooks/hal_hooks.cpp`
   - `csrc/hooks/acl_hooks/acl_hooks.cpp`
   - `csrc/core/framework/protocol.cpp`
   - `csrc/address_sanitizer/shadow_memory.cpp`

2. **关注漏洞类型**:
   - CWE-120: 缓冲区溢出（内存拷贝操作）
   - CWE-190: 整数溢出（大小参数计算）
   - CWE-476: NULL 指针解引用（指针参数处理）
   - CWE-787: 越界写入（Shadow Memory 操作）

---

*报告生成时间: 2026-04-21*  
*分析工具: Architecture Agent (自主分析模式)*