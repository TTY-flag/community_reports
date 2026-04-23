# 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析未使用 threat.md 约束文件，AI 自主识别所有攻击面。

## 项目架构概览

### 项目基本信息

| 属性 | 值 |
|------|-----|
| 项目名称 | triton-inference-server-ge-backend |
| 项目类型 | Triton Inference Server 自定义 Backend 库 |
| 语言组成 | C++17 (5个.cpp + 5个.h = 4722行) + Python (1个.py) |
| 依赖框架 | Triton Backend API, 华为 Ascend SDK, ONNX Runtime |
| 编译目标 | libtriton_npu_ge.so (动态库) |

### 架构设计

本项目是 Triton Inference Server 的自定义 backend 实现，用于支持华为昇腾 NPU (Neural Processing Unit) 进行深度学习模型推理。架构如下：

```
┌─────────────────────────────────────────────────────────────┐
│                   Remote Clients                              │
│              (HTTP/GRPC 推理请求)                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Triton Inference Server                      │
│                  (网络服务层)                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ HTTP Server │  │ GRPC Server │  │ Model Router│           │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (Backend API 调用)
┌─────────────────────────────────────────────────────────────┐
│              triton-inference-server-ge-backend               │
│                  (本项目 - Backend 库)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Backend API │  │Model State  │  │ Inference   │           │
│  │ (npu_ge.cpp)│  │(model_state)│  │ (engine)    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│  ┌─────────────┐  ┌─────────────┐                           │
│  │ Scheduler   │  │ GE Session  │                            │
│  └─────────────┘  └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  华为 Ascend SDK                               │
│                  (NPU Runtime)                                 │
└─────────────────────────────────────────────────────────────┘
```

### 模块划分

| 模块名称 | 文件 | 功能 | 风险等级 |
|----------|------|------|----------|
| backend_api | npu_ge.cpp/npu_ge.h | Triton Backend API 入口点 | High |
| model_management | model_state.cpp/h, model_instance_state.cpp/h | 模型配置解析、设备初始化 | Critical |
| inference_engine | inference.cpp/h | 推理执行、内存管理 | High |
| scheduler | scheduler.cpp/h | 实例调度、负载均衡 | Medium |
| example_client | client.py | 示例客户端 | Low |

## 模块风险评估

### Critical 级别模块

#### model_management 模块

| 文件 | 风险因素 | STRIDE 威胁 |
|------|----------|-------------|
| model_state.cpp | system() 命令执行 (行85) | E (权限提升) |
| model_state.cpp | 配置文件解析 (ParseGeConfig, ParseModelConfig) | T (篡改) |
| model_state.cpp | 文件系统遍历 (FindFirstFile) | I (信息泄露) |
| model_state.cpp | 环境变量设置 (setenv) | T (篡改) |
| model_instance_state.cpp | 环境变量读取 (getenv) | I (信息泄露) |
| model_instance_state.cpp | JSON 解析 (json::parse) | D (拒绝服务) |

### High 级别模块

#### backend_api 模块

| 文件 | 风险因素 | STRIDE 威胁 |
|------|----------|-------------|
| npu_ge.cpp | TRITONBACKEND_ModelInstanceExecute 接收推理请求 | S,T,I (欺骗/篡改/泄露) |
| npu_ge.cpp | TRITONBACKEND_ModelInitialize 模型初始化 | D (拒绝服务) |

#### inference_engine 模块

| 文件 | 风险因素 | STRIDE 威胁 |
|------|----------|-------------|
| inference.cpp | ProcessRequestInputsV2 处理请求输入 | T,I (篡改/泄露) |
| inference.cpp | aclrtMemcpy 内存复制操作 | I,D (泄露/拒绝服务) |
| inference.cpp | ExecuteGraphWithStreamAsync 推理执行 | D (拒绝服务) |

## 攻击面分析

### 信任边界模型

```
信任等级分布图：

┌─────────────────────────────────────────────────────────────┐
│                    Remote Clients                             │
│                  untrusted_network                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ (HTTP/GRPC 请求)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Triton Server                              │
│                    semi_trusted                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ (Backend API 调用)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Backend Plugin                             │
│                    semi_trusted                               │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Request Handler │  │ Config Parser   │                    │
│  │ (untrusted data)│  │ (trusted_admin) │                    │
│  └─────────────────┘  └─────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ (配置文件/模型文件)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Model Repository                           │
│                    trusted_admin                              │
└─────────────────────────────────────────────────────────────┘
```

### 入口点分析

| 入口点 | 文件:行号 | 类型 | 信任等级 | 数据来源 | 安全措施 |
|--------|-----------|------|----------|----------|----------|
| TRITONBACKEND_ModelInstanceExecute | npu_ge.cpp:165 | RPC | semi_trusted | Triton Server | 依赖 Triton Server 验证 |
| ProcessRequestInputsV2 | inference.cpp:275 | RPC | semi_trusted | 推理请求 | 有 buffer_size 检查 |
| ParseGeConfig | model_state.cpp:121 | ENV | trusted_admin | Backend 命令行配置 | JSON 解析 |
| ParseModelConfig | model_state.cpp:278 | FILE | trusted_admin | config.pbtxt | TritonJson 解析 |
| FindModelFile | model_state.cpp:478 | FILE | trusted_admin | 模型仓库目录 | 文件系统遍历 |
| SetDumpGraph | model_state.cpp:66 | FILE | trusted_admin | 配置参数 | 基本命令注入过滤 |
| GetEnvVar | model_instance_state.cpp:20 | ENV | trusted_admin | GE_NPU_CONFIG | getenv 读取 |

### 高风险操作

#### 1. system() 命令执行 (model_state.cpp:85)

```cpp
std::string cleanup_cmd = "rm -rf " + path + "/* 2>/dev/null";
int result = system(cleanup_cmd.c_str());
```

**风险分析**：
- 命令注入风险：路径来自配置参数 `dump_graph`
- 已有防护措施：检查路径中是否包含 `;`, `&`, `|` 字符 (行70-73)
- 潜在绕过：攻击者可能通过其他特殊字符（如 `$()` 反引号等）绕过过滤

**建议**：
- 增强过滤：使用白名单校验路径字符
- 替代方案：使用 C++ filesystem API 删除目录内容，避免 shell 命令执行

#### 2. 内存复制操作 (多处 aclrtMemcpy)

```cpp
// inference.cpp:253
acl_ret = aclrtMemcpy(indev_buffer, buffer_size, buffer, buffer_size, ACL_MEMCPY_HOST_TO_DEVICE);
```

**风险分析**：
- buffer_size 来自推理请求的输入属性
- 潜在整数溢出：shape[0] * indev_line_size 计算可能溢出
- 缓冲区溢出：如果 buffer_size 大于实际分配的内存

**建议**：
- 添加 buffer_size 上限检查
- 在内存分配前验证计算不会溢出

#### 3. JSON 解析 (model_state.cpp:127, model_instance_state.cpp:30)

```cpp
json j = json::parse(json_str);
```

**风险分析**：
- 解析异常可能导致程序崩溃（DoS）
- 配置数据来自管理员控制的环境变量/命令行

**建议**：
- 添加 JSON 格式预验证
- 限制 JSON 文件大小

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 恶意推理请求伪装 | TRITONBACKEND_ModelInstanceExecute | Medium | Triton Server 进行请求验证 |

### Tampering (篡改)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 推理输入数据篡改 | ProcessRequestInputsV2 | High | 验证 shape 和 buffer_size |
| 配置文件篡改 | ParseModelConfig | Low | 配置文件由管理员控制 |
| 环境变量篡改 | GetEnvVar, setenv | Low | 环境变量由管理员控制 |

### Repudiation (抵赖)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 无日志推理请求 | 整体系统 | Medium | Triton Server 提供日志 |

### Information Disclosure (信息泄露)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 推理输出数据泄露 | BuildComblineResponse | High | 依赖 Triton Server 访问控制 |
| 模型信息泄露 | FindModelFile, ParseOnnxInfo | Low | 模型文件由管理员控制 |
| 路径遍历泄露 | FindFirstFile | Low | 路径限定在模型仓库目录 |

### Denial of Service (拒绝服务)

| 娹胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 恶意大请求 | ProcessRequestInputsV2 | High | 验证 batch_size 上限 |
| JSON 解析异常 | json::parse | Medium | 异常捕获处理 |
| 内存分配失败 | aclrtMalloc | Medium | 错误码检查 |

### Elevation of Privilege (权限提升)

| 娹胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 命令注入 | SetDumpGraph (system()) | Medium | 基本字符过滤 |

## 安全加固建议

### 架构层面建议

1. **命令执行安全**
   - 完全移除 system() 调用，使用 std::filesystem API
   - 如果必须使用 shell 命令，采用更严格的输入验证

2. **内存安全**
   - 在 aclrtMemcpy 前添加 buffer_size 上限检查
   - 验证整数乘法不会溢出 (shape[0] * line_size)
   - 使用边界安全的内存操作函数

3. **输入验证**
   - 在 ProcessRequestInputsV2 中验证 shape 合理性
   - 添加 batch_size 上限限制
   - 验证 tensor dims 不超过合理范围

4. **错误处理**
   - 所有 API 调用添加完整的错误处理
   - JSON 解析添加格式预验证
   - 文件操作添加异常捕获

5. **日志与审计**
   - 记录推理请求的关键信息（不含敏感数据）
   - 记录配置变更操作
   - 添加异常情况的详细日志

### 代码层面建议

1. **SetDumpGraph 函数 (model_state.cpp:66-94)**
   ```cpp
   // 建议替换为：
   std::filesystem::path dump_path(path);
   if (!dump_path.is_relative() || dump_path.string().find("..") != std::string::npos) {
       LOG_MESSAGE(TRITONSERVER_LOG_ERROR, "Invalid dump path");
       return;
   }
   // 使用 filesystem API 清理目录
   for (auto& entry : std::filesystem::directory_iterator(dump_path)) {
       std::filesystem::remove_all(entry);
   }
   ```

2. **ProcessRequestInputsV2 函数 (inference.cpp:275-317)**
   ```cpp
   // 建议添加：
   const uint64_t MAX_BUFFER_SIZE = 1024 * 1024 * 1024; // 1GB 上限
   if (buffer_size > MAX_BUFFER_SIZE) {
       LOG_MESSAGE(TRITONSERVER_LOG_ERROR, "Buffer size exceeds limit");
       return RET_ERR;
   }
   ```

3. **AllocateSingleMemoryV2 函数 (inference.cpp:229-273)**
   ```cpp
   // 建议添加溢出检查：
   if (buffer_size > UINT64_MAX / sample_element_size) {
       LOG_MESSAGE(TRITONSERVER_LOG_ERROR, "Potential integer overflow");
       return RET_ERR;
   }
   ```

## 附录

### 数据流关键路径

| 路径 | 起点 | 终点 | 数据类型 |
|------|------|------|----------|
| 推理请求流 | TRITONBACKEND_Request | aclrtMemcpy | 推理输入张量 |
| 配置解析流 | Backend 命令行参数 | ParseCmdlineConfig | JSON 配置 |
| 模型加载流 | 模型文件路径 | aclgrphParseONNX | ONNX/PB 模型 |
| 命令执行流 | dump_graph 参数 | system() | 文件系统路径 |
| 输出响应流 | aclrtMemcpy | TRITONBACKEND_ResponseSend | 推理输出张量 |

### 外部依赖风险

| 依赖 | 版本/来源 | 风险因素 |
|------|-----------|----------|
| Triton Backend API | NVIDIA | API 版本兼容性 |
| Ascend SDK | 华为 | 设备驱动稳定性 |
| ONNX Runtime | Microsoft | 模型解析安全性 |
| nlohmann/json | v3.x | JSON 解析异常 |

---

> **报告生成时间**: 2026-04-22
> **分析工具**: Architecture Agent (自主分析模式)
> **后续步骤**: 建议进行 DataFlow Scanner 和 Security Auditor 阶段的深度代码审计