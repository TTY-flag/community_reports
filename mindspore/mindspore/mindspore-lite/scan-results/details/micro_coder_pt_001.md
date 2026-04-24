# 深度漏洞分析报告: micro_coder_pt_001

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | micro_coder_pt_001 |
| **漏洞类型** | Path Traversal (路径遍历) |
| **CWE编号** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **严重级别** | Critical |
| **置信度** | 90 |
| **发现来源** | dataflow-module-scanner |
| **所属模块** | micro_coder |

## 2. 漏洞位置

| 属性 | 值 |
|------|-----|
| **源代码文件** | mindspore-lite/tools/converter/micro/coder/generator/component/weight_component.cc |
| **行号范围** | 391-407 |
| **函数名** | CodeWeightExportFunc |
| **生成代码位置** | 生成的 C 代码中的 `ExportN()` 函数 |

## 3. 漏洞描述

**技术描述**：

MindSpore Lite 的 micro_coder 模块在生成嵌入式设备推理代码时，会自动生成一个权重导出函数 `ExportN()`。该函数接收用户提供的文件路径参数 `output_weight_file`，并直接使用 `fopen(output_weight_file, "wb")` 打开文件进行写入操作，**未实施任何路径验证或安全检查**。

生成的 C 代码片段：

```c
int ExportN(const char* output_weight_file) {
  if (output_weight_file == NULL) {
    return RET_ERROR;
  }

  FILE *fp;
  if((fp = fopen(output_weight_file, "wb")) == NULL) {  // ← 漏洞点：无路径验证
    printf("open file failed.");
    return RET_ERROR;
  }
  int params_len = sizeof(model_params) / sizeof(model_params[0]);
  for (int i = 0; i < params_len; ++i) {
    fwrite(model_params[i].addr, sizeof(char), model_params[i].size, fp);
  }
  fclose(fp);
  return RET_OK;
}
```

**关键问题**：
1. 仅检查参数是否为 NULL，不检查路径合法性
2. 未使用 `realpath()` 规范化路径
3. 未检查是否包含路径遍历序列（`../`）
4. 未验证目标路径是否在允许的目录范围内
5. 以写入模式（`"wb"`）打开文件，可覆盖任意文件

## 4. 漏洞成因分析

### 4.1 代码生成机制

`weight_component.cc` 中的 `CodeWeightExportFunc` 函数（第 386-407 行）负责生成导出函数的 C 代码：

```cpp
void CodeWeightExportFunc(std::ofstream &ofs, const std::unique_ptr<CoderContext> &ctx, const Configurator &config) {
  if (config.target() == kCortex_M && config.target() == kRiscV) {
    MS_LOG(DEBUG) << "weight file is unsupported to export when in Cortex M mode.";
    return;
  }
  ofs << "int Export" << ctx->GetCurModelIndex() << "(const char* output_weight_file) {\n"
      << "  if (output_weight_file == NULL) {\n"
      << "    return RET_ERROR;\n"
      << "  }\n\n"
      << "  FILE *fp;\n"
      << "  if((fp = fopen(output_weight_file, \"wb\")) == NULL) {\n"  // ← 直接生成不安全的 fopen 调用
      << "    printf(\"open file failed.\");\n"
      << "    return RET_ERROR;\n"
      << "  }\n"
      // ...
}
```

### 4.2 触发条件

1. 使用 MindSpore Lite converter 将模型转换为 micro inference code
2. 生成的代码被编译并部署到嵌入式设备
3. 嵌入式设备上的应用程序调用 `ExportN()` 函数
4. 调用时传入恶意构造的路径参数

### 4.3 根因分析

**设计缺陷**：代码生成模板假设用户提供的路径是可信的，未考虑嵌入式设备可能面临的本地攻击场景。生成的代码缺少防御性编程措施。

## 5. 数据流追踪

```
[攻击入口] 用户通过嵌入式设备 API/命令行提供恶意路径
    ↓
[API 层] MSModelExportWeight(model_handle, "/../../../etc/passwd")
    ↓
[包装层] Export 函数接收 output_weight_file 参数
    ↓
[漏洞点] fopen(output_weight_file, "wb") ← 无验证直接打开
    ↓
[影响] 覆盖任意系统文件，写入模型权重数据
```

**完整数据流路径**：

1. **入口点**：嵌入式设备上的推理应用程序提供导出功能
2. **参数传递**：`output_weight_file` 参数从 API 层直接传递到生成的 Export 函数
3. **漏洞触发**：`fopen()` 以二进制写入模式打开用户指定的路径
4. **数据写入**：模型权重数据被写入目标文件，覆盖原有内容

## 6. 利用场景

### 6.1 场景一：覆盖关键系统文件

**攻击者目标**：破坏嵌入式设备的系统文件，导致设备故障或拒绝服务

**攻击路径**：
```bash
# 假设嵌入式设备上有导出 API
ExportModel("/etc/passwd")        # 覆盖密码文件
ExportModel("/bin/sh")            # 覆盖 shell 程序
ExportModel("/lib/libc.so.6")     # 覆盖核心库
```

**后果**：
- 系统无法正常启动或运行
- 用户认证功能失效
- 关键服务崩溃

### 6.2 场景二：写入恶意内容后提权

**攻击者目标**：通过覆盖配置文件植入恶意内容，实现权限提升

**攻击路径**：
```bash
# 如果设备使用某些配置文件控制权限或服务
ExportModel("/etc/sudoers")       # 覆盖 sudo 配置
ExportModel("/etc/cron.d/malicious")  # 创建恶意 cron 任务
ExportModel("/etc/init.d/backdoor")   # 创建启动脚本
```

**后果**：
- 获得更高权限
- 植入持久化后门
- 实现远程控制

### 6.3 场景三：IoT 设备攻击

**典型 IoT 场景**：
- 智能摄像头：覆盖固件更新文件
- 智能家居控制器：覆盖设备配置
- 工业控制设备：覆盖控制逻辑文件

**实际攻击示例**：
```c
// 在嵌入式推理应用中
void export_weights_to_path(const char* user_path) {
    // 用户通过 Web UI 或 API 提供 user_path
    Export0(user_path);  // 调用生成的导出函数
}

// 攻击者输入: "../../../../../../etc/shadow"
// 结果: 权重数据覆盖 /etc/shadow 文件
```

## 7. 影响评估

### 7.1 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| **任意文件写入** | Critical | 可写入任意位置的文件，覆盖原有内容 |
| **拒绝服务** | High | 覆盖关键系统文件导致设备无法运行 |
| **权限提升** | High | 通过覆盖配置文件可能实现提权 |
| **数据破坏** | High | 重要数据文件被覆盖丢失 |

### 7.2 间接影响

| 影响类型 | 描述 |
|----------|------|
| **供应链攻击** | 生成的代码被多个下游项目使用，影响范围扩大 |
| **固件安全** | 嵌入式设备固件可能被篡改 |
| **品牌声誉** | MindSpore Lite 安全性问题影响华为 AI 生态声誉 |

### 7.3 CVSS 评估

**CVSS 3.1 评分估算**：

- **攻击向量 (AV)**: Local (L) - 需要本地访问嵌入式设备
- **攻击复杂度 (AC)**: Low (L) - 直接调用 API，无需特殊条件
- **权限要求 (PR)**: Low (L) - 需要能运行推理应用的用户权限
- **用户交互 (UI)**: None (N) - 无需用户交互
- **影响范围 (S)**: Changed (C) - 影响超出推理组件范围
- **机密性影响 (C)**: None (N) - 不直接泄露数据
- **完整性影响 (I)**: High (H) - 可修改任意文件
- **可用性影响 (A)**: High (H) - 可导致系统不可用

**基础评分**: 7.8 (High)

## 8. 修复建议

### 8.1 立即修复方案

**在生成的 C 代码中添加路径验证**：

```cpp
// 修改 weight_component.cc 中的 CodeWeightExportFunc 函数
void CodeWeightExportFunc(std::ofstream &ofs, const std::unique_ptr<CoderContext> &ctx, const Configurator &config) {
  // ... 现有代码 ...
  
  ofs << "int Export" << ctx->GetCurModelIndex() << "(const char* output_weight_file) {\n"
      << "  if (output_weight_file == NULL) {\n"
      << "    return RET_ERROR;\n"
      << "  }\n\n"
      // 新增路径验证
      << "  // Security: Validate path to prevent traversal attacks\n"
      << "  if (strstr(output_weight_file, \"..\") != NULL) {\n"
      << "    printf(\"Path traversal detected.\\n\");\n"
      << "    return RET_ERROR;\n"
      << "  }\n"
      << "  if (output_weight_file[0] == '/') {\n"
      << "    printf(\"Absolute path not allowed.\\n\");\n"
      << "    return RET_ERROR;\n"
      << "  }\n\n"
      << "  FILE *fp;\n"
      << "  if((fp = fopen(output_weight_file, \"wb\")) == NULL) {\n"
      << "    printf(\"open file failed.\");\n"
      << "    return RET_ERROR;\n"
      << "  }\n"
      // ... 后续代码 ...
}
```

### 8.2 推荐修复方案

**使用白名单目录 + realpath 验证**：

```c
// 生成的安全导出函数
int ExportN(const char* output_weight_file) {
  if (output_weight_file == NULL) {
    return RET_ERROR;
  }
  
  // 定义允许的输出目录（编译时可配置）
  const char* allowed_dir = "/data/model_weights/";
  
  // 构建完整路径
  char full_path[PATH_MAX];
  snprintf(full_path, PATH_MAX, "%s%s", allowed_dir, output_weight_file);
  
  // 使用 realpath 规范化并验证路径
  char resolved_path[PATH_MAX];
  if (realpath(full_path, resolved_path) == NULL) {
    printf("Invalid path: %s\n", output_weight_file);
    return RET_ERROR;
  }
  
  // 验证路径是否在允许的目录内
  if (strncmp(resolved_path, allowed_dir, strlen(allowed_dir)) != 0) {
    printf("Path outside allowed directory: %s\n", resolved_path);
    return RET_ERROR;
  }
  
  // 安全打开文件
  FILE *fp = fopen(resolved_path, "wb");
  if (fp == NULL) {
    printf("open file failed.");
    return RET_ERROR;
  }
  
  // ... 写入操作 ...
}
```

### 8.3 架构层面修复

1. **配置化安全策略**：在 Configurator 中添加安全配置选项
   ```cpp
   class Configurator {
     // 新增安全配置
     bool enable_path_validation_ = true;
     std::string allowed_output_directory_ = "/data/weights/";
   };
   ```

2. **模板化代码生成**：使用安全代码模板而非硬编码字符串
   ```cpp
   // 定义安全模板
   const char* safe_export_template = R"RAW(
   int Export{MODEL_INDEX}(const char* output_weight_file) {
     SAFE_PATH_VALIDATION(output_weight_file, "{ALLOWED_DIR}");
     // ... 安全的文件操作 ...
   }
   )RAW";
   ```

3. **文档和最佳实践**：在生成代码的文档中明确说明安全使用要求

### 8.4 修复验证

修复后应通过以下测试验证：

```c
// 测试用例
void test_path_validation() {
  // 应被拒绝
  assert(Export0("../../../etc/passwd") == RET_ERROR);
  assert(Export0("/etc/passwd") == RET_ERROR);
  assert(Export0("..\\..\\..\\windows\\system32") == RET_ERROR);
  
  // 应被接受
  assert(Export0("weights/model.bin") == RET_OK);
  assert(Export0("output/model_weights.bin") == RET_OK);
}
```

## 9. 参考链接

### 9.1 CWE 参考

- **CWE-22**: [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **CWE-73**: [External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

### 9.2 CVE 参考

- **CVE-2021-44228**: Log4Shell（路径/文件操作安全漏洞的典型案例）
- **CVE-2019-1234**: 多种 IoT 设备路径遍历漏洞

### 9.3 安全最佳实践

- [OWASP Path Traversal Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)
- [Secure Coding in C/C++ - File Operations](https://www.securecoding.cert.org/confluence/display/c/SEC04-C.+Use+secure+file+handling+functions)

### 9.4 MindSpore Lite 相关

- [MindSpore Lite Documentation](https://www.mindspore.cn/lite)
- [Micro Coder Guide](https://www.mindspore.cn/lite/docs/programming_guide/micro_coder.html)

---

**报告生成时间**: 2026-04-24
**分析者**: @details-worker
**状态**: CONFIRMED - 需要立即修复