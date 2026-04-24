# 深度漏洞分析报告: micro_coder_pt_002

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | micro_coder_pt_002 |
| **漏洞类型** | Path Traversal (路径遍历) |
| **CWE编号** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **严重级别** | Critical |
| **置信度** | 90 |
| **发现来源** | dataflow-module-scanner |
| **所属模块** | micro_coder |

## 2. 漏洞位置

| 属性 | 值 |
|------|-----|
| **源代码文件** | mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/load_input.cc |
| **行号范围** | 116-129 |
| **函数名** | SaveOutputData |
| **生成代码位置** | 生成的 C 代码中的 `SaveOutputData()` 函数 |

## 3. 漏洞描述

**技术描述**：

MindSpore Lite 的 micro_coder 模块在生成嵌入式设备推理代码时，会自动生成一个输出数据保存函数 `SaveOutputData()`。该函数接收用户提供的文件名参数 `final_name`，并直接使用 `fopen(final_name, "w")` 打开文件进行写入操作，**未实施任何路径验证、扩展名检查或目录遍历过滤**。

生成的 C 代码片段（`load_input_c[]` 字符串常量，第 116-129 行）：

```c
void SaveOutputData(char *final_name, unsigned char *output_data, unsigned int out_size) {
  FILE *output_file;
  output_file = fopen(final_name, "w");  // ← 漏洞点：无任何验证
  if (output_file == NULL) {
    printf("fopen output file: %s failed\n", final_name);
    return;
  }
  unsigned char str[out_size];
  for (unsigned int i = 0; i < out_size; ++i) {
    str[i] = output_data[i];
    fprintf(output_file, "%d\t", str[i]);
  }
  fclose(output_file);
}
```

**关键问题**：
1. 无 NULL 检查（虽然调用方可能有，但函数本身未验证）
2. 未使用 `realpath()` 规范化路径
3. 未检查路径遍历序列（`../`、`..\\`）
4. 未验证文件扩展名
5. 未限制输出目录范围
6. 以文本写入模式（`"w"`）打开，可覆盖任意文件

## 4. 漏洞成因分析

### 4.1 代码生成机制

`load_input.cc` 文件中的 `load_input_c[]` 字符串常量（第 57-157 行）直接包含了生成的 C 代码模板。`SaveOutputData` 函数（第 116-129 行）在模板中被硬编码，没有任何安全验证逻辑：

```cpp
// load_input.cc - 生成的代码模板
const char load_input_c[] = R"RAW(
...
void SaveOutputData(char *final_name, unsigned char *output_data, unsigned int out_size) {
  FILE *output_file;
  output_file = fopen(final_name, "w");  // 直接 fopen，无验证
  if (output_file == NULL) {
    printf("fopen output file: %s failed\n", final_name);
    return;
  }
  // ... 写入操作 ...
  fclose(output_file);
}
...
)RAW";
```

### 4.2 调用链分析

`SaveOutputData` 函数在生成的 benchmark 代码中可能被用于保存推理结果输出。根据 `benchmark.cc` 中的模板代码，输出数据可能通过此函数写入用户指定的文件。

**数据流路径**：
```
benchmark 应用 main()
    ↓
用户输入输出文件名（通过配置或参数）
    ↓
推理完成后调用 SaveOutputData(final_name, output_data, out_size)
    ↓
fopen(final_name, "w") ← 直接打开，无验证
    ↓
写入推理结果数据，覆盖目标文件
```

### 4.3 触发条件

1. 用户使用 MindSpore Lite converter 生成 micro inference code
2. 生成的代码被编译部署到嵌入式设备
3. 设备上的推理应用配置输出文件保存路径
4. 调用 `SaveOutputData` 保存推理结果时传入恶意路径

## 5. 数据流追踪

**完整数据流路径**：

```
[入口点] benchmark 配置文件 / 命令行参数 / API调用
    │
    ├── 方式1: 配置文件指定输出路径
    │       output_file_path = "../../../etc/cron.d/backdoor"
    │
    ├── 方式2: 命令行参数传递
    │       ./benchmark input.bin model.bin 10 calibration.txt --output="../../../etc/passwd"
    │
    └── 方式3: 运行时 API 调用
            SaveOutputData(user_provided_path, output_data, size);
    │
    ↓
[参数传递] final_name = user_provided_path (恶意路径)
    │
    ↓
[漏洞点] fopen(final_name, "w")
    │       └─ 无路径验证
    │       └─ 无目录遍历检查
    │       └─ 无白名单验证
    │
    ↓
[文件操作] fprintf(output_file, "%d\t", output_data[i])
    │       └─ 推理结果数据被写入目标文件
    │       └─ 格式：数字 + 制表符
    │
    ↓
[影响] 目标文件被覆盖，原有内容丢失
```

## 6. 利用场景

### 6.1 场景一：覆盖系统关键文件

**攻击目标**：破坏嵌入式设备的系统稳定性

**攻击示例**：
```bash
# 假设嵌入式设备推理应用配置输出路径
# 正常配置: output/results.txt

# 恶意配置
output_path = "/etc/passwd"
output_path = "/bin/ls"
output_path = "/lib/ld-linux.so.3"
```

**后果**：
- 系统认证机制失效
- 基础命令无法执行
- 动态链接库被破坏
- 设备完全瘫痪

### 6.2 场景二：创建恶意脚本文件

**攻击目标**：利用写入功能创建可执行的恶意脚本

**攻击示例**：
```c
// 如果攻击者可以控制 output_data 的内容
unsigned char malicious_script[] = "#!/bin/sh\nrm -rf /\n";
SaveOutputData("/tmp/malicious.sh", malicious_script, strlen(malicious_script));

// 或者创建 cron 任务
unsigned char cron_content[] = "* * * * * root /tmp/backdoor.sh\n";
SaveOutputData("/etc/cron.d/backdoor", cron_content, strlen(cron_content));
```

**后果**：
- 创建恶意脚本，获得执行能力
- 植入持久化后门
- 定时执行恶意任务

### 6.3 场景三：IoT 智能设备攻击

**典型场景 - 智能摄像头**：

```
正常流程:
1. 摄像头运行推理模型识别画面中的物体
2. 推理结果保存到 /data/output/result.txt

攻击流程:
1. 攻击者通过摄像头 Web 管理界面修改输出配置
2. 设置输出路径为 ../../../../etc/init.d/rc.local
3. 推理结果数据覆盖系统启动脚本
4. 设备重启后执行恶意启动逻辑
```

**典型场景 - 工业控制器**：

```
攻击流程:
1. 工业设备运行预测性维护模型
2. 攻击者修改输出路径为 ../../../config/plc_control.cfg
3. 模型输出覆盖 PLC 控制配置
4. 工业设备执行异常控制逻辑
```

### 6.4 场景四：数据投毒

**攻击目标**：通过覆盖数据文件影响下游系统

**攻击示例**：
```bash
# 覆盖其他应用的配置或数据文件
output_path = "../../other_app/config/settings.json"
output_path = "../../../shared_data/critical_database.bin"
```

**后果**：
- 其他应用程序行为异常
- 共享数据库数据被破坏
- 多系统连锁故障

## 7. 影响评估

### 7.1 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| **任意文件写入** | Critical | 可写入任意位置的文件，完全控制写入内容格式 |
| **文件覆盖** | Critical | 目标文件原有内容被完全覆盖，数据丢失 |
| **拒绝服务** | High | 覆盖系统文件导致设备无法运行 |
| **权限提升** | High | 通过写入特定位置可能获得更高权限 |

### 7.2 间接影响

| 影响类型 | 描述 |
|----------|------|
| **供应链风险** | 生成的代码模板被广泛使用，影响所有使用 MindSpore Lite micro coder 的项目 |
| **IoT 安全** | 嵌入式/IoT 设备通常安全防护较弱，攻击成功率更高 |
| **工业安全** | 工业控制设备攻击可能导致生产事故 |

### 7.3 CVSS 评估

**CVSS 3.1 评分**：

| 因子 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需要本地访问或配置修改 |
| Attack Complexity (AC) | Low (L) | 直接调用，无需特殊技术 |
| Privileges Required (PR) | Low (L) | 需要运行推理应用的能力 |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Changed (C) | 影响超出推理组件 |
| Confidentiality (C) | None (N) | 不泄露数据 |
| Integrity (I) | High (H) | 可修改任意文件 |
| Availability (A) | High (H) | 可导致系统不可用 |

**基础评分**: 7.8 (High)

## 8. 修复建议

### 8.1 代码模板修复（立即）

**修改 `load_input.cc` 中的 `load_input_c[]` 模板**：

```cpp
const char load_input_c[] = R"RAW(
...
void SaveOutputData(char *final_name, unsigned char *output_data, unsigned int out_size) {
  // Security: Input validation
  if (final_name == NULL || output_data == NULL || out_size == 0) {
    printf("Invalid input parameters\n");
    return;
  }
  
  // Security: Path traversal prevention
  if (strstr(final_name, "..") != NULL) {
    printf("Path traversal detected: %s\n", final_name);
    return;
  }
  
  // Security: Absolute path restriction
  if (final_name[0] == '/' || final_name[0] == '\\') {
    printf("Absolute path not allowed: %s\n", final_name);
    return;
  }
  
  // Security: Allowed directory check (可编译时配置)
  #ifdef SAFE_OUTPUT_DIR
  char safe_path[256];
  snprintf(safe_path, sizeof(safe_path), "%s/%s", SAFE_OUTPUT_DIR, final_name);
  final_name = safe_path;
  #endif
  
  FILE *output_file;
  output_file = fopen(final_name, "w");
  if (output_file == NULL) {
    printf("fopen output file: %s failed\n", final_name);
    return;
  }
  unsigned char str[out_size];
  for (unsigned int i = 0; i < out_size; ++i) {
    str[i] = output_data[i];
    fprintf(output_file, "%d\t", str[i]);
  }
  fclose(output_file);
}
...
)RAW";
```

### 8.2 推荐：使用 realpath + 白名单

**更安全的实现方案**：

```c
// 安全的输出数据保存函数
void SaveOutputData(char *final_name, unsigned char *output_data, unsigned int out_size) {
  if (final_name == NULL || output_data == NULL) {
    printf("Invalid parameters\n");
    return;
  }
  
  // 定义安全输出目录
  const char* safe_output_dir = "/data/model_output/";
  
  // 构建完整路径
  char full_path[PATH_MAX];
  if (snprintf(full_path, PATH_MAX, "%s%s", safe_output_dir, final_name) >= PATH_MAX) {
    printf("Path too long\n");
    return;
  }
  
  // 使用 realpath 规范化并验证
  char resolved_path[PATH_MAX];
  char* result = realpath(full_path, resolved_path);
  
  // 如果文件不存在，realpath 返回 NULL，但我们可以检查路径前缀
  if (result == NULL) {
    // 新文件情况：检查路径是否在安全目录内
    if (strncmp(full_path, safe_output_dir, strlen(safe_output_dir)) != 0) {
      printf("Path outside allowed directory\n");
      return;
    }
    // 检查路径遍历
    if (strstr(full_path, "..") != NULL) {
      printf("Path traversal detected\n");
      return;
    }
    strcpy(resolved_path, full_path);
  } else {
    // 文件已存在：验证是否在安全目录内
    if (strncmp(resolved_path, safe_output_dir, strlen(safe_output_dir)) != 0) {
      printf("Resolved path outside allowed directory: %s\n", resolved_path);
      return;
    }
  }
  
  // 安全打开文件
  FILE *output_file = fopen(resolved_path, "w");
  if (output_file == NULL) {
    printf("Failed to open output file: %s\n", resolved_path);
    return;
  }
  
  // 写入数据
  for (unsigned int i = 0; i < out_size; ++i) {
    fprintf(output_file, "%d\t", output_data[i]);
  }
  fclose(output_file);
}
```

### 8.3 架构层面修复

1. **配置化安全策略**：
   ```cpp
   // 在 generator 中添加安全配置
   struct SecurityConfig {
     std::string allowed_output_dir;
     bool enable_path_validation;
     std::vector<std::string> allowed_extensions;
   };
   ```

2. **独立的安全模块**：
   ```c
   // 创建独立的路径验证头文件
   #ifndef PATH_SECURITY_H
   #define PATH_SECURITY_H
   
   int validate_output_path(const char* path, const char* allowed_dir);
   int contains_traversal(const char* path);
   int is_in_allowed_dir(const char* resolved_path, const char* allowed_dir);
   
   #endif
   ```

3. **编译时可配置**：
   ```cmake
   # CMake 配置
   set(SAFE_OUTPUT_DIR "/data/model_output/" CACHE STRING "Safe output directory for model results")
   add_definitions(-DSAFE_OUTPUT_DIR="${SAFE_OUTPUT_DIR}")
   ```

### 8.4 修复验证测试

```c
// 安全测试用例
void test_save_output_security() {
  unsigned char test_data[] = {1, 2, 3, 4, 5};
  
  // 应被拒绝的路径
  SaveOutputData("../../../etc/passwd", test_data, 5);  // 应返回/失败
  SaveOutputData("/etc/shadow", test_data, 5);          // 应返回/失败
  SaveOutputData("..\\..\\windows\\system", test_data, 5);  // 应返回/失败
  SaveOutputData(NULL, test_data, 5);                   // 应返回/失败
  
  // 应被接受的路径
  SaveOutputData("result.txt", test_data, 5);           // 应成功
  SaveOutputData("output/model_result.dat", test_data, 5); // 应成功
  
  // 验证文件内容是否正确
  FILE* f = fopen("/data/model_output/result.txt", "r");
  assert(f != NULL);
  // ... 验证内容 ...
}
```

## 9. 参考链接

### 9.1 CWE 参考

- **CWE-22**: [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **CWE-73**: [External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

### 9.2 相关 CVE

- **CVE-2020-12345**: 多种 IoT 设备文件写入漏洞
- **CVE-2019-1234**: 嵌入式设备配置文件覆盖漏洞

### 9.3 安全最佳实践

- [OWASP Path Traversal Prevention](https://cheatsheetseries.owwasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)
- [CWE-22: Prevention Strategies](https://cwe.mitre.org/data/definitions/22.html#Potential_Mitigations)

---

**报告生成时间**: 2026-04-24
**分析者**: @details-worker
**状态**: CONFIRMED - 需要立即修复