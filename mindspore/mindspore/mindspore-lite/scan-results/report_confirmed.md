# 漏洞扫描报告 — 已确认漏洞

**项目**: mindspore-lite (华为 MindSpore Lite 推理引擎)
**扫描时间**: 2026-04-24T03:27:42.281Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

MindSpore Lite 是华为推出的轻量级深度学习推理引擎，专为嵌入式设备和 IoT 场景设计。本次安全扫描发现了 **4 个已确认的 Critical/High 级别路径遍历漏洞**，全部位于 `micro_coder` 模块生成的 C 代码模板中。

### 关键发现

- **漏洞集中度高**: 所有 4 个 CONFIRMED 漏洞均属于 **CWE-22 路径遍历** 类型，且全部位于 `micro_coder` 模块的代码生成模板中
- **攻击向量统一**: 漏洞均源于生成的嵌入式推理代码中缺乏对用户提供的文件路径参数进行安全验证
- **影响范围广**: 生成的代码被部署到各类嵌入式/IoT 设备后，攻击者可利用这些漏洞实现：
  - **任意文件写入** (micro_coder_pt_001, micro_coder_pt_002) — 可覆盖系统关键文件，导致拒绝服务或权限提升
  - **任意文件读取** (micro_coder_pt_003, micro_coder_pt_004) — 可泄露敏感信息，包括系统密码、SSH 密钥、配置文件等

### 风险评估

| 风险维度 | 评估结果 |
|---------|---------|
| **攻击难度** | Low — 直接调用 API/命令行参数，无需绕过技巧 |
| **影响严重性** | Critical — 可实现任意文件读写，影响系统完整性 |
| **影响范围** | High — 所有使用 MindSpore Lite micro coder 生成的嵌入式推理代码 |
| **修复紧迫性** | **立即** — 漏洞可被直接利用，建议优先修复代码生成模板 |

### 建议立即采取的措施

1. **修改代码生成模板**: 在 `load_input.cc` 和 `calib_output.cc` 的模板中添加路径验证逻辑
2. **发布安全公告**: 通知所有使用 MindSpore Lite micro coder 的下游项目检查生成的代码
3. **提供修复补丁**: 为已部署的嵌入式设备提供可升级的安全补丁

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 30 | 54.5% |
| POSSIBLE | 21 | 38.2% |
| CONFIRMED | 4 | 7.3% |
| **总计** | **55** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 50.0% |
| High | 2 | 50.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[micro_coder_pt_001]** Path Traversal (Critical) - `mindspore-lite/tools/converter/micro/coder/generator/component/weight_component.cc:391` @ `CodeWeightExportFunc` | 置信度: 90
2. **[micro_coder_pt_002]** Path Traversal (Critical) - `mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/load_input.cc:116` @ `SaveOutputData` | 置信度: 90
3. **[micro_coder_pt_003]** Path Traversal (High) - `mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/load_input.cc:79` @ `ReadInputData` | 置信度: 85
4. **[micro_coder_pt_004]** Path Traversal (High) - `mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/calib_output.cc:91` @ `ReadCalibData` | 置信度: 85

---

## 2. 攻击面分析

本项目为深度学习推理引擎，主要攻击面包括：

| 入口类型 | 信任等级 | 涉及模块 |
|---------|---------|---------|
| 模型文件输入 | untrusted_local | model_parser |
| 命令行参数 | untrusted_local | converter_core, benchmark_tool |
| API 调用 | untrusted_local | runtime_engine |
| 网络请求 (Triton Backend) | untrusted_network | hardware_providers |

**micro_coder 模块特殊攻击面**：

生成的嵌入式推理代码在目标设备上运行时，接受以下用户输入：
- 模型权重导出路径 (`ExportN()` 函数参数)
- 输入数据文件路径 (`ReadInputData()` 函数参数)
- 输出数据文件路径 (`SaveOutputData()` 函数参数)
- 校准数据文件路径 (`ReadCalibData()` 函数参数)

---

## 3. Critical 漏洞深度分析 (2)

### [micro_coder_pt_001] Path Traversal — 权重导出函数任意文件写入

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `mindspore-lite/tools/converter/micro/coder/generator/component/weight_component.cc:391-407` @ `CodeWeightExportFunc`
**模块**: micro_coder

#### 漏洞机制

MindSpore Lite 的 micro_coder 模块在生成嵌入式设备推理代码时，会自动生成一个权重导出函数 `ExportN()`。该函数接收用户提供的文件路径参数 `output_weight_file`，并直接使用 `fopen(output_weight_file, "wb")` 打开文件进行写入操作，**未实施任何路径验证或安全检查**。

生成的 C 代码：

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
  // ... 写入模型权重数据 ...
}
```

#### 利用场景

攻击者可通过嵌入式设备上的 API 或命令行提供恶意路径：

```bash
# 覆盖系统关键文件
ExportModel("/etc/passwd")        # 破坏认证机制
ExportModel("/bin/sh")            # 破坏 shell 程序
ExportModel("/lib/libc.so.6")     # 破坏核心库

# 权限提升
ExportModel("/etc/sudoers")       # 修改 sudo 配置
ExportModel("/etc/cron.d/backdoor")  # 创建恶意 cron 任务
```

#### 数据流路径

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

#### CVSS 评估

**评分**: 7.8 (High)

| 因子 | 值 |
|-----|---|
| Attack Vector | Local (L) |
| Attack Complexity | Low (L) |
| Privileges Required | Low (L) |
| Confidentiality | None (N) |
| Integrity | High (H) |
| Availability | High (H) |

---

### [micro_coder_pt_002] Path Traversal — 输出保存函数任意文件写入

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/load_input.cc:116-129` @ `SaveOutputData`
**模块**: micro_coder

#### 漏洞机制

生成的 `SaveOutputData()` 函数接收用户提供的文件名参数 `final_name`，并直接使用 `fopen(final_name, "w")` 打开文件进行写入操作，**未实施任何路径验证、扩展名检查或目录遍历过滤**。

生成的 C 代码：

```c
void SaveOutputData(char *final_name, unsigned char *output_data, unsigned int out_size) {
  FILE *output_file;
  output_file = fopen(final_name, "w");  // ← 漏洞点：无任何验证
  if (output_file == NULL) {
    printf("fopen output file: %s failed\n", final_name);
    return;
  }
  // ... 写入推理结果数据 ...
}
```

#### 利用场景

**场景1: 覆盖系统关键文件**

```bash
output_path = "/etc/passwd"
output_path = "/bin/ls"
output_path = "/lib/ld-linux.so.3"
```

**场景2: 创建恶意脚本文件**

```c
// 如果攻击者可以控制 output_data 的内容
unsigned char malicious_script[] = "#!/bin/sh\nrm -rf /\n";
SaveOutputData("/tmp/malicious.sh", malicious_script, strlen(malicious_script));

// 创建 cron 任务实现持久化
unsigned char cron_content[] = "* * * * * root /tmp/backdoor.sh\n";
SaveOutputData("/etc/cron.d/backdoor", cron_content, strlen(cron_content));
```

#### CVSS 评估

**评分**: 7.8 (High) — 与 micro_coder_pt_001 相同风险级别

---

## 4. High 漏洞深度分析 (2)

### [micro_coder_pt_003] Path Traversal — 输入读取函数不充分的路径验证

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/load_input.cc:79-114` @ `ReadInputData`
**模块**: micro_coder

#### 漏洞机制

生成的 `ReadInputData()` 函数使用 `strstr()` 检查输入路径是否包含 `.bin` 或 `.net` 扩展名，但这仅仅是字符串匹配检查，**无法阻止路径遍历攻击**。

生成的 C 代码：

```c
void *ReadInputData(const char *real_input_path, int *size) {
  if (real_input_path == NULL) {
    return NULL;
  }
  // ← 不充分的检查：仅检查扩展名字符串，不阻止路径遍历
  if (strstr(real_input_path, ".bin") || strstr(real_input_path, ".net")) {
    FILE *file;
    file = fopen(real_input_path, "rb");  // ← 漏洞点：无路径验证
    // ... 读取文件内容 ...
  }
}
```

#### 扩展名检查绕过示例

以下路径都能通过 strstr 检查：

```c
"../../../etc/passwd.bin"     // 包含 ".bin" 字符串 ✓ 通过检查
"/etc/shadow.net"             // 包含 ".net" 字符串 ✓ 通过检查
"../../../../root/.ssh/id_rsa.bin"  // 包含 ".bin" ✓ 通过检查
"/proc/self/environ.net"      // 包含 ".net" ✓ 通过检查
```

#### 利用场景

**读取系统密码文件**:

```bash
./benchmark "../../../etc/passwd.bin" model.bin 10
./benchmark "../../../etc/shadow.net" model.bin 10
```

**读取 SSH 密钥**:

```bash
./benchmark "../../../../root/.ssh/id_rsa.bin" model.bin 10
```

**读取进程环境变量**:

```bash
./benchmark "/proc/self/environ.bin" model.bin 10
```

#### CVSS 评估

**评分**: 5.5 → IoT 场景调整为 High

| 因子 | 值 |
|-----|---|
| Attack Vector | Local (L) |
| Attack Complexity | Low (L) |
| Confidentiality | High (H) |
| Integrity | None (N) |
| Availability | None (N) |

---

### [micro_coder_pt_004] Path Traversal — 校准数据读取函数零验证

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/calib_output.cc:91-96` @ `ReadCalibData`
**模块**: micro_coder

#### 漏洞机制

生成的 `ReadCalibData()` 函数**没有任何安全验证或路径限制**，直接使用用户提供的路径参数 `calib_data_path` 打开文件进行读取。

生成的 C 代码：

```c
int ReadCalibData(const char *calib_data_path, CalibTensor **calib_tensor_pointers, int *calib_num) {
  FILE *file = fopen(calib_data_path, "r");  // ← 漏洞点：无任何验证直接打开
  if (!file) {
    printf("Unable open %s", calib_data_path);
    return kMSStatusLiteError;
  }
  // ... 读取并解析文件内容 ...
}
```

#### 与其他漏洞对比

| 漏洞 ID | 验证措施 | 相对风险 |
|---------|----------|----------|
| micro_coder_pt_003 | strstr 扩展名检查（不充分） | 读文件（需绕过） |
| **micro_coder_pt_004** | **无任何验证** | **读任意文件（零门槛）** |

**micro_coder_pt_004 是这组路径遍历漏洞中最严重的一个**，因为完全没有任何验证措施。

#### 利用场景

**直接读取任意系统文件**:

```bash
./benchmark input.bin model.bin 10 "/etc/passwd"
./benchmark input.bin model.bin 10 "/etc/shadow"
./benchmark input.bin model.bin 10 "/root/.ssh/id_rsa"
```

**路径遍历攻击**:

```bash
./benchmark input.bin model.bin 10 "../../../etc/passwd"
./benchmark input.bin model.bin 10 "../../../../root/.bash_history"
```

#### 特殊风险：栈缓冲区

```c
#define kMaxTensorSize 400 * 400 * 4  // = 640000 bytes
char line[kMaxTensorSize];  // 栈上分配 640KB！
```

在嵌入式设备上，640KB 栈缓冲区可能导致：
- 栈溢出崩溃
- 数据覆盖其他栈变量
- 潜在的代码执行

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| micro_coder | 2 | 2 | 0 | 0 | 4 |
| **合计** | **2** | **2** | **0** | **0** | **4** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 4 | 100.0% |

---

## 7. 修复建议

### 7.1 立即修复方案

#### 修复代码生成模板

**修改 `load_input.cc` 和 `calib_output.cc` 中的 C 代码模板**，添加以下安全检查：

```c
// 通用路径安全检查模板
int validate_path(const char* path) {
  if (path == NULL) return -1;
  
  // 路径长度检查
  size_t path_len = strlen(path);
  if (path_len > PATH_MAX || path_len == 0) return -1;
  
  // 路径遍历检查
  if (strstr(path, "..") != NULL) return -1;
  
  // 绝对路径限制（根据使用场景可选）
  if (path[0] == '/' || path[0] == '\\') return -1;
  
  return 0;  // 路径有效
}
```

#### 修复 `ReadInputData` 扩展名检查

将不充分的 `strstr()` 检查改为正确的扩展名结尾检查：

```c
// 原代码（不安全）
if (strstr(real_input_path, ".bin") || strstr(real_input_path, ".net"))

// 修复代码（安全）
size_t len = strlen(real_input_path);
const char* ext = real_input_path + len - 4;
if (strcmp(ext, ".bin") != 0 && strcmp(ext, ".net") != 0) {
  printf("Invalid file extension\n");
  return NULL;
}
```

### 7.2 推荐修复方案

#### 使用 realpath + 白名单目录

```c
void *SafeReadFile(const char* user_path, int* size) {
  if (user_path == NULL) return NULL;
  
  // 定义安全的输入目录
  const char* safe_dir = "/data/model_inputs/";
  
  // 构建完整路径
  char full_path[PATH_MAX];
  snprintf(full_path, PATH_MAX, "%s%s", safe_dir, user_path);
  
  // 使用 realpath 规范化路径
  char resolved_path[PATH_MAX];
  if (realpath(full_path, resolved_path) == NULL) {
    printf("Cannot resolve path\n");
    return NULL;
  }
  
  // 验证路径在安全目录内
  if (strncmp(resolved_path, safe_dir, strlen(safe_dir)) != 0) {
    printf("Path outside allowed directory\n");
    return NULL;
  }
  
  // 安全打开文件
  FILE* file = fopen(resolved_path, "rb");
  // ... 后续操作 ...
}
```

### 7.3 架构层面改进

1. **配置化安全策略**

```cpp
// 在 Configurator 中添加安全配置
class SecurityConfig {
  std::string allowed_output_dir = "/data/weights/";
  std::string allowed_input_dir = "/data/inputs/";
  bool enable_path_validation = true;
  std::vector<std::string> allowed_extensions = {".bin", ".net", ".calib"};
};
```

2. **创建独立的安全验证头文件**

```c
// path_security.h
#ifndef PATH_SECURITY_H
#define PATH_SECURITY_H

int validate_file_path(const char* path, const char* allowed_dir);
int validate_extension(const char* path, const char** allowed_exts, int num_exts);
int contains_path_traversal(const char* path);

#endif
```

3. **在生成的代码中引用安全头文件**

```cpp
// 修改代码生成逻辑
ofs << "#include \"path_security.h\"\n";
ofs << "int Export" << ctx->GetCurModelIndex() << "(const char* output_weight_file) {\n"
    << "  if (validate_file_path(output_weight_file, SAFE_OUTPUT_DIR) != 0) {\n"
    << "    return RET_ERROR;\n"
    << "  }\n"
    << "  // ... 安全的文件操作 ...\n"
    << "}\n";
```

### 7.4 缓冲区安全问题修复

**修复 `ReadCalibData` 中的大栈缓冲区问题**：

```c
// 原代码（危险）
#define kMaxTensorSize 400 * 400 * 4  // 640KB 在栈上！
char line[kMaxTensorSize];

// 修复方案1：使用合理的安全大小
#define SAFE_LINE_SIZE 4096
char line[SAFE_LINE_SIZE];

// 修复方案2：使用动态分配
char* line = (char*)malloc(SAFE_LINE_SIZE);
if (line == NULL) return kMSStatusLiteError;
// ... 使用后释放 ...
free(line);
```

### 7.5 修复验证测试

修复后应通过以下安全测试验证：

```c
void test_path_validation() {
  // 路径遍历应被拒绝
  assert(Export0("../../../etc/passwd") == RET_ERROR);
  assert(Export0("..\\..\\..\\windows\\system32") == RET_ERROR);
  
  // 绝对路径应被拒绝
  assert(Export0("/etc/passwd") == RET_ERROR);
  assert(ReadInputData("/etc/shadow.bin", &size) == NULL);
  
  // 无扩展名应被拒绝
  assert(ReadInputData("secret", &size) == NULL);
  
  // 合法路径应被接受
  assert(Export0("weights/model.bin") == RET_OK);
  assert(ReadInputData("input.bin", &size) != NULL);
}
```

### 7.6 发布修复建议

建议 MindSpore Lite 团队采取以下步骤：

| 步骤 | 时间 | 行动 |
|-----|-----|-----|
| **立即** | 0-24h | 发布安全公告，通知下游项目 |
| **短期** | 1-7天 | 开发并发布修复补丁到代码生成模板 |
| **中期** | 1-2周 | 提供已部署设备的安全升级方案 |
| **长期** | 1-3月 | 建立代码生成的安全审查流程 |

---

## 8. 附录

### 8.1 深度分析报告

每个已确认漏洞的深度分析报告已生成，位于：

| 漏洞 ID | 报告路径 |
|---------|---------|
| micro_coder_pt_001 | `scan-results/details/micro_coder_pt_001.md` |
| micro_coder_pt_002 | `scan-results/details/micro_coder_pt_002.md` |
| micro_coder_pt_003 | `scan-results/details/micro_coder_pt_003.md` |
| micro_coder_pt_004 | `scan-results/details/micro_coder_pt_004.md` |

### 8.2 参考链接

- **CWE-22**: [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **CWE-36**: [Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
- **OWASP Path Traversal Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)
- **MindSpore Lite Documentation](https://www.mindspore.cn/lite)

---

**报告生成时间**: 2026-04-24T03:27:42.281Z
**报告生成者**: @reporter
**扫描工具**: OpenCode Vulnerability Scanner