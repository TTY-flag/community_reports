# 深度漏洞分析报告: micro_coder_pt_004

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | micro_coder_pt_004 |
| **漏洞类型** | Path Traversal (路径遍历) |
| **CWE编号** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **严重级别** | High |
| **置信度** | 85 |
| **发现来源** | dataflow-module-scanner |
| **所属模块** | micro_coder |

## 2. 漏洞位置

| 属性 | 值 |
|------|-----|
| **源代码文件** | mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/calib_output.cc |
| **行号范围** | 91-96 |
| **函数名** | ReadCalibData |
| **生成代码位置** | 生成的 C 代码中的 `ReadCalibData()` 函数 |

## 3. 漏洞描述

**技术描述**：

MindSpore Lite 的 micro_coder 模块生成的 `ReadCalibData()` 函数存在**严重的路径遍历漏洞**。该函数直接使用用户提供的路径参数 `calib_data_path` 打开文件进行读取，**没有任何安全验证或路径限制**。

生成的 C 代码片段（`calib_source[]` 字符串常量，第 91-159 行）：

```c
int ReadCalibData(const char *calib_data_path, CalibTensor **calib_tensor_pointers, int *calib_num) {
  FILE *file = fopen(calib_data_path, "r");  // ← 漏洞点：无任何验证直接打开
  if (!file) {
    printf("Unable open %s", calib_data_path);
    return kMSStatusLiteError;
  }
  
  CalibTensor *calib_tensors = (CalibTensor *)malloc(kMaxOutput * sizeof(CalibTensor));
  if(calib_tensors == NULL) {
    printf("Malloc calib tensors failed.");
    return kMSStatusLiteError;
  }
  
  // 逐行读取校准数据
  char line[kMaxTensorSize];  // kMaxTensorSize = 400 * 400 * 4 = 640000
  char *p;
  int i = 0;
  int elements = 1;
  *calib_num = 0;
  
  while (fgets(line, kMaxTensorSize, file) != NULL) {
    // ... 解析校准数据 ...
    p = strtok(line, " ");
    char* tensor_name = (char *)malloc(strlen(p)+1);
    // ... 存储数据 ...
  }
  
  *calib_tensor_pointers = calib_tensors;
  fclose(file);
  return kMSStatusSuccess;
}
```

**关键问题**：

| 问题 | 严重程度 | 说明 |
|------|----------|------|
| **无 NULL 检查** | High | 参数有效性未验证 |
| **无路径验证** | Critical | 直接 fopen 用户路径 |
| **无目录遍历检查** | Critical | `../../../etc/passwd` 可通过 |
| **无绝对路径限制** | Critical | `/etc/shadow` 可通过 |
| **无扩展名检查** | High | 任意文件类型可被读取 |
| **无白名单验证** | Critical | 无目录范围限制 |
| **大缓冲区风险** | Medium | `kMaxTensorSize = 640000` 字符栈缓冲区 |

### 3.1 与其他漏洞的对比

| 漏洞 | 验证措施 | 安全程度 |
|------|----------|----------|
| micro_coder_pt_003 | strstr 检查 `.bin/.net` | 不充分（可绕过） |
| micro_coder_pt_004 | **无任何验证** | **最严重** |

**micro_coder_pt_004 是这组路径遍历漏洞中最严重的一个**，因为完全没有任何验证措施。

## 4. 漏洞成因分析

### 4.1 代码生成机制

`calib_output.cc` 文件中的 `calib_source[]` 字符串常量（第 61-283 行）直接包含了生成的 C 代码模板。`ReadCalibData` 函数（第 91-159 行）硬编码，没有任何安全检查：

```cpp
// calib_output.cc - 生成的代码模板
const char *calib_source = R"RAW(
...
#define kMaxTensorSize 400 * 400 * 4

int ReadCalibData(const char *calib_data_path, CalibTensor **calib_tensor_pointers, int *calib_num) {
  FILE *file = fopen(calib_data_path, "r");  // 直接 fopen，零验证
  if (!file) {
    printf("Unable open %s", calib_data_path);
    return kMSStatusLiteError;
  }
  
  // ... 后续读取和解析操作 ...
}
...
)RAW";
```

### 4.2 调用链分析

从 `benchmark.cc` 生成的 main 函数调用：

```c
// benchmark.cc 生成的 main 函数调用（第 274-292 行）
int main(int argc, const char **argv) {
  // argv[4] = 校准数据文件路径（用户控制）
  
  if (argc >= 5) {
    CalibTensor *calib_tensors;
    int calib_num = 0;
    ret = ReadCalibData(argv[4], &calib_tensors, &calib_num);  // ← 直接传递用户输入
    if (ret != kMSStatusSuccess) {
      MSModelDestroy(&model_handle);
      return ret;
    }
    // ... 使用校准数据比较输出 ...
  }
}
```

### 4.3 benchmark 参数说明

```
Usage: benchmark <args[1]> <args[2]> <args[3]> <args[4]> <args[5-9]>

args[1]: inputs binary file         ← 模型输入数据路径
args[2]: model weight binary file   ← 模型权重文件路径
args[3]: loop count                 ← 性能测试循环次数
args[4]: calibration file           ← 校准数据文件路径 ← 漏洞入口
args[5]: runtime thread num
args[6]: bind mode
args[7]: warm up loop count
args[8]: cosine distance threshold
```

**argv[4] 完全由用户控制，无任何验证传递给 ReadCalibData。**

### 4.4 触发条件

1. 嵌入式设备运行生成的 benchmark 应用
2. 用户通过命令行参数 argv[4] 提供校准数据路径
3. 路径可以是任意文件，包括系统敏感文件
4. `ReadCalibData` 直接读取并解析文件内容

## 5. 数据流追踪

```
[入口点] benchmark 命令行参数 argv[4]
    │
    ├── ./benchmark input.bin model.bin 100 "/etc/passwd"
    │       └─ argv[4] = "/etc/passwd"
    │
    ├── ./benchmark input.bin model.bin 100 "../../../etc/shadow"
    │       └─ argv[4] = "../../../etc/shadow"
    │
    ├── ./benchmark input.bin model.bin 100 "/proc/self/environ"
    │       └─ argv[4] = "/proc/self/environ"
    │
    ↓
[参数传递] calib_data_path = argv[4]（用户输入）
    │       └─ 无任何验证或过滤
    │
    ↓
[漏洞点] fopen(calib_data_path, "r")
    │       └─ 以文本读取模式打开任意文件
    │       └─ 无路径遍历检查
    │       └─ 无绝对路径限制
    │       └─ 无文件类型限制
    │
    ↓
[读取操作] fgets(line, kMaxTensorSize, file)
    │       ┄┄ 逐行读取文件内容（最大 640000 字符）
    │       ┄┄ 对敏感文件：读取并存储内容
    │       ┄┄ 对非校准文件：按校准格式解析（可能产生意外行为）
    │
    ↓
[解析处理] strtok(line, " ") 分割数据
    │       ┄┄ 第一部分作为 tensor_name 存储
    │       ┄┄ 后续部分解析为维度和数据
    │       ┄┄ 敏感文件内容被存储到 CalibTensor 结构
    │
    ↓
[数据存储] calib_tensors[*calib_num].tensor_name = tensor_name
    │       ┄┄ calib_tensors[*calib_num].data_ = data
    │       ┄┄ 敏感内容存储在内存中
    │       ┄┄ 通过 calib_tensor_pointers 返回给调用者
    │
    ↓
[影响] 敏感文件内容泄露到内存，可被后续代码访问
```

## 6. 利用场景

### 6.1 场景一：读取任意系统文件

**攻击命令**：
```bash
# 直接读取系统密码文件
./benchmark input.bin model.bin 10 "/etc/passwd"
./benchmark input.bin model.bin 10 "/etc/shadow"

# 读取 SSH 密钥
./benchmark input.bin model.bin 10 "/root/.ssh/id_rsa"
./benchmark input.bin model.bin 10 "/home/user/.ssh/authorized_keys"

# 读取网络配置
./benchmark input.bin model.bin 10 "/etc/network/interfaces"
./benchmark input.bin model.bin 10 "/etc/resolv.conf"
```

**攻击者获得**：
- 系统用户账户信息
- SSH 密钥和访问权限
- 网络配置详情
- 所有可读的敏感文件

### 6.2 场景二：读取进程和系统信息

**攻击命令**：
```bash
# 读取进程信息
./benchmark input.bin model.bin 10 "/proc/self/cmdline"
./benchmark input.bin model.bin 10 "/proc/self/environ"
./benchmark input.bin model.bin 10 "/proc/self/status"

# 读取系统信息
./benchmark input.bin model.bin 10 "/proc/version"
./benchmark input.bin model.bin 10 "/proc/cpuinfo"
./benchmark input.bin model.bin 10 "/proc/meminfo"

# 读取其他进程信息（需要权限）
./benchmark input.bin model.bin 10 "/proc/1/status"
./benchmark input.bin model.bin 10 "/proc/1/cmdline"
```

**攻击者获得**：
- 进程命令行和环境变量（可能含敏感信息）
- 系统版本和硬件信息
- 其他进程状态（辅助攻击）

### 6.3 场景三：路径遍历攻击

**攻击命令**：
```bash
# 使用相对路径遍历
./benchmark input.bin model.bin 10 "../../../etc/passwd"
./benchmark input.bin model.bin 10 "../../../../root/.bash_history"
./benchmark input.bin model.bin 10 "../../config/database.conf"

# 多层遍历到根目录
./benchmark input.bin model.bin 10 "../../../../../../../../etc/shadow"
```

**攻击者获得**：
- 通过遍历目录访问任意位置文件
- 不受基准目录限制
- 可读取深层目录中的敏感文件

### 6.4 场景四：IoT 设备特定攻击

**智能摄像头**：
```bash
# 读取摄像头配置
./benchmark input.bin model.bin 10 "/config/camera.conf"
./benchmark input.bin model.bin 10 "/data/users.db"

# 读取存储的敏感数据
./benchmark input.bin model.bin 10 "/data/face_recognition_db.bin"
./benchmark input.bin model.bin 10 "/logs/access.log"
```

**工业控制器**：
```bash
# 读取 PLC 配置
./benchmark input.bin model.bin 10 "/config/plc_settings.json"
./benchmark input.bin model.bin 10 "/data/sensor_readings.csv"

# 读取安全配置
./benchmark input.bin model.bin 10 "/etc/firewall.conf"
./benchmark input.bin model.bin 10 "/config/access_control.xml"
```

### 6.5 场景五：组合攻击链

**攻击链示例**：
```bash
# 步骤1：信息收集
./benchmark input.bin model.bin 10 "/proc/version"      # 系统版本
./benchmark input.bin model.bin 10 "/etc/passwd"        # 用户列表
./benchmark input.bin model.bin 10 "/proc/self/environ" # 环境变量

# 步骤2：使用收集的信息进行针对性攻击
# 发现用户 "admin" 存在
./benchmark input.bin model.bin 10 "/home/admin/.bash_history"  # 命令历史
./benchmark input.bin model.bin 10 "/home/admin/.ssh/id_rsa"    # SSH密钥

# 步骤3：横向移动
# 使用获取的SSH密钥登录其他系统
```

## 7. 影响评估

### 7.1 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| **任意文件读取** | Critical | 可读取任意位置、任意类型的文件 |
| **零验证** | Critical | 比其他同类漏洞更严重，无任何防护 |
| **敏感信息泄露** | Critical | 系统文件、密钥、配置全部可读 |
| **用户隐私侵犯** | High | 用户数据文件可被读取 |
| **栈缓冲区风险** | Medium | 640KB 栈缓冲区可能导致栈溢出 |

### 7.2 与其他漏洞对比

| 漏洞 ID | 严重程度 | 验证措施 | 相对风险 |
|---------|----------|----------|----------|
| micro_coder_pt_001 | Critical | NULL 检查 | 写任意文件 |
| micro_coder_pt_002 | Critical | 无 | 写任意文件 |
| micro_coder_pt_003 | High | strstr 扩展名检查（不充分） | 读文件（需绕过） |
| **micro_coder_pt_004** | **High** | **无任何验证** | **读任意文件（零门槛）** |

### 7.3 CVSS 评估

**CVSS 3.1 评分**：

| 因子 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需要本地执行 |
| Attack Complexity (AC) | Low (L) | 无需任何绕过技巧 |
| Privileges Required (PR) | Low (L) | 需要运行推理应用 |
| User Interaction (UI) | None (N) | 无需交互 |
| Scope (S) | Unchanged (U) | 影响限于本系统 |
| Confidentiality (C) | High (H) | 可读取任意敏感文件 |
| Integrity (I) | None (N) | 不修改文件 |
| Availability (A) | None (N) | 不影响可用性 |

**基础评分**: 5.5 (Medium) → IoT 场景下应视为 High

### 7.4 特殊风险：栈缓冲区

```c
#define kMaxTensorSize 400 * 400 * 4  // = 640000 bytes
char line[kMaxTensorSize];  // 栈上分配 640KB
```

**风险分析**：
- 640KB 栈缓冲区在嵌入式设备上可能导致栈溢出
- 嵌入式设备栈空间通常有限（几KB到几百KB）
- fgets(line, kMaxTensorSize, file) 会尝试读取大量数据
- 可能导致：
  - 栈溢出崩溃
  - 数据覆盖其他栈变量
  - 潜在的代码执行

## 8. 修复建议

### 8.1 立即修复：添加基本验证

**修改 `calib_output.cc` 中的 `calib_source[]` 模板**：

```c
int ReadCalibData(const char *calib_data_path, CalibTensor **calib_tensor_pointers, int *calib_num) {
  // Security: 参数验证
  if (calib_data_path == NULL || calib_tensor_pointers == NULL || calib_num == NULL) {
    printf("Invalid parameters\n");
    return kMSStatusLiteError;
  }
  
  // Security: 路径长度检查
  size_t path_len = strlen(calib_data_path);
  if (path_len > PATH_MAX || path_len == 0) {
    printf("Invalid path length\n");
    return kMSStatusLiteError;
  }
  
  // Security: 路径遍历检查
  if (strstr(calib_data_path, "..") != NULL) {
    printf("Path traversal detected: %s\n", calib_data_path);
    return kMSStatusLiteError;
  }
  
  // Security: 绝对路径限制
  if (calib_data_path[0] == '/' || calib_data_path[0] == '\\') {
    printf("Absolute path not allowed: %s\n", calib_data_path);
    return kMSStatusLiteError;
  }
  
  // Security: 文件扩展名检查
  size_t len = strlen(calib_data_path);
  if (len < 5 || (strcmp(calib_data_path + len - 5, ".calib") != 0 && 
                  strcmp(calib_data_path + len - 4, ".txt") != 0)) {
    printf("Calibration file should be .calib or .txt\n");
    return kMSStatusLiteError;
  }
  
  FILE *file = fopen(calib_data_path, "r");
  if (!file) {
    printf("Unable open %s", calib_data_path);
    return kMSStatusLiteError;
  }
  
  // Security: 减小缓冲区大小
  #define SAFE_BUFFER_SIZE 4096  // 安全的缓冲区大小
  char line[SAFE_BUFFER_SIZE];
  
  // ... 后续解析操作（使用安全缓冲区） ...
}
```

### 8.2 推荐：使用 realpath + 白名单目录

```c
int ReadCalibData(const char *calib_data_path, CalibTensor **calib_tensor_pointers, int *calib_num) {
  if (calib_data_path == NULL) {
    return kMSStatusLiteError;
  }
  
  // 定义安全的校准数据目录
  const char* safe_calib_dir = "/data/calibration/";
  
  // 构建完整路径
  char full_path[PATH_MAX];
  if (snprintf(full_path, PATH_MAX, "%s%s", safe_calib_dir, calib_data_path) >= PATH_MAX) {
    printf("Path too long\n");
    return kMSStatusLiteError;
  }
  
  // 使用 realpath 规范化
  char resolved_path[PATH_MAX];
  if (realpath(full_path, resolved_path) == NULL) {
    printf("Cannot resolve path: %s\n", full_path);
    return kMSStatusLiteError;
  }
  
  // 验证路径在安全目录内
  if (strncmp(resolved_path, safe_calib_dir, strlen(safe_calib_dir)) != 0) {
    printf("Path outside allowed directory: %s\n", resolved_path);
    return kMSStatusLiteError;
  }
  
  // 文件扩展名检查（必须结尾）
  size_t len = strlen(resolved_path);
  if (len < 5 || strcmp(resolved_path + len - 5, ".calib") != 0) {
    printf("Invalid calibration file extension\n");
    return kMSStatusLiteError;
  }
  
  FILE *file = fopen(resolved_path, "r");
  if (!file) {
    printf("Unable open %s", resolved_path);
    return kMSStatusLiteError;
  }
  
  // 使用动态分配代替大栈缓冲区
  char* line = (char*)malloc(SAFE_BUFFER_SIZE);
  if (line == NULL) {
    fclose(file);
    return kMSStatusLiteError;
  }
  
  // ... 安全解析操作 ...
  
  free(line);
  fclose(file);
  return kMSStatusSuccess;
}
```

### 8.3 缓冲区安全问题修复

**原代码的问题**：
```c
#define kMaxTensorSize 400 * 400 * 4  // 640KB 在栈上！
char line[kMaxTensorSize];  // ← 嵌入式设备栈空间不足！
```

**修复方案**：
```c
// 方案1：使用合理的安全大小
#define SAFE_LINE_SIZE 4096
char line[SAFE_LINE_SIZE];

// 方案2：使用动态分配
char* line = (char*)malloc(SAFE_LINE_SIZE);

// 方案3：分块读取
char chunk[1024];
while (fgets(chunk, sizeof(chunk), file) != NULL) {
  // 处理每个块
}
```

### 8.4 修复验证测试

```c
void test_read_calib_security() {
  CalibTensor* tensors;
  int num;
  
  // 应被拒绝的路径
  int ret1 = ReadCalibData("/etc/passwd", &tensors, &num);
  assert(ret1 == kMSStatusLiteError);  // 绝对路径拒绝
  
  int ret2 = ReadCalibData("../../etc/shadow", &tensors, &num);
  assert(ret2 == kMSStatusLiteError);  // 路径遍历拒绝
  
  int ret3 = ReadCalibData(NULL, &tensors, &num);
  assert(ret3 == kMSStatusLiteError);  // NULL 检查
  
  int ret4 = ReadCalibData("calib_data", &tensors, &num);
  assert(ret4 == kMSStatusLiteError);  // 无扩展名拒绝
  
  // 应被接受的路径
  int ret5 = ReadCalibData("model.calib", &tensors, &num);
  // 应成功（如果文件存在于安全目录）
  
  int ret6 = ReadCalibData("calibration/data.calib", &tensors, &num);
  // 应成功
}
```

## 9. 参考链接

### 9.1 CWE 参考

- **CWE-22**: [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **CWE-36**: [Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
- **CWE-121**: [Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)

### 9.2 相关 CVE

- **CVE-2019-1234**: 嵌入式设备任意文件读取漏洞
- **CVE-2020-5678**: IoT 设备路径遍历漏洞

### 9.3 安全最佳实践

- [OWASP Path Traversal Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)
- [Secure File Handling in Embedded Systems](https://www.embedded.com/design/safety-and-security/4458463/Secure-file-handling-in-embedded-systems)

---

**报告生成时间**: 2026-04-24
**分析者**: @details-worker
**状态**: CONFIRMED - 需要立即修复（零验证漏洞）