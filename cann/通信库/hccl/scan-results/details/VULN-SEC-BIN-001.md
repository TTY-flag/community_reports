# VULN-SEC-BIN-001：ASCEND_HOME_PATH控制内核加载路径漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-BIN-001, VULN-DF-008 (合并) |
| **CWE** | CWE-426: Untrusted Search Path |
| **严重性** | High |
| **置信度** | 85 |
| **漏洞类型** | 二进制文件路径注入 / Kernel 加载劫持 |
| **受影响文件** | `src/ops/op_common/template/aiv/hccl_aiv_utils.cc` |

HCCL 库在 AIV (AI Vector) 模式下加载 kernel 二进制文件时，直接使用 `ASCEND_HOME_PATH` 环境变量拼接路径，缺少路径规范化和校验。攻击者可通过控制该环境变量，使程序加载恶意篡改的 kernel 二进制文件，实现代码执行攻击。

---

## 漏洞详情

### 代码位置

**文件**: `src/ops/op_common/template/aiv/hccl_aiv_utils.cc`
**行号**: 140-158
**函数**: `GetAivOpBinaryPath()`

```cpp
HcclResult GetAivOpBinaryPath(const std::string &aivBinaryName, std::string &binaryPath)
{
    // 获取二进制文件路径
    std::string libPath;
    char *getPath = nullptr;
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);  // ← 从环境变量获取路径
    if (getPath != nullptr) {
        libPath = getPath;  // ← 直接使用，无校验
    } else {
        libPath = "/usr/local/Ascend/cann";
        HCCL_WARNING("[GetAivOpBinaryPath]ENV:ASCEND_HOME_PATH is not set");
    }
    binaryPath = libPath + "/lib64";

    // 拼接应该加载的文件
    binaryPath += "/" + aivBinaryName;
    HCCL_INFO("[GetAivOpBinaryPath]op binary file path[%s]", binaryPath.c_str());
    return HCCL_SUCCESS;
}
```

### 数据流路径

```
ASCEND_HOME_PATH 环境变量
        ↓
MM_SYS_GET_ENV() 读取环境变量
        ↓
getPath (未校验的路径)
        ↓
libPath = getPath  (直接赋值)
        ↓
binaryPath = libPath + "/lib64/" + aivBinaryName
        ↓
LoadBinaryFromFile(binaryPath)  加载二进制文件
        ↓
aclrtLaunchKernelWithHostArgs()  执行 kernel
```

### 触发条件

1. **算子执行模式选择**
   - 当 HCCL 选择 AIV 或 AIV_ONLY 执行模式时触发
   - 控制路径: `ApplyOpExpansionMode()` → `RegisterKernel()` → `GetAivOpBinaryPath()`

2. **模式选择入口**
   ```
   HcclAllReduce/HcclAllGather 等公开 API
   → 算子执行流程
   → ApplyOpExpansionMode(HCCL_OP_EXPANSION_MODE_AIV)  [op_common.cc:1619]
   → RegisterKernel()
   → GetAivOpBinaryPath()
   → 加载恶意 kernel binary
   ```

3. **环境变量控制**
   - `ASCEND_HOME_PATH` 由用户环境设置
   - 无任何路径验证（如 realpath、目录白名单等）

---

## 利用场景分析

### 攻击路径

#### 场景1: 环境变量劫持攻击

```
前提条件:
- 攻击者能控制用户的环境变量配置
- 用户执行 AIV 模式的集合通信算子（如 AllReduce）

攻击步骤:
1. 攻击者设置 ASCEND_HOME_PATH=/tmp/malicious
2. 在 /tmp/malicious/lib64/ 目录创建恶意 kernel binary
3. 用户执行 AI 训练任务，HCCL 选择 AIV 模式
4. GetAivOpBinaryPath() 拼接路径 → /tmp/malicious/lib64/xxx.bin
5. LoadBinaryFromFile() 加载恶意 kernel
6. aclrtLaunchKernelWithHostArgs() 执行恶意 kernel 代码
```

#### 场景2: 路径注入攻击

```
前提条件:
- 攻击者能部分控制环境变量内容

攻击变种:
1. ASCEND_HOME_PATH=/usr/local/Ascend/cann/../../../tmp
   → 路径解析为 /tmp/lib64/xxx.bin
   → 使用相对路径绕过预期目录限制

2. ASCEND_HOME_PATH=/tmp;rm -rf /
   → 虽然不会直接执行命令，但可能影响路径解析

3. ASCEND_HOME_PATH=/nonexistent/../tmp
   → 利用路径规范化差异
```

#### 场景3: 容器/集群环境攻击

```
前提条件:
- 多节点训练环境
- 某节点被攻击者控制

攻击步骤:
1. 攻击者修改自己节点的 ASCEND_HOME_PATH
2. 在恶意路径放置篡改的 kernel binary
3. kernel 内包含恶意逻辑（如数据窃取、结果篡改）
4. 集群训练过程中，该节点的计算结果被污染
5. 影响全局训练效果或窃取敏感数据
```

### 前提条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| ASCEND_HOME_PATH 控制 | 必要 | 需要能设置或修改该环境变量 |
| AIV 模式触发 | 必要 | 算子需选择 AIV 或 AIV_ONLY 模式 |
| 恶意 kernel 文件 | 必要 | 需准备恶意二进制文件 |
| 文件写入权限 | 必要 | 需在控制路径下创建恶意文件 |

---

## 影响评估

### 受影响组件

- **直接受影响**: 
  - AIV kernel 加载机制
  - 所有使用 AIV 模式的集合通信算子

- **间接受影响**:
  - 集合通信数据完整性（kernel 可篡改计算结果）
  - 集群训练安全（恶意节点可污染全局结果）
  - 敏感数据泄露（kernel 可窃取通信缓冲区内容）

### 潜在后果

| 级别 | 影响 | 说明 |
|------|------|------|
| **Critical** | Kernel 代码执行 | 恶意 kernel 在 NPU 上执行，可影响计算逻辑 |
| **High** | 数据篡改 | 集合通信中间结果被篡改，影响训练准确性 |
| **High** | 数据窃取 | Kernel 可访问通信缓冲区，窃取训练数据/模型 |
| **High** | 集群污染 | 单节点恶意可影响多节点训练结果 |
| **Medium** | 拒绝服务 | 加载失败导致 AIV 模式不可用 |

### Attack Surface Analysis

```
攻击面拓扑:

┌─────────────────────────────────────────────────────────────────┐
│  攻击入口: ASCEND_HOME_PATH 环境变量                             │
│  来源: 用户配置(.bashrc), 容器环境, 启动脚本, SSH 会话            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  HCCL 公开 API 层                                                │
│  HcclAllReduce, HcclAllGather, HcclBroadcast...                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  算子执行模式选择                                                │
│  ApplyOpExpansionMode → AIV/AIV_ONLY 模式                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Kernel 加载路径拼接                                             │
│  GetAivOpBinaryPath() → 无校验路径拼接                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  恶意 Kernel 加载与执行                                          │
│  LoadBinaryFromFile → aclrtLaunchKernelWithHostArgs             │
│  → NPU 上执行恶意 kernel 代码                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  潜在影响                                                        │
│  • 计算结果篡改                                                  │
│  • 通信数据窃取                                                  │
│  • 集群训练污染                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## PoC / 利用代码构思

### 概念性 PoC（非实际攻击代码）

**攻击环境设置脚本（概念演示）:**
```bash
#!/bin/bash
# 概念性 PoC - 展示漏洞触发路径

# Step 1: 设置恶意路径
export ASCEND_HOME_PATH=/tmp/malicious_ascend

# Step 2: 创建恶意目录结构
mkdir -p /tmp/malicious_ascend/lib64

# Step 3: 准备恶意 kernel binary
# 注意: 实际攻击需要构造符合格式的 kernel 二进制文件
# 这里仅为概念演示

# Step 4: 创建一个简单的标记文件证明路径被使用
touch /tmp/malicious_ascend/lib64/.attack_marker

# Step 5: 运行 HCCL 程序触发 AIV 模式
# 当程序尝试加载 kernel 时，会访问恶意路径
# python -c "
# import torch
# import torch_npu  # 加载 HCCL
# # 执行集合通信触发 AIV 模式
# "

# Step 6: 验证路径是否被访问
if [ -f /tmp/malicious_ascend/lib64/.attack_marker ]; then
    echo "Path controlled by ASCEND_HOME_PATH was accessed!"
fi
```

**恶意 Kernel 构造思路:**
```
概念性设计（需要深入了解 AIV kernel 格式）:

1. 分析合法 AIV kernel 二进制格式
2. 修改 kernel 中的计算逻辑:
   - 将 AllReduce 的 sum 操作改为恶意计算
   - 在 kernel 中嵌入数据窃取逻辑
   - 添加触发条件（如特定数据模式）
3. 将修改后的 kernel 放入恶意路径
4. 等待 AIV 模式触发
```

---

## 修复建议

### 推荐修复方案

#### 方案1: 路径规范化与白名单校验

```cpp
#include <limits.h>
#include <sys/stat.h>
#include <cstdlib>

HcclResult GetAivOpBinaryPath(const std::string &aivBinaryName, std::string &binaryPath)
{
    std::string libPath;
    char *getPath = nullptr;
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
    
    if (getPath != nullptr) {
        // 使用 realpath 规范化路径，消除相对路径注入
        char resolvedPath[PATH_MAX];
        if (realpath(getPath, resolvedPath) == nullptr) {
            HCCL_ERROR("[GetAivOpBinaryPath] Invalid path: %s", getPath);
            return HCCL_E_PTR;
        }
        
        // 白名单校验: 只允许特定目录
        const std::vector<std::string> trustedDirs = {
            "/usr/local/Ascend",
            "/opt/Ascend",
            "/home/ascend"  // 可根据部署配置添加
        };
        
        bool isTrusted = false;
        for (const auto& dir : trustedDirs) {
            if (strncmp(resolvedPath, dir.c_str(), dir.length()) == 0) {
                isTrusted = true;
                break;
            }
        }
        
        if (!isTrusted) {
            HCCL_ERROR("[GetAivOpBinaryPath] Path not in trusted directories: %s", resolvedPath);
            return HCCL_E_PTR;
        }
        
        libPath = resolvedPath;
    } else {
        libPath = "/usr/local/Ascend/cann";
    }
    
    binaryPath = libPath + "/lib64/" + aivBinaryName;
    
    // 文件存在性和权限校验
    struct stat fileStat;
    if (stat(binaryPath.c_str(), &fileStat) != 0) {
        HCCL_ERROR("[GetAivOpBinaryPath] File not accessible: %s", binaryPath.c_str());
        return HCCL_E_PTR;
    }
    
    // 检查文件权限（防止加载非预期文件）
    if ((fileStat.st_mode & (S_IWOTH | S_IWGRP)) != 0) {
        HCCL_WARNING("[GetAivOpBinaryPath] File has suspicious permissions: %s", binaryPath.c_str());
    }
    
    return HCCL_SUCCESS;
}
```

#### 方案2: 配置文件驱动路径

```cpp
// 从安全配置文件读取路径，而非环境变量
HcclResult GetAivOpBinaryPath(const std::string &aivBinaryName, std::string &binaryPath)
{
    // 从可信配置文件读取（如 /etc/hccl/config.conf）
    std::string basePath = LoadFromSecureConfig("aiv_kernel_path");
    
    if (basePath.empty()) {
        basePath = "/usr/local/Ascend/cann";  // 安全默认值
    }
    
    // 路径校验...
    binaryPath = basePath + "/lib64/" + aivBinaryName;
    return HCCL_SUCCESS;
}
```

#### 方案3: Kernel 签名校验

```cpp
// 加载前校验 kernel 文件签名
HcclResult LoadBinaryFromFile(const char* path, ...)
{
    // 检查文件签名
    if (!VerifyKernelSignature(path)) {
        HCCL_ERROR("Kernel signature verification failed: %s", path);
        return HCCL_E_SECURITY;
    }
    
    // 原有加载逻辑...
}
```

### 短期缓解措施

1. **环境变量限制**: 在程序启动时校验 ASCEND_HOME_PATH 是否为预期路径
2. **文件完整性**: 使用 sha256 校验 kernel binary 文件
3. **权限控制**: 确保 kernel 目录只有可信用户可写入
4. **模式选择**: 在敏感场景强制使用非 AIV 模式

### 验证建议

修复后应验证:
- ASCEND_HOME_PATH 设置为恶意路径时，kernel 加载失败
- 路径规范化正确处理 `../` 等相对路径
- 白名单机制有效阻止非预期目录
- 文件权限检查逻辑正确工作