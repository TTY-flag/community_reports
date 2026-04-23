# VULN-SEC-BIN-002：ASCEND_HOME_PATH控制AICPU内核加载路径漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-BIN-002 |
| **CWE** | CWE-426: Untrusted Search Path |
| **严重性** | High |
| **置信度** | 85 |
| **漏洞类型** | 二进制文件路径注入 / Kernel 加载劫持 |
| **受影响文件** | `src/ops/op_common/template/aicpu/load_kernel.cc` |

HCCL 库在 AICPU (AI CPU) 模式下加载 kernel 配置文件时，直接使用 `ASCEND_HOME_PATH` 环境变量拼接路径，缺少路径规范化和校验。攻击者可通过控制该环境变量，使程序加载恶意篡改的 kernel 配置文件或二进制文件，实现代码执行或数据篡改攻击。

---

## 漏洞详情

### 代码位置

**文件**: `src/ops/op_common/template/aicpu/load_kernel.cc`
**行号**: 19-36
**函数**: `GetKernelFilePath()`

```cpp
HcclResult GetKernelFilePath(std::string &binaryPath)
{
    // 获取二进制文件路径
    std::string libPath;
    char *getPath = getenv("ASCEND_HOME_PATH");  // ← 直接调用 getenv
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);  // ← 又调用 MM_SYS_GET_ENV
    if (getPath != nullptr) {
        libPath = getPath;  // ← 直接使用，无校验
    } else {
        libPath = "/usr/local/Ascend/cann/";
        HCCL_WARNING("[GetKernelFilePath]ENV:ASCEND_HOME_PATH is not set");
    }

    libPath += "/opp/built-in/op_impl/aicpu/config/";
    binaryPath = libPath;
    HCCL_DEBUG("[GetKernelFilePath]kernel folder path[%s]", binaryPath.c_str());

    return HCCL_SUCCESS;
}
```

### 关键观察

代码中存在**重复读取环境变量**的问题:
```cpp
char *getPath = getenv("ASCEND_HOME_PATH");      // 第1次
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath); // 第2次 (可能覆盖 getPath)
```

这表明代码可能在不同版本/分支合并时产生冗余，但安全问题是相同的。

### 数据流路径

```
ASCEND_HOME_PATH 环境变量
        ↓
getenv() + MM_SYS_GET_ENV() 读取
        ↓
getPath (未校验的路径)
        ↓
libPath = getPath  (直接赋值)
        ↓
binaryPath = libPath + "/opp/built-in/op_impl/aicpu/config/"
        ↓
jsonPath = binaryPath + "libscatter_aicpu_kernel.json"
        ↓
LoadBinaryFromFile(jsonPath)  加载 kernel 配置
```

### 触发条件

1. **算子执行模式选择**
   - 当 HCCL 选择 AICPU 执行模式时触发
   - 控制路径: `ApplyOpExpansionMode()` → `LoadAICPUKernel()` → `GetKernelFilePath()`

2. **模式选择入口点**
   ```
   HcclAllReduce/HcclScatter 等公开 API
   → 算子执行流程
   → ApplyOpExpansionMode(HCCL_OP_EXPANSION_MODE_AI_CPU)  [op_common.cc:1613]
   → LoadAICPUKernel()
   → GetKernelFilePath()
   → 加载恶意 kernel config
   ```

3. **额外触发点**
   - `src/ops/op_common/op_common.cc:114` - 算子回退到 AICPU 模式时
   - `src/ops/scatter/scatter_op.cc:228` - Scatter 算子直接使用 AICPU

---

## 利用场景分析

### 攻击路径

#### 场景1: Kernel 配置文件劫持

```
前提条件:
- 攻击者能控制 ASCEND_HOME_PATH 环境变量
- 用户执行 AICPU 模式的集合通信算子

攻击步骤:
1. 攻击者设置 ASCEND_HOME_PATH=/tmp/malicious
2. 创建恶意目录结构:
   /tmp/malicious/opp/built-in/op_impl/aicpu/config/libscatter_aicpu_kernel.json
3. 在 JSON 配置中指定恶意 kernel 二进制文件路径
4. 用户执行集合通信算子，HCCL 选择 AICPU 模式
5. GetKernelFilePath() → 拼接路径 → 加载恶意配置
6. LoadBinaryFromFile() 加载配置指定的恶意 kernel
7. 恶意 kernel 在 AICPU 上执行
```

#### 场景2: 直接路径注入

```
前提条件:
- 攻击者控制环境变量，可设置任意路径

攻击变体:
1. ASCEND_HOME_PATH=/tmp/../tmp
   → 规范化后仍指向恶意路径

2. ASCEND_HOME_PATH=/attacker/path
   → 直接指向攻击者控制的目录

3. 通过符号链接攻击:
   ln -s /attacker/malicious /tmp/ascend_link
   ASCEND_HOME_PATH=/tmp/ascend_link
```

#### 场景3: Scatter 算子直接攻击

```
前提条件:
- 用户执行 HcclScatter 算子
- Scatter 算子直接调用 LoadAICPUKernel()

攻击路径:
HcclScatter API
→ scatter_op.cc:228
→ LoadAICPUKernel()
→ GetKernelFilePath()
→ 加载恶意配置

特点: Scatter 算子绕过通用模式选择，直接进入 AICPU 路径
```

### 前提条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| ASCEND_HOME_PATH 控制 | 必要 | 需要能设置或修改该环境变量 |
| AICPU 模式触发 | 必要 | 算子需选择 AICPU 模式或 Scatter 算子 |
| 恶意配置/kernel 文件 | 必要 | 需准备恶意 JSON 配置或 kernel 二进制 |
| 文件写入权限 | 必要 | 需在控制路径下创建恶意文件 |

---

## 影响评估

### 受影响组件

- **直接受影响**: 
  - AICPU kernel 加载机制
  - Scatter 算子（直接使用 AICPU）
  - 所有使用 AICPU 模式的算子

- **间接受影响**:
  - 集合通信数据完整性
  - AICPU 执行的计算结果
  - 集群训练安全性

### 潜在后果

| 级别 | 影响 | 说明 |
|------|------|------|
| **Critical** | Kernel 代码执行 | 恶意 kernel 在 AICPU 上执行 |
| **High** | 配置文件篡改 | JSON 配置可指定任意 kernel 文件 |
| **High** | 数据篡改 | Scatter 等算子的计算结果被篡改 |
| **High** | 数据窃取 | Kernel 可访问通信数据缓冲区 |
| **Medium** | 拒绝服务 | 加载失败导致 AICPU 模式不可用 |

### 与 VULN-SEC-BIN-001 的差异

| 特征 | VULN-SEC-BIN-001 (AIV) | VULN-SEC-BIN-002 (AICPU) |
|------|------------------------|--------------------------|
| 执行引擎 | AI Vector (NPU vector core) | AI CPU (CPU-like engine) |
| 加载文件类型 | Kernel binary (.bin) | Kernel JSON config + binary |
| 路径后缀 | `/lib64/` | `/opp/built-in/op_impl/aicpu/config/` |
| 直接触发算子 | 多个算子的 AIV 模式 | Scatter 算子直接触发 |

---

## PoC / 利用代码构思

### 概念性 PoC（非实际攻击代码）

**攻击环境设置脚本（概念演示）:**
```bash
#!/bin/bash
# 概念性 PoC - AICPU kernel 配置劫持

# Step 1: 设置恶意路径
export ASCEND_HOME_PATH=/tmp/aicpu_attack

# Step 2: 创建恶意目录结构（必须匹配预期路径）
mkdir -p /tmp/aicpu_attack/opp/built-in/op_impl/aicpu/config

# Step 3: 创建恶意 JSON 配置
cat > /tmp/aicpu_attack/opp/built-in/op_impl/aicpu/config/libscatter_aicpu_kernel.json << EOF
{
    "kernel_path": "/tmp/aicpu_attack/opp/built-in/op_impl/aicpu/bin/malicious_kernel.so",
    "kernel_name": "malicious_scatter",
    "version": "1.0.0"
}
EOF

# Step 4: 创建恶意 kernel 二进制（概念性）
mkdir -p /tmp/aicpu_attack/opp/built-in/op_impl/aicpu/bin
# 实际攻击需要构造合法格式的 AICPU kernel

# Step 5: 执行 Scatter 算子触发
# python -c "
# import torch
# import torch_npu
# # HcclScatter 会直接触发 AICPU 加载
# "

echo "Malicious AICPU config would be loaded when Scatter op is executed"
```

---

## 修复建议

### 推荐修复方案

#### 方案1: 路径规范化与白名单校验

```cpp
#include <limits.h>
#include <sys/stat.h>
#include <cstdlib>

HcclResult GetKernelFilePath(std::string &binaryPath)
{
    std::string libPath;
    char *getPath = nullptr;
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
    
    if (getPath != nullptr) {
        // 规范化路径
        char resolvedPath[PATH_MAX];
        if (realpath(getPath, resolvedPath) == nullptr) {
            HCCL_ERROR("[GetKernelFilePath] Invalid path: %s", getPath);
            return HCCL_E_PTR;
        }
        
        // 白名单校验
        const std::vector<std::string> trustedDirs = {
            "/usr/local/Ascend",
            "/opt/Ascend"
        };
        
        bool isTrusted = false;
        for (const auto& dir : trustedDirs) {
            if (strncmp(resolvedPath, dir.c_str(), dir.length()) == 0) {
                isTrusted = true;
                break;
            }
        }
        
        if (!isTrusted) {
            HCCL_ERROR("[GetKernelFilePath] Path not in trusted directories: %s", resolvedPath);
            return HCCL_E_PTR;
        }
        
        libPath = resolvedPath;
    } else {
        libPath = "/usr/local/Ascend/cann/";
    }

    libPath += "/opp/built-in/op_impl/aicpu/config/";
    binaryPath = libPath;
    
    return HCCL_SUCCESS;
}
```

#### 方案2: 移除冗余的 getenv 调用

```cpp
// 清理代码 - 只使用一种方式读取环境变量
HcclResult GetKernelFilePath(std::string &binaryPath)
{
    std::string libPath;
    char *getPath = nullptr;
    // 只使用 MM_SYS_GET_ENV，移除冗余的 getenv
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
    
    // 后续校验逻辑...
}
```

#### 方案3: JSON 配置文件签名校验

```cpp
HcclResult LoadAICPUKernel(void)
{
    if (g_binKernelHandle != nullptr) {
        return HCCL_SUCCESS;
    }
    
    std::string jsonPath;
    CHK_RET(GetKernelFilePath(jsonPath));
    jsonPath += "libscatter_aicpu_kernel.json";
    
    // 校验配置文件签名
    if (!VerifyConfigSignature(jsonPath)) {
        HCCL_ERROR("[LoadAICPUKernel] Config signature verification failed");
        return HCCL_E_SECURITY;
    }
    
    // 原有加载逻辑...
}
```

### 短期缓解措施

1. **路径校验**: 在程序启动时校验 ASCEND_HOME_PATH
2. **配置文件完整性**: 使用 sha256 校验 JSON 配置
3. **权限控制**: 确保 config 目录只有可信用户可写入
4. **Scatter 算子保护**: 在敏感场景禁用 Scatter 的 AICPU 模式

### 验证建议

修复后应验证:
- ASCEND_HOME_PATH 设置为恶意路径时，kernel 加载失败
- Scatter 算子正确执行路径校验
- JSON 配置签名校验有效
- 冗余代码已清理