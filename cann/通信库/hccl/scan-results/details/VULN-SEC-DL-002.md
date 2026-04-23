# VULN-SEC-DL-002：动态库加载相对路径注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-DL-002, VULN-DF-007 (合并) |
| **CWE** | CWE-426: Untrusted Search Path |
| **严重性** | High |
| **置信度** | 85 |
| **漏洞类型** | 动态库注入 / 搜索路径劫持 |
| **受影响文件** | `src/ops/op_common/dlhcomm_function.cc`, `src/common/hcomm_dlsym/hcomm_dlsym.cc` |

HCCL 库在多处使用 `dlopen("libhcomm.so", RTLD_NOW)` 加载动态库，未指定绝对路径。该调用依赖系统动态链接器的搜索顺序，攻击者可通过控制环境变量（如 `LD_LIBRARY_PATH`）或在预期目录放置恶意库文件实现库注入攻击。

---

## 漏洞详情

### 代码位置

**位置1 - dlhcomm_function.cc:49-50**
```cpp
void* h = dlopen("libhcomm.so", RTLD_NOW);
CHK_PRT_RET(h == nullptr, HCCL_WARNING("dlopen libhcomm.so failed, error: %s", dlerror()), HCCL_E_PTR);
```

**位置2 - hcomm_dlsym.cc:60-64**
```cpp
gLibHandle = dlopen("libhcomm.so", RTLD_NOW);
if (!gLibHandle) {
    fprintf(stderr, "[HcclWrapper] Failed to open libhcomm: %s\n", dlerror());
    return;
}
```

### 触发条件

1. **库加载时机**
   - `HcommDlInit()` 通过 `__attribute__((constructor))` 在库加载时自动执行（`src/common/compat.cc:17-24`）
   - 当任何应用程序加载 HCCL 库时，会立即触发 `dlopen("libhcomm.so")`

2. **搜索顺序（Linux glibc）**
   ```
   1. RPATH (编译时嵌入)
   2. LD_LIBRARY_PATH (环境变量)
   3. RUNPATH (编译时嵌入)
   4. /etc/ld.so.cache
   5. 默认路径 /lib, /usr/lib
   ```

3. **关键触发路径**
   ```
   应用程序加载 libhccl.so
   → __attribute__((constructor)) InitCompat()
   → pthread_once(CompatSymInit)
   → HcommDlInit()
   → dlopen("libhcomm.so")  ← 漏洞点
   → 加载恶意 libhcomm.so
   → 恶意代码执行
   ```

---

## 利用场景分析

### 攻击路径

#### 场景1: LD_LIBRARY_PATH 劫持
```
前提条件:
- 攻击者能控制用户环境变量（如通过 .bashrc、启动脚本或容器配置）
- 用户运行依赖 HCCL 的应用程序（如 PyTorch 训练脚本）

攻击步骤:
1. 攻击者修改用户的 shell 配置或启动脚本
2. 设置 LD_LIBRARY_PATH=/tmp/malicious
3. 在 /tmp/malicious 创建恶意 libhcomm.so
4. 用户执行 AI 训练任务
5. libhccl.so 加载 → HcommDlInit() → 从 LD_LIBRARY_PATH 加载恶意库
6. 恶意库的构造函数执行 → 获取代码执行权限
```

#### 场景2: 预期目录文件替换
```
前提条件:
- 攻击者有写入权限到 HCCL 预期搜索路径（如 /usr/local/Ascend/lib64）
- 或攻击者能创建同名文件覆盖原始库

攻击步骤:
1. 攻击者替换或创建恶意 libhcomm.so
2. 用户运行 HCCL 程序
3. dlopen 加载恶意库
4. 恶意代码执行
```

#### 场景3: 容器环境攻击
```
前提条件:
- AI 训练任务在容器中运行
- 容器镜像或挂载卷可被攻击者控制

攻击步骤:
1. 攻击者修改容器镜像或注入恶意文件到挂载卷
2. 在容器内放置恶意 libhcomm.so
3. 容器启动时 HCCL 自动加载 → 恶意库执行
```

### 前提条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| 环境变量控制 | 必要 | 需要能设置 LD_LIBRARY_PATH 或影响搜索路径 |
| 文件写入权限 | 可选 | 如果无法控制环境变量，需要能写入预期目录 |
| 用户执行 HCCL 程序 | 必要 | 漏洞在库加载时触发，需要触发路径 |

---

## 影响评估

### 受影响组件

- **直接受影响**: 
  - HCCL 集合通信库 (`libhccl.so`)
  - 所有依赖 HCCL 的应用程序

- **间接受影响**:
  - Ascend PyTorch Adapter
  - Ascend MindSpore
  - 所有使用昇腾 NPU 的 AI 训练/推理任务

### 潜在后果

| 级别 | 影响 | 说明 |
|------|------|------|
| **Critical** | 代码执行 | 恶意库加载后可执行任意代码，获取进程权限 |
| **High** | 数据窃取 | 可窃取训练数据、模型参数、通信内容 |
| **High** | 横向移动 | 在集群环境中，可尝试攻击其他节点 |
| **Medium** | 拒绝服务 | 加载失败可导致通信功能不可用 |

### 攻击面分析

```
攻击入口:
┌─────────────────────────────────────────────────────────────┐
│  用户环境配置 (.bashrc, .profile, 启动脚本)                   │
│  容器环境 (镜像构建, 挂载卷)                                  │
│  系统目录 (如果攻击者有 root 或目录写入权限)                  │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  dlopen("libhcomm.so") 搜索路径查找                          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  恶意 libhcomm.so 加载                                       │
│  → __attribute__((constructor)) 恶意代码执行                │
│  → dlsym 符号劫持                                            │
│  → 集合通信数据篡改/窃取                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## PoC / 利用代码构思

### 概念性 PoC（非实际攻击代码）

**恶意 libhcomm.so 构造思路:**
```cpp
// malicious_libhcomm.cc - 概念演示
#include <stdio.h>
#include <dlfcn.h>

// 构造函数 - 库加载时自动执行
__attribute__((constructor))
void malicious_init() {
    // 这里可执行任意恶意操作:
    // 1. 记录进程信息
    // 2. 提取敏感环境变量
    // 3. 连接攻击者控制的远程服务器
    // 4. 修改/监控后续的集合通信数据
    
    // 注意: 需要实现必要的符号以避免 dlsym 失败
}

// 符号劫持示例
// 原始 HcclThreadResGetInfo 符号可被劫持来监控通信内容
```

**攻击场景演示脚本（概念性）:**
```bash
# 场景: 通过 LD_LIBRARY_PATH 劫持
# 前提: 用户将运行 HCCL 程序

# Step 1: 创建恶意库目录
mkdir -p /tmp/hccl_attack

# Step 2: 编译恶意库（需要实现必要的符号接口）
# gcc -shared -fPIC -o /tmp/hccl_attack/libhcomm.so malicious_libhcomm.cc

# Step 3: 设置环境变量（可通过修改用户配置文件实现）
export LD_LIBRARY_PATH=/tmp/hccl_attack:$LD_LIBRARY_PATH

# Step 4: 用户运行程序时，恶意库自动加载
# python train.py  # HCCL 加载 → 恶意代码执行
```

---

## 修复建议

### 推荐修复方案

#### 方案1: 使用绝对路径加载

```cpp
// 修复代码示例
#include <limits.h>
#include <stdlib.h>

HcclResult DlHcommFunction::DlHcommFunctionInit() {
    std::lock_guard<std::mutex> lock(handleMutex_);
    if (handle_ != nullptr) {
        return HCCL_SUCCESS;
    }
    
    // 使用预定义的绝对路径或从可信配置获取
    std::string libPath = GetTrustedLibPath();  // 从安全配置获取
    libPath += "/libhcomm.so";
    
    // 验证路径安全性
    if (!ValidateLibraryPath(libPath)) {
        HCCL_ERROR("Invalid library path: %s", libPath.c_str());
        return HCCL_E_PTR;
    }
    
    void* h = dlopen(libPath.c_str(), RTLD_NOW);
    // ...
}
```

#### 方案2: 禁用环境变量搜索

使用 `dlopen` 时通过路径解析确保加载可信库:
```cpp
// 使用 realpath 规范化路径并验证
char resolvedPath[PATH_MAX];
if (realpath(libPath.c_str(), resolvedPath) == nullptr) {
    return HCCL_E_PTR;
}

// 验证路径在预期目录内
if (!IsPathInTrustedDirectory(resolvedPath)) {
    return HCCL_E_PTR;
}

void* h = dlopen(resolvedPath, RTLD_NOW);
```

#### 方案3: 编译时设置安全 RPATH/RUNPATH

在 CMakeLists.txt 中设置可信搜索路径:
```cmake
set_target_properties(libhccl PROPERTIES
    INSTALL_RPATH "/usr/local/Ascend/lib64"
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH_USE_LINK_PATH FALSE  # 禁用自动添加链接路径
)
```

### 短期缓解措施

1. **环境变量清理**: 在程序启动前清理 LD_LIBRARY_PATH
2. **目录权限控制**: 确保库目录只有可信用户可写入
3. **文件完整性校验**: 使用校验和验证 libhcomm.so 完整性
4. **安全配置文件**: 将库路径硬编码到安全配置文件中

### 验证建议

修复后应验证:
- 所有 dlopen 调用使用绝对路径
- 路径不依赖环境变量
- 库加载前有路径校验逻辑
- 测试 LD_LIBRARY_PATH 设置无法劫持库加载