# VULN-DF-BO-001 - 共享内存路径遍历漏洞深度利用分析

> **漏洞ID**: VULN-DF-BO-001  
> **类型**: Buffer Overflow / Path Traversal  
> **CWE**: CWE-120 (缓冲区溢出/路径遍历)  
> **严重性**: High  
> **置信度**: 85%  
> **文件**: src/runtime/driver/npu_driver_mem.cc  
> **行号**: 43-49  
> **函数**: MallocHostSharedMemory

---

## 1. 漏洞原理和根因分析

### 1.1 漏洞根因

该漏洞的核心问题在于**用户控制的共享内存名称参数未经路径遍历检查直接拼接到系统路径**。

**关键代码片段**：
```cpp
// npu_driver_mem.cc: 43-52
constexpr const char_t *path = "/dev/shm/";
char_t name[MMPA_MAX_PATH] = {};
errno_t retSafe = strcpy_s(&name[0], sizeof(name), path);  // 复制固定路径
COND_LOG_ERROR(retSafe != EOK, "strcpy_s failed...");
retSafe = strcat_s(name, sizeof(name), in->name);          // 直接拼接用户输入！
COND_LOG_ERROR(retSafe != EOK, "strcat_s failed...");
retVal = stat(name, &buf);

out->fd = shm_open(in->name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);  // 使用原始名称
```

### 1.2 问题分析

1. **路径拼接无验证**: `strcat_s` 安全函数仅防止缓冲区溢出，**不防止路径遍历**
2. **双重路径使用**:
   - `name` 用于 `stat()` 检查（拼接后的路径）
   - `shm_open()` 使用原始 `in->name`（未拼接）
3. **输入来源**: `in->name` 来自 `rtMallocHostSharedMemoryIn` 结构，由 API 调用者传入

### 1.3 漏洞类型判断

虽然 CWE 分类为 CWE-120 (缓冲区溢出)，但实际问题更符合 **CWE-22 (路径遍历)**：
- `strcpy_s/strcat_s` 已防止缓冲区溢出
- 但未阻止 `../` 目录遍历攻击

---

## 2. 利用条件和前提条件

### 2.1 前提条件

| 条件 | 状态 | 说明 |
|------|------|------|
| API 可访问性 | ✓ | `rtMallocHostSharedMemory` 为公开 API |
| 输入可控性 | ✓ | `in->name` 由调用者完全控制 |
| 特征支持检测 | 需确认 | 需要 `RT_FEATURE_MEM_HOST_REGISTER` 支持 |
| 权限要求 | 低权限 | 普通用户可调用（共享内存操作无特殊权限） |

### 2.2 利用限制

1. **功能特征依赖**: 代码路径需要 `IsSupportFeature(RT_FEATURE_MEM_HOST_REGISTER)` 返回 true
2. **路径检查分离**: `stat(name)` 检查拼接路径，但 `shm_open(in->name)` 使用原始名称
   - 如果攻击者输入 `../../../etc/passwd`：
     - `stat("/dev/shm/../../../etc/passwd")` → 可能失败（规范化后指向 `/etc/passwd`）
     - `shm_open("../../../etc/passwd")` → POSIX shm_open 规范化路径，仍指向 `/dev/shm/` 下

### 2.3 shm_open 行为分析

根据 POSIX 规范和 Linux 实现：
- `shm_open()` 名称参数会被规范化处理
- 结果始终在 `/dev/shm/` 目录下创建
- `../` 序列会被消除或拒绝

**实际测试结论**：Linux `shm_open()` 会拒绝包含路径分隔符（`/`）的名称，因此 `../../../xxx` 会直接报错。

### 2.4 可利用场景

尽管 `shm_open` 有保护，仍存在以下风险：

1. **信息泄露**: 通过 `stat(name)` 操作，攻击者可探测任意文件存在性：
   ```cpp
   in->name = "../../../etc/shadow"
   // stat("/dev/shm/../../../etc/shadow") → 成功返回文件信息（如果存在）
   // 但 shm_open 会失败
   ```

2. **资源耗尽**: 可创建任意名称的共享内存（仍有限制）

3. **潜在 symlink 攻击**: 如果攻击者能在 `/dev/shm/` 创建符号链接指向敏感文件，后续操作可能被劫持

---

## 3. 具体利用步骤和攻击路径

### 3.1 攻击场景 A: 信息泄露探测

```
步骤 1: 攻击者调用 rtMallocHostSharedMemory API
步骤 2: 设置 in->name = "../../../etc/passwd"
步骤 3: 代码执行 stat("/dev/shm/../../../etc/passwd")
步骤 4: stat 成功返回 → 攻击者确认文件存在
步骤 5: shm_open 失败，但信息已泄露
```

**PoC 概念**：
```cpp
rtMallocHostSharedMemoryIn input;
input.name = "../../../etc/shadow";  // 探测敏感文件
input.size = 4096;
input.flag = 0;

rtMallocHostSharedMemoryOut output;
rtError_t ret = rtMallocHostSharedMemory(&input, &output, deviceId);

// 虽然 API 返回错误，但 stat() 操作已执行
// 错误码可推断目标文件状态
```

### 3.2 攻击场景 B: 共享内存命名冲突

```
步骤 1: 攻击者使用特殊名称创建共享内存
步骤 2: 名称包含特殊字符，干扰其他进程
步骤 3: 重复创建消耗系统资源
```

---

## 4. 影响范围和危害评估

### 4.1 直接影响

| 影响类型 | 危害等级 | 说明 |
|----------|----------|------|
| 信息泄露 | Medium | 可探测敏感文件存在性 |
| 资源耗尽 | Low | 可创建大量共享内存消耗资源 |
| 权限提升 | None | shm_open 限制阻止目录逃逸 |
| 数据篡改 | None | 无写入能力 |

### 4.2 间接影响

- **日志信息泄露**: 如果错误日志包含完整路径，敏感路径可能被记录
- **后续攻击辅助**: 信息探测可辅助其他攻击路径

### 4.3 影响范围

- **受影响组件**: CANN Runtime 共享内存功能
- **受影响平台**: Linux 系统（使用 `/dev/shm`）
- **受影响版本**: 当前扫描版本

---

## 5. 修复建议和缓解措施

### 5.1 立即修复方案

**方案 A: 输入名称验证**
```cpp
// 在拼接前验证名称合法性
bool IsValidShmName(const char* name) {
    if (name == nullptr) return false;
    
    // 检查长度
    size_t len = strlen(name);
    if (len == 0 || len > NAME_MAX) return false;
    
    // 检查禁止字符
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '/' || name[i] == '\\') return false;
        if (name[i] == '.' && name[i+1] == '.') return false;  // 阻止 ..
    }
    
    return true;
}

// 在 MallocHostSharedMemory 开头添加:
if (!IsValidShmName(in->name)) {
    RT_LOG(RT_LOG_ERROR, "Invalid shared memory name: %s", in->name);
    return RT_ERROR_INVALID_VALUE;
}
```

**方案 B: 使用 basename 规范化**
```cpp
#include <libgen.h>

// 规范化名称，移除路径组件
char* safeName = basename(in->name);
if (safeName == nullptr || safeName[0] == '.') {
    return RT_ERROR_INVALID_VALUE;
}
// 使用 safeName 替代 in->name
```

### 5.2 缓解措施

1. **API 文档限制**: 明确禁止使用包含路径字符的名称
2. **运行时检查**: 添加 `strchr(in->name, '/')` 检查
3. **权限加固**: 限制共享内存 API 的调用权限

### 5.3 最佳实践

```cpp
// 推荐的完整修复
rtError_t NpuDriver::MallocHostSharedMemory(...) {
    // 1. 空指针检查
    if (in == nullptr || in->name == nullptr) {
        return RT_ERROR_INVALID_PARAM;
    }
    
    // 2. 名称验证
    const char* name = in->name;
    size_t nameLen = strlen(name);
    if (nameLen == 0 || nameLen > 255) {
        return RT_ERROR_INVALID_PARAM;
    }
    
    // 3. 路径字符检查
    if (strchr(name, '/') != nullptr || 
        strstr(name, "..") != nullptr) {
        RT_LOG(RT_LOG_ERROR, "Path characters forbidden in shm name");
        return RT_ERROR_INVALID_PARAM;
    }
    
    // 4. 只使用合法名称
    // ... 原有逻辑 ...
}
```

---

## 6. 总结

该漏洞虽然被标记为路径遍历，但由于 `shm_open()` 的 POSIX 规范限制，**实际利用范围有限**。主要风险在于：

1. **信息泄露**: `stat()` 操作可用于探测文件存在性
2. **代码质量问题**: 安全函数使用不当，缺乏输入验证

**建议优先级**: Medium - 应修复以符合安全编码规范，防止潜在风险演变。

---

*报告生成时间: 2026-04-25*  
*分析工具: CANN Vulnerability Scanner*