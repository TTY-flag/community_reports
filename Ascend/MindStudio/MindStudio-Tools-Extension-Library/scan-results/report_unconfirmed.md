# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Tools-Extension-Library
**扫描时间**: 2026-04-20T23:50:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 10 | 58.8% |
| POSSIBLE | 4 | 23.5% |
| CONFIRMED | 2 | 11.8% |
| FALSE_POSITIVE | 1 | 5.9% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 10 | 71.4% |
| Medium | 4 | 28.6% |
| **有效漏洞总计** | **14** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-NET-001]** unsafe_download (High) - `download_dependencies.py:93` @ `proc_artifact` | 置信度: 75
2. **[SEC-009]** Download Without Integrity Check (High) - `download_dependencies.py:101` @ `proc_artifact` | 置信度: 75
3. **[VULN-DF-PTR-001]** null_pointer_dereference (High) - `python/mstx_api.cpp:31` @ `WrapMstxMarkA` | 置信度: 65
4. **[VULN-DF-PTR-002]** null_pointer_dereference (High) - `python/mstx_api.cpp:58` @ `WrapMstxRangeStartA` | 置信度: 65
5. **[SEC-002]** NULL Pointer Dereference (High) - `c/include/mstx/mstx_detail/mstx_impl_core.h:22` @ `mstxMarkA` | 置信度: 65
6. **[SEC-003]** NULL Pointer Dereference (High) - `c/include/mstx/mstx_detail/mstx_impl_core.h:32` @ `mstxRangeStartA` | 置信度: 65
7. **[SEC-005]** NULL Pointer Dereference (High) - `c/include/mstx/mstx_detail/mstx_impl_core.h:134` @ `mstxDomainMarkA` | 置信度: 65
8. **[SEC-006]** NULL Pointer Dereference (High) - `c/include/mstx/mstx_detail/mstx_impl_core.h:144` @ `mstxDomainRangeStartA` | 置信度: 65
9. **[SEC-007]** NULL Pointer Dereference (High) - `python/mstx_api.cpp:31` @ `WrapMstxMarkA` | 置信度: 65
10. **[SEC-008]** NULL Pointer Dereference (High) - `python/mstx_api.cpp:58` @ `WrapMstxRangeStartA` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `mstxInitWithInjectionLib@c/include/mstx/mstx_detail/mstx_impl.h` | env | untrusted_local | 读取环境变量 MSTX_INJECTION_PATH，通过 getenv() 获取路径后使用 dlopen() 加载外部动态库，攻击者可通过控制环境变量加载恶意库 | 从环境变量加载注入库 |
| `WrapMstxMarkA@python/mstx_api.cpp` | rpc | semi_trusted | Python API 入口点，接收来自 Python 解释器的参数，message 字符串通过 PyArg_ParseTupleAndKeywords 解析后传递给底层 C API | Python mark API 入口 |
| `WrapMstxRangeStartA@python/mstx_api.cpp` | rpc | semi_trusted | Python API 入口点，接收来自 Python 解释器的参数，message 字符串通过 PyArg_ParseTupleAndKeywords 解析后传递给底层 C API | Python range_start API 入口 |
| `mstxMarkA@c/include/mstx/mstx_detail/mstx_impl_core.h` | rpc | semi_trusted | 公共 C API 入口点，message 参数声明为 'cannot be null' 但代码层面无 NULL 检查，直接传递给函数指针调用 | C mark API 入口 |
| `mstxRangeStartA@c/include/mstx/mstx_detail/mstx_impl_core.h` | rpc | semi_trusted | 公共 C API 入口点，message 参数声明为 'cannot be null' 但代码层面无 NULL 检查，直接传递给函数指针调用 | C range_start API 入口 |
| `proc_artifact@download_dependencies.py` | file | untrusted_network | 从远程 URL 下载文件并解压，使用 curl -Lfk 下载，存在 URL 重定向风险和恶意文件注入风险 | 依赖下载入口 |
| `mstxMemHeapRegister@c/include/mstx/mstx_detail/mstx_impl_core.h` | rpc | semi_trusted | 内存管理 API，接收复杂结构体指针 mstxMemHeapDesc_t，包含 void const *typeSpecificDesc 泛型指针，存在类型混淆风险 | 内存池注册 API |
| `mstxMemRegionsRegister@c/include/mstx/mstx_detail/mstx_impl_core.h` | rpc | semi_trusted | 内存区域注册 API，接收批量结构体指针，regionDescArray 和 regionHandleArrayOut 指针未经边界检查验证 | 内存区域批量注册 API |

**其他攻击面**:
- 环境变量注入: MSTX_INJECTION_PATH → dlopen()
- Python API: mstx.mark()/mstx.range_start() message 参数
- C API: mstxMarkA/mstxRangeStartA message 参数 (NULL 安全)
- 依赖下载: download_dependencies.py 远程文件下载
- 内存管理 API: mstxMemHeapRegister/mstxMemRegionsRegister 结构体指针

---

## 3. High 漏洞 (10)

### [VULN-DF-NET-001] unsafe_download - proc_artifact

**严重性**: High | **CWE**: CWE-494 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `download_dependencies.py:93-126` @ `proc_artifact`
**模块**: build_scripts

**描述**: 依赖下载脚本使用 curl -Lfk 参数下载远程文件。-k 参数禁用 SSL 证书验证，允许中间人攻击；-L 参数允许跟随重定向，攻击者可劫持重定向到恶意 URL。虽然配置了 SHA256 校验，但校验仅在 spec[name].get("sha256") 配置时才执行，未配置时无完整性校验。

**漏洞代码** (`download_dependencies.py:93-126`)

```c
self._exec_shell_cmd(["curl", "-Lfk", "--retry", "5", "--retry-delay", "2",
                      "-o", str(archive_path), url], msg=f"Download {name} ...")
if sha and hashlib.sha256(archive_path.read_bytes()).hexdigest() != sha:
```

**达成路径**

url (from dependencies.json) [SOURCE, line 101]
→ curl -Lfk -o archive_path url [SINK, line 104-105]
→ 禁用 SSL 验证 (-k)
→ 允许重定向 (-L)
→ SHA256 校验可选 (sha = spec[name].get("sha256"))

**验证说明**: 构建脚本 download_dependencies.py 使用 curl -Lfk 下载远程文件。-k 禁用 SSL 证书验证，允许 MITM 攻击。-L 允许跟随重定向，攻击者可劫持重定向。SHA256 校验仅当配置时执行，未配置时无完整性校验。但这是构建时脚本，由开发者/管理员执行，攻击面有限。调整为 LIKELY。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: -5 | cross_file: 0

---

### [SEC-009] Download Without Integrity Check - proc_artifact

**严重性**: High | **CWE**: CWE-494 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `download_dependencies.py:101-107` @ `proc_artifact`
**模块**: build_scripts

**描述**: Dependency download uses optional SHA256 checksum verification. If a dependency does not have sha256 configured in dependencies.json, the downloaded file is extracted without any integrity verification. This allows supply chain attacks where malicious actors could replace the downloaded artifact.

**漏洞代码** (`download_dependencies.py:101-107`)

```c
url, sha = spec[name]["url"], spec[name].get("sha256")
...
if sha and hashlib.sha256(archive_path.read_bytes()).hexdigest() != sha:
    sys.exit(f"SHA256 mismatch for {name}")
```

**达成路径**

spec[name].get("sha256") returns optional -> if sha is None, no integrity check is performed

**验证说明**: 与 VULN-DF-NET-001 相同漏洞。构建脚本依赖下载使用可选 SHA256 校验，未配置时无完整性验证，存在供应链攻击风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: -5 | cross_file: 0

---

### [VULN-DF-PTR-001] null_pointer_dereference - WrapMstxMarkA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/mstx_api.cpp:31-56` @ `WrapMstxMarkA`
**模块**: python_binding
**跨模块**: python_binding → c_core

**描述**: Python API WrapMstxMarkA 使用 PyArg_ParseTupleAndKeywords 的 "|sO" 格式解析参数，"|" 表示可选参数，导致 message 可能为 NULL。message 直接传递给底层 mstxMarkA 函数，而 mstxMarkA 内部调用 (*local)(message, stream) 时无 NULL 检查，可能导致空指针解引用崩溃。

**漏洞代码** (`python/mstx_api.cpp:31-56`)

```c
void ParseArgs(PyObject *args, PyObject *kwds, char *&message, aclrtStream &stream) {
    message = nullptr;
    PyArg_ParseTupleAndKeywords(args, kwds, "|sO", kwlist, &message, &stream);
}
...
mstxMarkA(message, stream);
```

**达成路径**

PyArg_ParseTupleAndKeywords("|sO") [SOURCE, line 38]
→ message (char*, nullable)
→ mstxMarkA(message, stream) [CALL, line 53]
→ mstx_impl_core.h: (*local)(message, stream) [SINK, line 27]
→ 无 NULL 检查，message 为 NULL 时崩溃

**验证说明**: Python API 使用 '|sO' 格式解析参数，允许 message 为 NULL。NULL message 传递给底层 mstxMarkA，虽然文档声明 'cannot be null'，但代码层面无 NULL 检查。若底层实现解引用 message，可能导致崩溃(DoS)。信任等级 semi_trusted，属间接外部输入。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PTR-002] null_pointer_dereference - WrapMstxRangeStartA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/mstx_api.cpp:58-73` @ `WrapMstxRangeStartA`
**模块**: python_binding
**跨模块**: python_binding → c_core

**描述**: Python API WrapMstxRangeStartA 使用 PyArg_ParseTupleAndKeywords 的 "|sO" 格式解析参数，"|" 表示可选参数，导致 message 可能为 NULL。message 直接传递给底层 mstxRangeStartA 函数，而 mstxRangeStartA 内部调用 (*local)(message, stream) 时无 NULL 检查，可能导致空指针解引用崩溃。

**漏洞代码** (`python/mstx_api.cpp:58-73`)

```c
ParseArgs(args, kwds, message, stream);
...
ret = mstxRangeStartA(message, stream);
```

**达成路径**

PyArg_ParseTupleAndKeywords("|sO") [SOURCE, line 38]
→ message (char*, nullable)
→ mstxRangeStartA(message, stream) [CALL, line 70]
→ mstx_impl_core.h: (*local)(message, stream) [SINK, line 36]
→ 无 NULL 检查，message 为 NULL 时崩溃

**验证说明**: 与 VULN-DF-PTR-001 相同模式，Python API WrapMstxRangeStartA 使用 '|sO' 允许 message 为 NULL，传递给 mstxRangeStartA 无检查。可能导致 DoS。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-002] NULL Pointer Dereference - mstxMarkA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `c/include/mstx/mstx_detail/mstx_impl_core.h:22-30` @ `mstxMarkA`
**模块**: c_core

**描述**: Function mstxMarkA receives 'message' parameter documented as 'cannot be null' but performs no NULL check before calling the function pointer. If caller passes NULL, the underlying implementation will dereference NULL causing crash (DoS).

**漏洞代码** (`c/include/mstx/mstx_detail/mstx_impl_core.h:22-30`)

```c
MSTX_DECLSPEC void mstxMarkA(const char *message, aclrtStream stream)
{
#ifndef MSTX_DISABLE
    mstxMarkAFunc local = g_mstxContext.mstxMarkAPtr;
    if (local != 0) {
        (*local)(message, stream);
    }
```

**达成路径**

message parameter (documented cannot be null) -> (*local)(message, stream) with no NULL check

**验证说明**: C API mstxMarkA 的 message 参数文档声明 'cannot be null'，但代码无 NULL 检查。调用方（如 Python binding）可能传入 NULL。若底层实现解引用，导致 DoS。信任等级 semi_trusted。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-003] NULL Pointer Dereference - mstxRangeStartA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `c/include/mstx/mstx_detail/mstx_impl_core.h:32-44` @ `mstxRangeStartA`
**模块**: c_core

**描述**: Function mstxRangeStartA receives 'message' parameter documented as 'cannot be null' but performs no NULL check before calling the function pointer.

**漏洞代码** (`c/include/mstx/mstx_detail/mstx_impl_core.h:32-44`)

```c
MSTX_DECLSPEC mstxRangeId mstxRangeStartA(const char *message, aclrtStream stream)
{
#ifndef MSTX_DISABLE
    mstxRangeStartAFunc local = g_mstxContext.mstxRangeStartAPtr;
    if (local != 0) {
        return (*local)(message, stream);
```

**达成路径**

message parameter (documented cannot be null) -> (*local)(message, stream) with no NULL check

**验证说明**: C API mstxRangeStartA 的 message 参数无 NULL 检查，与 SEC-002 相同模式。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-005] NULL Pointer Dereference - mstxDomainMarkA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `c/include/mstx/mstx_detail/mstx_impl_core.h:134-142` @ `mstxDomainMarkA`
**模块**: c_core

**描述**: Function mstxDomainMarkA receives 'message' parameter documented as 'cannot be null' but performs no NULL check before calling the function pointer.

**漏洞代码** (`c/include/mstx/mstx_detail/mstx_impl_core.h:134-142`)

```c
MSTX_DECLSPEC void mstxDomainMarkA(mstxDomainHandle_t domain, const char *message, aclrtStream stream)
{
#ifndef MSTX_DISABLE
    mstxDomainMarkAFunc local = g_mstxContext.mstxDomainMarkAPtr;
    if (local != 0) {
        (*local)(domain, message, stream);
```

**达成路径**

message parameter (documented cannot be null) -> (*local)(domain, message, stream) with no NULL check

**验证说明**: C API mstxDomainMarkA 的 message 参数无 NULL 检查，与 SEC-002 相同模式。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-006] NULL Pointer Dereference - mstxDomainRangeStartA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `c/include/mstx/mstx_detail/mstx_impl_core.h:144-156` @ `mstxDomainRangeStartA`
**模块**: c_core

**描述**: Function mstxDomainRangeStartA receives 'message' parameter documented as 'cannot be null' but performs no NULL check before calling the function pointer.

**漏洞代码** (`c/include/mstx/mstx_detail/mstx_impl_core.h:144-156`)

```c
MSTX_DECLSPEC mstxRangeId mstxDomainRangeStartA(mstxDomainHandle_t domain, const char *message, aclrtStream stream)
{
#ifndef MSTX_DISABLE
    mstxDomainRangeStartAFunc local = g_mstxContext.mstxDomainRangeStartAPtr;
    if (local != 0) {
        return (*local)(domain, message, stream);
```

**达成路径**

message parameter (documented cannot be null) -> (*local)(domain, message, stream) with no NULL check

**验证说明**: C API mstxDomainRangeStartA 的 message 参数无 NULL 检查，与 SEC-002 相同模式。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-007] NULL Pointer Dereference - WrapMstxMarkA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/mstx_api.cpp:31-54` @ `WrapMstxMarkA`
**模块**: python_binding
**跨模块**: python_binding → c_core

**描述**: Python binding ParseArgs function uses '|sO' format string where '|' indicates optional parameters. This allows 'message' to remain NULL when caller omits the argument. The NULL message is then passed to mstxMarkA and mstxRangeStartA, violating their documented requirement 'cannot be null' and potentially causing crash.

**漏洞代码** (`python/mstx_api.cpp:31-54`)

```c
void ParseArgs(PyObject *args, PyObject *kwds, char *&message, aclrtStream &stream)
{
    message = nullptr;
    stream = nullptr;
    ...
    PyArg_ParseTupleAndKeywords(args, kwds, "|sO", kwlist, &message, &stream);
}
...
mstxMarkA(message, stream);
```

**达成路径**

ParseArgs('|sO') -> message can be nullptr -> mstxMarkA(message, stream)

**验证说明**: 与 VULN-DF-PTR-001 相同漏洞，由 Security Auditor 发现。Python binding ParseArgs 使用 '|sO' 格式，允许 message 为 nullptr。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-008] NULL Pointer Dereference - WrapMstxRangeStartA

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/mstx_api.cpp:58-72` @ `WrapMstxRangeStartA`
**模块**: python_binding
**跨模块**: python_binding → c_core

**描述**: Python binding WrapMstxRangeStartA also uses ParseArgs with optional message parameter, allowing NULL to pass to mstxRangeStartA.

**漏洞代码** (`python/mstx_api.cpp:58-72`)

```c
PyObject *WrapMstxRangeStartA(PyObject *self, PyObject *args, PyObject *kwds)
{
    char *message;
    aclrtStream stream;
    ParseArgs(args, kwds, message, stream);
    ...
    ret = mstxRangeStartA(message, stream);
```

**达成路径**

ParseArgs('|sO') -> message can be nullptr -> mstxRangeStartA(message, stream)

**验证说明**: 与 VULN-DF-PTR-002 相同漏洞，由 Security Auditor 发现。WrapMstxRangeStartA 使用 ParseArgs 允许 message 为 nullptr。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (4)

### [VULN-DF-MEM-001] type_confusion - mstxMemHeapDesc_t

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `c/include/mstx/ms_tools_ext_mem.h:81-85` @ `mstxMemHeapDesc_t`
**模块**: c_core

**描述**: 内存管理 API mstxMemHeapRegister 接收 mstxMemHeapDesc_t 结构体，其中包含 void const *typeSpecificDesc 泛型指针。根据 type 字段的不同值，typeSpecificDesc 应指向不同类型的结构体（如 mstxMemVirtualRangeDesc_t），但代码层面无类型验证，调用方传入错误类型可能导致类型混淆和内存安全问题。

**漏洞代码** (`c/include/mstx/ms_tools_ext_mem.h:81-85`)

```c
typedef struct mstxMemHeapDesc_t {
    mstxMemHeapUsageType usage;
    mstxMemType type;
    void const *typeSpecificDesc;  // 泛型指针，无类型检查
} mstxMemHeapDesc_t;
```

**达成路径**

mstxMemHeapDesc_t.type [SOURCE]
→ mstxMemHeapDesc_t.typeSpecificDesc (void const*)
→ mstxMemHeapRegister(domain, desc) [CALL, line 56]
→ (*local)(domain, desc) [SINK, line 61]
→ 类型由 desc.type 决定，无验证

**验证说明**: 内存管理 API mstxMemHeapRegister 接收包含 void const *typeSpecificDesc 泛型指针的结构体，无类型验证。调用方需根据 type 字段正确匹配 typeSpecificDesc 类型。这是 API 设计问题，若调用方传入错误类型，可能导致类型混淆。但需要调用方主动错误使用，攻击面有限。调整为 POSSIBLE。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [SEC-004] NULL Pointer Dereference - mstxDomainCreateA

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-476 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `c/include/mstx/mstx_detail/mstx_impl_core.h:110-122` @ `mstxDomainCreateA`
**模块**: c_core

**描述**: Function mstxDomainCreateA receives 'name' parameter documented as 'a unique string' but performs no NULL check before calling the function pointer.

**漏洞代码** (`c/include/mstx/mstx_detail/mstx_impl_core.h:110-122`)

```c
MSTX_DECLSPEC mstxDomainHandle_t mstxDomainCreateA(const char *name)
{
#ifndef MSTX_DISABLE
    mstxDomainCreateAFunc local = g_mstxContext.mstxDomainCreateAPtr;
    if (local != 0) {
        return (*local)(name);
```

**达成路径**

name parameter -> (*local)(name) with no NULL check

**验证说明**: C API mstxDomainCreateA 的 name 参数无 NULL 检查。但 name 参数用于创建 Domain，攻击者若传入 NULL，底层实现可能崩溃。然而，Domain 创建通常由应用代码调用，攻击面相对较小。调整为 POSSIBLE。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [SEC-011] Missing Input Validation - mstxMemHeapRegister

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `c/include/mstx/mstx_detail/mstx_impl_core.h:56-88` @ `mstxMemHeapRegister`
**模块**: c_core

**描述**: Memory management APIs mstxMemHeapRegister and mstxMemRegionsRegister receive complex structure pointers (mstxMemHeapDesc_t, mstxMemRegionsRegisterBatch_t) containing void* generic pointers (typeSpecificDesc, regionDescArray) without validation. The batch structures also contain size fields (regionCount, refCount) without bounds checking.

**漏洞代码** (`c/include/mstx/mstx_detail/mstx_impl_core.h:56-88`)

```c
MSTX_DECLSPEC mstxMemHeapHandle_t mstxMemHeapRegister(mstxDomainHandle_t domain, mstxMemHeapDesc_t const *desc)
{
    ...
    return (*local)(domain, desc); // desc contains void const *typeSpecificDesc
}

MSTX_DECLSPEC void mstxMemRegionsRegister(mstxDomainHandle_t domain, mstxMemRegionsRegisterBatch_t const *desc)
{
    ...
    (*local)(domain, desc); // desc contains size_t regionCount, void const *regionDescArray
```

**达成路径**

desc parameter with void* typeSpecificDesc and size_t regionCount -> passed directly to function pointer without validation

**验证说明**: 与 VULN-DF-MEM-001/VULN-DF-MEM-002 相关，内存管理 API 接收复杂结构体指针，包含 void* 泛型指针和 size 字段，无输入验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-002] missing_input_validation - mstxMemRegionsRegisterBatch_t

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `c/include/mstx/ms_tools_ext_mem.h:94-100` @ `mstxMemRegionsRegisterBatch_t`
**模块**: c_core

**描述**: 内存区域批量注册 API mstxMemRegionsRegister 接收 mstxMemRegionsRegisterBatch_t 结构体，包含 regionCount 和 regionDescArray 字段。代码层面无边界检查验证 regionCount 是否在合理范围内，可能导致内存访问越界或资源耗尽。

**漏洞代码** (`c/include/mstx/ms_tools_ext_mem.h:94-100`)

```c
typedef struct mstxMemRegionsRegisterBatch_t {
    mstxMemHeapHandle_t heap;
    mstxMemType regionType;
    size_t regionCount;  // 无边界检查
    void const *regionDescArray;
    mstxMemRegionHandle_t* regionHandleArrayOut;
} mstxMemRegionsRegisterBatch_t;
```

**达成路径**

mstxMemRegionsRegisterBatch_t.regionCount [SOURCE]
→ mstxMemRegionsRegister(domain, desc) [CALL]
→ mstx_impl_core.h: (*local)(domain, desc) [SINK, line 85]
→ 无 regionCount 边界检查

**验证说明**: 内存区域批量注册 API mstxMemRegionsRegister 接收 mstxMemRegionsRegisterBatch_t，包含 regionCount 和 regionDescArray。代码层面无边界检查验证 regionCount。若调用方传入超大 regionCount，可能导致内存资源耗尽。但这是 API 设计问题，需要调用方主动错误使用。调整为 POSSIBLE。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| build_scripts | 0 | 2 | 0 | 0 | 2 |
| c_core | 0 | 4 | 4 | 0 | 8 |
| python_binding | 0 | 4 | 0 | 0 | 4 |
| **合计** | **0** | **10** | **4** | **0** | **14** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-476 | 9 | 64.3% |
| CWE-494 | 2 | 14.3% |
| CWE-704 | 1 | 7.1% |
| CWE-20 | 1 | 7.1% |
| CWE-129 | 1 | 7.1% |
