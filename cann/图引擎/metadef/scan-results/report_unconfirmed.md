# 漏洞扫描报告 — 待确认漏洞

**项目**: metadef  
**扫描时间**: 2026-04-22T00:00:00Z  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞  

---

## 执行摘要

本报告包含 **11 个待确认漏洞**，其中 9 个为 LIKELY 状态（高置信度），2 个为 POSSIBLE 状态（中等置信度）。这些漏洞与已确认的 Critical 级别漏洞（VULN-DF-CROSS-001 和 VULN-SEC-DYN-003）共享相同的根本原因：环境变量控制的动态库加载路径无安全验证。

### 待确认漏洞概述

这些漏洞本质上是同一核心安全问题在不同代码路径上的表现：

| 漏洞类型 | 数量 | 核心原因 |
|---------|------|---------|
| dynamic_library_injection | 6 | 环境变量控制 mmDlopen 加载路径 |
| untrusted_search_path | 2 | 环境变量决定算子库搜索路径 |
| path_injection | 1 | 环境变量控制工作路径创建 |
| uncontrolled_resource_consumption | 1 | 文件读取无大小限制 |
| path_traversal | 1 | realpath 无白名单验证 |

### 与已确认漏洞的关系

待确认漏洞与 VULN-DF-CROSS-001 和 VULN-SEC-DYN-003 具有以下关联：

1. **共享入口点**：均从 `ASCEND_OPP_PATH`、`ASCEND_CUSTOM_OPP_PATH`、`ASCEND_HOME_PATH` 等环境变量读取路径
2. **共享 Sink 点**：均以 `mmDlopen()`、`mmMkdir()` 或文件操作作为最终危险操作
3. **共享绕过机制**：均受 `opp_latest` 绕过和版本验证缺失影响

### 建议处理方式

由于这些漏洞与已确认漏洞的根本原因一致，建议采用**统一修复方案**：

- 实施签名验证机制后，大部分 LIKELY 级别的动态库注入漏洞将被同时修复
- 实施可信路径白名单后，路径注入类漏洞将被缓解
- 针对 POSSIBLE 级别漏洞，建议进行人工复核确认实际风险

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 9 | 64.3% |
| POSSIBLE | 2 | 14.3% |
| CONFIRMED | 2 | 14.3% |
| FALSE_POSITIVE | 1 | 7.1% |
| **总计** | **14** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 9 | 81.8% |
| Medium | 2 | 18.2% |
| **有效漏洞总计** | **11** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-DYN-002]** dynamic_library_injection (High) - `base/common/plugin/plugin_manager.cc:804` @ `Load` | 置信度: 75
2. **[VULN-DF-DYN-002]** dynamic_library_injection (High) - `base/common/plugin/plugin_manager.cc:253` @ `GetPluginPathFromCustomOppPath` | 置信度: 75
3. **[VULN-DF-DYN-004]** dynamic_library_injection (High) - `base/common/plugin/plugin_manager.cc:881` @ `LoadWithFlags` | 置信度: 75
4. **[VULN-SEC-DYN-001]** dynamic_library_injection (High) - `base/common/plugin/plugin_manager.cc:156` @ `GetOppPath` | 置信度: 70
5. **[VULN-SEC-ENV-001]** untrusted_search_path (High) - `base/common/plugin/plugin_manager.cc:249` @ `GetPluginPathFromCustomOppPath` | 置信度: 70
6. **[VULN-SEC-ENV-002]** untrusted_search_path (High) - `base/utils/file_utils.cc:315` @ `GetAscendWorkPath` | 置信度: 70
7. **[VULN-DF-DYN-001]** dynamic_library_injection (High) - `base/common/plugin/plugin_manager.cc:717` @ `LoadSoWithFlags` | 置信度: 70
8. **[VULN-DF-DYN-003]** dynamic_library_injection (High) - `base/common/plugin/plugin_manager.cc:185` @ `GetUpgradedOppPath` | 置信度: 70
9. **[VULN-DF-ENV-001]** path_injection (High) - `base/utils/file_utils.cc:317` @ `GetAscendWorkPath` | 置信度: 70
10. **[VULN-SEC-RES-001]** uncontrolled_resource_consumption (Medium) - `base/utils/file_utils.cc:152` @ `GetBinDataFromFile` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `LoadSo@base/common/plugin/plugin_manager.cc` | file | untrusted_local | 通过环境变量 ASCEND_OPP_PATH、ASCEND_CUSTOM_OPP_PATH 等指定的路径加载第三方算子动态库（.so 文件），路径可能被用户控制 | 加载指定路径的共享库（.so 文件） |
| `Load@base/common/plugin/plugin_manager.cc` | file | untrusted_local | 扫描目录并加载所有 .so 文件，目录路径可能来自环境变量 | 扫描目录并加载所有 .so 文件 |
| `GetOppPath@base/common/plugin/plugin_manager.cc` | env | untrusted_local | 读取环境变量 MM_ENV_ASCEND_OPP_PATH 确定算子包路径 | 获取算子包路径（从环境变量或默认路径） |
| `GetPluginPathFromCustomOppPath@base/common/plugin/plugin_manager.cc` | env | untrusted_local | 读取环境变量 MM_ENV_ASCEND_CUSTOM_OPP_PATH 确定自定义算子路径 | 从自定义算子路径获取插件路径 |
| `LoadSoAndInitDefault@base/registry/opp_so_manager.cc` | file | untrusted_local | 加载算子库并注册到默认空间，算子库路径来自环境变量或配置 | 加载算子库并初始化默认注册空间 |
| `LoadOpsProtoPackage@base/registry/opp_so_manager.cc` | file | untrusted_local | 加载算子原型包，路径由环境变量控制 | 加载算子原型包（.so 文件） |
| `ParseJsonFile@error_manager/error_manager.cc` | file | semi_trusted | 解析 JSON 配置文件，文件路径来自库目录相对路径 | 解析 JSON 配置文件（error_code.json） |
| `ReadJsonFile@error_manager/error_manager.cc` | file | semi_trusted | 读取 JSON 文件并解析，文件路径参数可能来自外部 | 读取 JSON 文件 |
| `GetBinFromFile@base/utils/file_utils.cc` | file | semi_trusted | 读取二进制文件内容，路径参数来自外部调用 | 读取二进制文件 |
| `WriteBinToFile@base/utils/file_utils.cc` | file | semi_trusted | 写入二进制文件，路径参数来自外部调用 | 写入二进制文件 |
| `SaveBinToFile@base/utils/file_utils.cc` | file | semi_trusted | 保存二进制数据到文件，路径参数来自外部调用 | 保存二进制数据到文件 |
| `GetAscendWorkPath@base/utils/file_utils.cc` | env | untrusted_local | 读取环境变量 MM_ENV_ASCEND_WORK_PATH 确定工作路径 | 获取 Ascend 工作路径 |

**其他攻击面**:
- 动态库加载: plugin_manager.cc 通过 mmDlopen 加载第三方算子库，路径由环境变量控制
- 环境变量处理: 多个环境变量（ASCEND_OPP_PATH、ASCEND_CUSTOM_OPP_PATH、ASCEND_WORK_PATH）控制库加载路径
- 文件路径处理: realpath、mmRealPath 等函数处理外部传入的文件路径
- JSON 解析: error_manager.cc 使用 nlohmann::json 解析配置文件
- 共享库符号查找: mmDlsym 动态查找库函数符号
- 目录扫描: mmScandir 扫算目录查找 .so 文件

---

## 3. High 漏洞 (9)

### [VULN-SEC-DYN-002] dynamic_library_injection - Load

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-114 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `base/common/plugin/plugin_manager.cc:804-924` @ `Load`
**模块**: plugin

**描述**: Load() 函数扫描目录并加载所有 .so 文件，目录路径来自 mmRealPath 规范化后的用户输入（环境变量控制）。虽然存在文件大小限制（800M）和数量限制（64个），但缺少对加载库的签名验证或来源验证，攻击者可注入恶意算子库。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:804-924`)

```c
const auto handle = mmDlopen(file_path_dlopen.c_str(), flags);
if (handle == nullptr) {
  const ge::char_t *error = mmDlerror();
  GELOGW("Failed in dlopen %s!", error);
  continue;
}
```

**达成路径**

MM_SYS_GET_ENV@plugin_manager.cc:159 → GetOppPath@plugin_manager.cc:156 → mmRealPath@plugin_manager.cc:821 → mmScandir@plugin_manager.cc:836 → mmDlopen@plugin_manager.cc:881

**验证说明**: Load()函数扫描目录并加载所有.so文件，路径来自环境变量。mmRealPath在mmScandir和mmDlopen前均被调用，但仅规范化路径。攻击者可设置环境变量指向包含恶意.so的目录，所有恶意库将被自动加载。比单路径控制更危险(自动加载目录中所有.so)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -10

---

### [VULN-DF-DYN-002] dynamic_library_injection - GetPluginPathFromCustomOppPath

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `base/common/plugin/plugin_manager.cc:253-273` @ `GetPluginPathFromCustomOppPath`
**模块**: plugin
**跨模块**: plugin → registry

**描述**: 环境变量 MM_ENV_ASCEND_CUSTOM_OPP_PATH 可控制自定义算子库加载路径。该环境变量允许用户指定多个冒号分隔的路径，程序将扫描这些路径下的 .so 文件并加载。攻击者可设置该环境变量指向恶意库目录，导致恶意算子库被加载执行。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:253-273`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_CUSTOM_OPP_PATH, custom_opp_path_env);
if (custom_opp_path_env == nullptr) {
  GELOGI("custom_op_lib_path_ is empty.");
  return;
}
custom_op_lib_path_ = std::string(custom_opp_path_env);
```

**达成路径**

MM_SYS_GET_ENV@base/common/plugin/plugin_manager.cc:253 [SOURCE] → GetPluginPathFromCustomOppPath()@plugin_manager.cc:249 → GetOpsProtoPath()@plugin_manager.cc:608 → LoadOpsProtoSo()@opp_so_manager.cc:168 → mmDlopen()@plugin_manager.cc:717 [SINK]

**验证说明**: ASCEND_CUSTOM_OPP_PATH支持多路径(冒号分隔)，扩大攻击面。数据流链: MM_SYS_GET_ENV→GetPluginPathFromCustomOppPath→mmIsDir检查→最终到达mmDlopen。IsVendorVersionValid检查版本但非路径白名单。攻击者可设置多个恶意路径实现任意代码执行。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -10

---

### [VULN-DF-DYN-004] dynamic_library_injection - LoadWithFlags

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `base/common/plugin/plugin_manager.cc:881-887` @ `LoadWithFlags`
**模块**: plugin

**描述**: Load() 函数扫描目录并加载所有 .so 文件。目录路径来自外部调用者，最终追溯到环境变量控制。mmDlopen 直接加载扫描发现的库文件，无额外的路径验证。攻击者可通过环境变量控制扫描目录，使程序加载恶意库。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:881-887`)

```c
const auto handle = mmDlopen(file_path_dlopen.c_str(), flags);
if (handle == nullptr) {
  const ge::char_t *error = mmDlerror();
  GE_IF_BOOL_EXEC(error == nullptr, error = "");
  GELOGW("Failed in dlopen %s!", error);
```

**达成路径**

MM_SYS_GET_ENV@base/common/plugin/plugin_manager.cc:159 [SOURCE] → GetOppPath() → Load()@plugin_manager.cc:804 → mmScandir()@plugin_manager.cc:836 → mmDlopen()@plugin_manager.cc:881 [SINK]

**验证说明**: 与VULN-SEC-DYN-002同一漏洞(Load函数扫描加载)。mmScandir自动加载目录中所有.so文件，攻击者只需在受控目录放置恶意库即可被自动加载。代码line 865调用RealPath规范化路径，line 872 ValidateSo仅检查大小。无签名验证或白名单。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -10

---

### [VULN-SEC-DYN-001] dynamic_library_injection - GetOppPath

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-114 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `base/common/plugin/plugin_manager.cc:156-180` @ `GetOppPath`
**模块**: plugin
**跨模块**: plugin → registry

**描述**: 环境变量控制动态库加载路径，攻击者可通过设置 ASCEND_OPP_PATH 或 ASCEND_CUSTOM_OPP_PATH 环境变量指定恶意 .so 文件路径，实现任意代码执行。加载过程缺少签名验证、白名单验证等安全措施。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:156-180`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_OPP_PATH, path_env);
if ((path_env != nullptr) && (strlen(path_env) > 0U)) {
  opp_path = path_env;
  std::string file_path = RealPath(opp_path.c_str());
}
```

**达成路径**

MM_SYS_GET_ENV@plugin_manager.cc:159 → GetOppPath@plugin_manager.cc:156 → LoadOpsProtoSo@opp_so_manager.cc:168 → mmDlopen@plugin_manager.cc:717

**验证说明**: 数据流链完整验证: MM_SYS_GET_ENV→GetOppPath→mmRealPath→mmDlopen。RealPath仅规范化路径，无法阻止攻击者将ASCEND_OPP_PATH设置为任意有效目录。ValidateSo的800M限制非安全措施(恶意库可<1KB)。本地攻击者可通过环境变量控制加载路径实现任意代码执行。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-SEC-ENV-001] untrusted_search_path - GetPluginPathFromCustomOppPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `base/common/plugin/plugin_manager.cc:249-273` @ `GetPluginPathFromCustomOppPath`
**模块**: plugin
**跨模块**: plugin → registry

**描述**: GetPluginPathFromCustomOppPath() 读取 ASCEND_CUSTOM_OPP_PATH 环境变量，用于构建自定义算子加载路径。环境变量可被攻击者控制，无白名单验证或安全范围检查。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:249-273`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_CUSTOM_OPP_PATH, custom_opp_path_env);
if (custom_opp_path_env == nullptr) {
  return;
}
custom_op_lib_path_ = std::string(custom_opp_path_env);
```

**达成路径**

MM_SYS_GET_ENV@plugin_manager.cc:253 → GetPluginPathFromCustomOppPath@plugin_manager.cc:249 → GetOpsProtoPath@plugin_manager.cc:608 → LoadOpsProtoSo@opp_so_manager.cc:168

**验证说明**: 与VULN-DF-DYN-002同一数据源(ASCEND_CUSTOM_OPP_PATH)。GetPluginPathFromCustomOppPath读取环境变量并分割多路径，仅做mmIsDir有效性检查。环境变量内容完全可控，无白名单或安全范围限制。攻击者可设置任意路径实现算子库劫持。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-SEC-ENV-002] untrusted_search_path - GetAscendWorkPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `base/utils/file_utils.cc:315-338` @ `GetAscendWorkPath`
**模块**: utils

**描述**: GetAscendWorkPath() 读取 ASCEND_WORK_PATH 环境变量作为工作路径，如果目录不存在会尝试创建。环境变量可被攻击者控制，可能导致在任意位置创建目录或文件。

**漏洞代码** (`base/utils/file_utils.cc:315-338`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_WORK_PATH, work_path);
if (work_path != nullptr) {
  if (mmAccess(work_path) != EN_OK) {
    if (CreateDir(work_path) != 0) {
```

**达成路径**

MM_SYS_GET_ENV@file_utils.cc:317 → GetAscendWorkPath@file_utils.cc:315 → CreateDir@file_utils.cc:101

**验证说明**: CreateDir 在 RealPath 验证前执行，攻击者可在任意位置创建目录（进程权限允许时）。环境变量完全可控，untrusted_local 增加实际风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-DYN-001] dynamic_library_injection - LoadSoWithFlags

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `base/common/plugin/plugin_manager.cc:717-728` @ `LoadSoWithFlags`
**模块**: plugin
**跨模块**: plugin → registry → utils

**描述**: 环境变量 MM_ENV_ASCEND_OPP_PATH 可控制动态库加载路径。攻击者可设置恶意环境变量，指向包含恶意代码的共享库，当程序调用 mmDlopen 加载该路径下的库时，恶意代码将被执行。虽然存在 RealPath 规范化路径和 ValidateSo 文件大小检查，但这些措施不能阻止攻击者使用有效的恶意库路径。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:717-728`)

```c
const auto handle = mmDlopen(file_path_dlopen.c_str(), flags);
if (handle == nullptr) {
  const ge::char_t *error = mmDlerror();
  GE_IF_BOOL_EXEC(error == nullptr, error = "");
  GELOGW(
      "[DLOpen][SharedLibraryPath]Failed, path[%s]. Message[%s]!",
      file_path_dlopen.c_str(), error);
```

**达成路径**

MM_SYS_GET_ENV@base/common/plugin/plugin_manager.cc:159 [SOURCE] → GetOppPath()@plugin_manager.cc:156 → RealPath()@base/utils/file_utils.cc:30 → LoadOpsProtoSo()@base/registry/opp_so_manager.cc:168 → GetFileListWithSuffix()@plugin_manager.cc:1085 → mmDlopen()@plugin_manager.cc:717 [SINK]

**验证说明**: 与VULN-SEC-DYN-001同一漏洞(同一环境变量ASCEND_OPP_PATH，同一sink mmDlopen)。数据流链完整验证: MM_SYS_GET_ENV→GetOppPath→RealPath@file_utils.cc→LoadOpsProtoSo→mmDlopen。RealPath在mmDlopen前调用(line 701)，但仅规范化路径无法阻止攻击。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-DF-DYN-003] dynamic_library_injection - GetUpgradedOppPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `base/common/plugin/plugin_manager.cc:185-196` @ `GetUpgradedOppPath`
**模块**: plugin

**描述**: 环境变量 MM_ENV_ASCEND_HOME_PATH 可控制升级 OPP 路径。程序读取该环境变量，拼接 '/opp_latest/' 后作为算子库路径。攻击者可设置该环境变量指向恶意目录，导致升级路径下的恶意库被加载。

**漏洞代码** (`base/common/plugin/plugin_manager.cc:185-196`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, path_env);
if ((path_env != nullptr) && (strlen(path_env) > 0U)) {
  opp_path = path_env;
  opp_path += "/opp_latest/";
```

**达成路径**

MM_SYS_GET_ENV@base/common/plugin/plugin_manager.cc:185 [SOURCE] → GetUpgradedOppPath()@plugin_manager.cc:182 → GetUpgradedOpsProtoPath()@plugin_manager.cc:622 → GetOppPluginPathNew()@plugin_manager.cc:486 → mmDlopen()@plugin_manager.cc:717 [SINK]

**验证说明**: ASCEND_HOME_PATH控制升级OPP路径。GetUpgradedOppPath读取环境变量并拼接'/opp_latest/'，RealPath验证路径有效性。攻击者可设置ASCEND_HOME_PATH指向恶意目录(需包含opp_latest子目录)，实现恶意算子库加载。路径完全可控。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-DF-ENV-001] path_injection - GetAscendWorkPath

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `base/utils/file_utils.cc:317-338` @ `GetAscendWorkPath`
**模块**: utils

**描述**: 环境变量 MM_ENV_ASCEND_WORK_PATH 可控制工作路径。程序读取该环境变量，如果路径不存在则创建目录，并使用 RealPath 规范化。虽然 RealPath 可防止路径遍历，但攻击者仍可设置恶意路径创建目录或访问敏感位置。

**漏洞代码** (`base/utils/file_utils.cc:317-338`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_WORK_PATH, work_path);
if (work_path != nullptr) {
  if (mmAccess(work_path) != EN_OK) {
    if (CreateDir(work_path) != 0) {
```

**达成路径**

MM_SYS_GET_ENV@base/utils/file_utils.cc:317 [SOURCE] → GetAscendWorkPath()@file_utils.cc:315 → CreateDir()@file_utils.cc:101 → mmMkdir()@file_utils.cc:77 [SINK]

**验证说明**: 数据流分析确认：MM_SYS_GET_ENV(Source) → CreateDir → mmMkdir(Sink)。与 VULN-SEC-ENV-002 是同一漏洞的不同分析角度，建议合并处理。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (2)

### [VULN-SEC-RES-001] uncontrolled_resource_consumption - GetBinDataFromFile

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `base/utils/file_utils.cc:152-175` @ `GetBinDataFromFile`
**模块**: utils

**描述**: GetBinFromFile() 和 GetBinDataFromFile() 函数读取文件时无文件大小检查。根据 ifs.tellg() 获取的文件大小直接分配内存，可能导致内存耗尽攻击。

**漏洞代码** (`base/utils/file_utils.cc:152-175`)

```c
(void) ifs.seekg(0, std::ifstream::end);
const uint32_t len = static_cast<uint32_t>(ifs.tellg());
(void) ifs.seekg(0, std::ifstream::beg);
auto bin_data = std::unique_ptr<ge::char_t[]>(new (std::nothrow) ge::char_t[len]);
```

**达成路径**

path 参数 → RealPath@file_utils.cc:154 → std::ifstream::read@file_utils.cc:171

**验证说明**: 无文件大小上限硬检查。攻击者可读取超大文件耗尽内存。DoS 类漏洞，semi_trusted 降低实际攻击概率。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-PATH-001] path_traversal - RealPath

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `base/utils/file_utils.cc:30-49` @ `RealPath`
**模块**: utils
**跨模块**: utils → plugin

**描述**: RealPath() 函数使用 mmRealPath 规范化路径，但未检查规范化后的路径是否在安全范围内（如特定目录白名单）。攻击者可能通过相对路径或符号链接访问敏感文件。

**漏洞代码** (`base/utils/file_utils.cc:30-49`)

```c
if (mmRealPath(path, &(resolved_path[0U]), MMPA_MAX_PATH) == EN_OK) {
  res = &(resolved_path[0]);
} else {
  GELOGW("[Util][realpath] Can not get real_path for [%s], reason:%s", path, strerror(errno));
}
```

**达成路径**

外部路径输入 → RealPath@file_utils.cc:30 → GetBinFromFile@file_utils.cc:152 → std::ifstream::read

**验证说明**: realpath() 仅规范路径，无白名单验证。攻击者可访问存在的任意文件（受权限限制）。semi_trusted 降低实际风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -25 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| plugin | 0 | 7 | 0 | 0 | 7 |
| utils | 0 | 2 | 2 | 0 | 4 |
| **合计** | **0** | **9** | **2** | **0** | **11** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 6 | 54.5% |
| CWE-22 | 2 | 18.2% |
| CWE-114 | 2 | 18.2% |
| CWE-400 | 1 | 9.1% |
