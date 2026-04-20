# 漏洞扫描报告 — MindIE-SD 待确认漏洞

**项目**: MindIE-SD (Mind Inference Engine for Stable Diffusion)
**项目描述**: 针对华为 Ascend 硬件优化的 Stable Diffusion 模型推理引擎
**版本**: 2.3.0
**厂商**: Huawei Technologies Co., Ltd.
**扫描时间**: 2026-04-17T08:33:48.809Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞（置信度 < 80）

---

## 执行摘要

本报告包含 **7 个待确认漏洞**，其中 5 个为 LIKELY 状态（置信度 60-79），2 个为 POSSIBLE 状态（置信度 40-59）。这些漏洞需要进一步验证或在特定条件下可能被利用。

### 风险概述

| 状态 | 数量 | 严重性分布 | 主要类型 |
|------|------|-----------|---------|
| LIKELY | 5 | Medium: 3, Low: 2 | 硬编码凭证、库注入、路径遍历、日志注入 |
| POSSIBLE | 2 | Low: 2 | 整数溢出、IPC无认证 |

### 主要风险点

1. **硬编码凭证 (VULN-SEC-001)**：EPLB 调度器使用默认弱凭证，本地攻击者或 SSRF 可利用
2. **动态库注入 (VULN-DF-CPP-001/002)**：环境变量控制 dlopen 路径，需先获得环境变量控制权
3. **模型加载路径 (VULN-DF-PY-003)**：用户可指定模型加载目录，可能加载恶意模型

### 建议措施

- 强制设置 `EPLB_AUTH_KEY` 环境变量，禁用默认凭证
- 添加环境变量路径校验或使用硬编码安全路径
- 对模型加载路径添加白名单验证
- 清洗日志输入防止注入攻击

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 5 | 55.6% |
| POSSIBLE | 2 | 22.2% |
| CONFIRMED | 2 | 22.2% |
| **总计** | **9** | 100% |

### 1.2 严重性分布（待确认漏洞）

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 4 | 57.1% |
| Low | 3 | 42.9% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 关键漏洞列表（按置信度排序）

| ID | 类型 | 严重性 | 置信度 | 状态 |
|-----|------|--------|--------|------|
| VULN-DF-PY-003 | path_traversal | Medium | 75 | LIKELY |
| VULN-SEC-001 | hardcoded_credentials | Medium | 70 | LIKELY |
| VULN-DF-CPP-001 | library_injection | Medium | 55 | LIKELY |
| VULN-DF-CPP-002 | library_injection | Medium | 55 | LIKELY |
| VULN-SEC-004 | log_injection | Low | 60 | LIKELY |
| VULN-DF-CPP-003 | integer_overflow | Low | 50 | POSSIBLE |
| VULN-DF-PY-004 | unauthenticated_ipc | Low | 45 | POSSIBLE |

---

## 2. 攻击面分析

### 潜在攻击入口

| 类型 | 位置 | 暴露程度 | 风险 | 说明 |
|------|------|----------|------|------|
| **环境变量** | `csrc/plugin/find_op_path.cpp` | 部署配置 | Medium | dlopen 加载路径由环境变量控制 |
| **IPC 网络** | `mindiesd/eplb/eplb_scheduler.py` | 本地默认 | Medium | BaseManager 使用默认弱凭证 |
| **IPC 网络** | `mindiesd/share_memory.py` | 本地默认 | Low | ZMQ 绑定可配置地址 |
| **日志系统** | `examples/service/worker.py` | 服务层 | Low | 用户输入直接写入日志 |

### 利用前置条件分析

| 漏洞 | 前置条件 | 利用难度 |
|------|---------|---------|
| VULN-DF-CPP-001/002 | 需控制环境变量（提权/容器逃逸/配置写入） | 中-高 |
| VULN-SEC-001 | 本地访问或 SSRF + 公网绑定配置 | 中 |
| VULN-DF-PY-003 | HTTP 访问 + 模型框架执行能力 | 中 |
| VULN-DF-PY-004 | 需管理员配置公网绑定 | 高 |
| VULN-DF-CPP-003 | 需构造特殊张量维度 + 框架限制 | 高 |

---

## 3. Medium 漏洞详情

### [VULN-DF-PY-003] 模型路径遍历

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-003 |
| **类型** | Path Traversal (Model Loading) |
| **CWE** | CWE-22 |
| **严重性** | Medium |
| **置信度** | 75/100 |
| **状态** | LIKELY |
| **位置** | `examples/service/request.py:37` |
| **函数** | `GeneratorRequest` |
| **模块** | examples/service |

#### 漏洞代码

```python
# examples/service/request.py:37
ckpt_dir: Optional[str] = '/data'
```

#### 数据流路径

```
HTTP request → GeneratorRequest.ckpt_dir → WanT2V/WanI2V(checkpoint_dir=args.ckpt_dir)
```

#### 验证说明

用户可通过 `ckpt_dir` 参数指定模型加载路径。虽然可加载任意目录的模型文件，但实际风险取决于模型框架是否支持执行模型内代码。存在加载恶意模型的可能性，但利用难度高于直接文件读写漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 = **75**

#### 修复建议

```python
# request.py - 添加 ckpt_dir 白名单验证
ALLOWED_CKPT_DIRS = ['/data', '/data/models', '/opt/models']

def validate_ckpt_dir(ckpt_dir: str) -> str:
    abs_path = os.path.realpath(ckpt_dir)
    for allowed in ALLOWED_CKPT_DIRS:
        if abs_path.startswith(os.path.realpath(allowed)):
            return abs_path
    raise ValueError(f"ckpt_dir must be within allowed directories: {ALLOWED_CKPT_DIRS}")
```

---

### [VULN-SEC-001] 硬编码默认凭证

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-001 |
| **类型** | Hardcoded Credentials |
| **CWE** | CWE-798 |
| **严重性** | Medium |
| **置信度** | 70/100 |
| **状态** | LIKELY |
| **位置** | `mindiesd/eplb/eplb_scheduler.py:48` |
| **函数** | `get_args` |
| **模块** | mindiesd/eplb |

#### 漏洞代码

```python
# mindiesd/eplb/eplb_scheduler.py:48
parser.add_argument("--auth_key", type=str, 
    default=os.environ.get("EPLB_AUTH_KEY", "secret_key"))
```

#### 数据流路径

```
CommandLine/EPLB_AUTH_KEY → auth_key → BaseManager(address=addr, authkey=auth_bytes)
```

#### 验证说明

硬编码默认凭证 `secret_key` 用于 EPLB 调度器网络认证。当未设置 `EPLB_AUTH_KEY` 环境变量时使用默认值。风险分析：
1) 默认 host=localhost 限制外部访问
2) 但部署时可能改为公网地址
3) 本地攻击者或通过 SSRF 可利用
4) 获得凭证后可连接调度器控制任务分发

**评分明细**: base: 30 | reachability: 20 | controllability: 20 = **70**

#### 修复建议

```python
# eplb_scheduler.py - 强制设置凭证，禁用默认值
auth_key = os.environ.get("EPLB_AUTH_KEY")
if auth_key is None:
    raise RuntimeError("EPLB_AUTH_KEY environment variable must be set for production use")
parser.add_argument("--auth_key", type=str, default=auth_key)

# 或使用随机生成
import secrets
default_key = secrets.token_hex(16) if os.environ.get("DEV_MODE") else None
if default_key is None and not os.environ.get("EPLB_AUTH_KEY"):
    raise RuntimeError("EPLB_AUTH_KEY must be set in production")
```

---

### [VULN-DF-CPP-001] 动态库注入 (ASCEND_CUSTOM_OPP_PATH)

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-CPP-001 |
| **类型** | Library Injection |
| **CWE** | CWE-426 |
| **严重性** | Medium（原: High → 验证后降级） |
| **置信度** | 55/100 |
| **状态** | LIKELY |
| **位置** | `csrc/plugin/find_op_path.cpp:174-178` |
| **函数** | `GetOpApiLibHandler` |
| **模块** | csrc/plugin |

#### 漏洞代码

```cpp
// csrc/plugin/find_op_path.cpp:174-178
auto handler = dlopen(libName, RTLD_LAZY);
if (handler == nullptr) {
    ASCEND_LOGW("dlopen %s failed, error:%s.", libName, dlerror());
}
return handler;
```

#### 数据流路径

```
Environment ASCEND_CUSTOM_OPP_PATH → GetCustomLibPath() → dlopen(libName)
```

#### 验证说明

环境变量控制动态库加载路径，攻击者可能注入恶意库导致代码执行。但利用需先获得控制环境变量的能力（通过提权、容器逃逸或配置文件写入）。RealPath() 仅解析路径而非验证，不是有效缓解措施。默认部署中环境变量由管理员配置。风险随部署环境变化：容器化部署风险更高。

**评分明细**: base: 30 | reachability: 10 | controllability: 25 | mitigations: -10 = **55**

#### 修复建议

```cpp
// find_op_path.cpp - 添加路径验证
#include <limits.h>

bool ValidateLibPath(const char* libPath) {
    char resolved[PATH_MAX];
    if (realpath(libPath, resolved) == nullptr) return false;
    
    // 白名单校验
    const char* allowedPrefixes[] = {
        "/usr/lib/ascend/",
        "/opt/ascend/",
        "/usr/local/lib/ascend/"
    };
    
    for (const char* prefix : allowedPrefixes) {
        if (strncmp(resolved, prefix, strlen(prefix)) == 0) {
            return true;
        }
    }
    return false;
}
```

---

### [VULN-DF-CPP-002] 动态库注入 (ASCEND_OPP_PATH)

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-CPP-002 |
| **类型** | Library Injection |
| **CWE** | CWE-426 |
| **严重性** | Medium（原: High → 验证后降级） |
| **置信度** | 55/100 |
| **状态** | LIKELY |
| **位置** | `csrc/plugin/find_op_path.cpp:146-155` |
| **函数** | `GetDefaultCustomLibPath` |
| **模块** | csrc/plugin |

#### 漏洞代码

```cpp
// csrc/plugin/find_op_path.cpp:146-155
const char *ascendOppPath = std::getenv("ASCEND_OPP_PATH");
if (ascendOppPath == nullptr) {
    ASCEND_LOGW("ASCEND_OPP_PATH is not exists");
    return std::vector<std::string>();
}
std::string vendorsPath(ascendOppPath);
vendorsPath = vendorsPath + "/vendors";
return ParseVendorsConfig(vendorsPath);
```

#### 验证说明

与 VULN-DF-CPP-001 类似，但经过更多中间处理（ParseVendorsConfig 读取 config.ini）。攻击链更长但仍可达。config.ini 解析提供了微弱缓解：需同时控制环境变量和配置文件才能完全利用。利用条件：
1) 控制 ASCEND_OPP_PATH 环境变量
2) 或修改 vendors/config.ini 文件
需提权后利用。

**评分明细**: base: 30 | reachability: 10 | controllability: 25 | mitigations: -10 = **55**

---

## 4. Low 漏洞详情

### [VULN-SEC-004] 日志注入

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-004 |
| **类型** | Log Injection |
| **CWE** | CWE-117 |
| **严重性** | Low |
| **置信度** | 60/100 |
| **状态** | LIKELY |
| **位置** | `examples/service/worker.py:138` |
| **函数** | `generate` |
| **模块** | examples/service |

#### 漏洞代码

```python
# examples/service/worker.py:138
logging.info(f"request: {request_info}")
```

#### 验证说明

用户输入的 prompt 字段直接写入日志，可注入换行符伪造日志条目或掩盖攻击痕迹。实际影响有限：主要风险是日志伪造而非系统入侵。属于低风险漏洞，但仍应清洗用户输入再记录日志。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 = **60**

#### 修复建议

```python
# worker.py - 清洗日志输入
def sanitize_for_log(text: str) -> str:
    """移除换行符和特殊字符"""
    return text.replace('\n', '\\n').replace('\r', '\\r')

logging.info(f"request: {sanitize_for_log(request_info)}")
```

---

### [VULN-DF-CPP-003] 整数溢出

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-CPP-003 |
| **类型** | Integer Overflow |
| **CWE** | CWE-190 |
| **严重性** | Low（原: Medium → 验证后降级） |
| **置信度** | 50/100 |
| **状态** | POSSIBLE |
| **位置** | `csrc/ops/block_sparse_attention/op_host/block_sparse_attention_tiling.cpp:3329-3333` |
| **函数** | `ConvertContextToBSAParams` |
| **模块** | csrc/ops/block_sparse_attention |

#### 漏洞代码

```cpp
// csrc/ops/block_sparse_attention/op_host/block_sparse_attention_tiling.cpp:3329-3333
h1 = n1Size * dSize;
h2 = n2Size * dSize;
s1StrideSize = gSize * n2Size * dSize;
s2StrideSize = n2Size * dSize;
```

#### 验证说明

张量维度乘法无溢出检查。代码有边界检查（OPS_ERR_IF 验证张量大小）但未检查乘法溢出。利用条件：
1) 用户通过 HTTP API 控制输入张量维度
2) 构造足够大的维度值触发溢出
3) 溢出导致缓冲区大小计算错误

但 NPU 硬件和框架对张量大小有上限，实际利用难度较高。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 = **50**

#### 修复建议

```cpp
// block_sparse_attention_tiling.cpp - 添加溢出检查
#include <limits>

bool CheckMultiplicationOverflow(size_t a, size_t b) {
    if (a == 0 || b == 0) return false;
    return a > std::numeric_limits<size_t>::max() / b;
}

// 使用前检查
if (CheckMultiplicationOverflow(n1Size, dSize)) {
    ASCEND_LOGE("Dimension multiplication overflow detected");
    return ACLNN_ERROR;
}
h1 = n1Size * dSize;
```

---

### [VULN-DF-PY-004] IPC 无认证

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-004 |
| **类型** | Unauthenticated IPC |
| **CWE** | CWE-287 |
| **严重性** | Low（原: Medium → 验证后降级） |
| **置信度** | 45/100 |
| **状态** | POSSIBLE |
| **位置** | `mindiesd/share_memory.py:44-49` |
| **函数** | `__init__` |
| **模块** | mindiesd/share_memory |

#### 漏洞代码

```python
# mindiesd/share_memory.py:44-49
self.rep_socket = ZMQ_CONTEXT.socket(zmq.REP)
self.rep_socket.bind(f"tcp://{self.master_addr}:{self.rep_port}")
self.pub_socket = ZMQ_CONTEXT.socket(zmq.PUB)
self.pub_socket.bind(f"tcp://{self.master_addr}:{self.pub_port}")
```

#### 验证说明

ZMQ IPC 通信绑定可配置网络地址，无认证机制。NPU 内存句柄通过网络广播。风险分析：
1) 默认 master_addr=127.0.0.1 仅本地可达
2) 支持跨机通信但需管理员配置为公网地址
3) 无认证意味着任何能到达该端口的攻击者可接收内存句柄
4) 内存句柄泄露可能暴露敏感数据

实际风险取决于部署配置，默认配置风险有限。

**评分明细**: base: 30 | controllability: 15 = **45**

#### 修复建议

```python
# share_memory.py - 添加认证和绑定限制
import zmq.auth

def create_authenticated_socket(context, socket_type, addr, port, cert_path):
    """创建带认证的 ZMQ socket"""
    socket = context.socket(socket_type)
    
    # 仅允许本地绑定（除非显式启用远程）
    if addr != "127.0.0.1":
        if not os.environ.get("ALLOW_REMOTE_SHARE_MEMORY"):
            raise ValueError("Remote binding requires ALLOW_REMOTE_SHARE_MEMORY=1")
    
    # 使用 CURVE 认证
    socket.curve_secretkey = load_secret_key(cert_path)
    socket.curve_publickey = load_public_key(cert_path)
    
    socket.bind(f"tcp://{addr}:{port}")
    return socket
```

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| csrc/plugin | 0 | 0 | 2 | 0 | 2 |
| examples/service | 0 | 0 | 1 | 1 | 2 |
| mindiesd/eplb | 0 | 0 | 1 | 0 | 1 |
| csrc/ops/block_sparse_attention | 0 | 0 | 0 | 1 | 1 |
| mindiesd/share_memory | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **0** | **4** | **3** | **7** |

---

## 6. CWE 分布

| CWE | 数量 | 占比 | 说明 |
|-----|------|------|------|
| CWE-426 | 2 | 28.6% | 不受信任的搜索路径（库注入） |
| CWE-22 | 1 | 14.3% | 路径遍历 |
| CWE-798 | 1 | 14.3% | 硬编码凭证 |
| CWE-287 | 1 | 14.3% | 认证不当 |
| CWE-190 | 1 | 14.3% | 整数溢出 |
| CWE-117 | 1 | 14.3% | 日志注入 |

---

## 7. 建议优先级排序

### 优先级 P1（高优先级）

| 漏洞 | 建议措施 | 实施难度 |
|------|---------|---------|
| VULN-SEC-001 | 强制设置 EPLB_AUTH_KEY，禁用默认凭证 | 低 |
| VULN-DF-PY-003 | 添加 ckpt_dir 白名单验证 | 低 |

### 优先级 P2（中优先级）

| 漏洞 | 建议措施 | 实施难度 |
|------|---------|---------|
| VULN-DF-CPP-001/002 | 添加 dlopen 路径白名单校验 | 中 |
| VULN-SEC-004 | 清洗日志输入 | 低 |

### 优先级 P3（低优先级）

| 漏洞 | 建议措施 | 实施难度 |
|------|---------|---------|
| VULN-DF-CPP-003 | 添加乘法溢出检查 | 中 |
| VULN-DF-PY-004 | 添加 IPC 认证（当启用远程绑定时） | 高 |

---

## 8. 参考资料

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

---

**报告生成时间**: 2026-04-17T08:33:48.809Z
**扫描系统**: OpenCode 多 Agent 漏洞扫描系统