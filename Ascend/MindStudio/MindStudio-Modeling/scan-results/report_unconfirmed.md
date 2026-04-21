# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Modeling
**扫描时间**: 2026-04-21T04:10:56.724Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 8 | 36.4% |
| CONFIRMED | 8 | 36.4% |
| POSSIBLE | 3 | 13.6% |
| LIKELY | 3 | 13.6% |
| **总计** | **22** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 6 | 100.0% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-006]** Path Traversal (High) - `tensor_cast/diffusers/diffusers_model.py:61` @ `load_config_from_file` | 置信度: 65
2. **[DF-003]** Path Traversal (High) - `tensor_cast/diffusers/diffusers_model.py:56` @ `load_config_from_file` | 置信度: 65
3. **[DF-011]** Path Traversal (High) - `cli/inference/video_generate.py:330` @ `main` | 置信度: 65
4. **[SEC-005]** Path Traversal (High) - `cli/inference/text_generate.py:121` @ `main` | 置信度: 55
5. **[SEC-008]** Path Traversal (High) - `tensor_cast/runtime.py:425` @ `Runtime.export_chrome_trace` | 置信度: 55
6. **[DF-005]** Path Traversal (High) - `serving_cast/config.py:108` @ `Config._parse_common_config` | 置信度: 55

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. High 漏洞 (6)

### [SEC-006] Path Traversal - load_config_from_file

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `tensor_cast/diffusers/diffusers_model.py:61-72` @ `load_config_from_file`
**模块**: tensor_cast.diffusers

**描述**: User-provided model_path is walked and files are opened without path validation. The os.walk() and subsequent file operations could access arbitrary directories if a malicious path is provided.

**漏洞代码** (`tensor_cast/diffusers/diffusers_model.py:61-72`)

```c
for root, _, files in os.walk(model_path):
    if "config.json" in files:
        folder_name = os.path.basename(root)
        config_path = os.path.join(root, "config.json")
        ...
with open(config_path) as f:
    config = json.load(f)
```

**达成路径**

model_path (user input) -> os.walk(model_path) -> open(config_path)

**验证说明**: 可能漏洞：os.walk 可遍历任意目录，open 可读取任意 config.json 文件。攻击者可读取敏感配置信息。

**评分明细**: 0: 数 | 1: 据 | 2: 流 | 3: 完 | 4: 整 | 5: ( | 6: 2 | 7: 0 | 8: ) | 9: + | 10: 攻 | 11: 击 | 12: 者 | 13: 可 | 14: 控 | 15: 输 | 16: 入 | 17: ( | 18: 1 | 19: 5 | 20: ) | 21: + | 22: 攻 | 23: 击 | 24: 路 | 25: 径 | 26: 直 | 27: 接 | 28: ( | 29: 1 | 30: 5 | 31: ) | 32: + | 33: 无 | 34: 安 | 35: 全 | 36: 控 | 37: 制 | 38: ( | 39: 1 | 40: 0 | 41: ) | 42: + | 43: 代 | 44: 码 | 45: 可 | 46: 执 | 47: 行 | 48: ( | 49: 1 | 50: 0 | 51: ) | 52: + | 53: 可 | 54: 读 | 55: 任 | 56: 意 | 57: c | 58: o | 59: n | 60: f | 61: i | 62: g | 63: ( | 64: + | 65: 5 | 66: ) | 67: = | 68: 6 | 69: 5

---

### [DF-003] Path Traversal - load_config_from_file

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `tensor_cast/diffusers/diffusers_model.py:56-71` @ `load_config_from_file`
**模块**: tensor_cast.diffusers
**跨模块**: cli → tensor_cast.diffusers

**描述**: User-controlled model_id path used in os.walk() and open() without proper path traversal validation. The code only checks if the directory exists, not if it is within an allowed boundary.

**验证说明**: 可能漏洞：与SEC-006相同，可遍历任意目录读取配置文件。

**评分明细**: 0: 数 | 1: 据 | 2: 流 | 3: 完 | 4: 整 | 5: ( | 6: 2 | 7: 0 | 8: ) | 9: + | 10: 攻 | 11: 击 | 12: 者 | 13: 可 | 14: 控 | 15: 输 | 16: 入 | 17: ( | 18: 1 | 19: 5 | 20: ) | 21: + | 22: 攻 | 23: 击 | 24: 路 | 25: 径 | 26: 直 | 27: 接 | 28: ( | 29: 1 | 30: 5 | 31: ) | 32: + | 33: 无 | 34: 安 | 35: 全 | 36: 控 | 37: 制 | 38: ( | 39: 1 | 40: 0 | 41: ) | 42: + | 43: 代 | 44: 码 | 45: 可 | 46: 执 | 47: 行 | 48: ( | 49: 1 | 50: 0 | 51: ) | 52: + | 53: 可 | 54: 读 | 55: 任 | 56: 意 | 57: 文 | 58: 件 | 59: ( | 60: + | 61: 5 | 62: ) | 63: = | 64: 6 | 65: 5

---

### [DF-011] Path Traversal - main

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `cli/inference/video_generate.py:330-333` @ `main`
**模块**: tensor_cast.diffusers
**跨模块**: cli → tensor_cast.diffusers

**描述**: Video generate CLI uses unvalidated model_id path. Unlike text_generate.py which has check_string_valid(), video_generate.py accepts model_id with type=str without any validation.

**验证说明**: 可能漏洞：video_generate.py的model_id参数完全没有验证，比text_generate.py更危险。

**评分明细**: 0: 数 | 1: 据 | 2: 流 | 3: 完 | 4: 整 | 5: ( | 6: 2 | 7: 0 | 8: ) | 9: + | 10: 攻 | 11: 击 | 12: 者 | 13: 可 | 14: 控 | 15: 输 | 16: 入 | 17: ( | 18: 1 | 19: 5 | 20: ) | 21: + | 22: 攻 | 23: 击 | 24: 路 | 25: 径 | 26: 直 | 27: 接 | 28: ( | 29: 1 | 30: 5 | 31: ) | 32: + | 33: 无 | 34: 安 | 35: 全 | 36: 控 | 37: 制 | 38: ( | 39: 1 | 40: 0 | 41: ) | 42: + | 43: 代 | 44: 码 | 45: 可 | 46: 执 | 47: 行 | 48: ( | 49: 1 | 50: 0 | 51: ) | 52: + | 53: 无 | 54: 任 | 55: 何 | 56: 验 | 57: 证 | 58: ( | 59: + | 60: 5 | 61: ) | 62: = | 63: 6 | 64: 5

---

### [SEC-005] Path Traversal - main

**严重性**: High | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cli/inference/text_generate.py:121-132` @ `main`
**模块**: cli
**跨模块**: cli → serving_cast.config → tensor_cast.runtime

**描述**: User-controlled file paths for debug outputs (--graph-log-url, --chrome-trace, --profiling-database) without validation. Could allow writing to arbitrary locations on the filesystem.

**漏洞代码** (`cli/inference/text_generate.py:121-132`)

```c
debug_group.add_argument(
    "--graph-log-url",
    help="For debug: the path for dumping the compiled graphs if compile is on",
)
...
debug_group.add_argument(
    "--chrome-trace",
    help="Generate chrome trace file",
)
```

**达成路径**

args.graph_log_url -> config.compilation.debug.graph_log_url; args.chrome_trace -> runtime.export_chrome_trace

**验证说明**: 可能漏洞：CLI 参数提供的文件路径缺少验证，可能用于路径遍历写入。需要确认是否有文件系统权限限制。

**评分明细**: 0: 攻 | 1: 击 | 2: 者 | 3: 可 | 4: 控 | 5: 输 | 6: 入 | 7: ( | 8: 1 | 9: 5 | 10: ) | 11: + | 12: 攻 | 13: 击 | 14: 路 | 15: 径 | 16: 直 | 17: 接 | 18: ( | 19: 1 | 20: 5 | 21: ) | 22: + | 23: 无 | 24: 安 | 25: 全 | 26: 控 | 27: 制 | 28: ( | 29: 1 | 30: 0 | 31: ) | 32: + | 33: 代 | 34: 码 | 35: 可 | 36: 执 | 37: 行 | 38: ( | 39: 1 | 40: 0 | 41: ) | 42: + | 43: 影 | 44: 响 | 45: 有 | 46: 限 | 47: ( | 48: - | 49: 5 | 50: ) | 51: = | 52: 5 | 53: 5

---

### [SEC-008] Path Traversal - Runtime.export_chrome_trace

**严重性**: High | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor, dataflow-scanner

**位置**: `tensor_cast/runtime.py:425-433` @ `Runtime.export_chrome_trace`
**模块**: tensor_cast.runtime
**跨模块**: cli → tensor_cast.runtime

**描述**: User-controlled trace_file path used for file write operations without validation. Could allow writing Chrome trace files to arbitrary locations.

**漏洞代码** (`tensor_cast/runtime.py:425-433`)

```c
if isinstance(trace_file, str):
    f = open(trace_file, "w")
...
json.dump({"traceEvents": trace_events}, f)
```

**达成路径**

chrome_trace (CLI arg) -> runtime.export_chrome_trace(chrome_trace) -> open(trace_file, 'w')

**验证说明**: 可能漏洞：用户可控制 Chrome trace 输出路径，可写入任意位置。

**评分明细**: 0: 攻 | 1: 击 | 2: 者 | 3: 可 | 4: 控 | 5: 输 | 6: 入 | 7: ( | 8: 1 | 9: 5 | 10: ) | 11: + | 12: 攻 | 13: 击 | 14: 路 | 15: 径 | 16: 直 | 17: 接 | 18: ( | 19: 1 | 20: 5 | 21: ) | 22: + | 23: 无 | 24: 安 | 25: 全 | 26: 控 | 27: 制 | 28: ( | 29: 1 | 30: 0 | 31: ) | 32: + | 33: 代 | 34: 码 | 35: 可 | 36: 执 | 37: 行 | 38: ( | 39: 1 | 40: 0 | 41: ) | 42: + | 43: 仅 | 44: 写 | 45: 入 | 46: ( | 47: + | 48: 5 | 49: ) | 50: = | 51: 5 | 52: 5

---

### [DF-005] Path Traversal - Config._parse_common_config

**严重性**: High | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner, security-auditor

**位置**: `serving_cast/config.py:108-121` @ `Config._parse_common_config`
**模块**: serving_cast

**描述**: User-provided config file paths passed directly to open() without validation. Attackers can read arbitrary YAML configuration files on the system.

**验证说明**: 可能漏洞：路径未验证但yaml.safe_load是安全的。主要风险是读取任意YAML文件，不是反序列化漏洞。

**评分明细**: 0: 攻 | 1: 击 | 2: 者 | 3: 可 | 4: 控 | 5: 输 | 6: 入 | 7: ( | 8: 1 | 9: 5 | 10: ) | 11: + | 12: 攻 | 13: 击 | 14: 路 | 15: 径 | 16: 直 | 17: 接 | 18: ( | 19: 1 | 20: 5 | 21: ) | 22: + | 23: 无 | 24: 安 | 25: 全 | 26: 控 | 27: 制 | 28: ( | 29: 1 | 30: 0 | 31: ) | 32: + | 33: 代 | 34: 码 | 35: 可 | 36: 执 | 37: 行 | 38: ( | 39: 1 | 40: 0 | 41: ) | 42: + | 43: y | 44: a | 45: m | 46: l | 47: . | 48: s | 49: a | 50: f | 51: e | 52: _ | 53: l | 54: o | 55: a | 56: d | 57: 安 | 58: 全 | 59: ( | 60: - | 61: 5 | 62: ) | 63: = | 64: 5 | 65: 5

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cli | 0 | 1 | 0 | 0 | 1 |
| serving_cast | 0 | 1 | 0 | 0 | 1 |
| tensor_cast.diffusers | 0 | 3 | 0 | 0 | 3 |
| tensor_cast.runtime | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **6** | **0** | **0** | **6** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 6 | 100.0% |
