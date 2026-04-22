# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Kernel-Performance-Prediction
**扫描时间**: 2026-04-21T12:02:18.654Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 3 | 33.3% |
| FALSE_POSITIVE | 3 | 33.3% |
| CONFIRMED | 3 | 33.3% |
| **总计** | **9** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CPP-004]** integer_overflow (Medium) - `csrc/prof_data/data_adapter.cpp:45` @ `MovClass::Get` | 置信度: 65
2. **[VULN-DF-PY-002]** path_traversal (Medium) - `mskpp/core/trace.py:146` @ `Trace.dump` | 置信度: 65
3. **[VULN-DF-PY-003]** path_traversal (Medium) - `mskpp/core/metric/output_tool.py:29` @ `TableOutputWrapper.__enter__` | 置信度: 65

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. Medium 漏洞 (3)

### [VULN-DF-CPP-004] integer_overflow - MovClass::Get

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/prof_data/data_adapter.cpp:45-51` @ `MovClass::Get`
**模块**: csrc.prof_data

**描述**: dataSize (long from Python) is cast to uint32_t without bounds checking. A large negative or positive value could cause overflow. Additionally, line 48 calculates dataSize - diff * func which could result in negative values if dataSize is smaller than the adjustment.

**漏洞代码** (`csrc/prof_data/data_adapter.cpp:45-51`)

```c
long dataSize;
... static_cast<uint32_t>(dataSize) // No bounds check
LinearInterpolate(curves, static_cast<uint32_t>(dataSize))
```

**达成路径**

init_profdata_module.cpp:43 PyArg_ParseTuple "l" -> long dataSize -> data_adapter.cpp:51 static_cast<uint32_t>(dataSize) -> LinearInterpolate

**验证说明**: dataSize (long from Python) is cast to uint32_t at line 51 without comprehensive bounds checking. If dataSize is negative or exceeds UINT32_MAX, overflow causes incorrect behavior. Partial mitigation exists at line 45 for specific case (transEnable && src=='GM' && dst=='L1'), but not for general paths. LinearInterpolate would receive incorrect value, potentially causing wrong performance predictions.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-002] path_traversal - Trace.dump

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mskpp/core/trace.py:146-161` @ `Trace.dump`
**模块**: mskpp.core

**描述**: output_dir parameter is used to construct trace_file path without proper validation. checker.check_path_exists only checks if file exists, but does not validate that output_dir is within allowed boundaries or prevent path traversal via '..' or absolute paths. User could potentially write trace.json to arbitrary locations. Mitigating factors: file permissions are secure (S_IWUSR | S_IRUSR), exception raised if file exists.

**漏洞代码** (`mskpp/core/trace.py:146-161`)

```c
trace_file = os.path.join(output_dir, 'trace.json')
if checker.check_path_exists(trace_file):
    raise Exception('The file {} already exists...')
with os.fdopen(os.open(trace_file, OPEN_FLAGS, SAVE_DATA_FILE_AUTHORITY), 'w') as f:
```

**达成路径**

User input (output_dir) -> os.path.join(output_dir, 'trace.json') -> os.fdopen(os.open(trace_file)) -> file write

**验证说明**: output_dir parameter is used to construct trace_file path without path traversal validation. User can pass paths containing '..' or absolute paths to write to arbitrary locations. Mitigations: secure file permissions (S_IWUSR|S_IRUSR), file existence check prevents overwrite. checker.check_path_exists only checks existence, not path boundaries. check_output_path function exists but is not called here.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-003] path_traversal - TableOutputWrapper.__enter__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mskpp/core/metric/output_tool.py:29-43` @ `TableOutputWrapper.__enter__`
**模块**: mskpp.core.metric

**描述**: filepath parameter is directly used in os.fdopen(os.open()) without path validation. User-provided filepath could contain '..' or absolute paths to write CSV data to arbitrary locations. No sanitization or boundary checking performed. Mitigating factors: secure file permissions (S_IWUSR | S_IRUSR) used.

**漏洞代码** (`mskpp/core/metric/output_tool.py:29-43`)

```c
self.file = os.fdopen(os.open(self.filepath, OPEN_FLAGS, SAVE_DATA_FILE_AUTHORITY), 'w')
```

**达成路径**

User input (filepath parameter) -> os.open(filepath) -> os.fdopen() -> CSV writer -> file write

**验证说明**: filepath parameter directly used in os.open without path validation. User can write to arbitrary locations. Mitigations: secure file permissions (S_IWUSR|S_IRUSR = 0600). No path boundary checking or '..' traversal prevention. Same pattern as VULN-DF-PY-002.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| csrc.prof_data | 0 | 0 | 1 | 0 | 1 |
| mskpp.core | 0 | 0 | 1 | 0 | 1 |
| mskpp.core.metric | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **3** | **0** | **3** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 2 | 66.7% |
| CWE-190 | 1 | 33.3% |
