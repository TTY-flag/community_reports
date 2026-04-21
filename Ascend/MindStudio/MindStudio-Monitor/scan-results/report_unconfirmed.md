# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Monitor
**扫描时间**: 2026-04-20T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 50.0% |
| POSSIBLE | 7 | 25.0% |
| LIKELY | 5 | 17.9% |
| CONFIRMED | 2 | 7.1% |
| **总计** | **28** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 5 | 41.7% |
| Low | 7 | 58.3% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-DAEMON-002]** information_exposure (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:228` @ `get_message` | 置信度: 70
2. **[DF-003]** config_injection (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:150` @ `handleSetKinetOnDemandRequest` | 置信度: 65
3. **[DF-XM-001]** config_injection_cross_boundary (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:150` @ `handleSetKinetOnDemandRequest` | 置信度: 65
4. **[VULN-SEC-DAEMON-005]** resource_exhaustion (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:303` @ `loop` | 置信度: 50
5. **[DF-XM-002]** path_traversal_cross_boundary (Medium) - `plugin/bindings.cpp:122` @ `enable_dyno_npu_monitor` | 置信度: 45
6. **[VULN-SEC-BIND-002]** Improper Input Validation (Low) - `plugin/bindings.cpp:128` @ `set_cluster_config_data` | 置信度: 65
7. **[VULN-SEC-IPC-002]** Acceptance of Extraneous Untrusted Data (Low) - `plugin/ipc_monitor/NpuIpcClient.cpp:27` @ `RegisterInstance` | 置信度: 60
8. **[VULN-SEC-DAEMON-003]** information_exposure (Low) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:169` @ `accept` | 置信度: 55
9. **[VULN-SEC-BIND-003]** Improper Input Validation (Low) - `plugin/bindings.cpp:131` @ `update_profiler_status` | 置信度: 55
10. **[DF-001]** json_parser (Low) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:70` @ `toJson` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `initSocket@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | TCP socket绑定到IPv6任意地址(in6addr_any)，监听指定端口(默认1778)，远程客户端可通过dyno CLI连接发送RPC请求，攻击者可触达 | TCP RPC服务入口，接收JSON格式的RPC请求 |
| `accept@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | 接受TCP连接，客户端可来自任何网络位置 | 接受TCP连接 |
| `get_message@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | 通过recv()或SSL_read()读取客户端发送的消息，消息内容完全由客户端控制 | 读取RPC请求消息 |
| `processOneImpl@dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h` | rpc | untrusted_network | 处理RPC请求，解析JSON并执行getStatus、setKinetOnDemandRequest等操作，输入来自网络 | 处理RPC请求，解析并执行命令 |
| `ipc_manager_->recv@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 通过Unix Domain Socket接收IPC消息，本地进程需有权限连接到socket文件 | IPC消息接收入口 |
| `data_ipc_manager_->recv@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 通过Unix Domain Socket接收数据消息，本地进程需有权限连接 | IPC数据消息接收入口 |
| `processMsg@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 处理IPC消息，解析消息类型并执行对应操作，输入来自本地进程 | 处理IPC消息 |
| `processDataMsg@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 处理IPC数据消息，解析JSON格式数据并记录，输入来自本地进程 | 处理IPC数据消息，包含性能数据 |
| `main@dynolog_npu/dynolog/src/Main.cpp` | cmdline | untrusted_local | 命令行参数由本地用户传入，启动daemon时可通过gflags配置端口、证书目录等 | 程序入口，解析命令行参数 |
| `run@dynolog_npu/dynolog/src/ThreadManager.cpp` | cmdline | untrusted_local | 解析命令行参数(gflags)，设置端口、启用IPC监控等配置 | 线程管理器运行，解析命令行参数 |
| `Init@plugin/ipc_monitor/NpuIpcClient.cpp` | rpc | semi_trusted | IPC客户端初始化，通过Unix Domain Socket与dynolog daemon通信 | IPC客户端初始化 |
| `IpcClientNpuConfig@plugin/ipc_monitor/NpuIpcClient.cpp` | rpc | semi_trusted | 向dynolog发送配置请求并接收响应，通过IPC | IPC配置请求 |

**其他攻击面**:
- TCP RPC服务: 端口1778（可配置），接收JSON格式RPC请求
- SSL/TLS加密通道: 支持证书验证，可选NO_CERTS模式
- Unix Domain Socket IPC: 抽象socket路径'dynolog'和'dynolog_data'
- JSON解析: RPC和IPC消息均使用JSON格式
- 配置参数: 命令行参数控制端口、证书目录、监控功能启用等
- Python C扩展: bindings.cpp暴露的Python接口

---

## 3. Medium 漏洞 (5)

### [VULN-SEC-DAEMON-002] information_exposure - get_message

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:228-230` @ `get_message`
**模块**: dynolog_daemon

**描述**: 部分接收的消息内容被记录到错误日志，可能泄露敏感数据片段。虽然仅在接收失败时触发，但仍可能泄露部分请求内容。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:228-230`)

```c
LOG(ERROR) << "Received partial message, expected size " << msg_size << " found : " << recv; LOG(ERROR) << "Message received = " << message;
```

**达成路径**

recv/SSL_read [SOURCE] → message → LOG(ERROR) [SINK]

**验证说明**: 部分接收的消息内容被记录到错误日志(LOG(ERROR) << "Message received = " << message)。仅在接收失败时触发，但仍可能泄露部分请求内容。攻击者可通过构造部分消息触发此错误路径。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: = | 38: 3 | 39: 0 | 40: , | 41:   | 42: c | 43: o | 44: n | 45: t | 46: r | 47: o | 48: l | 49: l | 50: a | 51: b | 52: i | 53: l | 54: i | 55: t | 56: y | 57: = | 58: p | 59: a | 60: r | 61: t | 62: i | 63: a | 64: l | 65: = | 66: 1 | 67: 5 | 68: , | 69:   | 70: m | 71: i | 72: t | 73: i | 74: g | 75: a | 76: t | 77: i | 78: o | 79: n | 80: s | 81: = | 82: - | 83: 5 | 84: ( | 85: 仅 | 86: 在 | 87: 错 | 88: 误 | 89: 时 | 90: 触 | 91: 发 | 92: ) | 93: , | 94:   | 95: t | 96: o | 97: t | 98: a | 99: l | 100: = | 101: 7 | 102: 0

---

### [DF-003] config_injection - handleSetKinetOnDemandRequest

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-74 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:150-157` @ `handleSetKinetOnDemandRequest`
**模块**: dynolog_daemon
**跨模块**: dynolog_daemon → ipc_monitor

**描述**: 来自网络的config字符串直接传递给setKinetOnDemandRequest处理函数。config字段在RPC请求中被解析并传递给handler_->setKinetOnDemandRequest，如果libkineto内部对config的处理存在不当（如文件路径操作、命令执行），可能导致配置注入风险。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:150-157`)

```c
std::string config = request.value("config", "");
...
auto result = handler_->setKinetOnDemandRequest(job_id, pids_set, config, process_limit);
```

**达成路径**

::recv() → get_message() → processOne() → processOneImpl() → handleSetKinetOnDemandRequest() → handler_->setKinetOnDemandRequest()

**验证说明**: config字符串从RPC请求传递到LibkinetoConfigManager::setOnDemandConfig，用于profiler配置而非命令执行。config存储到process.eventProfilerConfig/activityProfilerConfig。虽然不是直接命令注入，但config可用于影响profiler行为，需要验证者关注实际影响。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: = | 38: 3 | 39: 0 | 40: , | 41:   | 42: c | 43: o | 44: n | 45: t | 46: r | 47: o | 48: l | 49: l | 50: a | 51: b | 52: i | 53: l | 54: i | 55: t | 56: y | 57: = | 58: p | 59: a | 60: r | 61: t | 62: i | 63: a | 64: l | 65: = | 66: 1 | 67: 5 | 68: , | 69:   | 70: m | 71: i | 72: t | 73: i | 74: g | 75: a | 76: t | 77: i | 78: o | 79: n | 80: s | 81: = | 82: - | 83: 1 | 84: 0 | 85: ( | 86: c | 87: o | 88: n | 89: f | 90: i | 91: g | 92: 用 | 93: 途 | 94: 受 | 95: 限 | 96: ) | 97: , | 98:   | 99: c | 100: r | 101: o | 102: s | 103: s | 104: _ | 105: f | 106: i | 107: l | 108: e | 109: = | 110: c | 111: h | 112: a | 113: i | 114: n | 115: _ | 116: c | 117: o | 118: m | 119: p | 120: l | 121: e | 122: t | 123: e | 124: = | 125: 0 | 126: , | 127:   | 128: c | 129: o | 130: n | 131: t | 132: e | 133: x | 134: t | 135: = | 136: e | 137: x | 138: t | 139: e | 140: r | 141: n | 142: a | 143: l | 144: _ | 145: a | 146: p | 147: i | 148: = | 149: 0 | 150: , | 151:   | 152: t | 153: o | 154: t | 155: a | 156: l | 157: = | 158: 6 | 159: 5

---

### [DF-XM-001] config_injection_cross_boundary - handleSetKinetOnDemandRequest

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-74 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:150-157` @ `handleSetKinetOnDemandRequest`
**模块**: cross_module
**跨模块**: dynolog_daemon → ipc_monitor

**描述**: 跨模块配置注入风险：网络RPC请求的config字段通过dynolog_daemon处理后，最终影响ipc_monitor模块的行为。数据流路径：[dynolog_daemon] recv() → processOne() → handleSetKinetOnDemandRequest() → setKinetOnDemandRequest() → LibkinetoConfigManager → IPC同步发送 → [ipc_monitor] IPC接收 → DynoLogNpuMonitor::Poll() → EnableMsptiMonitor() → cmd.savePath → CheckAndSetSavePath()。恶意config可能导致ipc_monitor在任意目录创建文件。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:150-157`)

```c
std::string config = request.value("config", "");
...
auto result = handler_->setKinetOnDemandRequest(job_id, pids_set, config, process_limit);
```

**达成路径**

[dynolog_daemon] ::recv() → get_message() → processOne() → processOneImpl() → handleSetKinetOnDemandRequest() → config → LibkinetoConfigManager → IPC → [ipc_monitor] Poll() → EnableMsptiMonitor() → cmd.savePath → CheckAndSetSavePath() → savePath_

**验证说明**: 数据流完整验证:网络RPC请求的config字段通过完整的调用链传递到ipc_monitor模块。发现部分安全措施:InputParser验证路径长度,PathUtils::DirPathCheck检查软链接和目录有效性,PathUtils::RealPath解析真实路径。但CreateDir缺乏路径范围限制,攻击者可在权限允许的任意目录创建监控数据存储目录。影响有限:攻击者无法控制写入文件内容,只能影响存储位置。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: = | 21: 3 | 22: 0 | 23: ( | 24: d | 25: i | 26: r | 27: e | 28: c | 29: t | 30: _ | 31: e | 32: x | 33: t | 34: e | 35: r | 36: n | 37: a | 38: l | 39: ) | 40: , | 41: c | 42: o | 43: n | 44: t | 45: r | 46: o | 47: l | 48: l | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: = | 57: 1 | 58: 5 | 59: ( | 60: p | 61: a | 62: r | 63: t | 64: i | 65: a | 66: l | 67: - | 68: 仅 | 69: 控 | 70: 制 | 71: 目 | 72: 录 | 73: 位 | 74: 置 | 75: ) | 76: , | 77: m | 78: i | 79: t | 80: i | 81: g | 82: a | 83: t | 84: i | 85: o | 86: n | 87: s | 88: = | 89: - | 90: 2 | 91: 5 | 92: ( | 93: b | 94: o | 95: u | 96: n | 97: d | 98: s | 99: _ | 100: c | 101: h | 102: e | 103: c | 104: k | 105: = | 106: - | 107: 1 | 108: 0 | 109: , | 110: i | 111: n | 112: p | 113: u | 114: t | 115: _ | 116: v | 117: a | 118: l | 119: i | 120: d | 121: a | 122: t | 123: i | 124: o | 125: n | 126: = | 127: - | 128: 1 | 129: 5 | 130: ) | 131: , | 132: c | 133: r | 134: o | 135: s | 136: s | 137: _ | 138: f | 139: i | 140: l | 141: e | 142: = | 143: 0 | 144: ( | 145: c | 146: h | 147: a | 148: i | 149: n | 150: _ | 151: c | 152: o | 153: m | 154: p | 155: l | 156: e | 157: t | 158: e | 159: )

---

### [VULN-SEC-DAEMON-005] resource_exhaustion - loop

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:303-311` @ `loop`
**模块**: dynolog_daemon

**描述**: RPC端点缺少速率限制机制。攻击者可通过频繁连接请求消耗服务器资源，导致拒绝服务。虽有3秒超时，但无连接频率限制。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:303-311`)

```c
while (run_) { processOne(); }
```

**达成路径**

TCP RPC endpoint [SOURCE: untrusted_network] → loop() → processOne() → accept/get_message [SINK: resource consumption]

**验证说明**: RPC端点缺少速率限制机制。while(run_){processOne();}循环无连接频率限制。虽有CLIENT_QUEUE_LEN=50队列限制和3秒超时，但攻击者仍可通过频繁连接请求消耗服务器资源。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: = | 38: 3 | 39: 0 | 40: , | 41:   | 42: c | 43: o | 44: n | 45: t | 46: r | 47: o | 48: l | 49: l | 50: a | 51: b | 52: i | 53: l | 54: i | 55: t | 56: y | 57: = | 58: p | 59: a | 60: r | 61: t | 62: i | 63: a | 64: l | 65: = | 66: 1 | 67: 5 | 68: , | 69:   | 70: m | 71: i | 72: t | 73: i | 74: g | 75: a | 76: t | 77: i | 78: o | 79: n | 80: s | 81: = | 82: - | 83: 2 | 84: 5 | 85: ( | 86: b | 87: o | 88: u | 89: n | 90: d | 91: s | 92: _ | 93: c | 94: h | 95: e | 96: c | 97: k | 98: = | 99: - | 100: 1 | 101: 5 | 102: , | 103: n | 104: u | 105: l | 106: l | 107: _ | 108: c | 109: h | 110: e | 111: c | 112: k | 113: = | 114: - | 115: 1 | 116: 0 | 117: ) | 118: , | 119:   | 120: t | 121: o | 122: t | 123: a | 124: l | 125: = | 126: 5 | 127: 0

---

### [DF-XM-002] path_traversal_cross_boundary - enable_dyno_npu_monitor

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `plugin/bindings.cpp:122-124` @ `enable_dyno_npu_monitor`
**模块**: cross_module
**跨模块**: IPCMonitor_python → bindings → ipc_monitor

**描述**: 跨语言边界的路径遍历风险：Python用户通过IPCMonitor_python模块传入的config_map，通过Python C扩展(bindings.cpp)传递到ipc_monitor模块，最终用于文件路径操作。数据流路径：[Python] config_map → enable_dyno_npu_monitor() → [C++] PyDynamicMonitorProxy::EnableMsptiMonitor() → DynoLogNpuMonitor::EnableMsptiMonitor() → DynoLogGetOpts() → cmd.savePath → CheckAndSetSavePath()。缺少跨语言边界的数据验证。

**漏洞代码** (`plugin/bindings.cpp:122-124`)

```c
m.def("enable_dyno_npu_monitor", [](std::unordered_map<std::string, std::string>& config_map) -> void {
    dynolog_npu::ipc_monitor::PyDynamicMonitorProxy::GetInstance()->EnableMsptiMonitor(config_map);
}, py::arg("config_map"));
```

**达成路径**

[Python] config_map(user input) → IPCMonitor_C.enable_dyno_npu_monitor() → [C++] PyDynamicMonitorProxy::EnableMsptiMonitor() → DynoLogNpuMonitor::EnableMsptiMonitor() → DynoLogGetOpts() → cmd.savePath → MsptiMonitor::CheckAndSetSavePath() → savePath_

**验证说明**: 数据流验证:Python用户通过IPCMonitor_python模块传入config_map,经由Python C扩展(bindings.cpp)传递到ipc_monitor模块。发现与DF-XM-001相同的安全措施(InputParser验证,PathUtils路径检查)。但Python API入口点通常由可信用户调用,攻击者需要获得Python代码执行权限。风险较低:配置注入影响有限,且有多层验证。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: = | 21: 2 | 22: 0 | 23: ( | 24: i | 25: n | 26: d | 27: i | 28: r | 29: e | 30: c | 31: t | 32: _ | 33: e | 34: x | 35: t | 36: e | 37: r | 38: n | 39: a | 40: l | 41: - | 42: P | 43: y | 44: t | 45: h | 46: o | 47: n | 48:   | 49: A | 50: P | 51: I | 52: ) | 53: , | 54: c | 55: o | 56: n | 57: t | 58: r | 59: o | 60: l | 61: l | 62: a | 63: b | 64: i | 65: l | 66: i | 67: t | 68: y | 69: = | 70: 1 | 71: 5 | 72: ( | 73: p | 74: a | 75: r | 76: t | 77: i | 78: a | 79: l | 80: ) | 81: , | 82: m | 83: i | 84: t | 85: i | 86: g | 87: a | 88: t | 89: i | 90: o | 91: n | 92: s | 93: = | 94: - | 95: 2 | 96: 5 | 97: ( | 98: b | 99: o | 100: u | 101: n | 102: d | 103: s | 104: _ | 105: c | 106: h | 107: e | 108: c | 109: k | 110: = | 111: - | 112: 1 | 113: 0 | 114: , | 115: i | 116: n | 117: p | 118: u | 119: t | 120: _ | 121: v | 122: a | 123: l | 124: i | 125: d | 126: a | 127: t | 128: i | 129: o | 130: n | 131: = | 132: - | 133: 1 | 134: 5 | 135: ) | 136: , | 137: c | 138: r | 139: o | 140: s | 141: s | 142: _ | 143: f | 144: i | 145: l | 146: e | 147: = | 148: 0 | 149: ( | 150: c | 151: h | 152: a | 153: i | 154: n | 155: _ | 156: c | 157: o | 158: m | 159: p | 160: l | 161: e | 162: t | 163: e | 164: )

---

## 4. Low 漏洞 (7)

### [VULN-SEC-BIND-002] Improper Input Validation - set_cluster_config_data

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `plugin/bindings.cpp:128-130` @ `set_cluster_config_data`
**模块**: bindings
**跨模块**: bindings → ipc_monitor

**描述**: cluster_config data lacks validation. Python binding set_cluster_config_data accepts arbitrary key-value map without schema validation. Malformed configuration could lead to incorrect cluster settings or injection of invalid configuration parameters.

**漏洞代码** (`plugin/bindings.cpp:128-130`)

```c
m.def("set_cluster_config_data", [](const std::unordered_map<std::string, std::string>& cluster_config) -> void { dynolog_npu::ipc_monitor::MsptiMonitor::GetInstance()->SetClusterConfigData(cluster_config); }, py::arg("cluster_config"));
```

**达成路径**

Python caller → bindings.cpp:set_cluster_config_data(cluster_config) → MsptiMonitor.h:SetClusterConfigData [line 54-57: clusterConfigData_ = configData] [direct assignment without validation]

**验证说明**: Data flow confirmed: Python -> bindings.cpp -> MsptiMonitor.SetClusterConfigData. No schema validation at binding layer. However, downstream mitigations exist: (1) Parameterized SQL queries prevent SQL injection in DBProcessManager.cpp (sqlite3_bind_text used). (2) JSON output in JsonlProcessManager is safe. Impact limited to metadata storage quality, not security-critical.

**评分明细**: base_score: 30 | reachability: [object Object] | controllability: [object Object] | mitigations: [object Object] | context: [object Object] | cross_file: [object Object]

---

### [VULN-SEC-IPC-002] Acceptance of Extraneous Untrusted Data - RegisterInstance

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-349 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `plugin/ipc_monitor/NpuIpcClient.cpp:27-46` @ `RegisterInstance`
**模块**: ipc_monitor
**跨模块**: ipc_monitor → dynolog_daemon

**描述**: IPC client transmits self-reported process identifiers (PID, ancestor PIDs, jobId) to dynolog daemon without cryptographic binding or server-side verification. The NpuContext struct and NpuRequest message contain PID fields that could be spoofed by a malicious client, potentially leading to unauthorized monitoring or incorrect data attribution.

**漏洞代码** (`plugin/ipc_monitor/NpuIpcClient.cpp:27-46`)

```c
NpuContext context{ .npu = npu, .pid = getpid(), .jobId = JOB_ID, };
```

**达成路径**

[CREDENTIAL_FLOW] IpcClient::RegisterInstance -> Message::ConstructMessage -> SyncSendMessage -> dynolog daemon receives PID without verification

**验证说明**: PID spoofing in IPC communication. Client self-reports PID via getpid() which is system call - not spoofable. jobId and npu are configurable. PID used for monitoring/tracking, not security decisions. Low exploitability - attacker needs local IPC access. Design consideration rather than exploitable vulnerability.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: 2 | 23: 0 | 24: ( | 25: i | 26: n | 27: d | 28: i | 29: r | 30: e | 31: c | 32: t | 33: _ | 34: e | 35: x | 36: t | 37: e | 38: r | 39: n | 40: a | 41: l | 42: ) | 43: , | 44:   | 45: c | 46: o | 47: n | 48: t | 49: r | 50: o | 51: l | 52: l | 53: a | 54: b | 55: i | 56: l | 57: i | 58: t | 59: y | 60: = | 61: 1 | 62: 0 | 63: ( | 64: l | 65: e | 66: n | 67: g | 68: t | 69: h | 70: _ | 71: o | 72: n | 73: l | 74: y | 75: ) | 76: , | 77:   | 78: m | 79: i | 80: t | 81: i | 82: g | 83: a | 84: t | 85: i | 86: o | 87: n | 88: s | 89: = | 90: 0 | 91: , | 92:   | 93: c | 94: o | 95: n | 96: t | 97: e | 98: x | 99: t | 100: = | 101: 0

---

### [VULN-SEC-DAEMON-003] information_exposure - accept

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:169` @ `accept`
**模块**: dynolog_daemon

**描述**: 客户端IP地址被记录到日志文件，可能用于攻击者信息收集或隐私泄露。虽然IP本身不敏感，但在某些合规场景下需要关注。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:169`)

```c
LOG(INFO) << "Received connection from " << client_addr_str.data();
```

**达成路径**

accept() [SOURCE] → client_addr → inet_ntop → LOG(INFO) [SINK]

**验证说明**: 客户端IP地址被记录到日志(LOG(INFO) << "Received connection from " << client_addr_str.data())。IP地址本身不是敏感信息，但在某些合规场景下需要关注日志文件权限。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: = | 38: 3 | 39: 0 | 40: , | 41:   | 42: c | 43: o | 44: n | 45: t | 46: r | 47: o | 48: l | 49: l | 50: a | 51: b | 52: i | 53: l | 54: i | 55: t | 56: y | 57: = | 58: l | 59: e | 60: n | 61: g | 62: t | 63: h | 64: _ | 65: o | 66: n | 67: l | 68: y | 69: = | 70: 1 | 71: 0 | 72: , | 73:   | 74: m | 75: i | 76: t | 77: i | 78: g | 79: a | 80: t | 81: i | 82: o | 83: n | 84: s | 85: = | 86: - | 87: 5 | 88: ( | 89: I | 90: P | 91: 非 | 92: 敏 | 93: 感 | 94: ) | 95: , | 96:   | 97: t | 98: o | 99: t | 100: a | 101: l | 102: = | 103: 5 | 104: 5

---

### [VULN-SEC-BIND-003] Improper Input Validation - update_profiler_status

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `plugin/bindings.cpp:131-133` @ `update_profiler_status`
**模块**: bindings
**跨模块**: bindings → ipc_monitor

**描述**: profiler_status values lack range validation. Although type conversion is validated via Str2Int32, status values can be arbitrary integers beyond valid PROFILER_STATUS enum range (-1 to 2). Invalid status values may cause unexpected state transitions.

**漏洞代码** (`plugin/bindings.cpp:131-133`)

```c
m.def("update_profiler_status", [](std::unordered_map<std::string, std::string>& status) -> void { dynolog_npu::ipc_monitor::PyDynamicMonitorProxy::GetInstance()->UpdateProfilerStatus(status); }, py::arg("status"));
```

**达成路径**

Python caller → bindings.cpp:update_profiler_status(status) → PyDynamicMonitorProxy.h:UpdateProfilerStatus [line 88-101] → GetInt32FromMap [line 33-47: Str2Int32 validation but no range check] → NpuStatus.status assignment [line 91]

**验证说明**: Data flow confirmed: Python -> bindings.cpp -> PyDynamicMonitorProxy.UpdateProfilerStatus. GetInt32FromMap performs type conversion via Str2Int32 but no range validation against PROFILER_STATUS enum (-1 to 2). Invalid values (e.g., 999) would be passed through to IPC. Impact limited to state management in profiler, not security-critical operation.

**评分明细**: base_score: 30 | reachability: [object Object] | controllability: [object Object] | mitigations: [object Object] | context: [object Object] | cross_file: [object Object]

---

### [DF-001] json_parser - toJson

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-502 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:70-71` @ `toJson`
**模块**: dynolog_daemon

**描述**: 网络RPC入点的JSON解析可能被恶意输入利用导致资源消耗。虽然代码有CheckJsonDepth深度限制(MAX_DEPTH=10)和MAX_MESSAGE_LEN(8192)消息长度限制，但nlohmann::json::parse在处理恶意构造的JSON时仍可能导致内存消耗或解析异常。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:70-71`)

```c
result = json::parse(message);
```

**达成路径**

::recv() → read_helper() → get_message() → processOne() → processOneImpl() → toJson() → json::parse()

**验证说明**: JSON解析存在多重缓解措施(MAX_MESSAGE_LEN=8192, CheckJsonDepth MAX_DEPTH=10, json::accept预验证)，但nlohmann::json::parse对特殊构造JSON仍有潜在风险。数据流完整: recv→get_message→processOne→toJson→json::parse。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: = | 38: 3 | 39: 0 | 40: , | 41:   | 42: c | 43: o | 44: n | 45: t | 46: r | 47: o | 48: l | 49: l | 50: a | 51: b | 52: i | 53: l | 54: i | 55: t | 56: y | 57: = | 58: f | 59: u | 60: l | 61: l | 62: = | 63: 2 | 64: 5 | 65: , | 66:   | 67: m | 68: i | 69: t | 70: i | 71: g | 72: a | 73: t | 74: i | 75: o | 76: n | 77: s | 78: = | 79: - | 80: 3 | 81: 5 | 82: ( | 83: b | 84: o | 85: u | 86: n | 87: d | 88: s | 89: _ | 90: c | 91: h | 92: e | 93: c | 94: k | 95: = | 96: - | 97: 1 | 98: 5 | 99: , | 100: i | 101: n | 102: p | 103: u | 104: t | 105: _ | 106: v | 107: a | 108: l | 109: i | 110: d | 111: a | 112: t | 113: i | 114: o | 115: n | 116: = | 117: - | 118: 2 | 119: 0 | 120: ) | 121: , | 122:   | 123: c | 124: o | 125: n | 126: t | 127: e | 128: x | 129: t | 130: = | 131: e | 132: x | 133: t | 134: e | 135: r | 136: n | 137: a | 138: l | 139: _ | 140: a | 141: p | 142: i | 143: = | 144: 0 | 145: , | 146:   | 147: t | 148: o | 149: t | 150: a | 151: l | 152: = | 153: 5 | 154: 0

---

### [DF-009] information_disclosure - processDataMsg

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-200 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:162` @ `processDataMsg`
**模块**: dynolog_daemon

**描述**: IPC消息处理过程中将消息内容记录到日志。Line 162: LOG(INFO) << "Received data message : " << result; 可能导致来自本地进程的敏感数据泄露到日志文件。

**漏洞代码** (`dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:162`)

```c
LOG(INFO) << "Received data message : " << result;
```

**达成路径**

recvmsg() → processDataMsg() → result(json) → LOG(INFO) → log file

**验证说明**: IPC数据消息被记录到日志(LOG(INFO) << "Received data message : " << result)。虽然IPC来自本地进程(semi_trusted)，但日志可能被其他用户读取。需要评估日志文件权限配置。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: i | 23: n | 24: t | 25: e | 26: r | 27: n | 28: a | 29: l | 30: _ | 31: o | 32: n | 33: l | 34: y | 35: = | 36: 5 | 37: , | 38:   | 39: c | 40: o | 41: n | 42: t | 43: r | 44: o | 45: l | 46: l | 47: a | 48: b | 49: i | 50: l | 51: i | 52: t | 53: y | 54: = | 55: p | 56: a | 57: r | 58: t | 59: i | 60: a | 61: l | 62: = | 63: 1 | 64: 5 | 65: , | 66:   | 67: m | 68: i | 69: t | 70: i | 71: g | 72: a | 73: t | 74: i | 75: o | 76: n | 77: s | 78: = | 79: 0 | 80: , | 81:   | 82: c | 83: o | 84: n | 85: t | 86: e | 87: x | 88: t | 89: = | 90: e | 91: x | 92: t | 93: e | 94: r | 95: n | 96: a | 97: l | 98: _ | 99: a | 100: p | 101: i | 102: = | 103: 0 | 104: , | 105:   | 106: t | 107: o | 108: t | 109: a | 110: l | 111: = | 112: 5 | 113: 0

---

### [DF-004] path_traversal - CheckAndSetSavePath

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `plugin/ipc_monitor/mspti_monitor/MsptiMonitor.cpp:138-156` @ `CheckAndSetSavePath`
**模块**: ipc_monitor
**跨模块**: IPCMonitor_python → ipc_monitor

**描述**: savePath来自配置数据，经过RelativeToAbsPath和DirPathCheck验证，但没有白名单限制。如果恶意用户通过config_map传入恶意路径（如/etc/、/root/），可能导致在敏感目录创建文件。

**漏洞代码** (`plugin/ipc_monitor/mspti_monitor/MsptiMonitor.cpp:138-156`)

```c
std::string absPath = PathUtils::RelativeToAbsPath(path);
if (PathUtils::DirPathCheck(absPath)) {
  std::string realPath = PathUtils::RealPath(absPath);
  if (PathUtils::CreateDir(realPath)) {
    savePath_ = realPath;
...
```

**达成路径**

config_map(Python) → enable_dyno_npu_monitor → EnableMsptiMonitor → DynoLogGetOpts → cmd.savePath → CheckAndSetSavePath → savePath_

**验证说明**: Path validation exists (DirPathCheck, RealPath, IsSoftLink checks) but no whitelist restriction. External input via dynolog daemon IPC (indirect). Config from CLI/admin - not direct user input. RealPath resolves traversal sequences. Mitigations reduce classic path traversal risk, but arbitrary directory write remains possible.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: 2 | 23: 0 | 24: ( | 25: i | 26: n | 27: d | 28: i | 29: r | 30: e | 31: c | 32: t | 33: _ | 34: e | 35: x | 36: t | 37: e | 38: r | 39: n | 40: a | 41: l | 42: ) | 43: , | 44:   | 45: c | 46: o | 47: n | 48: t | 49: r | 50: o | 51: l | 52: l | 53: a | 54: b | 55: i | 56: l | 57: i | 58: t | 59: y | 60: = | 61: 1 | 62: 5 | 63: ( | 64: p | 65: a | 66: r | 67: t | 68: i | 69: a | 70: l | 71: ) | 72: , | 73:   | 74: m | 75: i | 76: t | 77: i | 78: g | 79: a | 80: t | 81: i | 82: o | 83: n | 84: s | 85: = | 86: - | 87: 1 | 88: 5 | 89: ( | 90: b | 91: o | 92: u | 93: n | 94: d | 95: s | 96: _ | 97: c | 98: h | 99: e | 100: c | 101: k | 102: ) | 103: - | 104: 1 | 105: 0 | 106: ( | 107: n | 108: u | 109: l | 110: l | 111: _ | 112: c | 113: h | 114: e | 115: c | 116: k | 117: )

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bindings | 0 | 0 | 0 | 2 | 2 |
| cross_module | 0 | 0 | 2 | 0 | 2 |
| dynolog_daemon | 0 | 0 | 3 | 3 | 6 |
| ipc_monitor | 0 | 0 | 0 | 2 | 2 |
| **合计** | **0** | **0** | **5** | **7** | **12** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-74 | 2 | 16.7% |
| CWE-22 | 2 | 16.7% |
| CWE-200 | 2 | 16.7% |
| CWE-20 | 2 | 16.7% |
| CWE-532 | 1 | 8.3% |
| CWE-502 | 1 | 8.3% |
| CWE-400 | 1 | 8.3% |
| CWE-349 | 1 | 8.3% |
