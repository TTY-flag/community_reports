# 漏洞扫描报告 — 待确认漏洞

**项目**: VMI (Video Streaming Engine for Cloud Phone)
**扫描时间**: 2025-04-21T19:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 11 | 44.0% |
| FALSE_POSITIVE | 8 | 32.0% |
| LIKELY | 6 | 24.0% |
| **总计** | **25** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 4 | 66.7% |
| Low | 2 | 33.3% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MSG-001]** integer_overflow (Critical) - `Common/Communication/MsgFragment/MsgReassemble.cpp:151` @ `MsgReassemble::Reassemble` | 置信度: 70
2. **[VULN-DF-MSG-002]** integer_overflow (Critical) - `Common/Communication/MsgFragment/MsgReassemble.cpp:143` @ `MsgReassemble::ProcessMiddleFragment` | 置信度: 70
3. **[VULN-MSGFRAG-001]** Integer Overflow (Critical) - `Common/Communication/MsgFragment/MsgReassemble.cpp:143` @ `ProcessMiddleFragment, ProcessEndFragment` | 置信度: 70
4. **[VULN-DF-CROSS-001]** buffer_overflow (Critical) - `Common/Communication/MsgFragment/MsgReassemble.cpp:151` @ `cross_module_data_flow_network_to_injection` | 置信度: 70
5. **[VULN-DF-CROSS-003]** buffer_overflow (Low) - `Common/Communication/Heartbeat/Heartbeat.cpp:98` @ `cross_module_data_flow_heartbeat` | 置信度: 70
6. **[VULN-DF-VMIAGENT-002]** memory_leak (Low) - `CloudPhoneService/VmiAgent/VmiAgent.cpp:140` @ `RecvDataRunnable::Run` | 置信度: 45

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `VmiListen@Common/Connection/Connection.cpp` | network | untrusted_network | TCP端口8888监听，接受来自远程Android客户端的连接请求，服务端公网可达 | 监听TCP端口8888，等待远程客户端连接 |
| `VmiAccept@Common/Connection/Connection.cpp` | network | untrusted_network | 接受远程客户端TCP连接，客户端身份未认证（仅有版本校验） | 接受新客户端的TCP连接 |
| `ParseStream@Common/Communication/StreamParse/StreamParser.cpp` | network | untrusted_network | 解析从网络接收的数据流，数据来自远程客户端，内容可被恶意构造 | 解析网络数据流，提取消息头和负载 |
| `ProcessMsg@Common/Communication/StreamParse/StreamParser.cpp` | network | untrusted_network | 处理网络接收的消息，消息内容和序列号来自不可信来源 | 处理网络消息，验证序列号和哈希 |
| `Reassemble@Common/Communication/MsgFragment/MsgReassemble.cpp` | network | untrusted_network | 重组网络分片数据包，分片大小和内容来自远程客户端，可能触发整数溢出或内存越界 | 重组网络消息分片 |
| `ServerConnection::Start@Common/Communication/Connection/ServerConnection.cpp` | network | untrusted_network | 启动TCP端口监听服务，默认端口8888，接受远程客户端连接 | 启动服务端网络监听 |
| `CallbackForRecv@CloudPhoneService/VmiAgent/VmiAgent.cpp` | network | untrusted_network | 处理远程客户端发送的数据（视频/音频/触摸配置），数据内容完全可控 | 服务端接收数据的回调处理 |
| `RecvDataRunnable::Run@CloudPhoneService/VmiAgent/VmiAgent.cpp` | network | untrusted_network | 处理接收到的命令和数据，执行InjectData/SetParam操作，数据来自远程客户端 | 执行接收到的命令（数据注入或参数设置） |
| `ExtractSPS@CloudPhoneClient/VideoDecoder/Control/Parser.cpp` | network | untrusted_network | 解析H264/H265视频流的SPS（Sequence Parameter Set），数据来自远程服务端，可能触发整数溢出 | 解析H264视频流SPS参数 |
| `HandleRecvMsg@Common/Communication/Heartbeat/Heartbeat.cpp` | network | untrusted_network | 处理心跳消息，消息大小和内容来自网络，可能被恶意构造 | 处理心跳请求和响应消息 |
| `RecvPayloadData@Common/Utils/VersionCheck.cpp` | network | untrusted_network | 接收版本校验数据，payloadSize由远程端发送，可能触发缓冲区溢出 | 接收版本校验数据 |
| `ConnectionSocket::Recv@Common/Communication/Connection/ConnectionSocket.cpp` | network | untrusted_network | TCP socket接收数据，数据来自远程端 | 从TCP socket接收数据 |
| `StartVideoModule@CloudPhoneService/VmiAgent/VmiAgent.cpp` | network | untrusted_network | 根据远程客户端发送的配置启动视频模块，分辨率参数来自网络 | 根据客户端配置启动视频模块 |
| `CallbackForRecvStart@CloudPhoneService/VmiAgent/VmiAgent.cpp` | network | untrusted_network | 处理远程客户端的模块启动命令，模块类型和配置来自网络 | 处理客户端的模块启动请求 |
| `RecvData@CloudPhoneClient/VideoDecoder/Control/VideoEngineClient.cpp` | network | untrusted_network | 客户端从网络接收数据包（视频/音频等），数据来自服务端 | 客户端接收网络数据 |

**其他攻击面**:
- TCP端口8888: 服务端监听端口，接受远程客户端连接
- H264/H265视频流解析: Parser.cpp解析视频流SPS参数
- 网络消息重组: MsgReassemble处理分片数据包
- 版本校验协议: VersionCheck处理连接建立时的版本数据交换
- 心跳消息: Heartbeat处理心跳请求/响应
- 触摸事件注入: 触摸数据从客户端发送到服务端Android系统
- 音频数据传输: OPUS/PCM音频数据在网络上传输
- GPS/传感器数据: GPS location和传感器数据从客户端传输到服务端

---

## 3. Critical 漏洞 (4)

### [VULN-DF-MSG-001] integer_overflow - MsgReassemble::Reassemble

**严重性**: Critical | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `Common/Communication/MsgFragment/MsgReassemble.cpp:151-220` @ `MsgReassemble::Reassemble`
**模块**: Communication-MsgFragment

**描述**: 整数溢出导致堆溢出。m_totalSize 是 uint32_t 类型，通过累加网络分片的 payloadSize 得到最终值。如果攻击者发送足够多的分片（每片 payloadSize <= 1404字节），累加过程可能导致 uint32_t 溢出（超过 2^32 后回绕到小值）。最终 malloc(m_totalSize) 会分配错误大小的内存，随后 memcpy 写入数据超过分配大小，导致堆缓冲区溢出。

**漏洞代码** (`Common/Communication/MsgFragment/MsgReassemble.cpp:151-220`)

```c
// ProcessMiddleFragment (Line 151)
m_totalSize += packet.GetPayloadSize();

// ProcessEndFragment (Line 182)
m_totalSize += packet.GetPayloadSize();

// Line 190: malloc with overflowed value
uint8_t *message = reinterpret_cast<uint8_t *>(malloc(m_totalSize));

// Line 210: memcpy writes more than allocated
memcpy(messageData, reinterpret_cast<uint8_t *>(msgHead + 1), msgHead->GetPayloadSize());
```

**达成路径**

网络分片数据包 [SOURCE] -> StreamMsgHead.GetPayloadSize() (来自网络头，uint32_t) -> MsgReassemble::Reassemble() -> ProcessFirstFragment: m_totalSize = payloadSize (初始值，最大1404) -> ProcessMiddleFragment: m_totalSize += payloadSize (累加，无上限检查直到 remainSize 检查，但 remainSize 计算使用 unsigned 可能回绕) -> ProcessEndFragment: m_totalSize += payloadSize (最终累加) -> malloc(m_totalSize) [如果 m_totalSize 溢出回绕到小值，分配过小内存] -> memcpy(messageData, ..., payloadSize) [写入超过分配大小 -> 堆溢出] [SINK]

**验证说明**: 与VULN-MSGFRAG-001相同漏洞的不同描述。MsgReassemble.cpp中m_totalSize累加无溢出检查。ProcessMiddleFragment(Line151)和ProcessEndFragment(Line182)累加payloadSize。当m_totalSize超过MAX_MSG_SIZE时，remainSize的unsigned减法回绕使边界检查失效。最终malloc(m_totalSize)分配错误大小，memcpy导致堆溢出。

**评分明细**: base_score: 30 | reachability: direct_external | controllability: full | mitigations: bounds_check | context: external_api | cross_file: chain_complete | final_score: 70 | components: [object Object]

---

### [VULN-DF-MSG-002] integer_overflow - MsgReassemble::ProcessMiddleFragment

**严重性**: Critical | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `Common/Communication/MsgFragment/MsgReassemble.cpp:143-155` @ `MsgReassemble::ProcessMiddleFragment`
**模块**: Communication-MsgFragment

**描述**: remainSize 计算使用 unsigned 运算可能导致回绕。当 m_totalSize 接近或超过 MAX_MSG_SIZE - sizeof(StreamMsgHead) 时，remainSize = MAX_MSG_SIZE - sizeof(StreamMsgHead) - m_totalSize 会产生 unsigned 回绕，变成一个大的正值。这会导致边界检查失效，允许继续累加 payloadSize。

**漏洞代码** (`Common/Communication/MsgFragment/MsgReassemble.cpp:143-155`)

```c
// Line 143: unsigned subtraction may wrap
uint32_t remainSize = MAX_MSG_SIZE - sizeof(StreamMsgHead) - m_totalSize;

// Line 144: check may pass due to wrap
if (packet.GetPayloadSize() > remainSize) {
    // error handling
}

// Line 151: accumulate without proper bounds
m_totalSize += packet.GetPayloadSize();
```

**达成路径**

网络分片 [SOURCE] -> m_totalSize 累加 -> remainSize = 33554416 - m_totalSize [unsigned 回绕风险] -> 检查失效 -> 继续累加 -> 整数溢出

**验证说明**: remainSize unsigned回绕漏洞确认。Line143: uint32_t remainSize = MAX_MSG_SIZE - sizeof(StreamMsgHead) - m_totalSize。当m_totalSize接近或超过33554416时，unsigned减法回绕产生大正数(约4GB)，使Line144检查失效。这允许继续累加payloadSize，最终导致VULN-DF-MSG-001所述的整数溢出。这是一个独立但相关的漏洞点。

**评分明细**: base_score: 30 | reachability: direct_external | controllability: full | mitigations: bounds_check | context: external_api | cross_file: chain_complete | final_score: 70 | components: [object Object]

---

### [VULN-MSGFRAG-001] Integer Overflow - ProcessMiddleFragment, ProcessEndFragment

**严重性**: Critical | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `Common/Communication/MsgFragment/MsgReassemble.cpp:143-182` @ `ProcessMiddleFragment, ProcessEndFragment`
**模块**: Communication-MsgFragment

**描述**: Integer overflow vulnerability in fragment size accumulation. The m_totalSize variable (uint32_t) is accumulated without overflow checking in ProcessMiddleFragment (line 151) and ProcessEndFragment (line 182). An attacker can craft malicious fragments with large payload sizes that cause integer overflow, leading to undersized memory allocation and subsequent heap buffer overflow in ProcessEndFragment memcpy operation.

**漏洞代码** (`Common/Communication/MsgFragment/MsgReassemble.cpp:143-182`)

```c
uint32_t remainSize = MAX_MSG_SIZE - sizeof(StreamMsgHead) - m_totalSize; // Line 143 - can underflow
if (packet.GetPayloadSize() > remainSize) { ... }
m_totalSize += packet.GetPayloadSize(); // Line 151 - no overflow check
```

**达成路径**

Attacker-controlled fragment payload size -> m_totalSize accumulation -> overflow -> undersized malloc -> heap buffer overflow in memcpy

**验证说明**: 整数溢出漏洞确认存在。m_totalSize(uint32_t)累加无溢出检查。remainSize检查(Line143)使用unsigned运算，当m_totalSize>MAX_MSG_SIZE-sizeof(StreamMsgHead)时unsigned回绕使检查失效。攻击路径:发送足够分片使m_totalSize接近32MB->remainSize回绕->检查失效->继续累加->uint32溢出->malloc分配小内存->memcpy堆溢出。有边界检查但因unsigned回绕可被绕过。

**评分明细**: base_score: 30 | reachability: direct_external | controllability: full | mitigations: bounds_check | context: external_api | cross_file: chain_complete | final_score: 70 | components: [object Object]

---

### [VULN-DF-CROSS-001] buffer_overflow - cross_module_data_flow_network_to_injection

**严重性**: Critical | **CWE**: CWE-122 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `Common/Communication/MsgFragment/MsgReassemble.cpp:151-220` @ `cross_module_data_flow_network_to_injection`
**模块**: cross_module
**跨模块**: Connection → Communication-Connection → Communication-StreamParse → Communication-PacketHandle → Communication-MsgFragment → VmiAgent

**描述**: 跨模块数据流漏洞：网络数据 -> 消息重组 -> 数据注入。攻击者可以通过网络发送精心构造的分片数据包，触发 MsgReassemble 模块的整数溢出，导致 malloc 分配过小内存，随后 memcpy 导致堆溢出。溢出的数据可能进一步被传递到 VmiAgent 的 InjectData 函数，导致触摸事件注入或其他安全问题。数据流跨越 Connection、StreamParse、PacketHandle、MsgFragment、VmiAgent 五个模块。

**漏洞代码** (`Common/Communication/MsgFragment/MsgReassemble.cpp:151-220`)

```c
跨模块数据流路径:

1. Connection.cpp (VmiRecv): 网络数据接收
2. StreamParser.cpp (ParseStream): 流解析
3. PacketHandle.cpp (Handle): 包处理
4. MsgReassemble.cpp (Reassemble): 消息重组 [整数溢出关键点]
   - m_totalSize += packet.GetPayloadSize() (Line 151, 182)
   - malloc(m_totalSize) (Line 190) [如果溢出，分配小内存]
   - memcpy(messageData, ..., payloadSize) (Line 210) [堆溢出]
5. VmiAgent.cpp (CallbackForRecv -> InjectData): 数据注入 [潜在 Sink]
```

**达成路径**

网络 TCP 数据流 [SOURCE] @ Connection.cpp:292 (VmiRecv)
-> ConnectionSocket::Recv() @ ConnectionSocket.cpp:56
-> StreamParseThread::RecvCloudPhoneData() @ StreamParser.cpp:279
-> StreamParse::ParseStream() @ StreamParser.cpp:188
-> StreamParse::ProcessMsg() @ StreamParser.cpp:148
-> PacketHandle::Handle() @ PacketHandle.cpp:28
-> MsgReassemble::Reassemble() @ MsgReassemble.cpp:226 [整数溢出关键点]
  -> ProcessMiddleFragment: m_totalSize += payloadSize [累加]
  -> ProcessEndFragment: malloc(m_totalSize) [分配内存]
  -> memcpy(messageData, ..., payloadSize) [堆溢出 SINK]
-> VmiAgent.cpp:200 (CallbackForRecv)
  -> RecvDataRunnable::Run() @ VmiAgent.cpp:110
  -> InjectData() @ VmiApi.cpp:33 [数据注入 SINK]

**验证说明**: 跨模块数据流漏洞完整确认。攻击路径: 1.Connection.cpp(VmiRecv)网络接收 2.StreamParser.cpp(ParseStream)流解析-有MAX_MSG_SIZE检查 3.PacketHandle.cpp(Handle)包处理-有检查 4.MsgReassemble.cpp(Reassemble)消息重组-整数溢出关键点 5.VmiAgent.cpp(InjectData)数据注入。各模块有边界检查但整数溢出可绕过。最终sink点InjectData无权限验证。

**评分明细**: base_score: 30 | reachability: direct_external | controllability: full | mitigations: bounds_check | context: external_api | cross_file: chain_complete | final_score: 70 | components: [object Object]

---

## 4. Low 漏洞 (2)

### [VULN-DF-CROSS-003] buffer_overflow - cross_module_data_flow_heartbeat

**严重性**: Low | **CWE**: CWE-120 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `Common/Communication/Heartbeat/Heartbeat.cpp:98-126` @ `cross_module_data_flow_heartbeat`
**模块**: cross_module
**跨模块**: Connection → Communication-StreamParse → Communication-MsgFragment → Communication-Heartbeat

**描述**: 跨模块数据流漏洞：网络心跳消息 -> 消息重组 -> 心跳处理。攻击者可以发送恶意构造的心跳消息数据包，经过消息重组后传递到 Heartbeat::HandleRecvMsg 函数。虽然函数中有大小检查，但如果重组后的数据大小超过预期，可能导致 memcpy 写入超出目标缓冲区大小的数据。

**漏洞代码** (`Common/Communication/Heartbeat/Heartbeat.cpp:98-126`)

```c
跨模块数据流路径:

1. Connection.cpp (VmiRecv): 网络数据接收
2. StreamParser.cpp (ParseStream): 流解析
3. MsgReassemble.cpp (Reassemble): 消息重组
4. Heartbeat.cpp (HandleRecvMsg): 心跳处理 [memcpy 关键点]
   - msgData, msgSize 来自重组后的数据
   - destSize = sizeof(loopbackMsg) - sizeof(StreamMsgHead) (Line 107)
   - memcpy(&loopbackMsg + sizeof(StreamMsgHead), msgData, msgSize) (Line 112)
```

**达成路径**

网络心跳数据包 [SOURCE] @ Connection.cpp:292 (VmiRecv)
-> Heartbeat::RecvHeartbeatResponse() @ Heartbeat.cpp:131
-> MsgReassemble::Reassemble() @ MsgReassemble.cpp:226
-> Heartbeat::HandleRecvMsg() @ Heartbeat.cpp:98
  -> msgData, msgSize 来自网络重组数据
  -> destSize = sizeof(loopbackMsg) - sizeof(StreamMsgHead)
  -> memcpy(loopbackMsg + ..., msgData, msgSize) [缓冲区溢出风险 SINK]

**验证说明**: 跨模块调用链完整验证: VmiRecv(Connection.cpp:292) -> Heartbeat::RecvHeartbeatResponse(Heartbeat.cpp:131) -> MsgReassemble::Reassemble(MsgReassemble.cpp:226) -> Heartbeat::HandleRecvMsg(Heartbeat.cpp:98) -> memcpy。关键发现: HandleRecvMsg函数(line 108-111)有明确的安全检查: if(destSize < msgSize) return; 此检查会阻止超过目标缓冲区大小的memcpy操作。漏洞报告的缓冲区溢出风险被此安全检查缓解。降级为Low，状态为LIKELY。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: : | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: : | 29: d | 30: i | 31: r | 32: e | 33: c | 34: t | 35: _ | 36: e | 37: x | 38: t | 39: e | 40: r | 41: n | 42: a | 43: l | 44: ( | 45: + | 46: 3 | 47: 0 | 48: ) | 49:   | 50: + | 51:   | 52: c | 53: o | 54: n | 55: t | 56: r | 57: o | 58: l | 59: l | 60: a | 61: b | 62: i | 63: l | 64: i | 65: t | 66: y | 67: : | 68: f | 69: u | 70: l | 71: l | 72: ( | 73: + | 74: 2 | 75: 5 | 76: ) | 77:   | 78: + | 79:   | 80: c | 81: r | 82: o | 83: s | 84: s | 85: _ | 86: f | 87: i | 88: l | 89: e | 90: : | 91: h | 92: a | 93: s | 94: _ | 95: s | 96: a | 97: f | 98: e | 99: t | 100: y | 101: _ | 102: c | 103: h | 104: e | 105: c | 106: k | 107: ( | 108: - | 109: 1 | 110: 5 | 111: ) | 112:   | 113: = | 114:   | 115: 7 | 116: 0

---

### [VULN-DF-VMIAGENT-002] memory_leak - RecvDataRunnable::Run

**严重性**: Low | **CWE**: CWE-401 | **置信度**: 45/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `CloudPhoneService/VmiAgent/VmiAgent.cpp:140-158` @ `RecvDataRunnable::Run`
**模块**: VmiAgent

**描述**: CMD_GET_PARAM 分支中存在潜在的内存泄漏。当 m_dataType == DATA_VIDEO 且 GetParam 成功后，调用 CallbackForSendVideoConfig 但没有释放 m_data.first。只有在 GetParam 失败时才会释放内存。

**漏洞代码** (`CloudPhoneService/VmiAgent/VmiAgent.cpp:140-158`)

```c
// Line 140-157: CMD_GET_PARAM branch
} else if (cmdTemp.info.cmdType == VmiCmdType::CMD_GET_PARAM) {
    err = GetParam(m_dataType, m_cmd, m_data.first + sizeof(VmiCmd), m_data.second - sizeof(VmiCmd));
    if (err != OK) {
        // ... free on error
    }
    if (m_dataType == VmiDataType::DATA_VIDEO) {
        CallbackForSendVideoConfig(...); // no free here!
    }
} // end of branch - m_data not freed!
```

**达成路径**

网络数据 [SOURCE] -> m_data.first (malloc 分配) -> GetParam 成功 -> CallbackForSendVideoConfig() -> 函数结束 [内存泄漏 SINK]

**验证说明**: 确认存在内存泄漏：CMD_GET_PARAM成功后（line 140-147），当m_dataType==DATA_VIDEO时调用CallbackForSendVideoConfig，但未释放m_data.first。对比其他分支（CMD_TRANS_DATA、CMD_SET_PARAM）成功后均有free。RecvDataRunnable无析构函数自动释放内存。但影响范围有限：仅特定命令类型+视频数据类型条件下发生，属于代码缺陷而非严重安全漏洞。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: : | 11: 3 | 12: 0 | 13: , | 14:   | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: i | 29: n | 30: t | 31: e | 32: r | 33: n | 34: a | 35: l | 36: _ | 37: o | 38: n | 39: l | 40: y | 41: ( | 42: + | 43: 5 | 44: ) | 45: , | 46:   | 47: c | 48: o | 49: n | 50: t | 51: r | 52: o | 53: l | 54: l | 55: a | 56: b | 57: i | 58: l | 59: i | 60: t | 61: y | 62: : | 63: l | 64: e | 65: n | 66: g | 67: t | 68: h | 69: _ | 70: o | 71: n | 72: l | 73: y | 74: ( | 75: + | 76: 1 | 77: 0 | 78: ) | 79: , | 80:   | 81: m | 82: i | 83: t | 84: i | 85: g | 86: a | 87: t | 88: i | 89: o | 90: n | 91: s | 92: : | 93: n | 94: o | 95: n | 96: e | 97: , | 98:   | 99: c | 100: o | 101: n | 102: t | 103: e | 104: x | 105: t | 106: : | 107: n | 108: o | 109: n | 110: e | 111: . | 112:   | 113: T | 114: o | 115: t | 116: a | 117: l | 118: : | 119: 4 | 120: 5 | 121: . | 122:   | 123: 降 | 124: 级 | 125: 为 | 126: L | 127: I | 128: K | 129: E | 130: L | 131: Y | 132: / | 133: L | 134: o | 135: w | 136: ： | 137: 代 | 138: 码 | 139: 缺 | 140: 陷 | 141: 而 | 142: 非 | 143: 安 | 144: 全 | 145: 漏 | 146: 洞

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| Communication-MsgFragment | 3 | 0 | 0 | 0 | 3 |
| VmiAgent | 0 | 0 | 0 | 1 | 1 |
| cross_module | 1 | 0 | 0 | 1 | 2 |
| **合计** | **4** | **0** | **0** | **2** | **6** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 3 | 50.0% |
| CWE-401 | 1 | 16.7% |
| CWE-122 | 1 | 16.7% |
| CWE-120 | 1 | 16.7% |
