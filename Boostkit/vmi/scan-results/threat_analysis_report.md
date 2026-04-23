# 威胁分析报告 - VMI (Video Streaming Engine for Cloud Phone)

> **分析模式：自主分析模式**
> 本次攻击面分析为自主识别，无 `threat.md` 约束文件。

---

## 1. 项目架构概览

### 1.1 项目简介

VMI (Video Streaming Engine) 是华为鲲鹏 BoostKit 的云手机视频流引擎，用于在 ARM 服务器上虚拟化 Android 系统（云手机）。项目采用客户端-服务端架构：

- **服务端 (CloudPhoneService)**：运行在鲲鹏服务器上，提供视频编码、音频采集、触摸注入等功能
- **客户端 (CloudPhoneClient)**：Android APK，运行在用户手机上，提供视频解码、音频播放、触摸捕获等功能

### 1.2 技术栈

- **语言**: 纯 C/C++
- **代码量**: 158 个源文件，约 40,209 行代码
- **网络协议**: 自定义 TCP 协议（消息头 + 负载）
- **视频编码**: H264/H265（支持 GPU 和 CPU 编码）
- **音频编码**: OPUS/PCM

### 1.3 核心模块

| 模块名称 | 路径 | 功能描述 | 语言 |
|---------|------|---------|------|
| VmiAgent | CloudPhoneService/VmiAgent | 服务端主程序，网络监听、连接管理、数据处理 | c_cpp |
| VideoEngine | CloudPhoneService/VideoEngine | GPU/CPU 视频编码引擎 | c_cpp |
| Communication | Common/Communication | 网络通信核心（Socket、Packet、消息分片、心跳） | c_cpp |
| Connection | Common/Connection | 底层 TCP 连接库 | c_cpp |
| VideoDecoder | CloudPhoneClient/VideoDecoder | 客户端视频解码控制 | c_cpp |
| AudioPlay | CloudPhoneClient/AudioPlay | 客户端音频播放 | c_cpp |

---

## 2. 模块风险评估

### 2.1 高风险模块

| 模块 | 风险等级 | 主要风险点 |
|------|----------|-----------|
| Connection | **Critical** | TCP 端口监听、接受远程连接、数据接收 |
| Communication-StreamParse | **Critical** | 网络数据流解析、消息头验证、序列号检查 |
| Communication-MsgFragment | **Critical** | 消息分片重组、内存分配、数据复制 |
| Communication-Connection | **Critical** | 服务端连接接受、版本校验 |
| VmiAgent | **High** | 数据回调处理、模块启动命令、触摸数据注入 |
| VideoDecoder-Control | **High** | H264/H265 视频流解析、SPS 参数提取 |

### 2.2 模块依赖关系

```
[Network] → Connection → ServerConnection → NetworkCommManager → VmiAgent
               ↓
         ConnectionSocket → StreamParse → PacketHandle → MsgReassemble
               ↓
         CallbackForRecv → InjectData/SetParam → VideoEncoder/AudioPlay
```

---

## 3. 攻击面分析

### 3.1 网络攻击面

| 入口点 | 位置 | 风险描述 |
|--------|------|---------|
| **TCP 端口 8888** | Connection.cpp:67 (VmiListen) | 服务端监听公网端口，接受任意客户端连接 |
| **数据流解析** | StreamParser.cpp:188 (ParseStream) | 解析网络数据包，处理消息头和负载 |
| **消息重组** | MsgReassemble.cpp:226 (Reassemble) | 重组分片数据包，存在整数溢出风险 |
| **版本校验** | VersionCheck.cpp:216 (RecvPayloadData) | 接收版本数据，payloadSize 来自网络 |

### 3.2 视频流攻击面

| 入口点 | 位置 | 风险描述 |
|--------|------|---------|
| **H264 SPS 解析** | Parser.cpp:164 (ExtractSPS) | 解析视频流参数，使用指数哥伦布编码解码 |
| **分辨率计算** | Parser.cpp:276 (GetH264Width) | 基于 SPS 参数计算宽高，可能整数溢出 |

### 3.3 数据注入攻击面

| 入口点 | 位置 | 风险描述 |
|--------|------|---------|
| **触摸事件注入** | VmiAgent.cpp:110 (InjectData) | 将网络数据注入 Android 系统 |
| **模块启动命令** | VmiAgent.cpp:475 (CallbackForRecvStart) | 根据网络数据启动/配置各模块 |

---

## 4. STRIDE 威胁建模

### 4.1 Spoofing (欺骗)

| 威胁场景 | 影响 | 缓解措施现状 |
|---------|------|-------------|
| 客户端身份伪造 | 版本校验仅检查版本号字符串，无身份认证 | **弱** - 仅有版本字符串匹配 |

### 4.2 Tampering (篡改)

| 威胁场景 | 影响 | 缓解措施现状 |
|---------|------|-------------|
| 网络数据包篡改 | MurmurHash 校验数据完整性 | **中等** - 有哈希校验但可被绕过 |
| 消息序列号篡改 | 序列号连续性检查 | **中等** - 有序列号验证 |
| 视频流参数篡改 | 客户端解析视频流 SPS | **弱** - 无完整性校验 |

### 4.3 Repudiation (抵赖)

| 威threat场景 | 影响 | 缓解措施现状 |
|---------|------|-------------|
| 无操作日志审计 | 无法追溯攻击行为 | **弱** - 仅有调试日志，无安全审计 |

### 4.4 Information Disclosure (信息泄露)

| 威胁场景 | 影响 | 缓解措施现状 |
|---------|------|-------------|
| 版本信息泄露 | 版本字符串在网络传输 | **低风险** - 版本号非敏感信息 |
| 视频内容截获 | 视频流无加密传输 | **高风险** - TCP 明文传输 |

### 4.5 Denial of Service (拒绝服务)

| 威胁场景 | 影响 | 缓解措施现状 |
|---------|------|-------------|
| 恶意连接耗尽资源 | 最大 backlog = 5 | **中等** - 有连接数限制 |
| 心跳超时断开 | 100 秒心跳间隔，30 次未响应断开 | **中等** - 有心跳检测 |
| 消息分片攻击 | MAX_MSG_SIZE = 32MB 限制 | **中等** - 有大小限制 |

### 4.6 Elevation of Privilege (权限提升)

| 威胁场景 | 影响 | 缓解措施现状 |
|---------|------|-------------|
| 触摸事件注入到 Android | InjectData 将触摸数据注入系统 | **高风险** - 可控制 Android 操作 |

---

## 5. 关键数据流分析

### 5.1 网络数据接收到内存操作的路径

```
[VmiAccept] → [ServerConnection::AcceptNewClient]
    → [ConnectionSocket::Recv] → [StreamParseThread::RecvCloudPhoneData]
    → [StreamParse::ParseStream] → [StreamParse::ProcessMsg]
    → [PacketHandle::Handle] → [MsgReassemble::Reassemble]
    → [malloc + memcpy]
```

**风险点**: `StreamMsgHead::GetPayloadSize()` 从网络获取大小，直接用于 `malloc()`

### 5.2 视频流解析路径

```
[ClientVideoHandleHook] → [PacketManager::PutPkt]
    → [VideoEngineClient::RecvData] → [Parser::ExtractSPS]
    → [Parser::ReadExponentialGolombCode] → [GetH264Width/GetH264Height]
```

**风险点**: SPS 参数解析使用指数哥伦布编码，可能存在整数溢出

### 5.3 触摸数据注入路径

```
[CallbackForRecv] → [RecvDataRunnable::Run]
    → [InjectData(DATA_TOUCH, SEND_TOUCH_EVENT, data)]
    → [Android System Touch Injection]
```

**风险点**: 客户端发送的触摸数据直接注入 Android 系统，无输入验证

---

## 6. 安全加固建议

### 6.1 网络层加固

1. **添加 TLS 加密**: 当前 TCP 明文传输，建议添加 TLS/SSL 加密层
2. **身份认证机制**: 版本校验仅为字符串匹配，建议添加证书/密钥认证
3. **消息大小严格限制**: `RecvPayloadData` 中 payloadSize 限制为 100KB，建议更严格的边界检查

### 6.2 数据解析加固

1. **MsgReassemble 整数溢出检查**: `m_totalSize`累加时应检查溢出
2. **Parser 指数哥伦布编码边界检查**: `ReadExponentialGolombCode` 应限制最大迭代次数
3. **视频分辨率有效性验证**: SPS 解析出的宽高应验证是否在合理范围内

### 6.3 数据注入加固

1. **触摸事件验证**: `InjectData` 前验证触摸数据的坐标范围和有效性
2. **模块启动权限控制**: 限制客户端可启动的模块类型和参数范围
3. **输入数据白名单**: 对网络接收的命令和数据建立白名单验证

### 6.4 运行时安全

1. **添加安全审计日志**: 记录关键操作（连接、断开、数据注入）
2. **速率限制**: 对心跳、数据发送频率进行限制
3. **内存安全检查**: 使用安全的内存操作函数，添加边界检查

---

## 7. 总结

### 7.1 高风险入口点统计

| 类别 | 数量 | 主要风险 |
|------|------|---------|
| Critical 风险 | 6 个 | 网络数据接收、解析、重组 |
| High 风险 | 9 个 | 数据回调处理、视频解析 |
| Medium 风险 | 4 个 | 数据发送、版本校验 |

### 7.2 主要安全缺口

1. **无加密传输**: 视频流、音频流、触摸数据均为明文 TCP 传输
2. **弱身份认证**: 仅版本字符串匹配，无真正的身份验证
3. **潜在整数溢出**: 消息重组、视频流解析存在整数溢出风险
4. **无输入验证**: 触摸数据、模块配置直接来自网络，无有效性检查

---

**报告生成时间**: 2025-04-21
**分析工具**: Architecture Agent (自主分析模式)