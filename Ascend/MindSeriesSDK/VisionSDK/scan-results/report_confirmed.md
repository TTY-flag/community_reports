# 漏洞扫描报告 — 已确认漏洞

**项目**: VisionSDK
**扫描时间**: 2026-04-20T10:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 3 | 50.0% |
| FALSE_POSITIVE | 2 | 33.3% |
| POSSIBLE | 1 | 16.7% |
| **总计** | **6** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `SetUrlProp@mxPlugins/src/module/MxpiRtspSrc/MxpiRtspSrc.cpp` | network | untrusted_network | RTSP URL从配置参数传入，连接远程RTSP服务器拉取视频流，远程服务器数据不可信 | 设置RTSP URL并建立与远程RTSP服务器的连接 |
| `ReadFile@mxPlugins/src/module/MxpiRtspSrc/MxpiRtspSrc.cpp` | file | semi_trusted | TLS证书文件读取，路径由配置传入，需要文件权限检查 | 读取TLS证书/密钥文件 |
| `post_stream_infer@mxStream/samples/streamserver/streamserverSourceCode/create_app.py` | web_route | untrusted_network | Flask HTTP POST接口，接收远程客户端的推理请求，数据完全由客户端控制 | HTTP POST推理接口，接收JSON格式的推理请求 |
| `CreateMultipleStreams@mxStream/src/module/StreamManager/MxStreamManager.cpp` | file | semi_trusted | JSON pipeline配置从字符串或文件解析，配置文件由应用开发者提供 | 从JSON配置创建多个Stream pipeline |
| `CreateMultipleStreamsFromFile@mxStream/src/module/StreamManager/MxStreamManager.cpp` | file | semi_trusted | 从文件读取pipeline配置，文件路径由应用传入 | 从文件创建Stream pipeline |
| `LoadConfiguration@mxBase/src/mxbase/module/Utils/ConfigUtil.cpp` | file | semi_trusted | 加载配置文件或JSON内容，配置由应用开发者提供 | 加载配置文件或JSON配置内容 |
| `Process@mxPlugins/src/module/MxpiVideoDecoder/MxpiVideoDecoder.cpp` | rpc | semi_trusted | 视频解码输入数据来自上游插件（如RTSP），数据流经SDK内部传递 | 处理视频解码请求，输入来自RTSP或其他数据源插件 |
| `Process@mxPlugins/src/module/MxpiImageDecoder/MxpiImageDecoder.cpp` | rpc | semi_trusted | 图像解码输入数据来自上游插件或用户应用，数据流经SDK内部传递 | 处理图像解码请求 |
| `read_json_config@mxStream/samples/streamserver/streamserverSourceCode/utils.py` | file | semi_trusted | 读取JSON配置文件，文件路径由应用传入 | 读取并解析JSON配置文件 |

**其他攻击面**:
- RTSP Network Stream: MxpiRtspSrc插件连接远程RTSP服务器，接收H264/H265视频流
- HTTP RESTful API: StreamServer Flask应用提供/v2/*/infer POST接口
- Pipeline Configuration: JSON格式的pipeline配置文件解析
- TLS Certificate Files: TLS证书/密钥文件读取和解析
- Video/Image Decode Input: 视频解码器和图像解码器处理外部输入数据
- Model Loading: 模型文件加载和推理
- Environment Variables: getenv()调用获取运行环境配置

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
