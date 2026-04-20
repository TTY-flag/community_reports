# Vision SDK 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析基于代码结构和文档分析，未使用 threat.md 约束文件。

## 项目架构概览

### 项目定位

华为 MindSeries SDK VisionSDK 是一个面向图片和视频视觉分析的 SDK，提供两种使用方式：

1. **API接口方式**：提供原生的推理 API 以及算子加速库
2. **流程编排方式**：将功能单元封装成插件，通过流程编排构建应用

### 项目类型

**SDK/Library（库/SDK）**

作为 SDK 被集成到用户应用中，典型部署在华为昇腾芯片服务器上。攻击面主要取决于 SDK 如何被集成使用。

### 目录结构

```
VisionSDK/
├── mxBase/         # 基础底座（图像处理、模型推理、资源管理）
├── mxStream/       # 流程编排管理（StreamManager、Stream、Packet）
├── mxPlugins/      # 功能插件（RTSP、视频解码、图像解码、模型推理等）
├── mxTools/        # 工具模块（PluginToolkit、PluginInspector）
├── opensource/     # 第三方开源组件（排除扫描）
├── test/           # 测试代码（排除扫描）
└── docs/           # 文档
```

### 语言组成

- C/C++ 源文件：665 个（排除测试和开源）
- Python 源文件：41 个（排除测试和开源）

## 模块风险评估

### 模块风险矩阵

| 模块 | 主要功能 | STRIDE威胁 | 风险等级 | 关键文件 |
|------|----------|------------|----------|----------|
| mxPlugins/MxpiRtspSrc | RTSP网络拉流 | S,T,I,D,E | Critical | MxpiRtspSrc.cpp |
| mxPlugins/MxpiVideoDecoder | 视频解码 | T,I,D | High | MxpiVideoDecoder.cpp |
| mxPlugins/MxpiImageDecoder | 图像解码 | T,I,D | High | MxpiImageDecoder.cpp |
| mxStream/StreamManager | 流程编排管理 | T,D | High | MxStreamManager.cpp |
| StreamServer (Python) | HTTP推理服务 | S,T,I,D | High | create_app.py |
| mxBase/ConfigUtil | 配置解析 | T,D | Medium | ConfigUtil.cpp |
| mxPlugins/MxpiModelInfer | 模型推理 | T,I | Medium | MxpiModelInfer.cpp |
| mxBase/ResourceManager | 资源管理 | D | Medium | GlobalInit.cpp |
| mxTools/PluginToolkit | 插件开发API | - | Low | MxPluginBase.cpp |

## 攻击面分析

### 1. RTSP 网络接口（Critical）

**组件**：mxPlugins/MxpiRtspSrc

**入口点**：
- `SetUrlProp()` - 设置 RTSP URL，建立与远程 RTSP 服务器的连接
- `OnPadAdded()` - RTSP 流连接建立回调，处理 H264/H265 视频流

**威胁场景**：
- 远程 RTSP 服务器可能发送恶意构造的视频流数据
- RTSP URL 可能被伪造或劫持
- TLS 证书验证配置不当可能导致中间人攻击

**数据流**：
```
RTSP URL → g_object_set(rtspsrc, location) → 建立连接 → 
OnPadAdded → rtph264depay/rtph265depay → MxpiVideoDecoder
```

**信任等级**：untrusted_network

### 2. TLS 证书文件处理（High）

**组件**：mxPlugins/MxpiRtspSrc

**入口点**：
- `ReadFile()` - 读取 TLS 证书/密钥文件
- `SetTlsRelatedProps()` - 设置 TLS 相关属性

**威胁场景**：
- 证书文件路径可能被操控（路径遍历）
- 证书内容可能被篡改
- 私钥文件权限不当可能导致泄露

**安全措施**：
- 已有路径规范化检查：`FileUtils::RegularFilePath()`
- 已有文件权限检查：`ConstrainPermission(pathList[i], FILE_MODE, true)`
- 已有密码强度检查：`CheckToken()`

### 3. HTTP RESTful API（High）

**组件**：mxStream/samples/streamserver (Python Flask)

**入口点**：
- `/v2/<infer_type>/<name>/infer` POST 接口

**威胁场景**：
- HTTP 请求注入恶意数据
- 请求体过大导致资源耗尽
- 请求速率过高导致拒绝服务
- JSON 解析错误导致异常

**安全措施**：
- 已有请求体大小限制：`MAX_CONTENT_LENGTH`
- 已有请求速率限制：`request_rate_limit` 装饰器
- 已有 IP 地址字符检查：`INVALID_CHARS` 过滤
- 已有输入字段验证：`_extract_input_json()`

### 4. Pipeline 配置解析（High）

**组件**：mxStream/StreamManager

**入口点**：
- `CreateMultipleStreams()` - 解析 JSON pipeline 配置
- `CreateMultipleStreamsFromFile()` - 从文件读取配置

**威胁场景**：
- JSON 配置注入恶意参数
- 配置文件路径遍历
- 配置参数导致资源耗尽

**安全措施**：
- 已有 JSON 大小限制：`MAX_PIPELINE_STRING` (10MB)
- 已有 pipeline 数量限制：`MAX_PIPELINE_SIZE` (256)
- 已有无效字符检查：`StringUtils::HasInvalidChar()`
- 已有路径规范化：`FileUtils::RegularFilePath()`

### 5. 视频/图像解码（High）

**组件**：mxPlugins/MxpiVideoDecoder, MxpiImageDecoder

**入口点**：
- `Process()` - 处理解码请求

**威胁场景**：
- 恶意构造的视频/图像数据导致解码器崩溃
- 超大视频帧导致内存耗尽
- 解码器漏洞利用

**安全措施**：
- 已有宽高范围检查：`MIN_VDEC_WIDTH/MAX_VDEC_WIDTH`
- 已有内存大小检查：`MemoryHelper::CheckDataSize()`

### 6. 配置文件解析（Medium）

**组件**：mxBase/ConfigUtil

**入口点**：
- `LoadConfiguration()` - 加载配置文件
- `InitJson()` - 解析 JSON 配置

**威胁场景**：
- 配置文件路径遍历
- JSON 注入攻击
- 配置参数篡改

**安全措施**：
- 已有路径规范化：`FileUtils::RegularFilePath()`
- 已有文件大小限制：`MAX_FILE_SIZE` (100MB)
- 已有行数限制：`MAX_FILE_LINES` (100000)
- 已有无效字符检查：`StringUtils::HasInvalidChar()`

## STRIDE 威胁建模

### Spoofing（欺骗）

| 威胁 | 影响组件 | 描述 | 风险 |
|------|----------|------|------|
| RTSP 服务器伪造 | MxpiRtspSrc | 连接到伪造的 RTSP 服务器，接收恶意视频流 | High |
| TLS 证书伪造 | MxpiRtspSrc | TLS 验证配置不当，接受伪造证书 | Medium |

### Tampering（篡改）

| 威胁 | 影响组件 | 描述 | 风险 |
|------|----------|------|------|
| 视频流数据篡改 | MxpiVideoDecoder | RTSP 流数据被篡改，注入恶意数据 | High |
| 配置文件篡改 | ConfigUtil, StreamManager | 配置文件被篡改，修改 pipeline 参数 | Medium |
| 图像数据篡改 | MxpiImageDecoder | 输入图像数据被篡改 | Medium |

### Repudiation（抵赖）

| 威胁 | 彃响组件 | 描述 | 风险 |
|------|----------|------|------|
| 操作日志缺失 | 全局 | 缺少关键操作的审计日志 | Low |

### Information Disclosure（信息泄露）

| 威胁 | 影响组件 | 描述 | 风险 |
|------|----------|------|------|
| TLS 私钥泄露 | MxpiRtspSrc | 私钥文件权限不当，导致泄露 | High |
| 模型信息泄露 | MxpiModelInfer | 模型路径泄露，暴露模型文件 | Medium |
| 配置信息泄露 | StreamManager | Pipeline 配置暴露内部结构 | Medium |

### Denial of Service（拒绝服务）

| 娅胁 | 影响组件 | 描述 | 风险 |
|------|----------|------|------|
| 资源耗尽 | StreamServer, VideoDecoder | 大量请求或超大视频帧耗尽资源 | High |
| Pipeline 过载 | StreamManager | 创建过多 pipeline 耗尽资源 | Medium |
| 解码器崩溃 | MxpiVideoDecoder | 恶意视频数据导致解码器崩溃 | Medium |

### Elevation of Privilege（权限提升）

| 威胁 | 影响组件 | 描述 | 风险 |
|------|----------|------|------|
| 配置注入 | StreamManager | 通过配置注入执行恶意插件 | Medium |
| 路径遍历 | ReadFile, ConfigUtil | 路径遍历访问敏感文件 | Medium |

## 安全加固建议

### 架构层面建议

1. **RTSP 接口加固**
   - 强制 TLS 证书验证，禁用 `tls-validation-flags` 为 0 的配置
   - 添加 RTSP URL 白名单校验
   - 添加 RTSP 流数据大小限制

2. **配置解析加固**
   - 添加插件名称白名单校验
   - 限制 pipeline 配置中的敏感参数
   - 添加配置签名验证机制

3. **资源管理加固**
   - 添加全局资源使用限制
   - 添加解码器异常恢复机制
   - 添加请求超时强制终止机制

4. **日志审计加固**
   - 添加关键操作审计日志
   - 添加异常事件告警机制
   - 添加请求来源追踪

5. **HTTP API 加固**
   - 添加请求认证机制
   - 添加请求内容签名验证
   - 添加更严格的速率限制

## 下一步扫描重点

根据架构分析结果，建议后续 Scanner 重点扫描：

1. **mxPlugins/MxpiRtspSrc** - RTSP 网络处理和数据解析
2. **mxPlugins/MxpiVideoDecoder** - 视频解码输入处理
3. **mxPlugins/MxpiImageDecoder** - 图像解码输入处理
4. **mxStream/StreamManager** - Pipeline 配置解析
5. **mxStream/samples/streamserver** - HTTP API 输入处理
6. **mxBase/ConfigUtil** - 配置文件解析

特别关注以下漏洞类型：
- 内存操作漏洞（strcpy, memcpy, sprintf）
- 文件路径漏洞（路径遍历）
- JSON 解析漏洞（注入攻击）
- 网络数据解析漏洞（格式解析）
- 进程执行漏洞（system, popen）

---

**报告生成时间**：2026-04-20T10:00:00Z
**分析工具**：Architecture Agent
**项目版本**：VisionSDK (Ascend HDK 25.5.0)