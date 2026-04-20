# 漏洞扫描报告 — 待确认漏洞

**项目**: VisionSDK
**扫描时间**: 2026-04-20T10:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Medium | 3 | 75.0% |
| Low | 1 | 25.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-001]** Integer Overflow (Medium) - `mxPlugins/src/module/MxpiImageCrop/MxpiImageCrop.cpp:923` @ `ProcessData` | 置信度: 65
2. **[VULN-002]** Integer Overflow (Medium) - `mxPlugins/src/module/MxpiImageResize/MxpiImageResize.cpp:648` @ `ProcessData` | 置信度: 65
3. **[VULN-006]** Integer Overflow (Medium) - `mxBase/src/mxbase/module/MbCV/Image/Image/Image.cpp:142` @ `CopyTo` | 置信度: 65
4. **[VULN-003]** Integer Overflow (Low) - `mxBase/src/mxbase/module/MbCV/Tensor/TensorOperations/TensorWarping/TensorWarping.cpp:478` @ `Multiple` | 置信度: 55

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

## 3. Medium 漏洞 (3)

### [VULN-001] Integer Overflow - ProcessData

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mxPlugins/src/module/MxpiImageCrop/MxpiImageCrop.cpp:923` @ `ProcessData`
**模块**: mxPlugins/MxpiImageCrop

**描述**: Potential integer overflow in image size calculation: width * height * YUV_BGR_SIZE_CONVERT_3 / YUV_BGR_SIZE_CONVERT_2. If width and height are large values from external input (image metadata), the multiplication could overflow before division, resulting in an undersized buffer allocation.

**漏洞代码** (`mxPlugins/src/module/MxpiImageCrop/MxpiImageCrop.cpp:923`)

```c
data.dataSize = width * height * YUV_BGR_SIZE_CONVERT_3 / YUV_BGR_SIZE_CONVERT_2;
```

**达成路径**

Image dimensions (width, height) from decoded image -> multiplication -> dataSize -> memory allocation

**验证说明**: Image dimensions come from decoded image data (indirect external input). Width/height multiplication could overflow for large images. However, the code has CheckDataSize validation after calculation, which provides partial mitigation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-002] Integer Overflow - ProcessData

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mxPlugins/src/module/MxpiImageResize/MxpiImageResize.cpp:648-674` @ `ProcessData`
**模块**: mxPlugins/MxpiImageResize

**描述**: Potential integer overflow in image size calculation: width * height * YUV_BGR_SIZE_CONVERT_3 / YUV_BGR_SIZE_CONVERT_2. Similar to VULN-001, large image dimensions could cause overflow.

**漏洞代码** (`mxPlugins/src/module/MxpiImageResize/MxpiImageResize.cpp:648-674`)

```c
dataSize = width * height * YUV_BGR_SIZE_CONVERT_3 / YUV_BGR_SIZE_CONVERT_2;
```

**达成路径**

Image dimensions -> multiplication -> dataSize -> memory allocation

**验证说明**: Similar to VULN-001. Image dimensions from external source could overflow multiplication.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-006] Integer Overflow - CopyTo

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mxBase/src/mxbase/module/MbCV/Image/Image/Image.cpp:142-166` @ `CopyTo`
**模块**: mxBase/Image

**描述**: Integer overflow risk in Image.cpp when calculating data size: dstSize.width * dstSize.height * channel. Large image dimensions from external sources could overflow.

**漏洞代码** (`mxBase/src/mxbase/module/MbCV/Image/Image/Image.cpp:142-166`)

```c
uint32_t dstSizeDataSize = dstSize.width * dstSize.height * channel;
```

**达成路径**

Image size parameters -> multiplication -> dataSize -> memory allocation

**验证说明**: Image dimensions from dstSize parameter could overflow. uint32_t multiplication may overflow before reaching memory allocation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Low 漏洞 (1)

### [VULN-003] Integer Overflow - Multiple

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mxBase/src/mxbase/module/MbCV/Tensor/TensorOperations/TensorWarping/TensorWarping.cpp:478-626` @ `Multiple`
**模块**: mxBase/TensorOperations

**描述**: Potential integer overflow in tensor size calculations involving width * height * channel multiplications. Multiple instances in TensorWarping.cpp where picture dimensions are multiplied without overflow checks.

**漏洞代码** (`mxBase/src/mxbase/module/MbCV/Tensor/TensorOperations/TensorWarping/TensorWarping.cpp:478-626`)

```c
inputDesc.picture_width * channel, ... width * height * widthExtend
```

**达成路径**

Image/tensor dimensions -> multiplication -> offset/size calculation -> memory operations

**验证说明**: Tensor dimensions come from internal processing with less direct external control. Overflow risk exists but exploitation requires crafted tensor input.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| mxBase/Image | 0 | 0 | 1 | 0 | 1 |
| mxBase/TensorOperations | 0 | 0 | 0 | 1 | 1 |
| mxPlugins/MxpiImageCrop | 0 | 0 | 1 | 0 | 1 |
| mxPlugins/MxpiImageResize | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **3** | **1** | **4** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 4 | 100.0% |
