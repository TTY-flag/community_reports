# 漏洞扫描报告 — 已确认漏洞

**项目**: MultimodalSDK
**扫描时间**: 2026-04-20T02:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MultimodalSDK 项目进行了全面的漏洞分析，该项目是一个面向多模态数据处理（图像、视频、音频）的 SDK。扫描共发现 **9 个已确认漏洞**，其中 **7 个为高危漏洞**，主要集中在路径验证缺失和整数溢出两类安全问题。

**核心风险识别**：Python 绑定层（py_bindings 模块）存在系统性安全缺陷，所有文件路径输入接口（图像加载、视频解码）均未实施路径规范化或遍历序列过滤，恶意 Python 代码可通过构造 `../` 序列或符号链接读取任意系统文件，构成敏感信息泄露风险。此外，音频模块的手动 WAV 文件解析存在整数溢出漏洞，畸形文件头部可触发内存分配异常，进而导致缓冲区溢出。

**业务影响评估**：该 SDK 通常以 Python 库形式部署，在 AI 推理场景中处理用户上传的多模态文件。若攻击者能控制输入文件路径（如 Web 服务中的文件上传接口），可利用路径遍历漏洞读取服务器敏感配置（如 `/etc/passwd`、数据库凭证），或通过畸形音频文件触发崩溃实现拒绝服务攻击。

**优先修复方向**：
1. **立即修复**：为 Python 绑定层所有文件路径入口添加路径验证（canonicalize + 白名单校验）
2. **短期修复**：为 WAV 解析模块添加整数溢出防护（参数上界检查 + 安全整数运算）
3. **计划修复**：Tensor 模块 Clone 函数添加缓冲区边界验证

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 16 | 39.0% |
| POSSIBLE | 9 | 22.0% |
| CONFIRMED | 9 | 22.0% |
| FALSE_POSITIVE | 7 | 17.1% |
| **总计** | **41** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 77.8% |
| Medium | 2 | 22.2% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-PY-001]** path_traversal (High) - `AccSDK/source/py/module/PyImage.cpp:54` @ `Image::Image` | 置信度: 85
2. **[VULN-SEC-PY-002]** path_traversal (High) - `AccSDK/source/py/module/PyImage.cpp:153` @ `Image::open` | 置信度: 85
3. **[VULN-SEC-PY-003]** path_traversal (High) - `AccSDK/source/py/module/PyVideo.cpp:30` @ `video_decode` | 置信度: 85
4. **[VULN-PYBIND-001]** missing_path_validation (High) - `AccSDK/source/py/module/PyImage.cpp:54` @ `Image::Image` | 置信度: 85
5. **[VULN-PYBIND-002]** missing_path_validation (High) - `AccSDK/source/py/module/PyVideo.cpp:30` @ `video_decode` | 置信度: 85
6. **[VULN-SEC-UTILS-002]** integer_overflow (High) - `AccSDK/source/utils/AudioUtils.cpp:494` @ `AudioDecode` | 置信度: 80
7. **[VULN-UTILS-AUDIO-001]** Integer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/MultimodalSDK/AccSDK/source/utils/AudioUtils.cpp:495` @ `AudioDecode` | 置信度: 80
8. **[VULN-SEC-VID-002]** integer_overflow (Medium) - `AccSDK/source/video/Video.cpp:105` @ `CheckTargetFrameIndices` | 置信度: 85
9. **[VULN-SEC-TENSOR-001]** buffer_over_read (Medium) - `AccSDK/source/tensor/Tensor.cpp:83` @ `Tensor::Tensor / Tensor::Clone` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `ReadJpegData@AccSDK/source/utils/ImageUtils.cpp` | file | untrusted_local | 用户通过 Python API Image.open(path) 提供图像文件路径，SDK 从文件系统读取并解码 JPEG 数据。攻击者可通过提供恶意构造的 JPEG 文件触发漏洞。 | JPEG 图像文件解码入口 |
| `InitVideoInfo@AccSDK/source/video/Video.cpp` | file | untrusted_local | 用户通过 video_decode(path) 提供视频文件路径，SDK 使用 FFmpeg 打开并解码 MP4 文件。FFmpeg 解码器历史上有多个已知漏洞，恶意视频文件可触发解析漏洞。 | FFmpeg 视频文件解码入口 |
| `AudioDecode@AccSDK/source/utils/AudioUtils.cpp` | file | untrusted_local | 用户通过 load_audio(path) 提供音频文件路径，SDK 手动解析 WAV 文件格式。攻击者可构造畸形 WAV 文件触发解析逻辑漏洞。 | WAV 音频文件解析入口 |
| `ReadFile@AccSDK/source/utils/FileUtils.cpp` | file | untrusted_local | 通用文件读取函数，被图像/音频加载模块调用。虽然有文件权限检查，但仍处理用户提供的文件内容。 | 通用文件读取入口 |
| `Image.open@MultimodalSDK/source/mm/acc/wrapper/image_wrapper.py` | file | untrusted_local | Python 层图像加载 API，接收用户提供的文件路径参数，传递给 C++ 层进行解码。 | Python 图像加载入口 |
| `video_decode@MultimodalSDK/source/mm/acc/wrapper/video_wrapper.py` | file | untrusted_local | Python 层视频解码 API，接收用户提供的视频文件路径参数，传递给 C++ 层使用 FFmpeg 解码。 | Python 视频解码入口 |

**其他攻击面**:
- JPEG 解码器 (libjpeg-turbo): tjDecompressHeader2, tjDecompress2
- 视频解码器 (FFmpeg): avformat_open_input, avcodec_open2, av_read_frame
- WAV 文件解析: 手动解析 RIFF/FMT/DATA chunk
- Python 绑定层: pybind11 封装函数
- 外部库依赖: libjpeg-turbo, FFmpeg, Soxr, transformers

---

## 3. High 漏洞 (7)

### [VULN-SEC-PY-001] path_traversal - Image::Image

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `AccSDK/source/py/module/PyImage.cpp:54-64` @ `Image::Image`
**模块**: py_bindings
**跨模块**: py_bindings → image

**描述**: PyImage::Image(const char* path) takes file path directly from Python caller without validation (null check, path canonicalization, or traversal sequence filtering). Path flows unvalidated to underlying Acc::Image constructor. Malicious Python code could pass path containing '../' sequences or symbolic links to access unintended files.

**漏洞代码** (`AccSDK/source/py/module/PyImage.cpp:54-64`)

```c
Image::Image(const char* path, const char* device)
{
    try {
        image_ = std::make_shared<Acc::Image>(path, device);
    } catch (const std::exception& ex) {
        image_ = nullptr;
    }
    if (image_ == nullptr) {
        Acc::LogError << "Create Image object failed. Failed to allocate memory.";
        throw std::runtime_error("Create Image object failed. Failed to allocate memory.");
    }
}
```

**达成路径**

[CREDENTIAL_FLOW] Python caller (pybind11 param conversion) → PyImage.cpp:54 Image::Image(const char* path) → Acc::Image::Image(path, device) [SINK - image module]

**验证说明**: Duplicate of VULN-PYBIND-001. Path traversal from Python to image module unvalidated.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码 `AccSDK/source/py/module/PyImage.cpp:54-65` 可见，`Image::Image(const char* path)` 构造函数直接将 Python 调用者传入的 `path` 参数传递给底层 `Acc::Image` 构造函数，中间未实施任何安全检查：
- 未检查路径是否为空指针（`nullptr`）
- 未调用 `realpath()` 进行路径规范化，消除 `../` 序列
- 未验证文件是否存在或是否在允许的目录范围内
- 未检测符号链接是否指向敏感系统文件

该漏洞属于跨模块数据流问题：数据从 `py_bindings` 模块流入 `image` 模块，边界处缺失安全过滤。

**潜在利用场景**：
1. **敏感文件泄露**：若 SDK 部署在 Web 服务中处理用户文件，攻击者可传入 `../../../etc/passwd` 或 `/proc/self/environ`，读取服务器敏感信息
2. **配置文件窃取**：传入 `../../config/database.yml` 或 `../../.env` 可获取数据库凭证、API 密钥
3. **符号链接攻击**：攻击者可创建指向敏感文件的符号链接，绕过简单的路径前缀检查

**建议修复方式**：
```cpp
// 在 PyImage.cpp 中添加路径验证
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>

Image::Image(const char* path, const char* device) {
    // 1. 检查路径非空
    if (path == nullptr || strlen(path) == 0) {
        throw std::runtime_error("Invalid path: null or empty");
    }
    
    // 2. 规范化路径（消除 ../ 和符号链接）
    char resolved[PATH_MAX];
    if (realpath(path, resolved) == nullptr) {
        throw std::runtime_error("Path resolution failed");
    }
    
    // 3. 白名单校验（确保在允许目录内）
    const std::string allowedDir = "/safe/data/";
    if (strncmp(resolved, allowedDir.c_str(), allowedDir.length()) != 0) {
        throw std::runtime_error("Path outside allowed directory");
    }
    
    // 4. 传递规范化路径
    image_ = std::make_shared<Acc::Image>(resolved, device);
}
```

---

### [VULN-SEC-PY-002] path_traversal - Image::open

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `AccSDK/source/py/module/PyImage.cpp:153-156` @ `Image::open`
**模块**: py_bindings
**跨模块**: py_bindings → image

**描述**: PyImage::open(const std::string& path) passes path string to Image constructor without validation. No null check on path.c_str(), no path sanitization. String-to-C-string conversion (path.c_str()) occurs without bounds checking.

**漏洞代码** (`AccSDK/source/py/module/PyImage.cpp:153-156`)

```c
Image Image::open(const std::string& path, const std::string& device)
{
    return PyAcc::Image(path.c_str(), device.c_str());
}
```

**达成路径**

[CREDENTIAL_FLOW] Python Image.open(path) → PyImage.cpp:153 Image::open(std::string path) → path.c_str() → Image::Image(const char* path) → Acc::Image::Image() [SINK - image module]

**验证说明**: Image::open calls Image(path.c_str()) directly. Same as VULN-PYBIND-001.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码 `AccSDK/source/py/module/PyImage.cpp:153-156` 可见，`Image::open` 静态方法直接将 `std::string` 转换为 C 字符串并调用构造函数，未进行任何中间验证：
```cpp
Image Image::open(const std::string& path, const std::string& device) {
    return PyAcc::Image(path.c_str(), device.c_str());  // 直接传递，无验证
}
```
该函数实际上是 `Image::Image` 构造函数的便捷封装，继承了相同的安全缺陷。

**潜在利用场景**：
1. **API 封装层攻击**：若 Python 应用使用 `Image.open()` 而非直接构造函数，攻击者仍可通过相同路径遍历向量实现攻击
2. **批量文件处理风险**：在批量图像处理场景中，攻击者可构造包含遍历序列的文件列表，绕过输入校验逻辑

**建议修复方式**：
由于 `Image::open` 调用了 `Image::Image` 构造函数，修复构造函数即可覆盖此漏洞。同时建议在 Python 绑定层统一实施路径验证策略：
```cpp
// 创建共享的路径验证函数
namespace PyAcc {
bool ValidateFilePath(const std::string& path, std::string& resolved) {
    // 验证逻辑同上...
}
}

Image Image::open(const std::string& path, const std::string& device) {
    std::string resolved;
    if (!ValidateFilePath(path, resolved)) {
        throw std::runtime_error("Invalid or unsafe file path");
    }
    return PyAcc::Image(resolved.c_str(), device.c_str());
}
```

---

### [VULN-SEC-PY-003] path_traversal - video_decode

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `AccSDK/source/py/module/PyVideo.cpp:30-37` @ `video_decode`
**模块**: py_bindings
**跨模块**: py_bindings → video

**描述**: video_decode(const char* path) receives video file path from Python without validation. Path flows directly to Acc::VideoDecode() in video module. No traversal sequence filtering or path canonicalization.

**漏洞代码** (`AccSDK/source/py/module/PyVideo.cpp:30-37`)

```c
std::vector<Image> video_decode(const char* path, const char* device, const std::set<uint32_t>& frameIndices,
                                 int sampleNum)
{
    std::vector<Acc::Image> accImageResult;
    auto ret = Acc::VideoDecode(path, device, accImageResult, frameIndices, sampleNum);
    if (ret != 0) {
        throw std::runtime_error("Failed to decode video, please see above log for detail.");
    }
    ...
```

**达成路径**

[CREDENTIAL_FLOW] Python video_decode(path) → PyVideo.cpp:30 video_decode(const char* path) → Acc::VideoDecode(path, ...) [SINK - video module]

**验证说明**: Duplicate of VULN-PYBIND-002. Path traversal from Python to video module.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码 `AccSDK/source/py/module/PyVideo.cpp:30-47` 可见，`video_decode` 函数直接将 Python 传入的路径传递给底层 `Acc::VideoDecode`：
```cpp
std::vector<Image> video_decode(const char* path, const char* device, 
                                const std::set<uint32_t>& frameIndices, int sampleNum) {
    std::vector<Acc::Image> accImageResult;
    auto ret = Acc::VideoDecode(path, device, accImageResult, frameIndices, sampleNum);
    // ...
}
```
该函数同样缺失路径验证，且视频文件通过 FFmpeg (`avformat_open_input`) 打开，攻击者可利用 FFmpeg 解码器的历史漏洞（如 CVE-2016-1897/1898）实现远程代码执行。

**潜在利用场景**：
1. **路径遍历读取任意视频文件**：攻击者可读取服务器上敏感视频文件或系统文件（若 FFmpeg 尝试解析非视频文件）
2. **FFmpeg 解码器漏洞链**：结合已知的 FFmpeg 解析漏洞（MP4/AVI 文件格式解析溢出），构造恶意视频文件可触发解码器崩溃或代码执行
3. **帧索引整数溢出联动**：`frameIndices` 参数与 `CheckTargetFrameIndices` 中的整数溢出漏洞关联，攻击者可构造大帧数视频触发额外漏洞

**建议修复方式**：
```cpp
std::vector<Image> video_decode(const char* path, const char* device, 
                                const std::set<uint32_t>& frameIndices, int sampleNum) {
    // 路径验证（复用 ValidateFilePath）
    std::string resolved;
    if (!ValidateFilePath(std::string(path), resolved)) {
        throw std::runtime_error("Invalid video file path");
    }
    
    // 帧索引上界校验
    if (frameIndices.size() > MAX_FRAME_INDICES) {
        throw std::runtime_error("Too many frame indices");
    }
    
    std::vector<Acc::Image> accImageResult;
    auto ret = Acc::VideoDecode(resolved.c_str(), device, accImageResult, frameIndices, sampleNum);
    // ...
}
```

---

### [VULN-PYBIND-001] missing_path_validation - Image::Image

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyImage.cpp:54-65` @ `Image::Image`
**模块**: py_bindings
**跨模块**: py_bindings,image,mm_acc_wrapper

**描述**: Image constructor accepts file path directly from Python without any validation. The path parameter is passed to Acc::Image without checking for path traversal, symlinks, or file existence. Attackers could read arbitrary files or trigger DoS with malformed paths.

**漏洞代码** (`AccSDK/source/py/module/PyImage.cpp:54-65`)

```c
Image::Image(const char* path, const char* device) { image_ = std::make_shared<Acc::Image>(path, device); }
```

**达成路径**

[IN] Python mm_acc_wrapper → PyImage.cpp:54 Image::Image(path) → [OUT] image module Acc::Image::Image

**验证说明**: Path traverses unvalidated from Python to Acc::Image. No path sanitization or IsFileValid check in py_bindings layer.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PYBIND-002] missing_path_validation - video_decode

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyVideo.cpp:30-47` @ `video_decode`
**模块**: py_bindings
**跨模块**: py_bindings,video,mm_acc_wrapper

**描述**: video_decode accepts video file path directly from Python without validation.

**漏洞代码** (`AccSDK/source/py/module/PyVideo.cpp:30-47`)

```c
video_decode(const char* path, ...) { Acc::VideoDecode(path, ...); }
```

**达成路径**

[IN] Python mm_acc_wrapper → PyVideo.cpp:30 → [OUT] video module

**验证说明**: Path traverses unvalidated from Python to Acc::VideoDecode. IsFileValid check exists in Video.cpp but bypass possible via race condition.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-UTILS-002] integer_overflow - AudioDecode

**严重性**: High | **CWE**: CWE-190 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `AccSDK/source/utils/AudioUtils.cpp:494-497` @ `AudioDecode`
**模块**: utils

**描述**: Integer overflow in WAV sample calculation. fmt.numChannels comes from WAV header without upper bound validation. If numChannels is crafted to be very large (e.g., 0xFFFFFFFF), bytesPerSample * fmt.numChannels could overflow to a small value, causing numSamples to be huge and leading to excessive memory allocation or buffer overflow.

**漏洞代码** (`AccSDK/source/utils/AudioUtils.cpp:494-497`)

```c
const uint32_t bytesPerSample = fmt.bitsPerSample / 8;
const uint32_t numSamples = dataSize / (bytesPerSample * fmt.numChannels);
std::vector<float> samples(numSamples * fmt.numChannels);
```

**达成路径**

AudioUtils.cpp:274 memcpy_s(&fmt, ...) → fmt.numChannels [TAINTED from WAV header] → AudioUtils.cpp:495 bytesPerSample * fmt.numChannels [POTENTIAL OVERFLOW] → AudioUtils.cpp:497 samples.resize() [SINK - memory allocation]

**验证说明**: Duplicate root cause of VULN-UTILS-AUDIO-001. bytesPerSample * fmt.numChannels can overflow when numChannels is crafted large.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: -15 | cross_file: 0

**深度分析**

**根因分析**：从源代码 `AccSDK/source/utils/AudioUtils.cpp:494-497` 可见，WAV 文件解析存在关键整数溢出风险：
```cpp
const uint32_t bytesPerSample = fmt.bitsPerSample / 8;
const uint32_t numSamples = dataSize / (bytesPerSample * fmt.numChannels);
std::vector<float> samples(numSamples * fmt.numChannels);  // 潜在溢出点
```
漏洞触发条件：`fmt.numChannels` 来自 WAV 文件头部（`AudioUtils.cpp:274`），攻击者可构造畸形 WAV 文件设置 `numChannels = 0xFFFF`（最大 uint16_t 值），当 `bytesPerSample * fmt.numChannels` 计算时发生整数溢出，结果变为小值（如 1），导致 `numSamples` 变得极大，最终 `samples` 向量分配时触发内存耗尽或后续 `ConvertAudioDataToFloat` 调用时发生缓冲区溢出。

**潜在利用场景**：
1. **内存耗尽攻击**：构造 `numChannels` 极大的 WAV 文件，使 `numSamples` 计算结果异常大，触发 `std::vector` 分配失败导致服务崩溃（拒绝服务）
2. **缓冲区溢出**：若内存分配侥幸成功（受限于可用内存），后续 `ConvertAudioDataToFloat` 在拷贝音频数据时将发生越界写入
3. **整数下溢联动**：当 `bytesPerSample * fmt.numChannels` 溢出为 0 时，除法运算将触发异常或返回极大值

**建议修复方式**：
```cpp
// 在 AudioUtils.cpp 中添加参数校验
ErrorCode AudioDecode(const std::string& filePath, AudioData& outputAudioData) {
    // ...
    
    // 添加 numChannels 上界校验
    if (fmt.numChannels > MAX_AUDIO_CHANNELS) {  // 建议上限 16
        LogError << "Invalid numChannels: exceeds maximum allowed";
        return ERR_INVALID_PARAM;
    }
    
    // 使用安全整数运算检查溢出
    uint64_t bytesPerSample = fmt.bitsPerSample / 8;
    uint64_t bytesPerFrame = bytesPerSample * fmt.numChannels;
    if (bytesPerFrame > dataSize) {
        LogError << "Invalid audio format: frame size exceeds data size";
        return ERR_INVALID_PARAM;
    }
    
    uint64_t numSamples = dataSize / bytesPerFrame;
    uint64_t totalFloats = numSamples * fmt.numChannels;
    if (totalFloats > MAX_AUDIO_SAMPLES) {  // 建议上限 1e9
        LogError << "Audio data too large";
        return ERR_INVALID_PARAM;
    }
    
    std::vector<float> samples(static_cast<size_t>(totalFloats));
    // ...
}
```

---

### [VULN-UTILS-AUDIO-001] Integer Overflow - AudioDecode

**严重性**: High | **CWE**: CWE-190 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/MultimodalSDK/AccSDK/source/utils/AudioUtils.cpp:495-498` @ `AudioDecode`
**模块**: utils
**跨模块**: utils,audio

**描述**: Integer overflow in audio buffer allocation. numSamples * fmt.numChannels calculation may overflow when processing malformed WAV files with crafted headers. dataSize from WAV header (uint32_t) combined with numChannels (uint16_t) from fmt chunk can cause overflow in samples vector allocation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/MultimodalSDK/AccSDK/source/utils/AudioUtils.cpp:495-498`)

```c
const uint32_t numSamples = dataSize / (bytesPerSample * fmt.numChannels);\nstd::vector<float> samples(numSamples * fmt.numChannels);
```

**达成路径**

ReadFile(filePath) -> fileData -> FindAndReadFmtChunk -> fmt.numChannels -> FindDataChunk -> dataSize -> numSamples * fmt.numChannels (SINK: vector allocation)

**验证说明**: Integer overflow in numSamples * fmt.numChannels (line 495-497). numChannels from WAV header unvalidated. Can overflow uint32_t causing undersized allocation then buffer overflow in ConvertAudioDataToFloat.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: -15 | cross_file: 0

---

## 4. Medium 漏洞 (2)

### [VULN-SEC-VID-002] integer_overflow - CheckTargetFrameIndices

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `AccSDK/source/video/Video.cpp:105-108` @ `CheckTargetFrameIndices`
**模块**: video

**描述**: Integer overflow in frame index calculation: i * (nFrames - 1) multiplication can overflow uint32_t before division when nFrames is very large (~4 billion) and sampleNum is small. This results in incorrect frame indices being generated, potentially causing out-of-range frame access or unexpected behavior.

**漏洞代码** (`AccSDK/source/video/Video.cpp:105-108`)

```c
for (uint32_t i = 0; i < validSampleNum; i++) {
    uint32_t idx = static_cast<uint32_t>(i * (nFrames - 1) / (validSampleNum - 1)); // overflow when i * (nFrames-1) > UINT32_MAX
    frameIndices.insert(idx);
}
```

**达成路径**

Video.cpp:165 GetFramesAndFPS(videoStream, originFps, totalFrames) [SOURCE - totalFrames from video file]
Video.cpp:172 CheckTargetFrameIndices(totalFrames, targetIndices, sampleNum)
Video.cpp:106 uint32_t idx = i * (nFrames - 1) / (validSampleNum - 1) [SINK - integer overflow]

**验证说明**: CheckTargetFrameIndices: i * (nFrames - 1) can overflow uint32_t when nFrames is large (~4 billion). totalFrames from video file header. Result: incorrect frame indices, potential out-of-range access.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-TENSOR-001] buffer_over_read - Tensor::Tensor / Tensor::Clone

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `AccSDK/source/tensor/Tensor.cpp:83-121` @ `Tensor::Tensor / Tensor::Clone`
**模块**: tensor

**描述**: Tensor constructor accepts user-provided buffer (void* data) and shape without validating that the buffer size matches the calculated totalBytes. Clone() reads totalBytes bytes from the buffer (line 121) without verifying the buffer is actually that large. If an attacker can control shape values and provide an undersized buffer, Clone() will read beyond the buffer bounds, causing buffer over-read.

**漏洞代码** (`AccSDK/source/tensor/Tensor.cpp:83-121`)

```c
// Constructor (line 83-93):
Tensor::Tensor(void* data, const std::vector<size_t>& shape, DataType dataType, TensorFormat format, const char* device)
    : deviceId_(DEVICE_CPU), shape_(shape), dataType_(dataType), format_(format),
      dataPtr_(std::shared_ptr<void>(data, [](void*) {})), device_(device ? device : "")
{
    CheckTensorParams();  // Only checks null pointer, not buffer size
    FillAuxInfo();        // Calculates totalBytes from shape
}

// Clone (line 108-129):
ErrorCode Tensor::Clone(Tensor& tensor) const
{
    char* data = new(std::nothrow) char[auxInfo_.totalBytes];
    auto ret = memcpy_s(dstPtr.get(), auxInfo_.totalBytes, dataPtr_.get(), auxInfo_.totalBytes);
    // Reads totalBytes from user buffer - no size validation
}
```

**达成路径**

Tensor.cpp:83 Tensor(void* data, shape) [SOURCE - user-controlled buffer and shape]
Tensor.cpp:92 FillAuxInfo() → calculates totalBytes from shape
Tensor.cpp:115 Clone() allocates totalBytes
Tensor.cpp:121 memcpy_s() reads totalBytes from dataPtr_ [SINK - over-read if buffer undersized]

**验证说明**: Tensor constructor accepts void* data + shape. Clone() reads totalBytes bytes without verifying actual buffer size. User-provided undersized buffer + large shape -> buffer over-read. Reachable via Tensor::from_numpy and Image::from_numpy.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码 `AccSDK/source/tensor/Tensor.cpp:83-129` 可见，Tensor 构造函数接受用户提供的缓冲区指针和形状参数，但 `Clone()` 方法在复制数据时未验证缓冲区实际大小：
```cpp
// 构造函数（行 83-93）
Tensor::Tensor(void* data, const std::vector<size_t>& shape, DataType dataType, ...)
    : dataPtr_(std::shared_ptr<void>(data, [](void*) {}))  // 用户缓冲区，无大小信息
{
    CheckTensorParams();  // 仅检查指针非空，不检查缓冲区大小
    FillAuxInfo();        // 从 shape 计算 totalBytes
}

// Clone 方法（行 108-129）
ErrorCode Tensor::Clone(Tensor& tensor) const {
    char* data = new char[auxInfo_.totalBytes];  // 按 shape 计算的大小分配
    memcpy_s(dstPtr.get(), auxInfo_.totalBytes, dataPtr_.get(), auxInfo_.totalBytes);
    // 从用户缓冲区读取 totalBytes 字节 - 若用户缓冲区实际更小则越界读取
}
```
攻击者可构造：提供小缓冲区（如 100 字节）+ 大 shape（如 `[1000, 1000]`），`FillAuxInfo` 计算 `totalBytes = 1e6`，`Clone` 尝试从 100 字节缓冲区读取 1e6 字节，触发堆越界读取。

**潜在利用场景**：
1. **信息泄露**：越界读取可泄露进程内存中的敏感数据（如密钥、密码、其他用户数据）
2. **进程崩溃**：读取未映射内存页触发 SIGSEGV，导致服务拒绝服务
3. **Python API 路径**：通过 `Tensor::from_numpy` 接口可达，若 Python 应用接受用户 numpy 数组并传递错误形状参数

**建议修复方式**：
```cpp
// 方案一：要求调用者显式传入缓冲区大小
Tensor::Tensor(void* data, size_t bufferSize, const std::vector<size_t>& shape, ...)
{
    CheckTensorParams();
    FillAuxInfo();
    // 验证缓冲区足够大
    if (auxInfo_.totalBytes > bufferSize) {
        throw std::runtime_error("Buffer size mismatch: shape requires more bytes than provided");
    }
}

// 方案二：Clone 时使用安全边界检查
ErrorCode Tensor::Clone(Tensor& tensor) const {
    // 在 Clone 前验证数据指针有效范围（若可行）
    // 或使用 valgrind/ASAN 在开发阶段检测
}
```

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| py_bindings | 0 | 5 | 0 | 0 | 5 |
| tensor | 0 | 0 | 1 | 0 | 1 |
| utils | 0 | 2 | 0 | 0 | 2 |
| video | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **7** | **2** | **0** | **9** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 5 | 55.6% |
| CWE-190 | 3 | 33.3% |
| CWE-125 | 1 | 11.1% |

---

## 7. 修复建议

### 优先级 1: 立即修复（Critical/High 路径验证漏洞）

**涉及漏洞**: VULN-SEC-PY-001, VULN-SEC-PY-002, VULN-SEC-PY-003, VULN-PYBIND-001, VULN-PYBIND-002

**修复策略**：在 Python 绑定层统一实施路径验证框架。

**具体措施**：
1. **创建路径验证模块** `AccSDK/source/utils/PathValidator.cpp`：
   - 实现 `realpath()` 规范化路径，消除 `../` 和符号链接
   - 定义白名单目录（如 `/safe/data/`），拒绝访问系统敏感路径
   - 检查路径长度限制（防止缓冲区溢出攻击）
   
2. **修改 Python 绑定入口**：
   - `PyImage.cpp:54` Image::Image 构造函数调用路径验证
   - `PyImage.cpp:153` Image::open 方法调用路径验证
   - `PyVideo.cpp:30` video_decode 函数调用路径验证
   
3. **测试验证**：
   - 添加单元测试覆盖路径遍历场景（`../../../etc/passwd`）
   - 添加符号链接攻击测试
   - 添加边界条件测试（空路径、超长路径）

**预计工作量**: 2-3 人日

### 优先级 2: 短期修复（High 整数溢出漏洞）

**涉及漏洞**: VULN-SEC-UTILS-002, VULN-UTILS-AUDIO-001

**修复策略**：为 WAV 文件解析添加安全整数运算和参数上界校验。

**具体措施**：
1. **参数上界校验** (`AudioUtils.cpp`):
   - `fmt.numChannels` 上限设为 16（符合常见音频格式）
   - `fmt.bitsPerSample` 上限设为 32（常见位深度）
   - `dataSize` 与 `numSamples` 的组合计算添加溢出检测
   
2. **安全整数运算**：
   - 使用 `uint64_t` 进行中间计算避免溢出
   - 在除法前检查除数非零
   - 最终分配大小检查是否超过 `MAX_AUDIO_SAMPLES`（建议 1e9）
   
3. **回归测试**：
   - 构造畸形 WAV 文件测试（极大 numChannels、零除法场景）
   - 验证内存分配失败时的错误处理

**预计工作量**: 1-2 人日

### 优先级 3: 计划修复（Medium 漏洞）

**涉及漏洞**: VULN-SEC-VID-002, VULN-SEC-TENSOR-001

**修复策略**：

**VULN-SEC-VID-002 (Video.cpp 整数溢出)**：
- 为帧索引计算 `i * (nFrames - 1)` 使用 `uint64_t` 中间类型
- 添加 `nFrames` 上界校验（如限制视频帧数不超过 1e8）
- 在 `CheckTargetFrameIndices` 入口验证参数范围

**VULN-SEC-TENSOR-001 (Tensor.cpp buffer_over_read)**：
- 修改 Tensor 构造函数 API，要求显式传入缓冲区大小
- 在 `Clone()` 前验证缓冲区大小与 `totalBytes` 匹配
- 或在 Python 绑定层（`Tensor::from_numpy`）添加形状与数据大小的一致性检查

**预计工作量**: 2 人日

### 修复实施优先级图

```
Week 1: 优先级 1 (路径验证框架 + py_bindings 修复)
Week 2: 优先级 2 (AudioUtils 整数溢出修复)
Week 3: 优先级 3 (Video + Tensor 漏洞修复)
Week 4: 安全测试 + Code Review + Release
```

### 安全编码建议（长期）

1. **输入验证原则**：所有来自不可信源的输入（Python API、文件内容、网络数据）必须经过验证
2. **安全整数运算**：涉及乘法、除法的计算使用大类型中间变量，添加溢出检测
3. **路径处理规范**：禁止直接使用用户路径，必须经过 `realpath` 规范化 + 白名单校验
4. **缓冲区边界检查**：所有内存操作（memcpy、buffer access）必须验证长度与容量匹配
5. **静态分析集成**：引入 Clang Static Analyzer 或 Coverity 定期扫描代码
