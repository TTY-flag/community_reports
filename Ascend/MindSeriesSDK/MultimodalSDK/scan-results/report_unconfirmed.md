# 漏洞扫描报告 — 待确认漏洞

**项目**: MultimodalSDK
**扫描时间**: 2026-04-20T02:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 4 | 16.7% |
| Medium | 16 | 66.7% |
| Low | 4 | 16.7% |
| **有效漏洞总计** | **24** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-PY-006]** arbitrary_memory_access (High) - `AccSDK/source/py/module/PyUtil.cpp:82` @ `GetNumpyData` | 置信度: 75
2. **[VULN-PYBIND-005]** unsafe_pointer_conversion (High) - `AccSDK/source/py/module/PyUtil.cpp:47` @ `GetNumpyData` | 置信度: 75
3. **[VULN-SEC-CORE-001]** use_after_free (High) - `AccSDK/source/core/framework/Pipeline.cpp:111` @ `Pipeline::Run` | 置信度: 75
4. **[VULN-SEC-AUDIO-001]** integer_overflow (High) - `AccSDK/source/audio/Audio.cpp:109` @ `ResampleAudio` | 置信度: 70
5. **[VULN-PYBIND-006]** missing_parameter_validation (Medium) - `AccSDK/source/py/module/PyTensor.cpp:124` @ `Tensor::normalize` | 置信度: 75
6. **[VULN-SEC-CORE-003]** uncontrolled_resource_consumption (Medium) - `AccSDK/source/core/framework/Pipeline.cpp:96` @ `Pipeline::Run` | 置信度: 75
7. **[VULN-SEC-CORE-004]** improper_array_index_validation (Medium) - `AccSDK/source/core/framework/Pipeline.cpp:109` @ `Pipeline::Run` | 置信度: 75
8. **[VULN-SEC-AUDIO-002]** unvalidated_parameter (Medium) - `AccSDK/source/audio/Audio.cpp:50` @ `LoadAudioData` | 置信度: 70
9. **[VULN-SEC-AUDIO-003]** resource_exhaustion (Medium) - `AccSDK/source/audio/Audio.cpp:111` @ `ResampleAudio` | 置信度: 70
10. **[VULN-SEC-UTILS-003]** missing_validation (Medium) - `AccSDK/source/utils/AudioUtils.cpp:331` @ `CheckAudioFormat` | 置信度: 65

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

## 3. High 漏洞 (4)

### [VULN-SEC-PY-006] arbitrary_memory_access - GetNumpyData

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/py/module/PyUtil.cpp:82-88` @ `GetNumpyData`
**模块**: py_bindings
**跨模块**: py_bindings → tensor

**描述**: GetNumpyData() extracts raw memory pointer from Python numpy array's __array_interface__ without validation. Line 84: reinterpret_cast<void*>(PyLong_AsVoidPtr(dataPtrObj)) directly uses Python-provided address as memory pointer. Malicious Python code could craft fake __array_interface__ with arbitrary address, enabling memory disclosure or corruption.

**漏洞代码** (`AccSDK/source/py/module/PyUtil.cpp:82-88`)

```c
PyObject *dataPtrObj = PyTuple_GetItem(dataTuple, 0);
numpyData.dataPtr = reinterpret_cast<void*>(PyLong_AsVoidPtr(dataPtrObj));
if (PyErr_Occurred() || !numpyData.dataPtr) {
    throw std::runtime_error("Failed to get valid data pointer from __array_interface__ of python numpy "
                             "ndarray. The data field's address must be legal");
}
```

**达成路径**

[CREDENTIAL_FLOW] Python numpy array __array_interface__.data[0] → PyUtil.cpp:84 PyLong_AsVoidPtr(dataPtrObj) → reinterpret_cast<void*> → numpyData.dataPtr → Acc::Tensor(dataPtr, ...) [SINK - tensor module]

**验证说明**: Duplicate of VULN-PYBIND-005. Arbitrary memory pointer from numpy __array_interface__.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-PYBIND-005] unsafe_pointer_conversion - GetNumpyData

**严重性**: High | **CWE**: CWE-704 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyUtil.cpp:47-137` @ `GetNumpyData`
**模块**: py_bindings
**跨模块**: py_bindings,tensor

**描述**: GetNumpyData converts Python pointer to void* without bounds validation. PyLong_AsVoidPtr extracts data pointer from numpy array without verifying the memory region is valid or within expected bounds. Malicious numpy objects could provide invalid pointers leading to memory access violations.

**漏洞代码** (`AccSDK/source/py/module/PyUtil.cpp:47-137`)

```c
numpyData.dataPtr = reinterpret_cast<void*>(PyLong_AsVoidPtr(dataPtrObj));
```

**达成路径**

[IN] Python numpy array → PyUtil.cpp:84 PyLong_AsVoidPtr → void* dataPtr → [OUT] tensor module Acc::Tensor

**验证说明**: PyLong_AsVoidPtr accepts arbitrary address from Python. Null check exists but not address validity check. Malicious numpy can provide invalid pointer.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CORE-001] use_after_free - Pipeline::Run

**严重性**: High | **CWE**: CWE-416 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/core/framework/Pipeline.cpp:111` @ `Pipeline::Run`
**模块**: core_framework

**描述**: Pipeline::Run 方法中使用空删除器包装外部 Tensor 的原始指针。std::shared_ptr<void>(input->second[i].Ptr(), [](void*) {}) 创建了一个不释放内存的 shared_ptr。如果外部 Tensor 对象在 shared_ptr 使用期间被销毁，会导致访问已释放内存，造成 Use After Free 漏洞。

**漏洞代码** (`AccSDK/source/core/framework/Pipeline.cpp:111`)

```c
std::shared_ptr<void> tensorSharedPtr(input->second[i].Ptr(), [](void*) {});
```

**达成路径**

Pipeline::Run() 接收 inputs 参数 → input->second[i].Ptr() 返回原始指针 → std::shared_ptr<void> 使用空删除器包装 → tensorList->ShareData() 使用该 shared_ptr → 如果外部 Tensor 被销毁，shared_ptr 指向的内存已释放

**验证说明**: Pipeline::Run: std::shared_ptr<void>(input->second[i].Ptr(), [](void*) {}) with null deleter. If external Tensor destroyed during pipeline execution -> Use After Free. Caller controls Tensor lifetime.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AUDIO-001] integer_overflow - ResampleAudio

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `AccSDK/source/audio/Audio.cpp:109-116` @ `ResampleAudio`
**模块**: audio
**跨模块**: audio → utils

**描述**: 音频重采样缓冲区大小计算存在整数溢出风险。ResampleAudio 函数在计算 expectedOutputLen 时未检查 originalSr 的有效范围，若 WAV 文件包含异常低的采样率(如 1 Hz)，与目标采样率(最高 64000 Hz)计算 ratio 时，乘以 monoAudio.size() 可导致整数溢出。在 32 位系统上溢出会分配过小缓冲区，soxr_oneshot 写入时触发堆溢出。

**漏洞代码** (`AccSDK/source/audio/Audio.cpp:109-116`)

```c
const double ratio = static_cast<double>(sr.value()) / originalSr;
expectedOutputLen = std::ceil(static_cast<double>(monoAudio.size()) * ratio);
std::shared_ptr<std::vector<float>> buffer = std::make_shared<std::vector<float>>(expectedOutputLen);
```

**达成路径**

[CREDENTIAL_FLOW] utils/AudioUtils.cpp:465 AudioDecode() [SOURCE] 解析 WAV fmt.sampleRate → Audio.cpp:44 LoadAudioData() → Audio.cpp:181 originalSr = audioData.sampleRate → Audio.cpp:109 ratio = sr.value() / originalSr → Audio.cpp:111 expectedOutputLen 计算溢出 → Audio.cpp:112 buffer 分配过小 → Audio.cpp:89 soxr_oneshot() [SINK] 堆溢出

**验证说明**: ResampleAudio: ratio = sr.value() / originalSr can be huge if originalSr is small. CheckSingleAudioInputs checks sr<=64000 but LoadAudioData only checks sampleRate<=0. Crafted WAV with sampleRate=1Hz can cause 64000x buffer expansion.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: -15

---

## 4. Medium 漏洞 (16)

### [VULN-PYBIND-006] missing_parameter_validation - Tensor::normalize

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyTensor.cpp:124-135` @ `Tensor::normalize`
**模块**: py_bindings
**跨模块**: py_bindings,tensor

**描述**: Tensor::normalize accepts mean/std vectors without size validation.

**漏洞代码** (`AccSDK/source/py/module/PyTensor.cpp:124-135`)

```c
normalize(mean, std) { TensorNormalize(*tensor_, outputAccTensor, mean, std, ...); }
```

**达成路径**

[IN] Python vectors → PyTensor.cpp:124 → [OUT] tensor module

**验证说明**: mean/std vectors passed to TensorNormalize without size validation against channel count.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CORE-003] uncontrolled_resource_consumption - Pipeline::Run

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/core/framework/Pipeline.cpp:96-102` @ `Pipeline::Run`
**模块**: core_framework

**描述**: Pipeline::Run 方法中只检查 tensorListSize 是否为 0，没有设置合理的上界限制。攻击者可以传入巨大的张量列表导致 AccDataTensorList::Create 分配过多内存，造成资源耗尽。

**漏洞代码** (`AccSDK/source/core/framework/Pipeline.cpp:96-102`)

```c
uint64_t tensorListSize = input->second.size();
if (tensorListSize == 0) {
    LogDebug << "The vector size of inputs is zero, please check the inputs." << GetErrorInfo(ERR_INVALID_PARAM);
    return ERR_INVALID_PARAM;
}
auto tensorList = AccDataTensorList::Create(tensorListSize);
```

**达成路径**

Pipeline::Run() 接收 inputs 参数 → input->second.size() 返回 tensorListSize → 只检查是否为 0 → AccDataTensorList::Create(tensorListSize) 可能分配过多内存

**验证说明**: Pipeline::Run: tensorListSize = input->second.size() only checks ==0. No upper bound. AccDataTensorList::Create can allocate excessive memory. Resource exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CORE-004] improper_array_index_validation - Pipeline::Run

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/core/framework/Pipeline.cpp:109-112` @ `Pipeline::Run`
**模块**: core_framework

**描述**: Pipeline::Run 方法中使用 input->second[i].Shape() 传递给 ShareData，但没有验证形状数据的合理性。极端形状值可能导致 AccDataTensorList 内部计算溢出或分配过多内存。

**漏洞代码** (`AccSDK/source/core/framework/Pipeline.cpp:109-112`)

```c
auto tensorDataType = Acc::ToTensorDataType(input->second[i].DType());
auto tensorLayout = Acc::ToTensorLayout(input->second[i].Format());
std::shared_ptr<void> tensorSharedPtr(input->second[i].Ptr(), [](void*) {});
accDataRet = tensorList->operator[](i).ShareData(tensorSharedPtr, input->second[i].Shape(), tensorDataType);
```

**达成路径**

Pipeline::Run() 接收 inputs 参数 → input->second[i].Shape() 未验证 → ShareData() 可能因极端形状值导致内存问题

**验证说明**: Pipeline::Run: input->second[i].Shape() passed to ShareData without validation. Extreme shape values may cause overflow in AccDataTensorList internals.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AUDIO-002] unvalidated_parameter - LoadAudioData

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `AccSDK/source/audio/Audio.cpp:50-55` @ `LoadAudioData`
**模块**: audio
**跨模块**: audio → utils

**描述**: LoadAudioData 函数仅检查 audioData.sampleRate <= 0，未对采样率设置合理的下限(如最低标准采样率 8000 Hz)。恶意 WAV 文件可包含极端采样率值(如 1 Hz)，导致后续重采样计算产生异常大的缓冲区分配请求，可能触发资源耗尽或 32 位系统上的整数溢出。

**漏洞代码** (`AccSDK/source/audio/Audio.cpp:50-55`)

```c
if (audioData.samples.empty() || audioData.numChannels <= 0 || audioData.sampleRate <= 0) {
    LogError << "Invalid audio data: empty samples, zero channels or zero sample rate."
             << GetErrorInfo(ERR_INVALID_PARAM);
    return ERR_INVALID_PARAM;
}
```

**达成路径**

[CREDENTIAL_FLOW] utils/AudioUtils.cpp:465 AudioDecode() [SOURCE] 解析 WAV fmt.sampleRate → Audio.cpp:50 sampleRate <= 0 检查(缺少下限验证) → Audio.cpp:109-112 重采样计算异常

**验证说明**: LoadAudioData: sampleRate <= 0 check exists but no lower bound (e.g. >=8000). Root cause of VULN-SEC-AUDIO-001. Crafted WAV can have sampleRate=1Hz causing extreme resampling ratio.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: -15

---

### [VULN-SEC-AUDIO-003] resource_exhaustion - ResampleAudio

**严重性**: Medium | **CWE**: CWE-789 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `AccSDK/source/audio/Audio.cpp:111-114` @ `ResampleAudio`
**模块**: audio
**跨模块**: audio → utils

**描述**: ResampleAudio 在 sr.has_value() 分支中分配 vector<float>(expectedOutputLen)，未检查 expectedOutputLen 的合理上限。50MB WAV 文件解析后约 25M 样本，64 倍重采样可请求分配 ~1.6G 元素(6.4GB 内存)，可能导致内存耗尽拒绝服务。

**漏洞代码** (`AccSDK/source/audio/Audio.cpp:111-114`)

```c
expectedOutputLen = std::ceil(static_cast<double>(monoAudio.size()) * ratio);
std::shared_ptr<std::vector<float>> buffer = std::make_shared<std::vector<float>>(expectedOutputLen);
```

**达成路径**

[CREDENTIAL_FLOW] utils/AudioUtils.cpp:469 ReadFile() [SOURCE] 50MB 文件 → Audio.cpp:60 numSamplesPerChannel 计算 → Audio.cpp:61 monoAudio.resize() → Audio.cpp:111 expectedOutputLen 过大 → Audio.cpp:112 vector 分配过大 [SINK]

**验证说明**: ResampleAudio: expectedOutputLen can be very large (up to 64000x monoAudio.size()). No upper bound check. 50MB WAV -> 25M samples -> 64x resample -> 1.6GB allocation. Resource exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: -15

---

### [VULN-SEC-UTILS-003] missing_validation - CheckAudioFormat

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/utils/AudioUtils.cpp:331-344` @ `CheckAudioFormat`
**模块**: utils

**描述**: CheckAudioFormat validates audioFormat and bitsPerSample but does NOT validate numChannels upper bound. A malicious WAV file could set numChannels=0 (causing division by zero) or numChannels to an extremely large value causing integer overflow in downstream calculations.

**漏洞代码** (`AccSDK/source/utils/AudioUtils.cpp:331-344`)

```c
ErrorCode CheckAudioFormat(const WavFmt& fmt)
{
    if (fmt.audioFormat != WAVE_FORMAT_PCM && fmt.audioFormat != WAVE_FORMAT_IEEE_FLOAT) {...}
    if (fmt.bitsPerSample != BITS_PER_SAMPLE_16 && ...) {...}
    // Missing: numChannels validation
    return SUCCESS;
}
```

**达成路径**

AudioUtils.cpp:274 memcpy_s(&fmt, ...) → fmt.numChannels [TAINTED] → CheckAudioFormat() [MISSING VALIDATION] → AudioDecode() downstream calculations

**验证说明**: CheckAudioFormat validates audioFormat and bitsPerSample but NOT numChannels. Root cause of VULN-UTILS-AUDIO-001. numChannels=0 causes div-by-zero, large numChannels causes overflow.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: -15 | cross_file: -15

---

### [VULN-PYBIND-007] missing_parameter_validation - Qwen2VLProcessor::Preprocess

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyPreprocess.cpp:33-72` @ `Qwen2VLProcessor::Preprocess`
**模块**: py_bindings
**跨模块**: py_bindings,fusion_operators

**描述**: Qwen2VLProcessor::Preprocess accepts mean/std vectors without size validation. While empty image check exists, mean/std vector sizes are not validated against expected channel count (should be 3 for RGB).

**漏洞代码** (`AccSDK/source/py/module/PyPreprocess.cpp:33-72`)

```c
std::vector<Tensor> Preprocess(const std::vector<Image>& pyImages, const std::vector<float>& mean, ...) { Acc::QwenPreprocessConfig config{mean, std, ...}; }
```

**达成路径**

[IN] Python mean/std vectors → PyPreprocess.cpp:33 Preprocess() → [OUT] fusion_operators module Qwen2VLImagePreprocess

**验证说明**: mean/std passed to QwenPreprocessConfig. Empty image check exists but no mean/std size validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-UTILS-004] toctou - VideoDecode

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/video/Video.cpp:313-325` @ `VideoDecode`
**模块**: utils
**跨模块**: video → utils

**描述**: TOCTOU race condition in video file handling. IsFileValid(path) validates file at line 313, but avformat_open_input uses the same path string at line 136 (via InitVideoInfo). Between validation and use, attacker could replace the validated file with a symlink or malicious file, bypassing the security checks.

**漏洞代码** (`AccSDK/source/video/Video.cpp:313-325`)

```c
if (!IsFileValid(path)) {...
    return ERR_INVALID_PARAM;
}
...
ret = VideoDecodeCpu(path, frames, frameIndices, sampleNum);
```

**达成路径**

Video.cpp:313 IsFileValid(path) [TIME OF CHECK] → Video.cpp:325 VideoDecodeCpu(path) → Video.cpp:291 InitVideoInfo(path) → Video.cpp:136 avformat_open_input(path) [TIME OF USE]
[CREDENTIAL_FLOW] Same path string used after validation without re-validation.

**验证说明**: TOCTOU: Video.cpp:313 IsFileValid(path) then Video.cpp:325 VideoDecodeCpu(path). Same path string, no re-validation. Attacker can replace file between check and use. Related to VULN-SEC-VID-001.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-VID-001] race_condition - DecodeKeyframesParallel

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/video/Video.cpp:190-233` @ `DecodeKeyframesParallel`
**模块**: video
**跨模块**: video → utils

**描述**: Time-of-check to time-of-use (TOCTOU) race condition: IsFileValid() validates path (symlink/owner/permissions) in single-threaded VideoDecode(), but multiple threads in DecodeKeyframesParallel() open the same file via FFmpeg (avformat_open_input) without re-validation. Between validation and parallel file opens, an attacker could replace the validated file with a symlink to another file owned by the same user.

**漏洞代码** (`AccSDK/source/video/Video.cpp:190-233`)

```c
futures.push_back(pool.Submit([i, &targetKeyframeIndices, &videoAuxInfo, path, &results, &errorOccurred, &resultsMutex]() {
    auto ret = VideoDecodeSeek(path, targetKeyframeIndices[i], videoAuxInfo, threadResult); // path validated earlier but used here without re-check
}))
```

**达成路径**

Video.cpp:313 IsFileValid(path) [VALIDATION]
Video.cpp:325 VideoDecodeCpu(path)
Video.cpp:291 InitVideoInfo(path)
Video.cpp:206 VideoDecodeSeek(path) [TOCTOU GAP]
VideoUtils.cpp:442 OpenInputFile(file)
VideoUtils.cpp:45 avformat_open_input(&formatCtx, file.c_str()) [SINK - FILE OPEN WITHOUT RE-VALIDATION]

**验证说明**: DecodeKeyframesParallel: Each thread opens file via avformat_open_input without re-validating path. IsFileValid check (Video.cpp:313) done before threads spawn. TOCTOU: attacker can replace file between check and thread file opens. Related to VULN-SEC-UTILS-004.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-CORE-002] null_pointer_dereference - Pipeline::Run

**严重性**: Medium | **CWE**: CWE-476 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/core/framework/Pipeline.cpp:111-112` @ `Pipeline::Run`
**模块**: core_framework

**描述**: Pipeline::Run 方法中直接使用 input->second[i].Ptr() 而没有检查是否为 nullptr。如果传入的张量数据指针为空，会导致后续 ShareData() 调用崩溃。

**漏洞代码** (`AccSDK/source/core/framework/Pipeline.cpp:111-112`)

```c
std::shared_ptr<void> tensorSharedPtr(input->second[i].Ptr(), [](void*) {});
accDataRet = tensorList->operator[](i).ShareData(tensorSharedPtr, input->second[i].Shape(), tensorDataType);
```

**达成路径**

Pipeline::Run() 接收 inputs 参数 → input->second[i].Ptr() 可能返回 nullptr → ShareData() 使用 nullptr 导致崩溃

**验证说明**: Pipeline::Run: input->second[i].Ptr() used without null check. ShareData may crash if Ptr() returns nullptr. Depends on caller providing valid Tensor.

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-007] improper_input_validation - Image::from_numpy

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `AccSDK/source/py/module/PyImage.cpp:158-203` @ `Image::from_numpy`
**模块**: py_bindings
**跨模块**: py_bindings → image

**描述**: Image::from_numpy(PyObject* pyObj, ...) accepts PyObject* for numpy array and device string without validation. GetNumpyData() extracts pointer, but device string passed directly to Acc::Image constructor. No validation that device string matches expected values (e.g., 'cpu', 'xpu').

**漏洞代码** (`AccSDK/source/py/module/PyImage.cpp:158-203`)

```c
Image Image::from_numpy(PyObject* pyObj, Acc::ImageFormat imageFormat, const char* device)
{
    NumpyData numpyData = GetNumpyData(pyObj);
    ...
    Acc::Image imgAcc(numpyData.dataPtr, imSize, imageFormat, numpyData.dataType, device);
    Image img;
    img.SetImage(imgAcc);
    return img;
}
```

**达成路径**

[CREDENTIAL_FLOW] Python Image.from_numpy(pyObj, format, device) → PyImage.cpp:158 from_numpy(PyObject*, device) → GetNumpyData() → Acc::Image(dataPtr, ..., device) [SINK - image module]

**验证说明**: from_numpy: GetNumpyData has checks, CheckDeviceFromConstructor validates device string. Limited attack surface.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-IMG-002] Integer Overflow in Tensor Size Calculation - Tensor::FillAuxInfo

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `AccSDK/source/tensor/Tensor.cpp:43` @ `Tensor::FillAuxInfo`
**模块**: image
**跨模块**: image → tensor

**描述**: Multiplication elementNums * perElementBytes in FillAuxInfo without overflow check. While stride overflow is checked, totalBytes multiplication is unchecked. Could cause undersized allocation if bounds validation is bypassed.

**漏洞代码** (`AccSDK/source/tensor/Tensor.cpp:43`)

```c
auxInfo_.totalBytes = auxInfo_.elementNums * auxInfo_.perElementBytes;
```

**达成路径**

[IN] Tensor shape from Image → FillAuxInfo → totalBytes → Clone allocation → memcpy_s

**验证说明**: Tensor::FillAuxInfo (line 43): elementNums * perElementBytes not checked against SIZE_MAX. Stride overflow checked against UINT_MAX (line 48-57) but not size_t overflow. 32-bit system risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-UTILS-AUDIO-004] Out-of-Bounds Read - ConvertPcm16ToFloatScalar/ConvertPcm24ToFloatScalar

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/MultimodalSDK/AccSDK/source/utils/AudioUtils.cpp:99-176` @ `ConvertPcm16ToFloatScalar/ConvertPcm24ToFloatScalar`
**模块**: utils
**跨模块**: utils,audio

**描述**: Potential out-of-bounds read in PCM conversion functions. ConvertPcm16ToFloatScalar, ConvertPcm24ToFloatScalar access raw buffer with calculated offsets without explicit bounds checking against raw buffer size.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/MultimodalSDK/AccSDK/source/utils/AudioUtils.cpp:99-176`)

```c
const size_t offset = i * bytesPerSample;\nint16_t sample = static_cast<int16_t>(raw[offset] | (raw[offset + 1] << 8));
```

**达成路径**

ConvertAudioDataToFloat -> raw.data() -> conversion loop (SINK: array access without bounds check)

**验证说明**: PCM conversion functions use calculated offsets. Depends on caller correctly computing numSamples. Need to trace expectedSize calculation from AudioDecode.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-SEC-PY-004] path_traversal - load_audio_impl

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `AccSDK/source/py/module/PyAudio.cpp:31-40` @ `load_audio_impl`
**模块**: py_bindings
**跨模块**: py_bindings → audio

**描述**: load_audio_impl(const std::string& path) passes audio file path directly to LoadAudioSingle() without validation. Path flows from Python through std::string to C++ audio module. Multiple entry points: load_audio() and load_audio with sr parameter.

**漏洞代码** (`AccSDK/source/py/module/PyAudio.cpp:31-40`)

```c
void load_audio_impl(const std::string& path, Tensor& dst, int& originalSr, std::optional<int> sr)
{
    Acc::Tensor tensor;
    Acc::ErrorCode ret = LoadAudioSingle(path.c_str(), tensor, originalSr, sr);
    if (ret != Acc::SUCCESS) {
        throw std::runtime_error(std::string("LoadAudio failed"));
    }
    dst.SetTensor(tensor);
}
```

**达成路径**

[CREDENTIAL_FLOW] Python load_audio(path) → PyAudio.cpp:61/68 load_audio(std::string path) → PyAudio.cpp:35 LoadAudioSingle(path.c_str()) [SINK - audio module]

**验证说明**: Duplicate of VULN-PYBIND-003. Has CheckSingleAudioInputs validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: -15

---

### [VULN-PYBIND-003] missing_path_validation - load_audio_impl

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyAudio.cpp:31-40` @ `load_audio_impl`
**模块**: py_bindings
**跨模块**: py_bindings,audio,mm_acc_wrapper

**描述**: load_audio_impl accepts audio file path without validation.

**漏洞代码** (`AccSDK/source/py/module/PyAudio.cpp:31-40`)

```c
load_audio_impl(path) { LoadAudioSingle(path.c_str(), ...); }
```

**达成路径**

[IN] Python → PyAudio.cpp:31 → [OUT] audio module

**验证说明**: CheckSingleAudioInputs has IsFileValid check (Audio.cpp:220). Path validated before reaching AudioDecode.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: -15

---

### [VULN-PYBIND-004] missing_path_validation - load_audio_batch_impl

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyAudio.cpp:42-55` @ `load_audio_batch_impl`
**模块**: py_bindings
**跨模块**: py_bindings,audio,mm_acc_wrapper

**描述**: load_audio_batch_impl accepts vector of file paths without validation.

**漏洞代码** (`AccSDK/source/py/module/PyAudio.cpp:42-55`)

```c
load_audio_batch_impl(wavFiles) { LoadAudioBatch(wavFiles, ...); }
```

**达成路径**

[IN] Python → PyAudio.cpp:42 → [OUT] audio module

**验证说明**: Same as VULN-PYBIND-003. CheckSingleAudioInputs validates each path in batch.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: -15

---

## 5. Low 漏洞 (4)

### [VULN-SEC-VID-003] resource_exhaustion - DecodeKeyframesParallel

**严重性**: Low | **CWE**: CWE-400 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `AccSDK/source/video/Video.cpp:198-216` @ `DecodeKeyframesParallel`
**模块**: video
**跨模块**: video → utils

**描述**: Potential file descriptor exhaustion: DecodeKeyframesParallel opens the same video file in multiple parallel threads via FFmpeg avformat_open_input. Each thread maintains its own AVFormatContext and AVCodecContext, consuming file descriptors and memory. With large keyframe counts, this could exhaust system resources (typically ~1024 file descriptors per process).

**漏洞代码** (`AccSDK/source/video/Video.cpp:198-216`)

```c
for (size_t i = 0; i < targetKeyframeIndices.size(); i++) {
    futures.push_back(pool.Submit([...VideoDecodeSeek(path, ...)...])); // each thread opens file via avformat_open_input
}
```

**达成路径**

[CREDENTIAL_FLOW] Video.cpp:313 IsFileValid(path) [utils module validation]
Video.cpp:206 VideoDecodeSeek(path) repeated in each thread
VideoUtils.cpp:45 avformat_open_input(&formatCtx, file.c_str()) [FFmpeg - opens file descriptor per thread]

**验证说明**: DecodeKeyframesParallel: Each thread opens file descriptor via FFmpeg. With many keyframes, can exhaust ~1024 fd limit per process. Resource exhaustion attack.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PYBIND-008] missing_shape_validation - GetNumpyData

**严重性**: Low | **CWE**: CWE-129 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `AccSDK/source/py/module/PyUtil.cpp:97-105` @ `GetNumpyData`
**模块**: py_bindings
**跨模块**: py_bindings,tensor

**描述**: GetNumpyData shape extraction lacks upper bound validation.

**漏洞代码** (`AccSDK/source/py/module/PyUtil.cpp:97-105`)

```c
PyLong_AsSize_t(dim); shape.push_back(dimSize);
```

**达成路径**

[IN] Python numpy → PyUtil.cpp:99 → [OUT] tensor module

**验证说明**: Shape dimensions extracted without upper bound. Only >0 check. Memory exhaustion possible with extreme values.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-TENSOR-002] integer_overflow - Tensor::FillAuxInfo

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `AccSDK/source/tensor/Tensor.cpp:40-59` @ `Tensor::FillAuxInfo`
**模块**: tensor

**描述**: FillAuxInfo() calculates totalBytes (line 43) by multiplying elementNums and perElementBytes without overflow protection. While stride calculations are checked against UINT_MAX (lines 48-57), the size_t multiplication at line 43 is not checked against SIZE_MAX. On 32-bit systems, if shape product * element_size exceeds 4GB, totalBytes wraps, causing incorrect memory sizing and potential data truncation in Clone().

**漏洞代码** (`AccSDK/source/tensor/Tensor.cpp:40-59`)

```c
// Line 41-43:
auxInfo_.elementNums = std::accumulate(shape_.begin(), shape_.end(), static_cast<size_t>(1), std::multiplies<size_t>());
auxInfo_.perElementBytes = GetByteSize(dataType_);
auxInfo_.totalBytes = auxInfo_.elementNums * auxInfo_.perElementBytes;  // No overflow check

// Stride loop checks UINT_MAX but not SIZE_MAX:
uint32_t currentStrideBase = 1;
for (size_t i = shape_.size(); i > 0; i--) {
    if (UINT_MAX / auxInfo_.perElementBytes < currentStrideBase) {...}  // Only checks uint32_t overflow
```

**达成路径**

Tensor.cpp:41 elementNums = product(shape) [potential size_t overflow]
Tensor.cpp:43 totalBytes = elementNums * perElementBytes [unchecked size_t multiplication]
Tensor.cpp:115 Clone() uses totalBytes for allocation [downstream impact]

**验证说明**: FillAuxInfo: totalBytes = elementNums * perElementBytes unchecked for size_t overflow. Stride checks use UINT_MAX but totalBytes multiplication not protected. 32-bit system overflow risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-IMG-003] ImplicitMalloc Integer Overflow - ResizeChecker::ImplicitMalloc

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `AccSDK/source/tensor/checker/OpsCustomChecker.cpp:136-139` @ `ResizeChecker::ImplicitMalloc`
**模块**: image
**跨模块**: image → tensor

**描述**: std::accumulate multiplication for totalBytes in ResizeChecker::ImplicitMalloc lacks explicit overflow check. Values bounded by CheckImSize (MAX 8192) but defensive overflow check recommended.

**漏洞代码** (`AccSDK/source/tensor/checker/OpsCustomChecker.cpp:136-139`)

```c
auto totalBytes = std::accumulate(dstShape.begin(), dstShape.end(), static_cast<size_t>(1), std::multiplies<size_t>()) * GetByteSize(src.DType());\nchar* data = new(std::nothrow) char[totalBytes];
```

**达成路径**

[IN] ImageResize params → ResizeChecker → ImplicitMalloc → new[] allocation → Tensor

**验证说明**: ResizeChecker::ImplicitMalloc uses std::accumulate for totalBytes. CheckImSize limits dimensions to 8192 but defensive overflow check recommended for robustness.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: -10

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| audio | 0 | 1 | 2 | 0 | 3 |
| core_framework | 0 | 1 | 3 | 0 | 4 |
| image | 0 | 0 | 1 | 1 | 2 |
| py_bindings | 0 | 2 | 6 | 1 | 9 |
| tensor | 0 | 0 | 0 | 1 | 1 |
| utils | 0 | 0 | 3 | 0 | 3 |
| video | 0 | 0 | 1 | 1 | 2 |
| **合计** | **0** | **4** | **16** | **4** | **24** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 4 | 16.7% |
| CWE-190 | 4 | 16.7% |
| CWE-22 | 3 | 12.5% |
| CWE-129 | 3 | 12.5% |
| CWE-400 | 2 | 8.3% |
| CWE-367 | 2 | 8.3% |
| CWE-789 | 1 | 4.2% |
| CWE-704 | 1 | 4.2% |
| CWE-476 | 1 | 4.2% |
| CWE-416 | 1 | 4.2% |
| CWE-125 | 1 | 4.2% |
| CWE-119 | 1 | 4.2% |
