# VULN-SEC-VID-002: Integer Overflow in Frame Index Calculation

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-VID-002 |
| **CWE类型** | CWE-190: Integer Overflow or Wraparound |
| **严重性** | Medium |
| **置信度** | 85/100 |
| **状态** | CONFIRMED |
| **发现模块** | video |
| **文件位置** | AccSDK/source/video/Video.cpp:105-108 |
| **函数** | CheckTargetFrameIndices |

## 漏洞描述

在 `CheckTargetFrameIndices` 函数中存在整数溢出漏洞。当处理用户提供的视频文件时，帧数 `nFrames` 来源于视频文件元数据（FFmpeg 的 `nb_frames` 字段）。如果该值非常大（接近 UINT32_MAX），在计算帧索引时 `i * (nFrames - 1)` 的乘法运算会在除法之前发生 uint32_t 溢出，导致生成错误的帧索引。

## 漏洞代码

**位置**: `AccSDK/source/video/Video.cpp:75-110`

```cpp
ErrorCode CheckTargetFrameIndices(uint32_t nFrames, std::set<uint32_t>& frameIndices, int sampleNum)
{
    if (nFrames == 0) {
        // ... error handling
    }
    // ...
    if (sampleNum == 1) {
        frameIndices.insert(0);
        return SUCCESS;
    }
    uint32_t validSampleNum = static_cast<uint32_t>(sampleNum);
    for (uint32_t i = 0; i < validSampleNum; i++) {
        // VULNERABILITY: i * (nFrames - 1) can overflow uint32_t
        uint32_t idx = static_cast<uint32_t>(i * (nFrames - 1) / (validSampleNum - 1));
        frameIndices.insert(idx);  // Line 106
    }
    return SUCCESS;
}
```

**数据流源点** (`AccSDK/source/video/Video.cpp:163-172`):

```cpp
int64_t totalFrames = 0;
ret = GetFramesAndFPS(videoStream, originFps, totalFrames);  // totalFrames from video file header
// ...
ret = CheckTargetFrameIndices(totalFrames, targetIndices, sampleNum);  // Implicit int64_t -> uint32_t narrowing
```

**GetFramesAndFPS 实现** (`AccSDK/source/utils/VideoUtils.cpp:264-296`):

```cpp
ErrorCode GetFramesAndFPS(AVStream* videoStream, double& originFps, int64_t& totalFrames)
{
    totalFrames = videoStream->nb_frames;  // User-controlled from video file metadata
    // ...
}
```

## 数据流分析

```
[Source] video file (nb_frames metadata)
    │
    ▼
FFmpeg avformat_open_input() / avformat_find_stream_info()
    │
    ▼
videoStream->nb_frames (int64_t, user-controlled)
    │
    ▼
GetFramesAndFPS() → totalFrames (int64_t)
    │
    ▼
[IMPLICIT NARROWING] int64_t → uint32_t at CheckTargetFrameIndices call (line 172)
    │
    ▼
CheckTargetFrameIndices(uint32_t nFrames, ...)
    │
    ▼
[SINK - INTEGER OVERFLOW] i * (nFrames - 1) at line 106
```

## 漏洞根因分析

### 问题1: 类型窄化转换 (Type Narrowing)

`totalFrames` 是 `int64_t` 类型，但 `CheckTargetFrameIndices` 函数接受 `uint32_t nFrames`。在调用时发生隐式类型转换：

```cpp
// Video.cpp:172
ret = CheckTargetFrameIndices(totalFrames, targetIndices, sampleNum);
// totalFrames (int64_t) → nFrames (uint32_t) 隐式转换
```

如果 `totalFrames > UINT32_MAX`，高位被截断，`nFrames` 会得到一个错误的较小值。

### 问题2: 整数溢出 (Integer Overflow)

在 `CheckTargetFrameIndices` 中：

```cpp
uint32_t idx = static_cast<uint32_t>(i * (nFrames - 1) / (validSampleNum - 1));
```

乘法运算 `i * (nFrames - 1)` 在 uint32_t 空间内进行，当：
- `nFrames` 接近 UINT32_MAX（约 42.9 亿）
- `i >= 2` 时

乘法结果会溢出 uint32_t 范围，导致计算出的 `idx` 值错误。

**溢出示例**:
```
假设 nFrames = 0x80000001 (约 21.5 亿)
当 i = 2 时:
  i * (nFrames - 1) = 2 * 0x80000000 = 0x100000000
  但 uint32_t 只能容纳 32 位，结果变为 0x00000000
  最终 idx = 0 / (validSampleNum - 1) = 0
```

## 攻击向量

1. **攻击入口**: 用户提供的视频文件
2. **信任级别**: untrusted_local
3. **攻击方式**: 
   - 制作恶意视频文件，在元数据中设置极大的 `nb_frames` 值
   - 例如: 将 `nb_frames` 设置为接近 UINT32_MAX 的值
4. **攻击结果**:
   - 生成的帧索引错误，可能导致：
     - 跳过预期的帧
     - 重复处理相同的帧
     - 后续解码操作中可能出现未定义行为

## 影响范围

### 受影响的代码路径

```
video_decode@MultimodalSDK/source/mm/acc/wrapper/video_wrapper.py:27
    │
    ▼
VideoDecode@AccSDK/source/video/Video.cpp:305
    │
    ▼
VideoDecodeCpu@AccSDK/source/video/Video.cpp:283
    │
    ▼
InitVideoInfo@AccSDK/source/video/Video.cpp:130
    │
    ├── GetFramesAndFPS (获取 nb_frames)
    │
    └── CheckTargetFrameIndices (整数溢出点)
```

### 受影响的调用者

- Python API: `MultimodalSDK/source/mm/acc/wrapper/video_wrapper.py:27` - `video_decode()`
- C++ API: `AccSDK/source/video/Video.cpp:305` - `VideoDecode()`

## 现有缓解措施

### 已存在的检查

1. **帧数有效性检查** (Video.cpp:77-79):
   ```cpp
   if (nFrames == 0) {
       LogError << "The frame number for decoding video must be greater than zero."
       return ERR_OUT_OF_RANGE;
   }
   ```

2. **sampleNum 范围检查** (Video.cpp:95-98):
   ```cpp
   if (static_cast<uint32_t>(sampleNum) > nFrames || sampleNum < 1) {
       // error
   }
   ```

3. **分辨率限制** (VideoUtils.h:43-46):
   ```cpp
   constexpr uint32_t MAX_STREAM_HEIGHT = 4096;
   constexpr uint32_t MAX_STREAM_WIDTH = 4096;
   constexpr uint32_t MIN_STREAM_HEIGHT = 480;
   constexpr uint32_t MIN_STREAM_WIDTH = 480;
   ```

### 缺失的保护

- **无帧数上限检查**: 虽然分辨率有上限，但 `nb_frames` 没有上限检查
- **无整数溢出保护**: 乘法运算没有使用安全的整数运算

## 修复建议

### 建议1: 添加帧数上限检查

```cpp
// 在 CheckTargetFrameIndices 或 InitVideoInfo 中添加
constexpr uint32_t MAX_FRAMES = 100000000; // 1亿帧，远超实际视频需求

if (totalFrames > MAX_FRAMES) {
    LogError << "Frame count exceeds maximum allowed limit.";
    return ERR_OUT_OF_RANGE;
}
```

### 建议2: 使用安全的整数运算

```cpp
// 方案A: 使用 64 位运算
uint64_t numerator = static_cast<uint64_t>(i) * static_cast<uint64_t>(nFrames - 1);
uint64_t denominator = static_cast<uint64_t>(validSampleNum - 1);
uint32_t idx = static_cast<uint32_t>(numerator / denominator);

// 方案B: 添加溢出检查
if (nFrames > UINT32_MAX / validSampleNum) {
    // potential overflow, handle error
}
```

### 建议3: 修复类型窄化问题

```cpp
// 修改函数签名，使用 int64_t
ErrorCode CheckTargetFrameIndices(int64_t nFrames, std::set<uint32_t>& frameIndices, int sampleNum)
{
    // 添加范围检查
    if (nFrames <= 0 || nFrames > MAX_FRAMES) {
        return ERR_OUT_OF_RANGE;
    }
    // ...
}
```

## 修复优先级

| 因素 | 评分 |
|------|------|
| 基础分数 | 30 |
| 可达性 | 30 (用户输入直接触发) |
| 可控性 | 25 (通过视频文件元数据控制) |
| 缓解措施 | 0 (无有效缓解) |
| **综合严重性** | **Medium** |

## 测试用例

### PoC 构造思路

1. 创建一个 MP4 文件，修改其 `nb_frames` 元数据为极大值
2. 使用 FFmpeg 命令修改:
   ```bash
   # 需要手动编辑视频容器元数据
   ffmpeg -i input.mp4 -c copy -metadata:s:v:0 nb_frames=4294967295 output.mp4
   ```

### 预期行为

- 当前行为: 可能生成错误的帧索引，无错误提示
- 期望行为: 应检测到异常帧数并返回错误

## 相关漏洞

- **VULN-SEC-TENSOR-001**: 同文件中的缓冲区过度读取漏洞

## 参考资料

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [SEI CERT C Coding Standard: INT30-C](https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap)
- FFmpeg Documentation: `nb_frames` field in AVStream

---
*报告生成时间: 2026-04-20*
*分析工具: security-module-scanner*
