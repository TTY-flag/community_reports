# VULN-PYBIND-002 漏洞分析报告

## 漏洞判定：误报 (FALSE POSITIVE)

---

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-PYBIND-002 |
| **原始分类** | CWE-22 路径遍历 |
| **原始位置** | `AccSDK/source/py/module/PyVideo.cpp:30` |
| **原始严重性** | High |
| **验证结果** | **误报 - 存在有效的安全防护机制** |

---

## 2. 完整数据流分析

### 2.1 调用链路

```
Python 层                           C++ 绑定层                          C++ 实现层
─────────────────────────────────────────────────────────────────────────────────
video_wrapper.py:27-49
├── video_decode(video_path, device, frame_indices, sample_num)
│   │
│   └── path_bytes = _ensure_bytes(video_path, "path")
│   │
│   └── _acc.video_decode(path_bytes, device_bytes, frame_indices, sample_num)
│                                          │
│                                          ▼
│                              PyVideo.cpp:30-47
│                              └── video_decode(const char* path, ...)
│                                  └── Acc::VideoDecode(path, device, ...)
│                                         │
│                                         ▼
│                              Video.cpp:305-330
│                              └── VideoDecode(const char* path, ...)
│                                  ├── ✅ IsFileValid(path) [安全检查]
│                                  ├── ✅ CheckFileExtension(path, "mp4")
│                                  └── VideoDecodeCpu(path, ...)
│                                         │
│                                         ▼
│                              Video.cpp:283-303
│                              └── VideoDecodeCpu(const char* path, ...)
│                                  └── InitVideoInfo(path, ...)
│                                         │
│                                         ▼
│                              Video.cpp:130-188
│                              └── InitVideoInfo(const char* path, ...)
│                                  └── avformat_open_input(&formatCtx, path, ...)
│                                         │
│                                         ▼
│                              FFmpeg libavformat
│                              └── avformat_open_input() [最终使用点]
```

### 2.2 安全检查机制详解

#### 2.2.1 VideoDecode 入口验证 (Video.cpp:305-330)

```cpp
ErrorCode VideoDecode(const char* path, const char* device, std::vector<Image>& frames,
                      const std::set<uint32_t>& frameIndices, int sampleNum)
{
    if (!device || strcmp(device, "cpu") != 0) {
        return ERR_UNSUPPORTED_TYPE;
    }
    
    // 关键安全检查 1: 文件路径有效性验证
    if (!IsFileValid(path)) {
        LogError << "Video decode failed, video path is invalid.";
        return ERR_INVALID_PARAM;
    }

    // 关键安全检查 2: 文件扩展名验证
    if (!CheckFileExtension(path, "mp4")) {
        LogError << "Video decode failed, invalid video suffix, only support 'mp4', 'MP4'.";
        return ERR_INVALID_PARAM;
    }
    
    return VideoDecodeCpu(path, frames, frameIndices, sampleNum);
}
```

#### 2.2.2 路径验证 (FileUtils.cpp:128-158)

```cpp
bool CheckFilePath(const std::string& path)
{
    // 1. 空路径检查
    if (path.empty()) { return false; }
    
    // 2. 路径长度限制 (4096 字符)
    if (path.size() > FILE_PATH_MAX) { return false; }
    
    // 3. 转换为绝对路径
    fs::path pathObj = fs::absolute(path);
    
    // 4. 文件存在性检查
    if (!fs::exists(pathObj)) { return false; }
    
    // 5. 符号链接检查 - 阻止符号链接攻击
    if (fs::is_symlink(pathObj)) { return false; }
    
    // 6. 普通文件检查
    if (!fs::is_regular_file(pathObj)) { return false; }
    
    return true;
}
```

#### 2.2.3 文件所有者验证 (FileUtils.cpp:160-176)

```cpp
bool CheckFileOwner(const std::string& path)
{
    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) != 0) { return false; }
    
    uid_t currentUid = getuid();
    // 关键安全检查：文件必须属于当前进程用户
    if (fileStat.st_uid != currentUid) {
        LogError << "File owner mismatch. Process UID: " << currentUid 
                 << ", file UID: " << fileStat.st_uid;
        return false;
    }
    return true;
}
```

#### 2.2.4 文件权限验证 (FileUtils.cpp:178-201)

```cpp
bool CheckFilePermission(const std::string& path, const mode_t mode)
{
    // 检查文件权限不超过 0640 (rw-r-----)
    // 这进一步限制了可读取的文件范围
}
```

#### 2.2.5 综合验证入口 (FileUtils.cpp:203-223)

```cpp
bool IsFileValid(const char* path)
{
    if (!path) { return false; }
    std::string pathStr(path);
    if (!CheckFilePath(pathStr))   { return false; }  // 路径、符号链接检查
    if (!CheckFileOwner(pathStr))  { return false; }  // 所有者检查
    if (!CheckFilePermission(pathStr, 0640)) { return false; }  // 权限检查
    return true;
}
```

---

## 3. 与 VULN-PYBIND-001 对比分析

### 3.1 相同的安全架构

| 漏洞 | 文件类型 | 安全检查位置 | IsFileValid调用 |
|------|----------|--------------|-----------------|
| VULN-PYBIND-001 | 图像 (JPEG) | ImageUtils.cpp:64 | ✅ 存在 |
| VULN-PYBIND-002 | 视频 (MP4) | Video.cpp:313 | ✅ 存在 |

### 3.2 相同的验证函数

两个漏洞都调用相同的 `IsFileValid()` 函数，包含：

1. **CheckFilePath()** - 路径有效性、符号链接检测
2. **CheckFileOwner()** - 文件所有者验证（关键防护）
3. **CheckFilePermission()** - 权限限制

### 3.3 VULN-PYBIND-001 已判定为误报

根据已完成的 VULN-PYBIND-001 分析：
- 判定结果：**误报 (FALSE POSITIVE)**
- 原因：`IsFileValid()` 的多层安全检查有效阻止路径遍历

VULN-PYBIND-002 具有完全相同的安全机制，应采用相同的判定逻辑。

---

## 4. 误报原因分析

### 4.1 原报告的局限性

原始报告只分析了以下数据流：
```
Python → PyVideo.cpp:30 → VideoDecode → FFmpeg
```

但未深入分析 `VideoDecode` 函数内部的安全检查机制：
```cpp
// Video.cpp:305-330
ErrorCode VideoDecode(const char* path, ...)
{
    if (!IsFileValid(path)) {  // ← 关键安全检查被遗漏
        return ERR_INVALID_PARAM;
    }
    if (!CheckFileExtension(path, "mp4")) {  // ← 扩展名限制
        return ERR_INVALID_PARAM;
    }
    // ...
}
```

### 4.2 安全机制有效性证明

| 攻击场景 | 防护机制 | 结果 |
|----------|----------|------|
| `../../../etc/passwd` | `CheckFileOwner` 要求文件属于当前用户 | ✅ 阻止 |
| `/etc/shadow` | `CheckFileOwner` + `CheckFilePermission` | ✅ 阻止 |
| 符号链接指向敏感文件 | `fs::is_symlink()` 检查 | ✅ 阻止 |
| 设备文件 (`/dev/null`) | `fs::is_regular_file()` 检查 | ✅ 阻止 |
| 空路径/超长路径 | `CheckFilePath` 边界检查 | ✅ 阻止 |
| 非 MP4 文件 | `CheckFileExtension(path, "mp4")` | ✅ 阻止 |

### 4.3 关键防护：文件所有者检查

`CheckFileOwner` 是最关键的防护措施：

```cpp
uid_t currentUid = getuid();
if (fileStat.st_uid != currentUid) {
    LogError << "File owner mismatch...";
    return false;
}
```

这意味着：
- SDK 进程以用户 A 运行，只能读取用户 A 拥有的文件
- 即使攻击者传入 `/etc/passwd`，该文件属于 root，检查失败
- 即使攻击者传入 `/home/userB/secret.txt`，文件属于用户 B，检查失败
- 路径遍历攻击仅限于当前用户有权限的文件范围内

---

## 5. 信任边界分析

### 5.1 SDK 架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  (负责验证用户输入，定义允许访问的目录)                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Python Wrapper (video_wrapper.py)              │
│  类型转换，无路径验证（正确：由底层统一处理）                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│               PyBind11 Layer (PyVideo.cpp)                  │
│  参数传递，无路径验证（正确：由底层统一处理）                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                C++ Core Layer (Video.cpp)                   │
│  ✅ IsFileValid() - 统一的安全验证入口                        │
│  ✅ CheckFileExtension() - 扩展名限制                        │
│  业务逻辑处理                                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Security Layer (FileUtils.cpp)                 │
│  ✅ CheckFilePath() - 路径有效性、符号链接检查                │
│  ✅ CheckFileOwner() - 文件所有者验证                         │
│  ✅ CheckFilePermission() - 权限限制                         │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 安全分层设计评估

| 层级 | 验证责任 | 评估 |
|------|----------|------|
| Application | 输入验证、目录白名单 | 应用层责任 |
| Python Wrapper | 类型转换 | 正确 |
| PyBind11 | 参数传递 | 正确 |
| Core Layer | **统一安全验证** | ✅ 已实现 |

**结论**：安全验证集中在 Core Layer 实现是正确的分层设计，避免了重复验证和遗漏。

---

## 6. 潜在风险评估

### 6.1 非漏洞风险

| 风险 | 描述 | 严重性 | 缓解措施 |
|------|------|--------|----------|
| TOCTOU 竞争 | `IsFileValid` 和 `avformat_open_input` 之间存在时间窗口 | 低 | 利用难度高，需要精确控制文件系统 |
| 缺少目录白名单 | 无基础目录限制 | 信息性 | 文件所有者检查提供等效保护 |
| 缺少路径规范化 | 未使用 `lexically_normal()` | 信息性 | 文件所有者检查提供等效保护 |

### 6.2 TOCTOU 分析

```cpp
// Video.cpp
if (!IsFileValid(path)) { return ERR_INVALID_PARAM; }  // 时间点 1
// ... 时间窗口 ...
avformat_open_input(&formatCtx, path, nullptr, nullptr);  // 时间点 2
```

**攻击可行性评估**：
- 需要在毫秒级时间窗口内替换文件
- 需要保持文件所有者不变（只能替换为同用户的其他文件）
- 新文件仍需满足所有验证条件（必须是 MP4 格式）
- 实际攻击收益极低（只能访问同用户的其他 MP4 文件）

**结论**：TOCTOU 风险存在但利用难度极高，且攻击收益有限，不构成实际漏洞。

---

## 7. 安全增强建议 (非必需)

虽然当前实现不存在路径遍历漏洞，以下建议可进一步提升安全性：

### 7.1 添加可选的目录白名单

```cpp
// 可选：为特定部署场景添加目录限制
std::vector<std::string> allowedDirectories = {"/data/videos", "/tmp/uploads"};

bool IsPathInAllowedDirectory(const std::string& path) {
    fs::path canonical = fs::canonical(path);
    for (const auto& dir : allowedDirectories) {
        if (canonical.string().find(fs::canonical(dir).string()) == 0) {
            return true;
        }
    }
    return false;
}
```

### 7.2 使用 canonical() 替代 absolute()

```cpp
// 当前实现
fs::path pathObj = fs::absolute(path);

// 建议实现（解析所有符号链接和 .. 组件）
fs::path pathObj = fs::canonical(path);
```

### 7.3 在应用层添加输入验证

```python
# video_wrapper.py - 可选的早期验证
def video_decode(video_path: str | bytes, device: str | bytes, 
                 frame_indices: set = None, sample_num: int = -1) -> list:
    path_bytes = _ensure_bytes(video_path, "path")
    
    # 可选：添加基础目录检查
    # if not is_allowed_directory(path_bytes):
    #     raise ValueError("Path not in allowed directory")
    
    return _acc.video_decode(path_bytes, device_bytes, frame_indices, sample_num)
```

---

## 8. 结论

**VULN-PYBIND-002 是误报**。

原始报告遗漏了 `VideoDecode` 函数中的多层安全检查机制：
1. 文件所有者验证 (`CheckFileOwner`)
2. 符号链接检测 (`fs::is_symlink`)
3. 权限限制 (`CheckFilePermission`)
4. 路径有效性验证 (`CheckFilePath`)
5. 文件扩展名限制 (`CheckFileExtension(path, "mp4")`)

这些检查确保：
- 用户只能读取自己拥有的文件
- 无法通过符号链接绕过保护
- 无法访问其他用户的敏感文件
- 只能处理 MP4 格式文件

**与 VULN-PYBIND-001 一致性分析**：
- VULN-PYBIND-001 已正确判定为误报
- VULN-PYBIND-002 具有相同的安全机制
- 应采用相同的判定逻辑

**建议**：将此漏洞从确认列表移除，归档为误报。

---

## 9. 相关文件

| 文件 | 用途 |
|------|------|
| `/AccSDK/source/py/module/PyVideo.cpp` | Python 绑定层 |
| `/AccSDK/source/video/Video.cpp` | 视频处理核心（含安全验证） |
| `/AccSDK/source/utils/FileUtils.cpp` | 文件安全验证 |
| `/MultimodalSDK/source/mm/acc/wrapper/video_wrapper.py` | Python API 层 |

---

**报告生成时间**: 2026-04-20  
**分析工具版本**: detail-opencode/opencode_tty  
**验证方法**: 静态代码分析 + 数据流追踪 + 与 VULN-PYBIND-001 对比分析
