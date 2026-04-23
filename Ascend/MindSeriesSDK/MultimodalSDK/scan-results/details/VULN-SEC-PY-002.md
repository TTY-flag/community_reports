# VULN-SEC-PY-002: Image.open 路径未完全规范化致潜在路径遍历风险

## 漏洞摘要

| 属性 | 值 |
|-----------|-------|
| **CWE ID** | CWE-22: 路径名限制不当，未能限制到受限目录 |
| **严重程度** | 中等（已缓解） |
| **信任级别** | untrusted_local |
| **受影响模块** | py_bindings (Python-C++ 绑定) |
| **主要位置** | `AccSDK/source/py/module/PyImage.cpp:153` |
| **次要位置** | `AccSDK/source/image/Image.cpp:180`, `AccSDK/source/utils/ImageUtils.cpp:61` |

## 漏洞描述

`Image.open()` 静态方法接受用户提供的文件路径，并在未进行适当路径规范化的情况下，通过 Python-C++ 绑定层传递给底层 C++ 图像加载代码。虽然该实现包含多项安全检查（符号链接阻止、文件所有权验证、权限检查），但缺少使用 `realpath()` 或 `std::filesystem::canonical()` 进行完整路径规范化，留下了潜在的攻击向量。

## 调用链分析

```
Python 层                         C++ 绑定层                            核心 C++ 层
─────────────────────────────────────────────────────────────────────────────────────────
image_wrapper.py:35               PyImage.cpp:153                      Image.cpp:180
Image.open(path)            →     Image::open(path)              →    Image::Image(path)
     │                                  │                                 │
     │ _ensure_bytes(path)              │ PyAcc::Image(path)               │ ReadJpegData()
     │ (仅 NULL 检查)                    │ (直接传递)                       │     │
     │                                  │                                  │     ▼
     └──────────────────────────────────┴──────────────────────────────────┴─→ FileUtils.cpp
                                                                          IsFileValid()
```

### 第 1 层：Python 包装器 (`image_wrapper.py:35-51`)

```python
@classmethod
def open(cls, path: str | bytes, device: str | bytes = b"cpu") -> "Image":
    path_bytes = _ensure_bytes(path, "path")  # 仅转换为字节，检查 NULL
    device_bytes = _ensure_bytes(device, "device")
    acc_img = _acc.Image.open(path_bytes, device_bytes)  # 直接传递给 C++
```

**安全控制**：`_ensure_bytes()` 仅：
- 将字符串转换为字节
- 拒绝 NULL 字节 (`\x00`)
- 不 sanitization `../` 序列或验证路径结构

### 第 2 层：PyBind C++ 绑定 (`PyImage.cpp:153-156`)

```cpp
Image Image::open(const std::string& path, const std::string& device)
{
    return PyAcc::Image(path.c_str(), device.c_str());  # 直接传递，无验证
}
```

**安全控制**：无 - 路径直接传递给构造函数。

### 第 3 层：C++ Image 构造函数 (`Image.cpp:180-201`)

```cpp
Image::Image(const char* path, const char* device)
{
    CheckDeviceFromConstructor(device);
    auto decodeRet = ReadJpegData(path, imData, imWidth, imHeight, ptr);  # 文件读取
    // ...
}
```

**安全控制**：仅设备验证；路径传递给文件读取函数。

### 第 4 层：JPEG 数据读取器 (`ImageUtils.cpp:61-75`)

```cpp
ErrorCode ReadJpegData(const char* path, ...) {
    if (!IsFileValid(path)) {  # 验证发生在这里
        return ERR_INVALID_PARAM;
    }
    // 扩展名检查
    if (!CheckFileExtension(path, "jpg") && !CheckFileExtension(path, "jpeg")) {
        return ERR_INVALID_PARAM;
    }
    ErrorCode ret = ReadFile(path, rawData, IMAGE_MAX_FILE_SIZE);
    // ...
}
```

### 第 5 层：文件验证 (`FileUtils.cpp:203-223`)

```cpp
bool IsFileValid(const char* path) {
    std::string pathStr(path);
    if (!CheckFilePath(pathStr)) return false;    # 符号链接和存在性检查
    if (!CheckFileOwner(pathStr)) return false;   # 所有者必须与进程 UID 匹配
    if (!CheckFilePermission(pathStr, FILE_MODE)) return false;  # 权限 <= 0640
    return true;
}
```

## 现有安全控制

代码实现了多项安全检查，部分缓解了该漏洞：

### 1. 符号链接检测 (`FileUtils.cpp:148-151`)

```cpp
bool CheckFilePath(const std::string& path) {
    fs::path pathObj = fs::absolute(path);
    // ...
    if (fs::is_symlink(pathObj)) {  # 如果是最终路径组件是符号链接则阻止
        LogError << "Check file path failed. The file is a symlink.";
        return false;
    }
    // ...
}
```

**有效性**：阻止直接符号链接，但无法检测父目录中的符号链接。

### 2. 文件所有权验证 (`FileUtils.cpp:160-176`)

```cpp
bool CheckFileOwner(const std::string& path) {
    struct stat fileStat;
    stat(path.c_str(), &fileStat);
    uid_t currentUid = getuid();
    if (fileStat.st_uid != currentUid) {  # 只有所有者可以访问
        return false;
    }
    return true;
}
```

**有效性**：强力缓解措施 - 限制访问进程用户拥有的文件。

### 3. 权限验证 (`FileUtils.cpp:178-201`)

```cpp
bool CheckFilePermission(const std::string& path, const mode_t mode) {
    # 确保文件权限不超过 0640
    // ...
}
```

**有效性**：阻止访问权限过大的文件。

## 剩余漏洞

尽管有缓解措施，以下攻击向量仍然存在：

### 1. 缺少路径规范化

代码使用 `fs::absolute(path)`，它不：
- 针对实际文件系统解析 `..` 路径组件
- 跟随和解析中间路径组件中的符号链接
- 调用 `realpath()` 或 `canonical()` 进行完整路径解析

**漏洞代码** (`FileUtils.cpp:141`)：
```cpp
fs::path pathObj = fs::absolute(path);  # 应使用 fs::canonical(path)
```

**影响**：路径遍历序列可能在所有场景中未得到适当解析。

### 2. TOCTOU 竞态条件

检查按顺序执行，缺乏原子性：
1. 检查是否为符号链接
2. 检查文件所有者
3. 检查权限
4. 打开文件

竞态条件可能允许攻击者在检查之间将有效文件替换为符号链接。

### 3. 中间符号链接绕过

```cpp
# 仅检查最终组件
if (fs::is_symlink(pathObj)) { ... }
```

攻击者可以创建如下路径：
- `/home/user/attacker_dir/image.jpg`，其中 `attacker_dir` 是指向另一个目录的符号链接

最终文件 `image.jpg` 将通过符号链接检查，即使父目录是符号链接。

## 概念验证

### 场景 1：路径遍历（受所有权检查限制）

```python
from mm.acc.wrapper.image_wrapper import Image

# 尝试读取系统文件 - 被 CheckFileOwner 阻止
# （文件必须由当前用户拥有）
img = Image.open("../../../etc/passwd")  # 将失败 - 非用户拥有
```

### 场景 2：中间符号链接（可能可利用）

```bash
# 攻击者创建目录结构
mkdir -p /home/user/images
ln -s /home/user/other_location /home/user/images/link_dir
# 在 other_location 放置用户拥有的图像
cp my_image.jpg /home/user/other_location/
```

```python
# 如果仅检查最终组件，这可能绕过符号链接检测
img = Image.open("/home/user/images/link_dir/my_image.jpg")
```

## 影响评估

| 因素 | 评估 |
|--------|-------------|
| **攻击复杂度** | 中等 - 需要理解文件系统和竞态条件 |
| **所需权限** | 低 - 需要 Python 运行时的本地访问 |
| **用户交互** | 无 |
| **影响范围** | 受所有权检查限制 - 仅能访问用户拥有的文件 |
| **机密性影响** | 低到中等 - 限于用户拥有的文件 |
| **完整性影响** | 无 - 只读操作 |
| **可用性影响** | 低 - 可能通过畸形路径导致拒绝服务 |

**整体严重程度**：中等（由于缓解控制，从高降低）

## 建议

### 立即（高优先级）

1. **使用 `fs::canonical()` 进行路径解析**：

```cpp
# 在 FileUtils.cpp 中
bool CheckFilePath(const std::string& path) {
    std::error_code ec;
    fs::path canonicalPath = fs::canonical(path, ec);  # 完全解析路径
    if (ec) {
        LogError << "Path canonicalization failed";
        return false;
    }
    # 对所有后续检查使用 canonicalPath
    // ...
}
```

2. **实施基础目录白名单**：

```cpp
bool IsPathWithinAllowedDirectory(const fs::path& path) {
    static const std::vector<fs::path> allowedDirs = {
        fs::canonical("/home/user/images"),
        fs::canonical("/var/data/images"),
        // ...
    };
    fs::path canonicalPath = fs::canonical(path);
    for (const auto& allowedDir : allowedDirs) {
        if (canonicalPath.string().find(allowedDir.string()) == 0) {
            return true;
        }
    }
    return false;
}
```

### 短期（中优先级）

3. **使用基于文件描述符的操作添加 TOCTOU 保护**：

```cpp
# 先打开文件，然后使用文件描述符进行验证
int fd = open(path, O_RDONLY | O_NOFOLLOW);
if (fd < 0) return false;
struct stat st;
fstat(fd, &st);  # 使用 fd 防止竞态条件
# 使用 st 进行验证
```

4. **检查所有路径组件是否有符号链接**：

```cpp
bool HasSymlinkInPath(const fs::path& path) {
    fs::path current;
    for (const auto& component : path) {
        current /= component;
        if (fs::is_symlink(current)) {
            return true;
        }
    }
    return false;
}
```

### 长期（低优先级）

5. **添加 Python 级路径验证**：

```python
# 在 image_wrapper.py 中
import os
from pathlib import Path

@classmethod
def open(cls, path: str | bytes, device: str | bytes = b"cpu") -> "Image":
    path_str = path if isinstance(path, str) else path.decode('utf-8')
    
    # 解析并验证路径
    try:
        resolved_path = Path(path_str).resolve(strict=True)
        # 可选检查允许的基目录
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid or unsafe path: {e}")
    
    # 继续使用 resolved_path
```

## 相关漏洞

- **VULN-SEC-PY-001**：`Image::Image` 构造函数中的路径遍历 (PyImage.cpp:54) - 不同函数中的相同漏洞
- **VULN-SEC-PY-003**：`video_decode` 中的路径遍历 (PyVideo.cpp:30) - 视频模块中的类似模式

## 参考资料

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [C++ std::filesystem::canonical](https://en.cppreference.com/w/cpp/filesystem/canonical)

## 附录：文件参考

| 文件 | 行号 | 用途 |
|------|-------|---------|
| `AccSDK/source/py/module/PyImage.cpp` | 153-156 | PyBind 绑定层 |
| `AccSDK/source/py/module/PyImage.cpp` | 54-65 | PyBind 构造函数 |
| `AccSDK/source/image/Image.cpp` | 180-201 | 核心图像加载 |
| `AccSDK/source/utils/ImageUtils.cpp` | 61-119 | JPEG 文件读取 |
| `AccSDK/source/utils/FileUtils.cpp` | 203-223 | 文件验证 |
| `AccSDK/source/utils/FileUtils.cpp` | 128-158 | 路径检查 |
| `AccSDK/source/utils/FileUtils.cpp` | 160-176 | 所有权检查 |
| `MultimodalSDK/source/mm/acc/wrapper/image_wrapper.py` | 35-51 | Python 入口点 |
| `MultimodalSDK/source/mm/acc/wrapper/util.py` | 20-31 | 字节转换 |

(文件结束 - 共 341 行)
