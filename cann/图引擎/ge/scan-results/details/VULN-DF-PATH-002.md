# VULN-DF-PATH-002: Path Traversal in Model Serialization Weight Loading

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-DF-PATH-002 |
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| 类型 | Path Traversal (路径遍历) |
| 置信度 | 85 |
| 严重性 | **Critical** |
| 文件 | `graph_metadef/graph/serialization/model_serialize.cc:1174-1181` |
| 函数 | `SetWeightForModel` |

## 漏洞描述

模型权重文件路径直接从不可信的 protobuf 属性中读取，未经过适当的路径验证。攻击者可以通过构造恶意的 protobuf 模型文件，在 `ATTR_NAME_LOCATION` 属性中注入路径遍历序列，导致系统读取任意位置的文件作为模型权重数据。

### 核心问题

1. **数据来源不可信**: `ATTR_NAME_LOCATION` 属性值来自外部 protobuf 数据，可被攻击者完全控制
2. **路径拼接不安全**: 路径直接拼接到基础目录，未验证是否包含 `../` 等路径遍历序列
3. **RealPath 无法防护**: `realpath()` 函数仅用于解析符号链接和规范化路径，并不能限制访问范围

## 完整数据流路径

```
ModelSerialize::UnserializeModel(data, len, model)
    ↓ [model_serialize.cc:1194-1221]
ReadProtoFromBinaryFile() 解析 protobuf 数据
    ↓
ModelSerializeImp::UnserializeModel(model, model_proto)
    ↓ [model_serialize.cc:853-886]
ModelSerializeImp::UnserializeGraphWithoutEdge(graph, graph_proto)
    ↓ [model_serialize.cc:919-926]
对 CONSTANT/CONSTANTOP 类型节点调用:
    ↓
ModelSerializeImp::SetWeightForModel(op_def_proto)
    ↓ [model_serialize.cc:1168-1192]
==========================================
从 op_def_proto.attr() 读取 ATTR_NAME_LOCATION  ← [SOURCE: 不可信数据]
    ↓ [model_serialize.cc:1170-1174]
const std::string file_path = iter->second.s();  ← 文件路径来自 protobuf 字串属性
    ↓
LoadWeightFromFile(file_path, length, weight)
    ↓ [model_serialize.cc:1138-1166]
==========================================
路径拼接:
    ↓ [model_serialize.cc:1150-1158]
if (!air_directory.empty()) {
    weight_path = air_directory + "/" + file_path;  ← 拼接不安全路径
} else {
    weight_path = file_path;  ← 直接使用绝对路径
}
    ↓
GetBinFromFile(weight_path, buffer, data_len)
    ↓ [file_utils.cc:197-222]
==========================================
RealPath(weight_path)  ← [SINK: 仅解析符号链接，不阻止路径遍历]
    ↓
读取文件内容到内存 ← 攻击者控制的文件被读取
```

## 触发条件分析

### 入口点

1. **`Model::Load()`** - 从二进制数据加载模型
   - 位置: `graph_metadef/graph/normal_graph/model.cc:116-130`
   - 调用链: `Model::Load → ModelSerialize::UnserializeModel`

2. **直接调用 `ModelSerialize::UnserializeModel`**
   - 多个位置调用此函数加载模型:
     - `tests/graph_metadef/ut/graph/testcase/model_serialize_unittest.cc`
     - `tests/ge/ut/common/graph/testcase/ge_model_serialize_unittest.cc`
     - 以及其他模型加载场景

3. **隐式触发点**
   - 任何从 `.air` 或 `.om` 模型文件加载模型的场景
   - ONNX 模型解析中的 FileConstant 节点
   - 用户通过 `aclmdlLoadFromFile` 等 API 加载模型

### 触发条件

1. 加载的 protobuf 模型数据中包含 CONSTANT 或 CONSTANTOP 类型的算子节点
2. 该节点具有 `ATTR_NAME_LOCATION` 属性（字符串类型）
3. 该属性值包含路径遍历序列或指向敏感文件

## 攻击路径构造思路

### PoC 构造思路

攻击者需要构造一个恶意的 protobuf 模型文件，包含:

1. **OpDef 结构**: 
   - `type = "Constant"` 或 `type = "ConstantOp"`
   - `name = "malicious_weight"` (任意名称)

2. **恶意属性设置**:
   ```
   attr_map["location"] = "../../../etc/passwd"  // 相对路径遍历
   attr_map["location"] = "/etc/passwd"          // 绝对路径直接访问
   attr_map["length"] = 1024                     // 读取长度
   attr_map["weights"] = 空Tensor                // 占位
   ```

3. **攻击向量示例**:
   - 读取敏感配置文件: `"../../etc/shadow"` 或 `"../../../root/.ssh/id_rsa"`
   - 读取其他用户的模型文件: `"../../../home/other_user/.models/private.air"`
   - 读取系统凭证: `"../../../proc/self/environ"` 或 `"../../../var/log/auth.log"`

### 攻击效果

1. **信息泄露**: 任意文件内容被读取到模型权重内存中
2. **潜在内存破坏**: 如果文件内容不符合预期格式，可能导致后续处理中的内存问题
3. **权限绕过**: 利用应用程序的权限读取用户本无法访问的文件

## 关键代码分析

### SetWeightForModel 函数 (漏洞核心)

```cpp
// model_serialize.cc:1168-1192
bool ModelSerializeImp::SetWeightForModel(proto::OpDef &op_def) const {
  auto attr_map = op_def.mutable_attr();
  auto iter = attr_map->find(ATTR_NAME_LOCATION);
  if (iter == attr_map->end()) {
    return true;
  }
  // [!] file_path 直接从 protobuf 属性读取，未验证
  const std::string file_path = iter->second.s();
  
  iter = attr_map->find(ATTR_NAME_LENGTH);
  if (iter == attr_map->end()) {
    return true;
  }
  const int64_t length = iter->second.i();
  
  std::string weight;
  // [!] 调用路径拼接函数，file_path 未经过安全验证
  if (!LoadWeightFromFile(file_path, length, weight)) {
    GELOGE(GRAPH_FAILED, "Load weight from path %s failed.", file_path.c_str());
    return false;
  }
  // ... 权重数据被设置为 tensor 数据
}
```

### LoadWeightFromFile 函数 (路径拼接)

```cpp
// model_serialize.cc:1138-1166
bool ModelSerializeImp::LoadWeightFromFile(const std::string &file_path,
                                           const int64_t &length,
                                           std::string &weight) const {
  // ...
  std::string air_directory;
  std::string air_filename;
  SplitFilePath(air_path_, air_directory, air_filename);
  
  std::string weight_path;
  // [!] 路径拼接逻辑：如果 air_directory 为空，直接使用 file_path
  if (!air_directory.empty()) {
    weight_path = air_directory + "/" + file_path;  // [!] 拼接可能导致路径遍历
  } else {
    weight_path = file_path;  // [!] 绝对路径直接使用
  }
  
  // [!] RealPath 仅解析符号链接，不阻止 ../ 序列导致的目录逃逸
  if (GetBinFromFile(weight_path, ...) != GRAPH_SUCCESS) {
    return false;
  }
}
```

### GetBinFromFile 函数 (最终读取)

```cpp
// file_utils.cc:197-222
graphStatus GetBinFromFile(const std::string &path, char_t *buffer, size_t &data_len) {
  GE_ASSERT_TRUE(!path.empty());
  GE_ASSERT_TRUE(buffer != nullptr);
  // [!] RealPath 解析路径但允许任何绝对路径
  std::string real_path = RealPath(path.c_str());
  GE_ASSERT_TRUE(!real_path.empty(), "Path: %s is invalid...", path.c_str());
  
  std::ifstream ifs(real_path, std::ifstream::binary);
  // [!] 文件被打开并读取
  if (!ifs.is_open()) {
    return GRAPH_FAILED;
  }
  // ... 读取文件内容到 buffer
}
```

### RealPath 函数分析

```cpp
// acl_graph_parser_util.cc:764-784
std::string RealPath(const char *path) {
  if (path == nullptr) { return ""; }
  if (strlen(path) >= PATH_MAX) { return ""; }
  
  std::string res;
  char resolved_path[PATH_MAX] = {0};
  // [!] realpath() 仅解析符号链接并返回规范化绝对路径
  // [!] 它不会阻止访问 /etc/passwd 等敏感文件
  if (realpath(path, resolved_path) != nullptr) {
    res = resolved_path;
  }
  return res;
}
```

**关键点**: `realpath()` 函数的行为:
- 将相对路径转换为绝对路径
- 解析所有符号链接
- 规范化路径（消除 `.` 和 `..`）
- **但不能阻止对任意文件的访问** - 规范化后的 `/etc/passwd` 仍然是有效路径

## 影响范围评估

### 高风险场景

1. **模型共享平台**: 用户上传恶意模型文件，加载时读取服务器敏感文件
2. **AI推理服务**: 接收外部模型文件进行推理，攻击者可读取部署环境敏感信息
3. **模型转换工具**: 用户转换外部模型格式时触发漏洞
4. **边缘设备**: NPU 设备上加载模型，可能读取设备上的配置或密钥文件

### 潜在影响

| 影响 | 描述 |
|------|------|
| **信息泄露** | 任意文件读取，可能暴露系统配置、用户凭证、私钥等敏感信息 |
| **权限提升** | 利用应用程序权限读取用户无法直接访问的文件 |
| **横向渗透** | 读取其他用户目录下的模型或数据文件 |
| **DoS风险** | 读取特殊文件（如 `/dev/random`）可能导致资源耗尽 |

## 修复建议

### 1. 路径白名单验证 (推荐)

```cpp
bool ModelSerializeImp::LoadWeightFromFile(const std::string &file_path,
                                           const int64_t &length,
                                           std::string &weight) const {
  // 获取期望的权重目录
  std::string air_directory;
  std::string air_filename;
  SplitFilePath(air_path_, air_directory, air_filename);
  
  std::string weight_path;
  if (!air_directory.empty()) {
    // [FIX] 构造完整路径
    weight_path = air_directory + "/" + file_path;
  } else {
    // [FIX] 禁止直接使用绝对路径，除非有明确的白名单配置
    GELOGE(GRAPH_FAILED, "Air model path is empty, cannot load external weight");
    return false;
  }
  
  // [FIX] 获取规范化的绝对路径
  std::string real_weight_path = RealPath(weight_path.c_str());
  std::string real_base_dir = RealPath(air_directory.c_str());
  
  // [FIX] 关键安全检查：确保最终路径在允许的目录范围内
  if (real_weight_path.empty() || real_base_dir.empty()) {
    GELOGE(GRAPH_FAILED, "Invalid path resolution");
    return false;
  }
  
  // [FIX] 检查路径是否以基础目录开头
  if (real_weight_path.find(real_base_dir) != 0) {
    GELOGE(GRAPH_FAILED, "Path traversal detected: weight path escapes base directory");
    return false;
  }
  
  // [FIX] 额外检查：确保没有路径遍历序列在原始输入中
  if (file_path.find("..") != std::string::npos) {
    GELOGE(GRAPH_FAILED, "Path traversal sequence detected in file_path");
    return false;
  }
  
  // 继续加载文件...
}
```

### 2. 禁止路径遍历字符

```cpp
// 在 SetWeightForModel 中添加输入验证
bool ModelSerializeImp::SetWeightForModel(proto::OpDef &op_def) const {
  auto attr_map = op_def.mutable_attr();
  auto iter = attr_map->find(ATTR_NAME_LOCATION);
  if (iter == attr_map->end()) {
    return true;
  }
  const std::string file_path = iter->second.s();
  
  // [FIX] 验证路径安全性
  if (!IsValidWeightPath(file_path)) {
    GELOGE(GRAPH_FAILED, "Invalid weight path: contains forbidden characters");
    return false;
  }
  // ...
}

// 新增路径验证函数
bool IsValidWeightPath(const std::string &path) {
  // 禁止路径遍历
  if (path.find("..") != std::string::npos) {
    return false;
  }
  // 禁止绝对路径（除非明确允许）
  if (!path.empty() && path[0] == '/') {
    return false;
  }
  // 禁止符号链接引用
  if (path.find("..") != std::string::npos) {
    return false;
  }
  // 只允许相对路径且在安全范围内
  return true;
}
```

### 3. 配置化白名单机制

```cpp
// 允许用户配置可信的权重文件目录
class WeightPathValidator {
public:
  static bool IsPathAllowed(const std::string &resolved_path) {
    // 从配置获取允许的目录列表
    static const std::vector<std::string> allowed_dirs = GetAllowedWeightDirs();
    
    for (const auto &allowed_dir : allowed_dirs) {
      std::string real_allowed = RealPath(allowed_dir.c_str());
      if (resolved_path.find(real_allowed) == 0) {
        return true;
      }
    }
    return false;
  }
  
private:
  static std::vector<std::string> GetAllowedWeightDirs() {
    // 从环境变量或配置文件读取
    // 例如: AIR_WEIGHT_DIR, /usr/local/ascend/models/weights 等
    std::vector<std::string> dirs;
    // ...
    return dirs;
  }
};
```

### 4. 记录和审计

```cpp
// 添加安全日志记录
GELOGI("Loading weight from resolved path: %s (original: %s, base_dir: %s)",
       real_weight_path.c_str(), file_path.c_str(), real_base_dir.c_str());

// 检测到可疑路径时记录警告
if (file_path.find("..") != std::string::npos || file_path[0] == '/') {
  REPORT_SECURITY_EVENT("E_SEC_PATH_TRAVERSAL", 
                        "Potential path traversal in weight path: " + file_path);
}
```

## 相关 CVE 参考

- CVE-2019-20916: Path traversal in Python package installation
- CVE-2021-22945: Path traversal in curl
- CVE-2022-24785: Path traversal in Moment.js

## 总结

此漏洞是一个**真实的路径遍历漏洞**，攻击者可以通过构造恶意的 protobuf 模型文件，诱导系统读取任意位置的文件作为模型权重数据。该漏洞存在于模型反序列化的核心流程中，影响范围广泛，潜在危害严重。

建议立即实施路径白名单验证机制，确保所有外部权重文件的加载路径都在明确指定的安全目录范围内。
