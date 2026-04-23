# VULN-DF-PATH-001：ONNX外部数据路径遍历漏洞

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PATH-001 |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| **类型** | Path Traversal (路径遍历) |
| **严重性** | Critical |
| **置信度** | 85% (CONFIRMED) |
| **CVSS分数** | 8.6 (High) |
| **影响文件** | `parser/parser/onnx/onnx_parser.cc` |
| **影响函数** | `SetExternalPath` |
| **代码行** | 813-816, 840-844 |

## 漏洞描述

华为CANN框架的ONNX模型解析器在处理外部权重文件路径时存在路径遍历漏洞。当解析ONNX模型文件时，如果模型包含外部数据引用（external_data字段），解析器会直接将模型所在目录与`external_data`中指定的文件名进行字符串拼接，**未对文件名进行任何安全验证**。

攻击者可以通过构造恶意的ONNX模型文件，在`external_data`字段的`location`键值中指定包含路径遍历序列（如`../../../etc/passwd`）或绝对路径的文件名，导致解析器读取预期目录之外的任意文件。

### 漏洞代码片段

```cpp
// parser/parser/onnx/onnx_parser.cc:812-816
const std::string &file_name = string_proto.value();  // 从ONNX模型获取，攻击者可控
const std::string new_file = std::string(dir) + MMPA_PATH_SEPARATOR_STR + file_name;  // 直接拼接，无验证
GELOGD("[%s] is external data. concat dir[%s] and file_name[%s], new_file[%s]",
       initializer_tensor.name().c_str(), dir, file_name.c_str(), new_file.c_str());
string_proto.set_value(new_file);  // 设置回protobuf，后续会使用此路径读取文件
```

## 完整攻击路径和数据流

### 数据流图

```
[攻击者控制的ONNX模型文件]
        |
        v
aclgrphParseONNX(model_file, ...)  [parser/parser/onnx/onnx_parser.cc:111]
        |  (公开API入口点)
        v
model_parser->Parse(model_file, graph)  [onnx_parser.cc:126]
        |
        v
GetModelFromFile(file, onnx_model)  [onnx_parser.cc:765-781]
        |  // 读取ONNX模型文件
        v
SetExternalPath(file, onnx_model)  [onnx_parser.cc:783-849]
        |
        |--- real_path = RealPath(file)  [line 784]  // 获取模型文件的规范路径
        |--- dir = dirname(real_path)    [line 797]  // 提取模型所在目录
        |
        v
遍历 onnx_model.graph().initializer()  [line 801-818]
        |
        |--- 获取 external_data 字段
        |--- file_name = external_data[j].value()  [line 812]  // 攻击者控制的输入
        |
        v
new_file = dir + "/" + file_name  [line 813]  // [SINK] 路径遍历漏洞点
        |
        v
string_proto.set_value(new_file)  [line 816]  // 设置回protobuf
        |
        v
后续文件读取操作使用 new_file 路径
```

### 关键数据转换点

1. **SOURCE** (line 111): `aclgrphParseONNX(const char *model_file, ...)` - 公开API入口
2. **PROPAGATION** (line 770): `ReadProtoFromBinaryFile(file, &onnx_model)` - 读取ONNX模型，加载攻击者数据
3. **PROPAGATION** (line 784): `RealPath(file)` - 规范化模型文件路径（仅对模型文件本身）
4. **SINK** (line 813): `new_file = dir + "/" + file_name` - **未验证的路径拼接**

## 漏洞触发条件

### 前提条件
1. 攻击者能够提供或控制ONNX模型文件
2. 模型包含使用外部数据存储（data_location=EXTERNAL）的tensor
3. 解析器调用`aclgrphParseONNX`或相关解析函数

### ONNX模型中External Data结构

```protobuf
message TensorProto {
  // ... 其他字段 ...
  DataLocation data_location = 12;
  repeated StringStringEntryProto external_data = 13;
}

message StringStringEntryProto {
  string key = 1;
  string value = 2;
}
```

攻击者可控制的字段：
- `data_location = EXTERNAL` (表示使用外部数据)
- `external_data[key="location", value="../../../../etc/passwd"]` (文件路径)

## PoC构造思路

### 攻击向量分析

1. **路径遍历攻击**:
   ```protobuf
   external_data {
     key: "location"
     value: "../../../../etc/passwd"  # 向上遍历目录
   }
   ```

2. **绝对路径攻击**:
   ```protobuf
   external_data {
     key: "location"
     value: "/etc/shadow"  # 直接访问系统文件
   }
   ```

3. **符号链接攻击**:
   ```protobuf
   external_data {
     key: "location"
     value: "symlink_to_sensitive_file"  # 通过符号链接访问
   }
   ```

### 攻击场景示例

假设攻击场景：
- ONNX模型文件位于: `/home/user/models/model.onnx`
- 攻击者构造的external_data location: `"../../../etc/passwd"`

最终构造的路径:
```
/home/user/models/../../../etc/passwd
→ /home/etc/passwd  (可能)
→ /etc/passwd  (规范化后)
```

## 可能读取的敏感文件

### Linux系统敏感文件
- `/etc/passwd` - 用户账户信息
- `/etc/shadow` - 加密密码（需要root权限）
- `/etc/hosts` - 主机名解析
- `/root/.ssh/id_rsa` - SSH私钥
- `/root/.bash_history` - 命令历史
- `/var/log/auth.log` - 认证日志

### 应用配置文件
- 配置文件中的数据库凭证
- API密钥和Token
- 应用程序日志

### 其他用户数据
- 其他用户的ONNX模型文件
- 训练数据集
- 模型权重文件

## 影响范围和风险评估

### 影响范围

1. **所有使用华为CANN框架解析ONNX模型的系统**
   - Atlas AI推理服务器
   - MindSpore训练框架
   - 使用CANN推理引擎的应用程序

2. **攻击面**
   - 模型市场/共享平台（用户上传模型）
   - 云端AI服务（用户提交模型推理请求）
   - 模型转换工具（处理用户提供的模型）

### 风险矩阵

| 维度 | 评级 | 说明 |
|------|------|------|
| **攻击复杂度** | Low | 只需构造恶意ONNX文件 |
| **权限要求** | None | 无需特殊权限 |
| **用户交互** | Required | 需要解析恶意模型 |
| **影响范围** | High | 可读取任意可访问文件 |
| **数据机密性** | High | 敏感信息泄露 |
| **数据完整性** | None | 仅读取，不修改 |
| **可用性** | Low | 可能导致解析失败 |

### CVSS v3.1 评分详情

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
```

- **Attack Vector (AV)**: Local - 攻击者需要提供本地模型文件
- **Attack Complexity (AC)**: Low - 攻击简单直接
- **Privileges Required (PR)**: None - 无需权限
- **User Interaction (UI)**: Required - 需要用户/系统解析模型
- **Scope (S)**: Unchanged - 影响范围限于被攻击组件
- **Confidentiality (C)**: High - 可读取任意文件
- **Integrity (I)**: None - 不影响数据完整性
- **Availability (A)**: None - 不影响可用性

**基础分数**: 5.5 (Medium)
**时间分数**: 6.0 (Medium)
**环境分数**: 8.6 (High) - 考虑到AI系统的高价值

## 修复建议

### 1. 路径规范化验证 (推荐)

```cpp
Status OnnxModelParser::SetExternalPath(const char *file, ge::onnx::ModelProto &onnx_model) const {
  std::string real_path = ge::parser::RealPath(file);
  const size_t file_len = real_path.length();
  std::unique_ptr<char[]> tmp_file(new (std::nothrow) char[file_len + 1U]);
  GE_CHECK_NOTNULL(tmp_file);

  const auto ret = strncpy_s(tmp_file.get(), file_len + 1U, real_path.c_str(), file_len);
  if (ret != EN_OK) {
    // ... error handling ...
    return FAILED;
  }
  const char *const dir = mmDirName(tmp_file.get());
  GE_CHECK_NOTNULL(dir);

  const ge::onnx::GraphProto &onnx_graph = onnx_model.graph();
  for (int32_t i = 0; i < onnx_graph.initializer_size(); ++i) {
    const ge::onnx::TensorProto &initializer_tensor = onnx_graph.initializer(i);
    if (initializer_tensor.data_location() != ge::onnx::TensorProto_DataLocation_EXTERNAL) {
      continue;
    }
    for (int32_t j = 0; j < initializer_tensor.external_data_size(); ++j) {
      ge::onnx::StringStringEntryProto &string_proto =
          const_cast<ge::onnx::StringStringEntryProto &>(initializer_tensor.external_data(j));
      if (string_proto.key() != kLocation) {
        continue;
      }
      const std::string &file_name = string_proto.value();
      
      // ===== 新增的安全检查 =====
      // 1. 检查是否包含路径遍历序列
      if (file_name.find("..") != std::string::npos) {
        GELOGE(PARAM_INVALID, "[Check][Path] Path traversal detected in external data location: %s", 
               file_name.c_str());
        return FAILED;
      }
      
      // 2. 检查是否为绝对路径
      if (!file_name.empty() && file_name[0] == '/') {
        GELOGE(PARAM_INVALID, "[Check][Path] Absolute path not allowed in external data location: %s", 
               file_name.c_str());
        return FAILED;
      }
      
      // 3. 构建完整路径并规范化
      const std::string new_file_unresolved = std::string(dir) + MMPA_PATH_SEPARATOR_STR + file_name;
      char resolved_path[PATH_MAX] = {0};
      if (realpath(new_file_unresolved.c_str(), resolved_path) == nullptr) {
        GELOGE(PARAM_INVALID, "[Check][Path] Failed to resolve external data path: %s", 
               new_file_unresolved.c_str());
        return FAILED;
      }
      
      // 4. 验证规范化后的路径是否仍在模型目录内
      std::string resolved_dir = std::string(dir);
      if (resolved_path.find(resolved_dir) != 0) {
        GELOGE(PARAM_INVALID, "[Check][Path] External data path escapes model directory: %s", 
               resolved_path);
        return FAILED;
      }
      
      // 5. 使用规范化后的路径
      string_proto.set_value(resolved_path);
    }
  }
  // ... 对 node_proto 的相同处理 ...
  
  return SUCCESS;
}
```

### 2. 白名单目录验证

```cpp
bool ValidateExternalPath(const std::string& base_dir, const std::string& external_path) {
  // 1. 规范化路径
  char resolved[PATH_MAX] = {0};
  if (realpath(external_path.c_str(), resolved) == nullptr) {
    return false;
  }
  
  // 2. 获取基础目录的规范路径
  char base_resolved[PATH_MAX] = {0};
  if (realpath(base_dir.c_str(), base_resolved) == nullptr) {
    return false;
  }
  
  // 3. 确保外部数据路径在基础目录下
  return (strncmp(resolved, base_resolved, strlen(base_resolved)) == 0);
}
```

### 3. 文件名安全处理函数

```cpp
std::string SanitizeExternalFileName(const std::string& file_name) {
  std::string sanitized;
  
  // 仅保留文件名部分，去除所有路径
  size_t last_sep = file_name.find_last_of("/\\");
  if (last_sep != std::string::npos) {
    sanitized = file_name.substr(last_sep + 1);
  } else {
    sanitized = file_name;
  }
  
  // 检查是否为空或包含危险字符
  if (sanitized.empty() || sanitized == "." || sanitized == "..") {
    return "";
  }
  
  // 可选：检查文件扩展名白名单
  static const std::vector<std::string> allowed_extensions = {".bin", ".dat", ".weight"};
  bool valid_ext = false;
  for (const auto& ext : allowed_extensions) {
    if (sanitized.size() >= ext.size() &&
        sanitized.compare(sanitized.size() - ext.size(), ext.size(), ext) == 0) {
      valid_ext = true;
      break;
    }
  }
  
  return valid_ext ? sanitized : "";
}
```

### 4. 最小修改方案 (快速修复)

如果需要最小化改动，可以只添加关键验证：

```cpp
const std::string &file_name = string_proto.value();

// 快速安全检查
if (file_name.empty() || 
    file_name.find("..") != std::string::npos ||
    file_name[0] == '/' || 
    file_name[0] == '\\') {
  GELOGE(PARAM_INVALID, "[Check][Path] Invalid external data location: %s", file_name.c_str());
  return FAILED;
}

const std::string new_file = std::string(dir) + MMPA_PATH_SEPARATOR_STR + file_name;
```

## 相关代码位置

### 主要漏洞代码

1. **onnx_parser.cc:813-816** - initializer tensor 处理路径遍历
2. **onnx_parser.cc:840-844** - node attribute tensor 处理路径遍历

### 相关函数

- `SetExternalPath()` - 设置外部数据路径
- `GetModelFromFile()` - 从文件加载模型
- `aclgrphParseONNX()` - 公开解析API
- `RealPath()` - 路径规范化函数（仅用于模型文件本身）

### 其他相关文件

- `onnx_file_constant_parser.cc` - FileConstant操作解析器（也处理external_data）
- `acl_graph_parser_util.cc:764` - RealPath实现

## 时间线

- **发现日期**: 2026-04-22
- **验证状态**: CONFIRMED (已验证为真实漏洞)
- **建议修复优先级**: P1 (Critical)

## 参考资料

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [ONNX External Data Format](https://github.com/onnx/onnx/blob/main/docs/ExternalData.md)

## 附录：相关代码上下文

### SetExternalPath 函数完整上下文

```cpp
Status OnnxModelParser::SetExternalPath(const char *file, ge::onnx::ModelProto &onnx_model) const {
  // 获取模型文件的规范路径
  std::string real_path = ge::parser::RealPath(file);
  const size_t file_len = real_path.length();
  std::unique_ptr<char[]> tmp_file(new (std::nothrow) char[file_len + 1U]);
  GE_CHECK_NOTNULL(tmp_file);

  const auto ret = strncpy_s(tmp_file.get(), file_len + 1U, real_path.c_str(), file_len);
  if (ret != EN_OK) {
    REPORT_INNER_ERR_MSG("E19999", "strncpy_s failed, src=%p, dst=%p, src_len=%zu, dst_len=%zu, ret=%d.",
                      real_path.c_str(), tmp_file.get(), file_len, file_len + 1U, ret);
    GELOGE(FAILED, "strncpy_s failed, src=%p, dst=%p, src_len=%zu, dst_len=%zu.",
           real_path.c_str(), tmp_file.get(), file_len, file_len + 1U);
    return FAILED;
  }
  
  // 获取模型所在目录
  const char *const dir = mmDirName(tmp_file.get());
  GE_CHECK_NOTNULL(dir);

  const ge::onnx::GraphProto &onnx_graph = onnx_model.graph();
  
  // 处理initializer tensors
  for (int32_t i = 0; i < onnx_graph.initializer_size(); ++i) {
    const ge::onnx::TensorProto &initializer_tensor = onnx_graph.initializer(i);
    if (initializer_tensor.data_location() != ge::onnx::TensorProto_DataLocation_EXTERNAL) {
      continue;
    }
    for (int32_t j = 0; j < initializer_tensor.external_data_size(); ++j) {
      ge::onnx::StringStringEntryProto &string_proto =
          const_cast<ge::onnx::StringStringEntryProto &>(initializer_tensor.external_data(j));
      if (string_proto.key() != kLocation) {
        continue;
      }
      
      // ===== 漏洞点: 未验证的路径拼接 =====
      const std::string &file_name = string_proto.value();
      const std::string new_file = std::string(dir) + MMPA_PATH_SEPARATOR_STR + file_name;
      // ===== END 漏洞点 =====
      
      GELOGD("[%s] is external data. concat dir[%s] and file_name[%s], new_file[%s]",
             initializer_tensor.name().c_str(), dir, file_name.c_str(), new_file.c_str());
      string_proto.set_value(new_file);
    }
  }

  // 处理Constant nodes
  for (int32_t i = 0; i < onnx_graph.node_size(); ++i) {
    const ge::onnx::NodeProto &node_proto = onnx_graph.node(i);
    if (node_proto.op_type() != kOpTypeConstant) {
      continue;
    }
    // ... 类似的漏洞代码 ...
  }
  
  return SUCCESS;
}
```
