# 娔胁分析报告 - MindSpeed-Core-MS

> **分析模式：自主分析模式**
> 本次攻击面分析基于项目源码和文档的自主分析，未发现 `threat.md` 约束文件。

## 项目架构概览

### 项目定位
- **项目名称**: MindSpeed-Core-MS
- **项目类型**: Python库/SDK（library）
- **主要功能**: 将PyTorch模型代码转换到MindSpore框架，提供代码一键适配功能
- **语言组成**: 纯 Python 项目（47个文件，13,274行代码）
- **典型部署**: 在开发环境中使用，通过CLI工具或Shell脚本进行代码转换操作

### 核心模块
| 模块 | 路径 | 功能 | 风险等级 |
|------|------|------|----------|
| tools_convert | tools/convert | API代码转换工具 | Medium |
| tools_patch_merge | tools/convert/patch_merge/modules | Patch合并工具 | High |
| tools_transfer | tools | 基于规则的代码转换工具 | Medium |
| tools_load_weights | tools/load_ms_weights_to_pt | 权重加载工具 | Critical |
| tools_rules_rl | tools/rules_rl | RL规则定义 | Low |
| src_mindspeed | src/mindspeed/mindspore | MindSpore适配器 | Low |
| src_mindspeed_mm | src/mindspeed_mm/mindspore | 多模态MindSpore适配器 | Low |

### 依赖关系图
```
Shell脚本入口 (auto_convert.sh, auto_convert_rl.sh)
    │
    ├──→ tools/transfer.py (CLI入口)
    │       ├──→ getfiles() → 文件遍历
    │       ├──→ convert_general_rules() → 文件读写
    │       ├──→ convert_special_rules() → 正则替换
    │       └──→ convert_special_rules_by_line() → 按行替换
    │
    └────→ tools/convert/convert.py (CLI入口)
            ├──→ source_file_iterator() → 文件遍历
            └──→ FileConverter.convert() → AST转换
                    ├──→ load_json_file() → 加载API映射
                    └──→ APITransformer → AST修改

Library API入口
    │
    ├──→ src/mindspeed/mindspore/mindspore_adaptor.py
    │       └──→ mindspore_adaptation() → 注册patch
    │
    └──→ src/mindspeed_mm/mindspore/mindspore_adaptor.py
            └──→ apply_mindspore_patch() → 注册并应用patch

高风险入口
    │
    └──→ tools/load_ms_weights_to_pt/serialization.py
            └──→ load_ms_weights() → pickle反序列化（Critical）
                    └──→ _load() → UnpicklerWrapper.load()
    
    └──→ src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py
            └──→ get_data_from_feature_data() → torch.load（High）
```

## 攻击面分析

### 入口点列表

| 入口类型 | 文件 | 函数 | 信任等级 | 风险 | 说明 |
|----------|------|------|----------|------|------|
| cmdline | tools/convert/convert.py | main | untrusted_local | Medium | 接收--path_to_change参数，处理代码转换 |
| cmdline | tools/transfer.py | main | untrusted_local | Medium | 接收多个路径参数，基于规则转换代码 |
| cmdline | tools/load_ms_weights_to_pt/transfer.py | main | untrusted_local | High | 接收mindspeed_llm_path参数，复制文件 |
| cmdline | tools/convert/patch_merge/modules/merge.py | main | untrusted_local | High | 接收root-dir和json-file参数，合并patch |
| file | tools/load_ms_weights_to_pt/serialization.py | load_ms_weights | untrusted_local | Critical | 接收文件路径，使用pickle反序列化 |
| file | src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py | get_data_from_feature_data | untrusted_local | High | 使用torch.load加载.pt文件 |
| file | tools/convert/modules/api_transformer.py | load_json_file | untrusted_local | Medium | 加载api_mapping.json配置文件 |

### 信任边界分析

| 信任边界 | 可信侧 | 不可信侧 | 风险等级 | 潜在威胁 |
|----------|--------|----------|----------|----------|
| CLI Interface | 应用逻辑 | 命令行参数（文件路径） | Medium | 路径遍历、恶意文件处理 |
| File System Interface | 应用逻辑 | 用户指定路径的文件内容 | High | 恶意代码注入、敏感数据泄露 |
| Pickle Deserialization | 应用逻辑 | .pt权重文件内容 | Critical | 任意代码执行、远程代码执行 |
| Git Repository Clone | Shell脚本 | 远程Git仓库（硬编码URL） | Low | 供应链攻击（需外部配合） |

## STRIDE 娔胁建模

### S - Spoofing (欺骗)
| 组件 | 威胁描述 | 风险等级 | 缓解措施建议 |
|------|----------|----------|--------------|
| 权重加载 | 恶意构造的.pt文件可能伪装成合法权重文件 | High | 建议验证文件来源和完整性 |
| Git Clone | 硬编码的Git仓库URL可能被劫持 | Low | 建议使用SSH验证或签名验证 |

### T - Tampering (篡改)
| 组件 | 威胁描述 | 风险等级 | 缓解措施建议 |
|------|----------|----------|--------------|
| 代码转换工具 | 用户指定的源文件可能在转换过程中被篡改 | Medium | 建议添加文件完整性检查 |
| Patch合并 | JSON patch文件可能包含恶意代码注入指令 | High | 建议验证patch内容合法性 |
| api_mapping.json | 配置文件篡改可能导致不安全的API映射 | Medium | 建议使用白名单机制 |
| 权重加载 | pickle反序列化过程中数据可能被篡改 | Critical | 建议使用weights_only=True参数 |

### R - Repudiation (抵赖)
| 组件 | 威胁描述 | 风险等级 | 缓解措施建议 |
|------|----------|----------|--------------|
| CLI工具 | 工具执行日志可能不完整 | Low | 建议添加详细日志记录 |

### I - Information Disclosure (信息泄露)
| 组件 | 威胁描述 | 风险等级 | 缓解措施建议 |
|------|----------|----------|--------------|
| 文件处理 | 处理敏感代码文件时可能泄露信息 | Low | 建议限制日志输出 |
| 权重加载 | 权重文件内容可能包含敏感信息 | Low | 建议权限控制 |

### D - Denial of Service (拒绝服务)
| 组件 | 威胁描述 | 风险等级 | 缓解措施建议 |
|------|----------|----------|--------------|
| AST转换 | 大文件或复杂AST可能导致内存耗尽 | Medium | 建议添加文件大小限制 |
| 文件遍历 | 深层目录遍历可能导致资源耗尽 | Low | 建议添加深度限制 |

### E - Elevation of Privilege (权限提升)
| 组件 | 威胁描述 | 风险等级 | 缓解措施建议 |
|------|----------|----------|--------------|
| pickle反序列化 | 恶意.pt文件可能导致任意代码执行 | Critical | **强烈建议：使用weights_only=True，或使用safetensors替代pickle** |
| torch.load | torch.load内部使用pickle，存在相同风险 | High | **强烈建议：使用torch.load(..., weights_only=True)** |

## 高风险模块评估

### Critical 风险：pickle反序列化

**文件**: `tools/load_ms_weights_to_pt/serialization.py`
**函数**: `load_ms_weights()` (line 384), `_load()` (line 428)

**风险描述**:
- 使用pickle进行反序列化操作
- pickle.load()可以直接执行任意Python代码
- 用户可以通过恶意构造的.pt文件触发任意代码执行
- 虽然有UnpicklerWrapper自定义find_class逻辑，但仍可能存在绕过方式

**攻击路径**:
```
用户传入恶意.pt文件 → load_ms_weights() → _load() → UnpicklerWrapper.load()
→ pickle反序列化 → find_class() → 可能执行任意代码
```

**缓解建议**:
1. **强烈建议使用 `weights_only=True` 参数**：限制pickle只能加载基本数据类型
2. 建议使用safetensors格式替代pickle格式，避免反序列化风险
3. 建议添加文件完整性校验（如SHA256验证）
4. 建议限制find_class返回的函数白名单

### High 风险：torch.load调用

**文件**: `src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py`
**函数**: `get_data_from_feature_data()` (line 21)

**风险描述**:
- 直接调用torch.load加载外部文件
- torch.load默认使用pickle反序列化
- 未使用weights_only=True参数

**攻击路径**:
```
用户传入恶意feature_path → get_data_from_feature_data() → torch.load()
→ 内部pickle反序列化 → 可能执行任意代码
```

**缓解建议**:
1. **强烈建议添加 `weights_only=True` 参数**
2. 建议添加文件路径白名单验证
3. 建议使用safetensors格式

### High 风险：Patch合并和代码修改

**文件**: `tools/convert/patch_merge/modules/merge.py`
**函数**: `merge()`, `PatchMerger`

**风险描述**:
- 直接修改源代码文件
- 从JSON文件读取patch指令并应用到源代码
- preprocess/postprocess函数修改megatron_adaptor.py文件
- 如果JSON文件被篡改，可能注入恶意代码

**攻击路径**:
```
用户指定恶意JSON文件 → merge() → PatchMerger → json.load()
→ AST修改 → flush_cst_into_file() → 源代码文件被修改
```

**缓解建议**:
1. 建议添加JSON内容白名单验证
2. 建议限制patch只能修改特定类型的AST节点
3. 建议添加修改前备份机制

## 安全加固建议

### 1. 反序列化安全（Critical优先级）
- **立即行动**: 所有pickle/torch.load调用必须添加 `weights_only=True` 参数
- **长期方案**: 将权重文件格式从pickle转换为safetensors

### 2. 文件路径安全
- 添加路径验证，防止路径遍历攻击
- 使用白名单限制可访问的目录
- 添加文件大小和类型验证

### 3. 代码修改安全
- 添加修改操作的审计日志
- 实现修改前备份机制
- 限制可修改的文件类型

### 4. 配置文件安全
- 使用签名验证api_mapping.json完整性
- 添加配置内容白名单验证

### 5. 运行安全
- 建议以非root用户运行（参考SECURITYNOTE.md）
- 设置适当的文件权限（参考SECURITYNOTE.md附录）
- 添加操作审计日志

## 模块风险评估汇总

| 模块 | S | T | R | I | D | E | 综合风险 |
|------|---|---|---|---|---|---|----------|
| tools_load_weights | Low | Critical | Low | Low | Low | Critical | **Critical** |
| tools_patch_merge | Low | High | Low | Low | Medium | Low | **High** |
| src_mindspeed_mm/data | Low | High | Low | Low | Low | High | **High** |
| tools_convert | Low | Medium | Low | Low | Medium | Low | **Medium** |
| tools_transfer | Low | Medium | Low | Low | Low | Low | **Medium** |
| src_mindspeed | Low | Low | Low | Low | Low | Low | **Low** |

---

**分析完成时间**: 2026-04-20
**分析模式**: 自主分析模式（无threat.md约束）
**LSP可用性**: 不可用（pyright-langserver报错）