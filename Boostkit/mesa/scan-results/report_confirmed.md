# 漏洞扫描报告 — 已确认漏洞

**项目**: Mesa 3D Graphics Library
**扫描时间**: 2025-04-21T19:10:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## Executive Summary

本次漏洞扫描针对 Mesa 3D Graphics Library 项目进行了全面的安全审计，重点关注 SPIR-V Shader 解析器和 GLSL 编译器等关键攻击面。扫描发现了 **2 个已确认的高严重度漏洞**，均位于 SPIR-V 解析器模块中。

### 关键发现

| 发现 | 详情 |
|------|------|
| **已确认漏洞** | 2 个 High 级别漏洞 |
| **主要威胁** | SPIR-V 字节码解析中的数组越界访问 |
| **攻击向量** | 恶意应用程序提交特制的 SPIR-V shader |
| **潜在影响** | 信息泄露、拒绝服务、潜在沙箱逃逸 |

### 漏洞概要

1. **VULN-DF-SPIRV-001**: SPIR-V 解析器中 OpCompositeExtract/OpCompositeInsert 处理存在 off-by-one 边界检查缺陷。边界检查使用 `>` 而非 `>=`，允许攻击者提供等于数组长度 (`length`) 的索引值，导致越界内存访问。

2. **VULN-DF-SPIRV-003**: SPIR-V 解析器中 OpAccessChain 处理缺少 struct member 索引的边界验证。攻击者可通过特制的 SPIR-V bytecode 提供任意索引值（如 UINT_MAX），导致 `type->members[field]` 越界访问，可能实现任意内存偏移读取。

### 风险评估

这两个漏洞均可通过恶意应用程序提交特制的 SPIR-V shader 字节码触发。由于现代图形应用常运行在沙箱环境中（如浏览器 WebGL、Chrome GPU 进程），此类漏洞可能导致：
- **信息泄露**: 读取越界内存中的敏感数据
- **拒绝服务**: 触发内存访问异常导致进程崩溃
- **沙箱逃逸**: 在特定条件下可能突破沙箱限制

### 修复建议

1. **VULN-DF-SPIRV-001**: 将 `spirv_to_nir.c:2140` 处的 `vtn_fail_if(w[i] > type->length, ...)` 改为 `vtn_fail_if(w[i] >= type->length, ...)`

2. **VULN-DF-SPIRV-003**: 在 `vtn_variables.c:454` 处添加边界检查：`vtn_fail_if(field >= type->length, "struct member index out of bounds")`

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 7 | 41.2% |
| LIKELY | 4 | 23.5% |
| FALSE_POSITIVE | 4 | 23.5% |
| CONFIRMED | 2 | 11.8% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-SPIRV-001]** out_of_bounds_access (High) - `src/compiler/spirv/spirv_to_nir.c:2140` @ `vtn_handle_constant` | 置信度: 85
2. **[VULN-DF-SPIRV-003]** out_of_bounds_access (High) - `src/compiler/spirv/vtn_variables.c:449` @ `vtn_pointer_dereference` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `vk_common_CreateShaderModule@src/vulkan/runtime/vk_shader_module.c` | decorator | untrusted_network | Vulkan API入口点，应用程序传入SPIR-V shader代码字节流，可被恶意应用利用进行代码注入攻击 | 接收应用程序传入的SPIR-V shader模块字节码 |
| `spirv_to_nir@src/compiler/spirv/spirv_to_nir.c` | decorator | untrusted_network | SPIR-V shader解析器主入口，直接处理来自应用程序的字节流，历史上有多次漏洞报告 | 解析SPIR-V字节码转换为NIR中间表示 |
| `_mesa_glsl_parse@src/compiler/glsl/glsl_parser.yy` | decorator | untrusted_network | GLSL shader源码解析器，处理来自应用程序的shader源代码文本 | 解析GLSL shader源代码 |
| `glcpp_parser_parse@src/compiler/glsl/glcpp/glcpp-parse.y` | decorator | untrusted_network | GLSL预处理器，处理shader源代码中的预处理指令 | GLSL shader预处理器 |
| `eglInitialize@src/egl/main/eglapi.c` | decorator | semi_trusted | EGL API入口点，初始化图形显示连接 | EGL显示初始化 |
| `eglCreateContext@src/egl/main/eglapi.c` | decorator | semi_trusted | EGL上下文创建，接收配置参数 | 创建EGL渲染上下文 |
| `_mesa_ShaderSource@src/mesa/main/shaderapi.c` | decorator | untrusted_network | OpenGL shader源码提交入口，接收应用程序传入的shader字符串 | 设置OpenGL shader源代码 |
| `_mesa_SpecializeShader@src/mesa/main/glspirv.c` | decorator | untrusted_network | SPIR-V shader特化入口，处理来自应用程序的shader数据 | SPIR-V shader特化处理 |
| `parseConfigFile@src/util/xmlconfig.c` | file | semi_trusted | XML配置文件解析，读取系统/用户配置文件，可能被篡改 | 解析XML配置文件 |
| `disk_cache_create@src/util/disk_cache.c` | file | semi_trusted | 磁盘shader缓存操作，读写缓存文件，可能被篡改导致加载恶意shader | 创建磁盘shader缓存 |
| `disk_cache_load@src/util/disk_cache.c` | file | semi_trusted | 从磁盘加载缓存的shader二进制，文件可被外部篡改 | 从磁盘加载shader缓存 |
| `radv_CmdDraw@src/amd/vulkan/radv_cmd_buffer.c` | decorator | untrusted_network | Vulkan绘制命令处理，处理GPU命令缓冲区 | 处理Vulkan绘制命令 |
| `genX_CmdDraw@src/intel/vulkan/genX_cmd_buffer.c` | decorator | untrusted_network | Intel Vulkan绘制命令处理，处理GPU命令缓冲区 | 处理Intel Vulkan绘制命令 |
| `vn_renderer_vtest_connect@src/virtio/vulkan/vn_renderer_vtest.c` | network | untrusted_network | virtio-gpu渲染器连接，通过网络socket与远程guest VM通信 | virtio渲染器网络连接 |
| `vn_cs_decoder_read@src/virtio/vulkan/vn_cs.c` | network | untrusted_network | virtio命令流解码，从网络接收数据 | virtio命令流解码 |
| `loader_get_driver_for_device@src/loader/loader.c` | file | semi_trusted | 驱动加载器，根据设备信息加载GPU驱动 | GPU驱动加载 |
| `v3dv_CreatePipeline@src/broadcom/vulkan/v3dv_pipeline.c` | decorator | untrusted_network | Broadcom Vulkan pipeline创建，处理shader编译 | 创建Broadcom Vulkan pipeline |
| `tu_CreatePipeline@src/freedreno/vulkan/tu_pipeline.c` | decorator | untrusted_network | Freedreno Vulkan pipeline创建，处理shader编译 | 创建Freedreno Vulkan pipeline |
| `nir_shader_create@src/compiler/nir/nir.c` | internal | semi_trusted | NIR shader创建，内部处理编译后的shader | 创建NIR shader对象 |

**其他攻击面**:
- SPIR-V Shader Parsing: Applications submit SPIR-V bytecode that is parsed by spirv_to_nir parser - direct bytecode manipulation attack vector
- GLSL Shader Parsing: Applications submit GLSL source code parsed by glsl_parser - source code injection attack vector
- Vulkan API Calls: Application-initiated Vulkan commands processed by driver - API parameter manipulation attack vector
- OpenGL/EGL API Calls: Application-initiated GL/EGL calls - API parameter manipulation attack vector
- Shader Cache Files: Disk cache stores compiled shaders - cache file tampering attack vector
- XML Config Files: Driver configuration files parsed by xmlconfig - config file tampering attack vector
- virtio-gpu Network: virtio renderer communicates with guest VM via socket - network data injection attack vector
- GPU Command Buffers: Command buffers submitted by applications processed by drivers - command buffer manipulation attack vector
- GPU Memory Operations: Memory allocation and data transfer between CPU and GPU - memory corruption attack vector

---

## 3. High 漏洞 (2)

### [VULN-DF-SPIRV-001] out_of_bounds_access - vtn_handle_constant

**严重性**: High | **CWE**: CWE-129 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/compiler/spirv/spirv_to_nir.c:2140-2159` @ `vtn_handle_constant`
**模块**: spirv-parser
**跨模块**: spirv-parser → nir-compiler → vulkan-runtime → amd-vulkan → intel-vulkan

**描述**: Off-by-one bounds check in OpCompositeExtract/OpCompositeInsert handling. The validation at line 2140 uses 'w[i] > type->length' which allows index equal to length, causing out-of-bounds array access at lines 2153/2158/2159 when accessing (*c)->elements[w[i]] or type->members[w[i]].

**漏洞代码** (`src/compiler/spirv/spirv_to_nir.c:2140-2159`)

```c
vtn_fail_if(w[i] > type->length, ...)
...
c = &(*c)->elements[w[i]]; // line 2153
...
type = type->members[w[i]]; // line 2159
```

**达成路径**

SPIR-V bytecode w[i] (user-controlled) -> bounds check (flawed: > instead of >=) -> array access elements[w[i]]/members[w[i]] (out-of-bounds if w[i] == length)

**验证说明**: Off-by-one bounds check verified: w[i] > type->length allows index equal to length, causing out-of-bounds array access at elements[w[i]]/members[w[i]]. SPIR-V bytecode is direct external input (trust_level=untrusted_network). No mitigations found. Attacker can craft SPIR-V with w[i]=type->length to trigger.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-SPIRV-003] out_of_bounds_access - vtn_pointer_dereference

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-129 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/compiler/spirv/vtn_variables.c:449-464` @ `vtn_pointer_dereference`
**模块**: spirv-parser
**跨模块**: spirv-parser → vulkan-runtime

**描述**: Unchecked struct member index in pointer dereference. The field index from deref_chain->link[idx].id is used to access type->members[field] at line 454 without bounds validation against the actual struct member count (type->length). While vtn_assert checks that mode is literal for structs, it doesn't validate the index range.

**漏洞代码** (`src/compiler/spirv/vtn_variables.c:449-464`)

```c
if (glsl_type_is_struct_or_ifc(type->type)) {
  vtn_assert(deref_chain->link[idx].mode == vtn_access_mode_literal);
  unsigned field = deref_chain->link[idx].id;
  tail = nir_build_deref_struct(&b->nb, tail, field);
  type = type->members[field];
```

**达成路径**

SPIR-V bytecode index -> deref_chain->link[idx].id -> field variable -> type->members[field] (no bounds check against type->length)

**验证说明**: Unchecked struct member index verified. deref_chain->link[idx].id used to access type->members[field] without bounds check against type->length. vtn_assert only checks mode, not index range. Attacker can craft SPIR-V OpAccessChain with out-of-bounds struct member index.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -5

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| spirv-parser | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **2** | **0** | **0** | **2** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-129 | 2 | 100.0% |
