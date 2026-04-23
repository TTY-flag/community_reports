# 漏洞扫描报告 — 待确认漏洞

**项目**: Mesa 3D Graphics Library
**扫描时间**: 2025-04-21T19:10:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Medium | 4 | 40.0% |
| Low | 6 | 60.0% |
| **有效漏洞总计** | **10** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-VIRTIO-002]** integer_overflow (Medium) - `src/virtio/vulkan/vn_renderer_vtest.c:281` @ `vtest_vcmd_get_capset` | 置信度: 70
2. **[VULN-DF-SPIRV-002]** integer_overflow (Medium) - `src/compiler/spirv/vtn_variables.c:165` @ `vtn_access_chain_create` | 置信度: 65
3. **[VULN-DF-SPIRV-004]** integer_overflow (Medium) - `src/compiler/spirv/spirv_to_nir.c:4410` @ `vtn_handle_entry_point` | 置信度: 60
4. **[VULN-DF-SPIRV-005]** integer_overflow (Medium) - `src/compiler/spirv/spirv_to_nir.c:1522` @ `vtn_handle_type` | 置信度: 60
5. **[VULN-DF-GLSL-001]** integer_overflow (Low) - `src/compiler/glsl/link_varyings.cpp:1966` @ `varying_matches::record` | 置信度: 55
6. **[VULN-DF-GLSL-002]** integer_overflow (Low) - `src/compiler/glsl/link_uniforms.cpp:108` @ `is_top_level_shader_storage_block_member` | 置信度: 50
7. **[VULN-DF-UTIL-001]** integer_overflow (Low) - `src/util/disk_cache.c:140` @ `disk_cache_create` | 置信度: 50
8. **[SEC-004]** Untrusted Input Processing (Low) - `src/vulkan/runtime/vk_shader_module.c:44` @ `vk_common_CreateShaderModule` | 置信度: 45
9. **[SEC-007]** Integrity Check Weakness (Low) - `src/util/disk_cache_os.c:509` @ `parse_and_validate_cache_item` | 置信度: 45
10. **[SEC-005]** Path Injection (Low) - `src/mesa/main/shaderapi.c:169` @ `_mesa_get_shader_capture_path` | 置信度: 40

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

## 3. Medium 漏洞 (4)

### [VULN-DF-VIRTIO-002] integer_overflow - vtest_vcmd_get_capset

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/virtio/vulkan/vn_renderer_vtest.c:281-283` @ `vtest_vcmd_get_capset`
**模块**: virtio
**跨模块**: virtio → vulkan-runtime

**描述**: Integer overflow in capset size calculation. When vtest_hdr[VTEST_CMD_LEN] comes from the remote renderer and is very large, the multiplication (CMD_LEN - 1) * 4 can overflow, potentially resulting in a small read_size that bypasses the capset_size check and causes buffer overflow.

**漏洞代码** (`src/virtio/vulkan/vn_renderer_vtest.c:281-283`)

```c
vtest_read(vtest, vtest_hdr, sizeof(vtest_hdr));
...
size_t read_size = (vtest_hdr[VTEST_CMD_LEN] - 1) * 4;
if (capset_size >= read_size) {
  vtest_read(vtest, capset, read_size);
```

**达成路径**

vtest_hdr[VTEST_CMD_LEN] (network data) -> (CMD_LEN - 1) * 4 -> read_size -> vtest_read into capset buffer

**验证说明**: Integer overflow in capset size calculation verified. vtest_hdr[VTEST_CMD_LEN] from network (untrusted) used in (CMD_LEN-1)*4 calculation. If CMD_LEN is crafted (e.g., 0x40000001), overflow wraps to 0, causing read_size=0 and bypassing size validation. Attacker can send crafted network packet to virtio renderer.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-SPIRV-002] integer_overflow - vtn_access_chain_create

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/compiler/spirv/vtn_variables.c:165-176` @ `vtn_access_chain_create`
**模块**: spirv-parser
**跨模块**: spirv-parser → nir-compiler

**描述**: Integer overflow in access chain size calculation. When length from SPIR-V bytecode is extremely large (e.g., UINT_MAX), the size calculation sizeof(*chain) + (MAX2(length, 1) - 1) * sizeof(chain->link[0]) can overflow, potentially causing undersized allocation and subsequent buffer overflow.

**漏洞代码** (`src/compiler/spirv/vtn_variables.c:165-176`)

```c
size_t size = sizeof(*chain) + (MAX2(length, 1) - 1) * sizeof(chain->link[0]);
chain = rzalloc_size(b, size);
```

**达成路径**

SPIR-V bytecode count -> length = count - 4 (OpAccessChain) -> size calculation with potential overflow -> rzalloc_size with undersized buffer

**验证说明**: Integer overflow in access chain size calculation verified. When length from SPIR-V is very large, sizeof(*chain) + (MAX2(length,1)-1) * sizeof(chain->link[0]) can overflow. However, vtn_assert at line 483 validates count bounds, limiting practical exploitability. Attacker needs to craft extremely large SPIR-V module.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: -5

---

### [VULN-DF-SPIRV-004] integer_overflow - vtn_handle_entry_point

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/compiler/spirv/spirv_to_nir.c:4410-4413` @ `vtn_handle_entry_point`
**模块**: spirv-parser
**跨模块**: spirv-parser → vulkan-runtime

**描述**: Potential integer overflow in interface_ids memcpy. The multiplication b->interface_ids_count * 4 at line 4413 could overflow if count - start is large enough (e.g., > UINT_MAX/4). While there's a bounds check at vtn_foreach_instruction, it doesn't prevent overflow in the multiplication.

**漏洞代码** (`src/compiler/spirv/spirv_to_nir.c:4410-4413`)

```c
size_t start = 3 + name_words;
b->interface_ids_count = count - start;
b->interface_ids = ralloc_array(b, uint32_t, b->interface_ids_count);
memcpy(b->interface_ids, &w[start], b->interface_ids_count * 4);
```

**达成路径**

SPIR-V bytecode count/start -> interface_ids_count = count - start -> multiplication count * 4 (potential overflow) -> memcpy size parameter

**验证说明**: Potential integer overflow in interface_ids memcpy. Multiplication interface_ids_count * 4 could overflow. However, ralloc_array uses same count parameter, so allocation size matches. Requires crafted SPIR-V with extreme count values to trigger overflow in both allocation and memcpy.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-SPIRV-005] integer_overflow - vtn_handle_type

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/compiler/spirv/spirv_to_nir.c:1522-1528` @ `vtn_handle_type`
**模块**: spirv-parser
**跨模块**: spirv-parser → nir-compiler

**描述**: Integer overflow in struct type member allocation. num_fields = count - 2 is derived directly from SPIR-V bytecode. If extremely large, ralloc_array allocations for members and offsets arrays could overflow, causing undersized allocations.

**漏洞代码** (`src/compiler/spirv/spirv_to_nir.c:1522-1528`)

```c
unsigned num_fields = count - 2;
val->type->length = num_fields;
val->type->members = ralloc_array(b, struct vtn_type *, num_fields);
val->type->offsets = ralloc_array(b, unsigned, num_fields);
```

**达成路径**

SPIR-V bytecode count -> num_fields = count - 2 -> ralloc_array size parameter (potential overflow)

**验证说明**: Integer overflow in struct type member allocation verified. num_fields = count - 2 from SPIR-V. If count is crafted to be UINT_MAX-1 or similar, ralloc_array could overflow. However, SPIR-V module size validation limits practical exploitability.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Low 漏洞 (6)

### [VULN-DF-GLSL-001] integer_overflow - varying_matches::record

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/compiler/glsl/link_varyings.cpp:1966-1970` @ `varying_matches::record`
**模块**: glsl-parser
**跨模块**: glsl-parser → mesa-main

**描述**: Integer overflow in varying_matches::record during array reallocation. When matches_capacity is doubled repeatedly, the multiplication sizeof(*this->matches) * this->matches_capacity can overflow, causing realloc to allocate a tiny or zero-sized buffer leading to buffer overflow on subsequent writes.

**漏洞代码** (`src/compiler/glsl/link_varyings.cpp:1966-1970`)

```c
if (this->num_matches == this->matches_capacity) {
  this->matches_capacity *= 2;
  this->matches = (match *) realloc(this->matches, sizeof(*this->matches) * this->matches_capacity);
```

**达成路径**

matches_capacity (dynamic growth) -> capacity *= 2 -> sizeof(*matches) * capacity (potential overflow) -> realloc size

**验证说明**: Integer overflow in varying_matches array reallocation verified. When matches_capacity doubles repeatedly, sizeof(*matches) * capacity could overflow. However, practical limits on shader complexity and varying count make exploitation difficult. Requires shader with extreme number of varyings.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-GLSL-002] integer_overflow - is_top_level_shader_storage_block_member

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/compiler/glsl/link_uniforms.cpp:108-116` @ `is_top_level_shader_storage_block_member`
**模块**: glsl-parser
**跨模块**: glsl-parser → mesa-main

**描述**: Integer overflow in uniform name length calculation. When interface_name and field_name are extremely long (from shader source), the addition in name_length calculation could overflow, causing calloc to allocate a small buffer. Subsequent snprintf would then write beyond allocated bounds.

**漏洞代码** (`src/compiler/glsl/link_uniforms.cpp:108-116`)

```c
int name_length = strlen(interface_name) + 1 + strlen(field_name) + 1;
char *full_instanced_name = (char *) calloc(name_length, sizeof(char));
snprintf(full_instanced_name, name_length, "%s.%s", interface_name, field_name);
```

**达成路径**

interface_name/field_name (shader source) -> strlen -> name_length calculation -> calloc(name_length, 1)

**验证说明**: Integer overflow in uniform name length calculation verified. strlen(interface_name) + 1 + strlen(field_name) + 1 could overflow if both strings are extremely long. However, GLSL parser has practical limits on identifier length. Exploitation requires crafted shader with very long interface/block names.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-UTIL-001] integer_overflow - disk_cache_create

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/util/disk_cache.c:140-159` @ `disk_cache_create`
**模块**: util

**描述**: Integer overflow in disk cache max size parsing. The environment variable MESA_SHADER_CACHE_MAX_SIZE is parsed with strtoul then multiplied by up to 1024*1024*1024 (1GB). On 32-bit systems or with large input values, this multiplication can overflow, leading to unexpectedly small cache limits.

**漏洞代码** (`src/util/disk_cache.c:140-159`)

```c
max_size = strtoul(max_size_str, &end, 10);
...
case 'K': max_size *= 1024;
case 'M': max_size *= 1024*1024;
case 'G': max_size *= 1024*1024*1024;
```

**达成路径**

MESA_SHADER_CACHE_MAX_SIZE (environment variable) -> strtoul -> max_size *= multiplier (potential overflow)

**验证说明**: strtoul + 乘法可能导致整数溢出，仅影响缓存大小设置，无内存安全风险

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 15

---

### [SEC-004] Untrusted Input Processing - vk_common_CreateShaderModule

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/vulkan/runtime/vk_shader_module.c:44-58` @ `vk_common_CreateShaderModule`
**模块**: vulkan-runtime
**跨模块**: vulkan-runtime → spirv-parser

**描述**: vk_shader_module.c directly copies SPIR-V shader code from application without validation. memcpy copies the entire shader code without checking SPIR-V magic number or format validity before processing. Malformed or malicious SPIR-V could cause issues during parsing.

**漏洞代码** (`src/vulkan/runtime/vk_shader_module.c:44-58`)

```c
module = vk_object_alloc(device, pAllocator, sizeof(*module) + pCreateInfo->codeSize, VK_OBJECT_TYPE_SHADER_MODULE);
module->size = pCreateInfo->codeSize;
memcpy(module->data, pCreateInfo->pCode, module->size);
```

**达成路径**

Application SPIR-V code -> memcpy -> shader module

**验证说明**: SPIR-V 代码通过 memcpy 存储后，后续在 spirv_to_nir 编译过程中验证。SHA1 校验用于缓存键计算降低了缓存污染的可能性

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [SEC-007] Integrity Check Weakness - parse_and_validate_cache_item

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-354 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/util/disk_cache_os.c:509-553` @ `parse_and_validate_cache_item`
**模块**: util

**描述**: disk_cache_os.c uses CRC32 for cache item integrity verification. CRC32 is not cryptographically secure and can be manipulated. Cache files could be tampered with without detection.

**漏洞代码** (`src/util/disk_cache_os.c:509-553`)

```c
if (cf_data->crc32 != util_hash_crc32(data, cache_data_size))
// CRC32 used for integrity check
```

**达成路径**

Cache file -> CRC32 check -> load

**验证说明**: CRC32 用于缓存完整性检查，不是加密安全的完整性验证机制。仅影响本地缓存文件完整性

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-005] Path Injection - _mesa_get_shader_capture_path

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mesa/main/shaderapi.c:169-190` @ `_mesa_get_shader_capture_path`
**模块**: mesa-main

**描述**: shaderapi.c reads shader capture path directly from environment variable without sanitization. MESA_SHADER_CAPTURE_PATH could contain path traversal characters leading to files being written outside intended directories.

**漏洞代码** (`src/mesa/main/shaderapi.c:169-190`)

```c
path = getenv("MESA_SHADER_CAPTURE_PATH");
// path used directly for shader capture without validation
```

**达成路径**

Environment variable -> path -> shader capture

**验证说明**: getenv 直接读取 shader 捕获路径，信任边界为 trusted_admin (环境变量由用户或管理员设置)

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -10 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| glsl-parser | 0 | 0 | 0 | 2 | 2 |
| mesa-main | 0 | 0 | 0 | 1 | 1 |
| spirv-parser | 0 | 0 | 3 | 0 | 3 |
| util | 0 | 0 | 0 | 2 | 2 |
| virtio | 0 | 0 | 1 | 0 | 1 |
| vulkan-runtime | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **0** | **4** | **6** | **10** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 7 | 70.0% |
| CWE-354 | 1 | 10.0% |
| CWE-22 | 1 | 10.0% |
| CWE-20 | 1 | 10.0% |
