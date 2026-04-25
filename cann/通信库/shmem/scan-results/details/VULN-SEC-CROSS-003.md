# VULN-SEC-CROSS-003: 跨模块任意内存访问攻击链

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CROSS-003 |
| **类型** | arbitrary_memory_access_chain |
| **CWE** | CWE-668 (资源暴露给错误的作用域) |
| **严重性** | High |
| **状态** | CONFIRMED |
| **涉及模块** | Python核心模块、Python绑定模块、数据面RMA |

**核心问题**: 这是一个完整的跨模块任意内存访问攻击链，从Python层无参数验证开始，经过Python绑定层的任意指针转换，最终在RMA层执行远程内存操作，攻击者可以读写任意远程进程的内存地址。

## 详细技术分析

### 漏洞链路

```
Python层 → C++绑定层 → C++ RMA层 → 设备内核 → 远程内存访问
```

#### 第一层: Python核心模块 (无参数验证)

**文件**: `/src/python/shmem/core/rma.py`

**问题代码**:
```python
# 第83-94行: put函数 - 无地址验证
def put(dst: Buffer, src: Buffer, remote_pe: int=-1, stream: int=None) -> None:
    """
    Copy contiguous data from the local PE to a symmetric memory address on a remote PE.
    """
    _pyshmem.aclshmemx_putmem_on_stream(dst.addr, src.addr, src.length, remote_pe, stream)

# 第96-107行: get函数 - 无地址验证
def get(dst: Buffer, src: Buffer, remote_pe: int=-1, stream: int=None) -> None:
    """
    Copy contiguous data from symmetric memory on a remote PE to a local buffer.
    """
    _pyshmem.aclshmemx_getmem_on_stream(dst.addr, src.addr, src.length, remote_pe, stream)
```

**Buffer类定义** (`/src/python/shmem/core/utils.py`):
```python
# 第85-101行: Buffer类 - 仅检查非负，不验证地址范围
class Buffer:
    __slots__ = ('addr', 'length')

    def __init__(self, addr: int, length: int):
        if addr < 0:                      # 仅检查非负
            raise ValueError("Address must be non-negative")
        if length <= 0:                   # 仅检查正长度
            raise ValueError("Length must be positive")
        self.addr = addr                  # 接受任意地址!
        self.length = length
```

**安全问题**:
- 用户可以构造任意地址的Buffer对象
- 仅检查地址非负，不验证是否在合法的对称内存范围内
- 地址可以是任意值，如其他进程内存、内核内存等

#### 第二层: Python绑定层 (intptr_t直接转换)

**文件**: `/src/host/python_wrapper/pyshmem.cpp`

**问题代码**:
```cpp
// 第924-946行: aclshmemx_putmem_on_stream - 直接指针转换
m.def(
    "aclshmemx_putmem_on_stream",
    [](intptr_t dst, intptr_t src, size_t elem_size, int pe, intptr_t stream) {
        auto dst_addr = (void *)dst;           // 无验证，直接转换!
        auto src_addr = (void *)src;           // 无验证，直接转换!
        aclrtStream acl_stream = nullptr;
        if (stream != 0) {
            acl_stream = reinterpret_cast<aclrtStream>(stream);
        }
        aclshmemx_putmem_on_stream(dst_addr, src_addr, elem_size, pe, acl_stream);
    },
    py::call_guard<py::gil_scoped_release>(), ...)

// 第947-962行: aclshmemx_getmem_on_stream - 同样问题
m.def(
    "aclshmemx_getmem_on_stream",
    [](intptr_t dst, intptr_t src, size_t elem_size, int pe, intptr_t stream) {
        auto dst_addr = (void *)dst;           // 无验证，直接转换!
        auto src_addr = (void *)src;           // 无验证，直接转换!
        aclrtStream acl_stream = nullptr;
        if (stream != 0) {
            acl_stream = reinterpret_cast<aclrtStream>(stream);
        }
        aclshmemx_getmem_on_stream(dst_addr, src_addr, elem_size, pe, acl_stream);
    },
    ...)

// 第494-510行: aclshmem_putmem - 同样问题
m.def(
    "aclshmem_putmem",
    [](intptr_t dst, intptr_t src, size_t elem_size, int pe) {
        auto dst_addr = (void *)dst;           // 无验证!
        auto src_addr = (void *)src;           // 无验证!
        aclshmem_putmem(dst_addr, src_addr, elem_size, pe);
    },
    ...)

// 第591-607行: aclshmem_getmem - 同样问题
m.def(
    "aclshmem_getmem",
    [](intptr_t dst, intptr_t src, size_t elem_size, int pe) {
        auto dst_addr = (void *)dst;           // 无验证!
        auto src_addr = (void *)src;           // 无验证!
        aclshmem_getmem(dst_addr, src_addr, elem_size, pe);
    },
    ...)
```

**安全问题**:
- `intptr_t` 直接转换为 `void*`，无任何边界验证
- 没有检查地址是否在合法的对称堆内存范围内
- 没有使用 `aclshmem_ptr()` 进行地址验证和转换
- 攻击者传入的任意整数都会被当作有效指针

#### 第三层: C++ RMA层 (无边界检查的内存操作)

**文件**: `/src/host/data_plane/shmem_host_rma.cpp`

**问题代码**:
```cpp
// 第326-337行: aclshmemx_getmem_on_stream - 直接使用指针
void aclshmemx_getmem_on_stream(void* dst, void* src, size_t elem_size, int32_t pe, aclrtStream stream)
{
    if (stream == nullptr) {
        stream = g_state_host.default_stream;
    }
    int ret = aclshmemi_prepare_and_post_rma("aclshmemx_getmem_on_stream", ACLSHMEMI_OP_GET, NO_NBI, 
                                              (uint8_t *)dst, (uint8_t *)src, elem_size, 1, pe, 
                                              nullptr, 0, 0, 1, 1, stream, g_state_host.default_block_num);
    // dst和src未经验证直接传入内核!
}

// 第339-351行: aclshmemx_putmem_on_stream - 同样问题
void aclshmemx_putmem_on_stream(void* dst, void* src, size_t elem_size, int32_t pe, aclrtStream stream)
{
    if (stream == nullptr) {
        stream = g_state_host.default_stream;
    }
    int ret = aclshmemi_prepare_and_post_rma("aclshmemx_putmem_on_stream", ACLSHMEMI_OP_PUT, NO_NBI, 
                                              (uint8_t *)dst, (uint8_t *)src, elem_size, 1, pe, 
                                              nullptr, 0, 0, 1, 1, stream, g_state_host.default_block_num);
    // dst和src未经验证直接传入内核!
}

// 第286-294行: aclshmem_putmem - 同样问题
void aclshmem_putmem(void *dst, void *src, size_t elem_size, int32_t pe)
{
    int ret = aclshmemi_prepare_and_post_rma("shmem putmem", ACLSHMEMI_OP_PUT, NO_NBI, 
                                              (uint8_t *)dst, (uint8_t *)src, elem_size, 1, pe, 
                                              nullptr, 0, 0, 1, 1, g_state_host.default_stream,
                                              g_state_host.default_block_num);
}

// 第296-304行: aclshmem_getmem - 同样问题
void aclshmem_getmem(void *dst, void *src, size_t elem_size, int32_t pe)
{
    int ret = aclshmemi_prepare_and_post_rma("shmem getmem", ACLSHMEMI_OP_GET, NO_NBI, 
                                              (uint8_t *)dst, (uint8_t *)src, elem_size, 1, pe, 
                                              nullptr, 0, 0, 1, 1, g_state_host.default_stream,
                                              g_state_host.default_block_num);
}
```

**对比正确的实现** - `aclshmem_ptr()` 函数:
```cpp
// 第36-57行: aclshmem_ptr - 正确实现地址验证
void *aclshmem_ptr(void *ptr, int32_t pe)
{
    // 第38-41行: PE范围验证
    if (pe < 0 || pe >= aclshmem_n_pes()) {
        SHM_LOG_ERROR("aclshmem_ptr Failed. PE: " << aclshmem_my_pe() << " Got Illegal PE !!");
        return nullptr;
    }
    
    // 第42-46行: 地址边界验证
    uint64_t heap_base = is_host_mem_heap(ptr) ? (uint64_t)g_state.host_heap_base : (uint64_t)g_state.heap_base;
    if (!check_heap_addr(ptr, heap_base, g_state.heap_size)) {
        SHM_LOG_ERROR("aclshmem_ptr Failed. PE: " << aclshmem_my_pe() << " Got Illegal Address !!");
        return nullptr;
    }
    
    // 计算合法的远程对称地址
    uint64_t offset = (uint64_t)ptr - heap_base;
    void *symm_ptr = is_host_mem_heap(ptr) ? g_state.p2p_host_heap_base[pe] : g_state.p2p_device_heap_base[pe];
    ...
}
```

**安全问题**:
- `aclshmem_putmem`/`aclshmem_getmem` 系列函数没有调用 `aclshmem_ptr()` 进行地址验证
- 用户传入的任意指针直接传递给内核执行
- 没有检查地址是否在合法的对称堆内存边界内

#### 第四层: 设备内核层 (执行远程内存访问)

**文件**: `/src/device/gm2gm/shmemi_device_rma.cpp`

**问题代码**:
```cpp
// 第120-173行: aclshmemi_prepare_and_post_rma - 核心RMA执行函数
int32_t aclshmemi_prepare_and_post_rma(const char *api_name, aclshmemi_op_t desc, bool is_nbi, 
                                        uint8_t *dst, uint8_t *src, size_t n_elems, size_t elem_bytes, 
                                        int pe, uint8_t *sig_addr, int32_t signal, int sig_op, 
                                        ptrdiff_t lstride, ptrdiff_t rstride, aclrtStream acl_strm,
                                        size_t block_size)
{
    if (is_nbi) {
        switch (desc) {
            case ACLSHMEMI_OP_PUT:
                // 第128行: 直接使用未验证的指针启动内核!
                aclshmemi_putmem_nbi<<<block_size, 0, acl_strm>>>(dst, src, n_elems * elem_bytes, pe);
                break;
            case ACLSHMEMI_OP_GET:
                // 第131行: 直接使用未验证的指针启动内核!
                aclshmemi_getmem_nbi<<<block_size, 0, acl_strm>>>(dst, src, n_elems * elem_bytes, pe);
                break;
            ...
        }
    } else {
        switch (desc) {
            case ACLSHMEMI_OP_PUT:
                // 第144行: 直接使用未验证的指针!
                aclshmemi_putmem<<<block_size, 0, acl_strm>>>(dst, src, n_elems * elem_bytes, pe);
                break;
            case ACLSHMEMI_OP_GET:
                // 第147行: 直接使用未验证的指针!
                aclshmemi_getmem<<<block_size, 0, acl_strm>>>(dst, src, n_elems * elem_bytes, pe);
                break;
            ...
        }
    }
    return 0;
}

// 第34-42行: 内核函数直接使用指针执行内存操作
ACLSHMEM_GLOBAL void aclshmemi_putmem(GM_ADDR dst, GM_ADDR src, uint32_t elem_size, int32_t pe)
{
    aclshmem_uint8_put(dst, src, elem_size, pe);  // 执行远程内存写入!
}

ACLSHMEM_GLOBAL void aclshmemi_getmem(GM_ADDR dst, GM_ADDR src, uint32_t elem_size, int32_t pe)
{
    aclshmem_uint8_get(dst, src, elem_size, pe);  // 执行远程内存读取!
}
```

**安全问题**:
- 内核函数直接使用传入的指针执行远程内存读写
- 没有任何边界检查或地址验证
- 攻击者指定的任意地址都会被当作目标地址

## 利用场景和攻击路径

### 攻击场景1: 远程进程内存读取 (数据泄露)

**攻击者视角**:
```python
import shmem
import shmem.core as core

# 假设已知目标进程PE号
target_pe = 1

# 构造任意地址的Buffer对象 - 例如已知目标进程的数据段地址
arbitrary_addr = 0x7FFFF0000000  # 可能是其他进程的堆地址

# 创建恶意Buffer (绕过验证)
malicious_src = core.Buffer(addr=arbitrary_addr, length=4096)
local_dst = core.buffer(4096)  # 本地合法Buffer

# 创建stream
stream = acl.rt.create_stream()[0]

# 执行恶意get操作 - 从任意地址读取数据
core.get(local_dst, malicious_src, target_pe, stream)

# 攻击者现在拥有了目标地址的数据!
```

**后果**:
- 读取任意远程进程内存
- 泄露敏感数据(密钥、凭证、个人信息)
- 跨PE数据泄露

### 攻击场景2: 远程进程内存写入 (数据篡改)

**攻击者视角**:
```python
import shmem
import shmem.core as core
import acl

# 目标进程PE
target_pe = 1

# 构造目标地址 - 例如目标进程的关键数据结构地址
arbitrary_addr = 0x7FFFF0000000

# 创建恶意Buffer
malicious_dst = core.Buffer(addr=arbitrary_addr, length=4096)
local_src = core.buffer(4096)

# 填充恶意数据
acl.rt.memset(local_src.addr, 4096, 0xDE, 4096)  # 填充0xDE

stream = acl.rt.create_stream()[0]

# 执行恶意put操作 - 向任意地址写入数据
core.put(malicious_dst, local_src, target_pe, stream)

# 目标进程的关键数据被篡改!
```

**后果**:
- 破坏目标进程的数据完整性
- 可能导致目标进程崩溃
- 可能注入恶意代码(如果目标地址是可执行内存)

### 攻击场景3: 跨PE代码注入

**攻击者视角**:
```python
import shmem
import shmem.core as core

# 假设已知目标进程的可执行内存区域
target_code_addr = 0x7FFFF0001000  # 可能是代码段地址

# 构造shellcode或恶意指令
shellcode_buffer = core.buffer(256)
# 填充恶意指令数据...

# 构造恶意目标Buffer
malicious_dst = core.Buffer(addr=target_code_addr, length=256)

stream = acl.rt.create_stream()[0]

# 向目标进程代码段写入shellcode
core.put(malicious_dst, shellcode_buffer, target_pe, stream)
```

**后果**:
- 远程代码执行
- 完全控制目标PE进程
- 横向移动攻击

### 完整攻击链路图

```
┌─────────────────────────────────────────────────────────────────────┐
│                        攻击入口点                                    │
│  Python API: Buffer(addr=任意值, length=N)                          │
│  rma.py: put(dst=恶意Buffer, src=合法Buffer, pe=目标)               │
└─────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点1: 无地址验证                              │
│  utils.py: 第95-101行                                               │
│  if addr < 0: raise ValueError  # 仅检查非负                        │
│  self.addr = addr  # 任意地址被接受!                                │
└─────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点2: 直接指针转换                            │
│  pyshmem.cpp: 第927-928行                                           │
│  auto dst_addr = (void *)dst;  // 无边界检查                        │
│  auto src_addr = (void *)src;  // intptr_t直接转为void*             │
└─────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点3: 无验证传递                              │
│  shmem_host_rma.cpp: 第344-346行                                    │
│  aclshmemi_prepare_and_post_rma(..., (uint8_t *)dst, ...)          │
│  // 未调用aclshmem_ptr()验证地址                                    │
└─────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点4: 内核执行                                │
│  shmemi_device_rma.cpp: 第144行                                     │
│  aclshmemi_putmem<<<...>>>(dst, src, elem_size, pe);               │
│  // 恶意地址被传递给内核执行远程内存操作                              │
└─────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        最终后果                                     │
│  • 远程进程任意内存地址被写入攻击者数据                               │
│  • 数据泄露、数据篡改、远程代码执行                                   │
│  • 整个集群安全被破坏                                                │
└─────────────────────────────────────────────────────────────────────┘
```

## PoC 概念验证思路

### PoC 1: 地址验证缺失验证

```python
#!/usr/bin/env python3
"""
概念验证: 验证任意地址可以被接受并执行RMA操作
"""
import shmem._pyshmem as _pyshmem
from shmem.core.utils import Buffer

# 测试1: 构造非法地址的Buffer
try:
    # 非对称堆地址 - 应该被拒绝，但实际被接受
    arbitrary_buffer = Buffer(addr=0xDEADBEEF000, length=1024)
    print("[PoC] Arbitrary address buffer created successfully!")
    print(f"[PoC] Address: 0x{arbitrary_buffer.addr:x}")
except ValueError as e:
    print(f"[PoC] Rejected: {e}")  # 预期不会执行到这里

# 测试2: 尝试使用恶意Buffer调用RMA
# (需要实际NPU环境和PE配置)
# mal_dst = Buffer(addr=0x7FFFF0000000, length=4096)
# _pyshmem.aclshmem_putmem(mal_dst.addr, legitimate_src.addr, 4096, target_pe)
```

### PoC 2: 绑定层指针转换验证

```cpp
// 通过调试或日志验证指针转换
// 在pyshmem.cpp中添加日志:
// std::cout << "dst_addr: " << dst_addr << " (from intptr_t: " << dst << ")" << std::endl;

// 验证: 即使传入非法intptr_t，也会被转换为void*并传递给下层
```

### PoC 3: RMA层边界检查缺失验证

```cpp
// 在shmem_host_rma.cpp中验证aclshmem_ptr未被调用
// 对比aclshmem_ptr的正确实现与putmem/getmem的无验证实现

// 正确的地址验证 (aclshmem_ptr):
void *aclshmem_ptr(void *ptr, int32_t pe) {
    if (!check_heap_addr(ptr, heap_base, heap_size)) {
        return nullptr;  // 拒绝非法地址
    }
    ...
}

// 问题实现 (aclshmem_putmem):
void aclshmem_putmem(void *dst, void *src, ...) {
    // 没有调用aclshmem_ptr或check_heap_addr!
    aclshmemi_prepare_and_post_rma(..., dst, src, ...);
}
```

## 修复建议

### 立即修复 (High优先级)

#### 修复点1: Python层添加地址范围验证

**文件**: `src/python/shmem/core/utils.py`

```python
class Buffer:
    __slots__ = ('addr', 'length')
    
    # 添加对称堆地址范围常量
    SYMMETRIC_HEAP_MIN = 0x100000000  # 示例，需要从实际配置获取
    SYMMETRIC_HEAP_MAX = 0x200000000
    
    def __init__(self, addr: int, length: int):
        if addr < 0:
            raise ValueError("Address must be non-negative")
        if length <= 0:
            raise ValueError("Length must be positive")
        
        # 修复: 添加地址范围验证
        # 对于合法分配的Buffer，需要验证地址来源
        # 或者添加验证标记
        if not hasattr(self, '_validated'):
            # 非通过buffer()函数创建的Buffer需要验证
            if addr < self.SYMMETRIC_HEAP_MIN or addr > self.SYMMETRIC_HEAP_MAX:
                raise ValueError(f"Address 0x{addr:x} outside symmetric heap bounds")
        
        self.addr = addr
        self.length = length
    
    @classmethod
    def validated_buffer(cls, addr: int, length: int):
        """仅用于内部可信的Buffer创建"""
        buf = cls(addr, length)
        buf._validated = True
        return buf
```

#### 修复点2: Python绑定层添加地址验证

**文件**: `src/host/python_wrapper/pyshmem.cpp`

```cpp
m.def(
    "aclshmemx_putmem_on_stream",
    [](intptr_t dst, intptr_t src, size_t elem_size, int pe, intptr_t stream) {
        // 修复: 添加地址验证
        void *dst_addr = (void *)dst;
        void *src_addr = (void *)src;
        
        // 使用aclshmem_ptr验证目标地址
        void *validated_dst = aclshmem_ptr(dst_addr, pe);
        if (validated_dst == nullptr) {
            throw std::runtime_error("Invalid destination address for PE " + std::to_string(pe));
        }
        
        // 验证源地址在本地对称堆范围内
        uint64_t heap_base = (uint64_t)g_state.heap_base;
        uint64_t heap_end = heap_base + g_state.heap_size;
        if ((uint64_t)src_addr < heap_base || (uint64_t)src_addr >= heap_end) {
            throw std::runtime_error("Invalid source address - outside symmetric heap");
        }
        
        aclrtStream acl_stream = nullptr;
        if (stream != 0) {
            acl_stream = reinterpret_cast<aclrtStream>(stream);
        }
        aclshmemx_putmem_on_stream(validated_dst, src_addr, elem_size, pe, acl_stream);
    },
    py::call_guard<py::gil_scoped_release>(), ...)
```

#### 修复点3: RMA层添加地址边界检查

**文件**: `src/host/data_plane/shmem_host_rma.cpp`

```cpp
void aclshmemx_putmem_on_stream(void* dst, void* src, size_t elem_size, int32_t pe, aclrtStream stream)
{
    // 修复: 添加地址边界检查
    void *validated_dst = aclshmem_ptr(dst, pe);
    if (validated_dst == nullptr) {
        SHM_LOG_ERROR("aclshmemx_putmem_on_stream: invalid destination address");
        return;
    }
    
    // 验证源地址
    if (!check_heap_addr(src, (uint64_t)g_state.heap_base, g_state.heap_size)) {
        SHM_LOG_ERROR("aclshmemx_putmem_on_stream: invalid source address");
        return;
    }
    
    if (stream == nullptr) {
        stream = g_state_host.default_stream;
    }
    
    int ret = aclshmemi_prepare_and_post_rma("aclshmemx_putmem_on_stream", ACLSHMEMI_OP_PUT, NO_NBI, 
                                              (uint8_t *)validated_dst, (uint8_t *)src, elem_size, 1, pe, 
                                              nullptr, 0, 0, 1, 1, stream, g_state_host.default_block_num);
    ...
}
```

### 长期改进建议

1. **统一地址验证机制**: 所有RMA操作必须通过 `aclshmem_ptr()` 验证地址
2. **添加API级别保护**: Python API层添加类型检查和地址来源验证
3. **审计日志**: 记录所有RMA操作的地址范围，用于安全审计
4. **内存隔离**: 严格的对称堆内存边界管理
5. **权限检查**: 添加PE间访问权限控制

## 影响范围评估

### 直接影响

| 影项范围 | 描述 | 严重程度 |
|---------|------|---------|
| **远程内存泄露** | 可读取任意远程进程内存 | Critical |
| **远程内存篡改** | 可修改任意远程进程内存 | Critical |
| **集群安全** | 整个集群内存安全被破坏 | High |
| **数据完整性** | 跨PE数据可被任意篡改 | High |
| **潜在RCE** | 可能实现远程代码执行 | High |

### 受影响代码模块

| 模块 | 文件 | 行号 | 漏洞类型 |
|------|------|------|---------|
| Python核心 | rma.py | 83-107 | 无地址验证 |
| Python工具 | utils.py | 95-101 | Buffer接受任意地址 |
| Python绑定 | pyshmem.cpp | 494-510, 591-607, 924-962 | 直接指针转换 |
| RMA层 | shmem_host_rma.cpp | 286-304, 326-351 | 无边界检查 |
| 内核层 | shmemi_device_rma.cpp | 120-173 | 无验证执行 |

### 攻击复杂度

| 因素 | 评估 |
|------|------|
| **攻击入口** | 低 - 公开Python API |
| **利用难度** | 中 - 需要了解目标内存布局 |
| **所需权限** | 低 - 用户级权限 |
| **影响范围** | 高 - 整个集群 |

### 关联漏洞

- VULN-SEC-PYBIND-004: Python绑定层指针安全问题
- 此漏洞为跨模块攻击链的完整实现

## 结论

这是一个**真实且严重的跨模块任意内存访问漏洞链**，涉及多个关键安全问题：

1. **Python层无验证**: Buffer类接受任意地址，put/get函数无参数验证
2. **绑定层直接转换**: intptr_t直接转为void*，无边界检查
3. **RMA层无保护**: 未调用aclshmem_ptr()进行地址验证
4. **内核层无限制**: 任意地址被传递给内核执行远程内存操作

**漏洞链完整性**: 多个漏洞点串联形成完整的攻击路径，从Python层任意地址构造到远程内存读写，形成可直接利用的安全漏洞链。

**建议立即修复**: 这是High级别的安全漏洞，应立即进行修复，优先在RMA层添加地址边界检查。

---
**报告生成时间**: 2026-04-25
**分析者**: security-auditor
**状态**: CONFIRMED
