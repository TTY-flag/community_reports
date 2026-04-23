# VULN-SEC-SNAPPY-001：缓冲区溢出漏洞

## 1. 漏洞确认结论

**状态：真实漏洞（CONFIRMED）**

**严重性：High**
**CWE：CWE-787（Out-of-bounds Write）**
**置信度：95%（提升原因：对比同项目其他模块，确认边界检查缺失）**

---

## 2. 漏洞详情

### 2.1 漏洞位置
- **文件**：`KAESnappy/src/v1/kaesnappy_comp.c`（赋值位置）+ `KAESnappy/src/v1/kaesnappy_ctx.c`（memcpy执行位置）
- **关键代码行**：
  - 赋值：kaesnappy_comp.c:58
  - 复制：kaesnappy_ctx.c:251

### 2.2 漏洞触发路径

```
公开API入口
└── kaesnappy_compress(SNAPPY_CCtx* zc, const void* src, size_t srcSize)
    └── kaesnappy_adapter.c:83-99
        └── kaesnappy_compress_v1(zc, src, srcSize)  // 无边界检查
            └── kaesnappy_comp.c:41-79
                ├── kaesnappy_ctx->in_len = srcSize        // Line 51
                ├── kaesnappy_ctx->do_comp_len = in_len    // Line 58 - 关键漏洞点！
                └── kaesnappy_set_input_data(kaesnappy_ctx)
                    └── memcpy(op_data.in, in, do_comp_len)  // Line 251 - 溢出发生点
```

### 2.3 关键代码分析

**漏洞代码（kaesnappy_comp.c:58）：**
```c
kaesnappy_ctx->in_len       = srcSize;           // Line 51 - 用户输入直接赋值
kaesnappy_ctx->do_comp_len = kaesnappy_ctx->in_len;  // Line 58 - 无上限检查！
```

**溢出代码（kaesnappy_ctx.c:251）：**
```c
memcpy((uint8_t *)kz_ctx->op_data.in, kz_ctx->in, kz_ctx->do_comp_len);
```

**缓冲区分配（kaesnappy_ctx.c:112）：**
```c
kz_ctx->op_data.in = kz_ctx->setup.br.alloc(kz_ctx->setup.br.usr, COMP_BLOCK_SIZE);
// COMP_BLOCK_SIZE = 2 * 1024 * 1024 (2MB)
```

### 2.4 漏洞根本原因

**do_comp_len 无上限验证**：
- `do_comp_len` 直接等于用户提供的 `srcSize`
- 缓冲区 `op_data.in` 固定为 2MB
- 当 `srcSize > 2MB` 时，memcpy 溢出

---

## 3. 对比分析（关键证据）

### 3.1 同项目正确实现对比

**KAEZstd 正确实现（kaezstd_ctx.c:284-288）：**
```c
if (kaezstd_ctx->in_len >= KAEZIP_STREAM_CHUNK_IN) {
    kaezstd_ctx->do_comp_len = KAEZIP_STREAM_CHUNK_IN;  // 强制限制！
} else {
    kaezstd_ctx->do_comp_len = kaezstd_ctx->in_len;
}
```

**KAEZlib 正确实现（kaezip_deflate.c:205）：**
```c
kaezip_ctx->in_len = (strm->avail_in < KAEZIP_STREAM_CHUNK_IN) 
                     ? strm->avail_in : KAEZIP_STREAM_CHUNK_IN;  // 三元运算符限制
```

**KAESnappy 漏洞实现（无限制）：**
```c
kaesnappy_ctx->do_comp_len = kaesnappy_ctx->in_len;  // 直接赋值，无检查
```

### 3.2 项目常量定义

| 常量 | 值 | 用途 |
|------|------|------|
| COMP_BLOCK_SIZE | 2MB (2*1024*1024) | 缓冲区分配大小 |
| KAEZIP_STREAM_CHUNK_IN | 256KB (COMP_BLOCK_SIZE >> 3) | 安全输入上限 |

**关键发现**：
- KAEZstd/KAEZlib 使用 `KAEZIP_STREAM_CHUNK_IN` (256KB) 作为输入上限
- KAESnappy 应使用相同限制，但完全缺失

---

## 4. 利用分析

### 4.1 攻击向量

**输入来源**：公开 API 参数
```c
int kaesnappy_compress(SNAPPY_CCtx* zc, const void* src, size_t srcSize);
```

**攻击者控制**：`srcSize` 参数（无任何验证）

### 4.2 漏洞触发条件

```c
// 触发条件：srcSize > COMP_BLOCK_SIZE (2MB)
kaesnappy_compress(ctx, data, 3*1024*1024);  // 传入3MB数据

// 内部流程：
in_len = 3MB;                  // 用户输入
do_comp_len = 3MB;             // 无限制赋值
memcpy(op_data.in, in, 3MB);   // 溢出！op_data.in只有2MB
```

### 4.3 影响分析

**内存破坏**：
- 缓冲区溢出 1MB 数据（如输入3MB）
- 溢出数据写入相邻内存区域
- 可能覆盖相邻缓冲区 `op_data.out`（Line 118）

**潜在后果**：
- 内存破坏导致程序崩溃（DoS）
- 可能覆盖关键数据结构
- 在特定环境下可能利用进行代码执行

### 4.4 现有缓解措施评估

**报告中提到的"COMP_BLOCK_SIZE分配"**：
- 这只是缓冲区分配大小，不是边界检查
- 缓解措施无效，反而证明了漏洞存在

---

## 5. 修复建议

### 5.1 正确修复方案

**参照 KAEZstd 实现（推荐）**：

```c
// kaesnappy_comp.c:58 修改为：
if (kaesnappy_ctx->in_len >= KAEZIP_STREAM_CHUNK_IN) {
    kaesnappy_ctx->do_comp_len = KAEZIP_STREAM_CHUNK_IN;
} else {
    kaesnappy_ctx->do_comp_len = kaesnappy_ctx->in_len;
}
```

**或参照 KAEZlib 实现（更简洁）**：

```c
// kaesnappy_comp.c:58 修改为：
kaesnappy_ctx->do_comp_len = (kaesnappy_ctx->in_len < KAEZIP_STREAM_CHUNK_IN) 
                              ? kaesnappy_ctx->in_len : KAEZIP_STREAM_CHUNK_IN;
```

### 5.2 需引入的常量

```c
#include "kaesnappy_utils.h"  // 已定义 KAEZIP_STREAM_CHUNK_IN
```

### 5.3 修复位置

| 文件 | 行号 | 原代码 | 修复后 |
|------|------|--------|--------|
| kaesnappy_comp.c | 58 | `do_comp_len = in_len;` | 添加上限检查 |

---

## 6. 验证方法

### 6.1 漏洞验证代码

```c
// 创建测试用例
SNAPPY_CCtx ctx;
kaesnappy_init(&ctx);

// 分配超过2MB的输入数据
size_t overflow_size = 3 * 1024 * 1024;  // 3MB
void* input_data = malloc(overflow_size);
memset(input_data, 'A', overflow_size);

// 触发漏洞
int ret = kaesnappy_compress(&ctx, input_data, overflow_size);
// 预期：内存溢出，可能导致崩溃或内存破坏
```

### 6.2 安全边界测试

```c
// 测试边界值
size_t safe_size = KAEZIP_STREAM_CHUNK_IN;     // 256KB - 应安全
size_t boundary = COMP_BLOCK_SIZE;              // 2MB - 边界值
size_t overflow = COMP_BLOCK_SIZE + 1;          // 2MB+1 - 应溢出
```

---

## 7. 相关文件清单

| 文件路径 | 作用 | 相关行号 |
|----------|------|----------|
| kaesnappy_comp.c | 压缩逻辑，do_comp_len赋值 | 58 |
| kaesnappy_ctx.c | memcpy执行位置 | 112, 251 |
| kaesnappy_adapter.c | 公开API入口 | 83-99 |
| kaesnappy.h | 公开API定义 | 94 |
| kaesnappy_utils.h | 常量定义 | 49-50 |

---

## 8. 总结

这是一个**真实的缓冲区溢出漏洞**，根本原因是缺少对用户输入大小的边界检查。同项目的 KAEZstd 和 KAEZlib 模块都有正确的实现，证明这是代码质量问题而非设计限制。

修复简单：添加上限检查，参照同项目已有正确实现。建议立即修复，避免潜在的内存破坏和 DoS 攻击风险。

**风险评估**：
- 技术可利用性：高（公开API，用户控制输入大小）
- 修复难度：低（单行修改，参照已有代码）
- 影响范围：KAESnappy v1 硬件加速模块所有用户
