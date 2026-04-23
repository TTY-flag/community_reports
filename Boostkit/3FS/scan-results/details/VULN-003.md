# VULN-003: Buffer Overflow in hf3fs_iovopen

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-003 |
| **CWE** | CWE-120 (Buffer Copy without Checking Size of Input) |
| **类型** | buffer_overflow |
| **严重性** | Critical |
| **置信度** | 85% |
| **位置** | src/lib/api/UsrbIo.cc:273 |
| **函数** | hf3fs_iovopen |
| **模块** | lib/api |

## 漏洞详情

### 问题代码

```cpp
// UsrbIo.cc:226-281
int hf3fs_iovopen(struct hf3fs_iov *iov,
                  const uint8_t id[16],
                  const char *hf3fs_mount_point,
                  size_t size,
                  size_t block_size,
                  int numa) {
  // ... 省略前面的代码 ...
  
  // Line 273 - 漏洞点：strcpy 无长度检查
  strcpy(iov->mount_point, hf3fs_mount_point);
  iov->size = size;
  iov->block_size = block_size;
  iov->numa = numa;

  succ = true;
  return 0;
}
```

### 目标缓冲区

```cpp
// hf3fs_usrbio.h:17-26
struct hf3fs_iov {
  uint8_t *base;
  hf3fs_iov_handle iovh;
  char id[16];
  char mount_point[256];  // 目标缓冲区：256字节
  size_t size;
  size_t block_size;
  int numa;
};
```

### 对比分析

同一文件中其他函数有正确的长度检查：

```cpp
// hf3fs_iovcreate_general (UsrbIo.cc:122-125) - 有长度检查
if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
  XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
  return -EINVAL;
}

// hf3fs_iovwrap (UsrbIo.cc:303-306) - 有长度检查
if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
  XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
  return -EINVAL;
}

// hf3fs_iorwrap (UsrbIo.cc:398-401) - 有长度检查
if (strlen(hf3fs_mount_point) >= sizeof(ior->mount_point)) {
  XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
  return -EINVAL;
}
```

**结论**：`hf3fs_iovopen` 函数遗漏了其他函数已有的安全检查，属于编码疏忽。

## 攻击路径

### 数据流

```
API参数 hf3fs_mount_point
  │
  ▼
strcpy(iov->mount_point, hf3fs_mount_point)  [漏洞点]
  │
  ▼
iov->mount_point[256]  [溢出目标]
```

### 入口点可达性

| 层级 | 入口 | 信任等级 |
|------|------|----------|
| 1 | hf3fs_iovopen API | untrusted_local (本地用户进程) |
| 2 | Python binding (py::hf3fs_iovopen) | untrusted_local |
| 3 | 用户态应用程序 | untrusted_local |

**攻击者路径**：
1. 本地用户进程调用 hf3fs_iovopen API
2. 传入超过255字节的 hf3fs_mount_point 参数
3. strcpy 造成 iov->mount_point 缓冲区溢出
4. 溢出数据覆盖 iov 结构体后续字段 (id, size, block_size, numa)
5. 可能进一步覆盖堆内存中的其他数据

### 触发条件

```cpp
// 最小触发代码
struct hf3fs_iov iov;
char mount_point[300];
memset(mount_point, 'A', 299);
mount_point[299] = '\0';

hf3fs_iovopen(&iov, id, mount_point, size, block_size, numa);
// 触发缓冲区溢出
```

## 利用场景

### 场景1：堆破坏攻击

如果 `iov` 结构体分配在堆上：
1. 溢出数据覆盖 iov 后续的堆对象
2. 通过精心构造的溢出数据，可以修改相邻堆对象的元数据
3. 结合其他漏洞可实现任意代码执行

### 场景2：栈破坏攻击

如果 `iov` 结构体分配在栈上：
1. 溢出数据覆盖栈上的返回地址
2. 构造 ROP 链实现代码执行
3. 绕过 ASLR 需要信息泄露漏洞配合

### 场景3：信息泄露

即使无法直接获取代码执行：
1. 溢出可修改 iov->size、iov->block_size 等字段
2. 可能导致后续操作读写超出预期范围的内存
3. 为后续攻击提供信息泄露基础

## 影响评估

### 直接影响

| 影响 | 描述 |
|------|------|
| 内存破坏 | 缓冲区溢出导致 iov 结构体后续字段被覆盖 |
| 程序崩溃 | 溢出数据可能导致程序异常崩溃 |
| 数据损坏 | iov->id 等字段被破坏可能导致数据不一致 |

### 间接影响

| 影响 | 描述 |
|------|------|
| 代码执行 | 在堆/栈攻击场景下可实现任意代码执行 |
| 权限提升 | 结合其他漏洞可提升进程权限 |
| 服务拒绝 | 恶意输入导致存储服务崩溃 |

### 影响范围

- **攻击面**：FUSE Mount Point (本地用户进程)
- **攻击者**：任何能调用 hf3fs API 的本地用户
- **影响对象**：使用 hf3fs 用户态 API 的所有应用程序

## 修复建议

### 方案1：添加长度检查（推荐）

```cpp
int hf3fs_iovopen(struct hf3fs_iov *iov,
                  const uint8_t id[16],
                  const char *hf3fs_mount_point,
                  size_t size,
                  size_t block_size,
                  int numa) {
  // 添加长度检查，与其他函数保持一致
  if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
    XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
    return -EINVAL;
  }
  
  // ... 其他代码 ...
  
  strcpy(iov->mount_point, hf3fs_mount_point);  // 现安全
  // ... 其他代码 ...
}
```

### 方案2：使用安全字符串函数

```cpp
// 使用 strncpy + 手动添加空终止符
size_t len = strlen(hf3fs_mount_point);
if (len >= sizeof(iov->mount_point)) {
  return -EINVAL;
}
memcpy(iov->mount_point, hf3fs_mount_point, len + 1);
```

### 方案3：使用 snprintf

```cpp
// 使用 snprintf 防止溢出
snprintf(iov->mount_point, sizeof(iov->mount_point), "%s", hf3fs_mount_point);
```

### 修复优先级

| 优先级 | 原因 |
|--------|------|
| **高** | Critical 级别漏洞，影响 API 安全性 |

### 测试建议

修复后应添加单元测试：

```cpp
TEST(UsrbIo, MountPointLengthValidation) {
  struct hf3fs_iov iov;
  char long_mount_point[300];
  memset(long_mount_point, 'A', 299);
  long_mount_point[299] = '\0';
  
  // 应返回错误而非溢出
  int result = hf3fs_iovopen(&iov, id, long_mount_point, size, block_size, numa);
  EXPECT_EQ(result, -EINVAL);
}
```

## 总结

这是一个典型的缓冲区溢出漏洞，由于 `hf3fs_iovopen` 函数遗漏了其他类似函数已有的长度检查而导致。攻击者通过传入超长的 mount_point 参数可触发溢出，可能实现代码执行或服务拒绝。修复方案简单明确，只需添加与其他函数一致的长度检查即可。