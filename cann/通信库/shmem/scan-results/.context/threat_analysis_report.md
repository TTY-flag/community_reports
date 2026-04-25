# SHMEM 项目威胁分析报告

## 项目概览

| 属性 | 值 |
|------|-----|
| 项目名称 | SHMEM (华为昇腾平台共享内存通信库) |
| 项目类型 | C/C++ + Python 混合项目 |
| 文件数量 | C/C++: 175个源文件, 250个头文件; Python: 43个文件 |
| 分析日期 | 2026-04-25 |
| 风险等级 | **高风险** |

---

## 1. 执行摘要

SHMEM是一个面向华为昇腾(Ascend)平台的多机多卡内存通信库，提供跨设备的高效内存访问与数据同步能力。该项目涉及网络通信、TLS加密、远程内存访问(RDMA/MTE/SDMA)、Python绑定等高风险组件。

**关键发现**:
- 存在**7个高风险模块**，其中2个为关键级别
- **5个主要攻击面**：网络通信、内存操作、加密处理、输入验证、Python绑定
- 使用了TLS1.3加密和多项安全编译选项作为防护措施
- 潜在漏洞类型包括整数溢出、内存越界、输入验证不当、加密问题等

---

## 2. 模块风险评估

### 2.1 关键风险模块 (Critical)

#### 2.1.1 TLS安全模块 (`src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **Critical** |
| 功能 | TLS证书加载、私钥处理、密码解密 |
| 潜在CWE | CWE-321(硬编码密钥), CWE-326(弱加密), CWE-310(加密问题) |

**关键风险点**:
1. **密码解密回调**: `GetPkPass()` 函数接受用户提供的解密回调函数，可能被注入恶意代码
2. **私钥内存处理**: 私钥以内存形式加载，需要确保敏感数据被正确擦除
3. **证书验证**: 证书过期检查可能被绕过

**代码分析**:
```cpp
// acc_tcp_ssl_helper.cpp:186-212
AccResult AccTcpSslHelper::GetPkPass() {
    if (mDecryptHandler_ == nullptr) {
        // 直接使用明文密码 - 安全风险
        mKeyPass = std::make_pair(new char[len + 1], len);
        std::copy(encryptedText.begin(), encryptedText.end(), mKeyPass.first);
    } else {
        // 用户回调解密 - 注入风险
        auto ret = static_cast<AccResult>(mDecryptHandler_(encryptedText, buffer, bufferLen));
    }
}
```

#### 2.1.2 初始化模块 (`src/host/init/shmem_init.cpp`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **Critical** |
| 功能 | 参数验证、全局状态初始化 |
| 潜在CWE | CWE-20(输入验证不当), CWE-190(整数溢出) |

**关键风险点**:
1. **参数边界验证**: `check_attr()` 验证 my_pe, n_pes, local_mem_size 等参数
2. **整数溢出风险**: `local_mem_size + ACLSHMEM_EXTRA_SIZE` 可能溢出
3. **全局状态暴露**: `g_state` 结构体包含敏感的堆地址信息

**代码分析**:
```cpp
// shmem_init.cpp:140-157
int32_t check_attr(aclshmemx_init_attr_t *attributes) {
    SHM_VALIDATE_RETURN(attributes->my_pe >= 0, "my_pe is less than zero", ACLSHMEM_INVALID_VALUE);
    SHM_VALIDATE_RETURN(attributes->n_pes <= ACLSHMEM_MAX_PES, "n_pes is too large", ACLSHMEM_INVALID_VALUE);
    SHM_VALIDATE_RETURN(attributes->my_pe < attributes->n_pes, ...);
    SHM_VALIDATE_RETURN(attributes->local_mem_size > 0, ...);
    SHM_ASSERT_RETURN(attributes->local_mem_size <= ACLSHMEM_MAX_LOCAL_SIZE, ACLSHMEM_INVALID_VALUE);
}
```

### 2.2 高风险模块 (High)

#### 2.2.1 Socket通信模块 (`src/host/bootstrap/socket/uid_socket.cpp`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **High** |
| 功能 | TCP socket连接、数据收发 |
| 潜在CWE | CWE-20(输入验证不当), CWE-400(资源消耗), CWE-287(认证问题) |

**关键风险点**:
1. **网络数据接收**: `socket_recv()` 直接接收网络数据，缺乏长度验证
2. **Magic验证**: 使用固定magic number进行连接验证，可能被伪造
3. **超时处理**: 连接超时可能被利用进行DoS攻击

#### 2.2.2 RDMA地址解析模块 (`src/host/transport/device_rdma/device_rdma_helper.cpp`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **High** |
| 功能 | RDMA网络地址字符串解析 |
| 潜在CWE | CWE-20(输入验证不当), CWE-787(内存越界) |

**关键风险点**:
1. **IPv4/IPv6地址解析**: 用户输入的网络地址字符串直接解析
2. **端口验证**: 端口字符串长度和字符验证
3. **协议名称验证**: 仅做字符范围检查，可能遗漏特殊字符

#### 2.2.3 Python绑定模块 (`src/host/python_wrapper/pyshmem.cpp`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **High** |
| 功能 | Python API绑定、回调处理 |
| 潜在CWE | CWE-20(输入验证不当), CWE-668(资源暴露), CWE-362(竞态条件) |

**关键风险点**:
1. **Python回调函数**: `g_py_decrypt_func` 全局函数可能被替换
2. **整数指针转换**: Python整数到C指针的转换缺乏验证
3. **GIL释放**: `py::gil_scoped_release` 后可能存在竞态条件
4. **密码解密**: Python层解密回调可能泄露敏感信息

**代码分析**:
```cpp
// pyshmem.cpp:72-97
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, 
                                       char *plainText, size_t &plainTextLen) {
    if (cipherTextLen > MAX_CIPHER_LEN || !g_py_decrypt_func) {
        return -1;
    }
    // Python回调 - 注入风险
    py::str py_cipher = py::str(cipherText, cipherTextLen);
    std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
}
```

#### 2.2.4 内存管理模块 (`src/host/mem/shmem_host_heap.h`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **High** |
| 功能 | 共享内存分配 |
| 潜在CWE | CWE-190(整数溢出), CWE-415(双重释放), CWE-476(空指针) |

**关键风险点**:
1. **size参数**: 用户指定的分配大小可能导致整数溢出
2. **对齐参数**: `aclshmem_align()` 的alignment参数验证
3. **内存释放**: 可能存在双重释放风险

#### 2.2.5 远程内存访问模块 (`src/host/data_plane/shmem_host_rma.h`)

| 属性 | 描述 |
|------|------|
| 风险级别 | **High** |
| 功能 | RMA远程内存读写 |
| 潜在CWE | CWE-787(越界写入), CWE-125(越界读取), CWE-119(缓冲区溢出) |

**关键风险点**:
1. **远程地址**: `dst/src` 指针指向远程PE内存
2. **数据大小**: `elem_size` 参数控制传输大小
3. **PE编号**: `pe` 参数指定目标处理元素

---

## 3. 攻击面分析

### 3.1 网络通信攻击面

| 组件 | 文件 | 威胁类型 |
|------|------|----------|
| TCP Socket | uid_socket.cpp | 数据注入、DoS、连接伪造 |
| RDMA传输 | device_rdma_helper.cpp | 地址伪造、内存破坏 |
| TLS加密 | acc_tcp_ssl_helper.cpp | 中间人攻击、证书伪造 |

**攻击场景**:
- 恶意节点发送伪造的magic number建立连接
- 网络数据包注入导致内存破坏
- RDMA地址解析绕过导致非法内存访问

### 3.2 内存操作攻击面

| 组件 | 文件 | 威胁类型 |
|------|------|----------|
| 内存分配 | shmem_host_heap.h | 整数溢出、OOM |
| 远程内存访问 | shmem_host_rma.h | 越界读写、信息泄露 |
| 内存管理 | shmem_mgr.cpp | 双重释放、内存泄漏 |

**攻击场景**:
- `local_mem_size` 设置超大值导致整数溢出
- `elem_size` 参数伪造导致远程内存越界
- 对齐参数设置导致内存对齐问题

### 3.3 加密处理攻击面

| 组件 | 文件 | 威胁类型 |
|------|------|----------|
| TLS初始化 | acc_tcp_ssl_helper.cpp | 弱加密、证书问题 |
| 私钥处理 | acc_tcp_ssl_helper.cpp | 密钥泄露、注入 |
| 密码解密 | pyshmem.cpp | 回调注入、信息泄露 |

**攻击场景**:
- 提供过期或伪造的证书
- 通过解密回调函数注入恶意代码
- TLS配置不当导致加密失效

### 3.4 输入验证攻击面

| 参数 | 来源 | 验证位置 | 风险 |
|------|------|----------|------|
| my_pe | 用户/API | check_attr() | 负数、越界 |
| n_pes | 用户/API | check_attr() | 超限 |
| local_mem_size | 用户/API | check_attr() | 整数溢出 |
| elem_size | 用户/API | putmem/getmem | 越界 |
| nic | 环境变量 | ParseDeviceNic() | 格式伪造 |
| tlsPk/tlsPkPwd | 用户/API | GetPkPass() | 泄露 |

### 3.5 Python绑定攻击面

| 函数 | 风险 | 影响范围 |
|------|------|----------|
| aclshmem_init | 参数验证 | 全局初始化 |
| set_conf_store_tls_key | 密码处理 | TLS配置 |
| aclshmem_malloc | 内存分配 | 共享内存 |
| aclshmem_putmem | 远程写入 | 内存破坏 |

---

## 4. 数据流分析

### 4.1 关键数据流路径

#### 初始化流程
```
用户参数(attributes) -> aclshmemx_init_attr -> check_attr -> g_state
    ├── my_pe -> g_state.mype
    ├── n_pes -> g_state.npes  
    └── local_mem_size -> g_state.heap_size (潜在溢出)
```

#### TLS私钥处理流程
```
tlsPkPwd -> aclshmemx_set_config_store_tls_key -> GetPkPass
    ├── 明文路径: 直接复制到mKeyPass
    └── 解密路径: mDecryptHandler_(cipherText) -> plainText
        -> LoadPrivateKey -> SSL_CTX_use_PrivateKey
```

#### 网络数据接收流程
```
socket_recv -> recv(sock->fd, data, size) -> ptr
    -> socket_finalize_accept (magic验证)
    -> socket_finalize_connect
```

#### 远程内存访问流程
```
aclshmem_putmem(dst, src, elem_size, pe)
    -> aclshmemx_putmem_on_stream
    -> RDMA/MTE传输引擎
    -> 远程PE内存写入
```

### 4.2 污点标记

| 污点源 | 汇点 | 类型 |
|--------|------|------|
| attributes->local_mem_size | memory_allocation | 整数溢出 |
| tlsPkPwd | private_key_password | 加密敏感 |
| socket_recv -> ptr | network_data | 网络输入 |
| nic字符串 | rdma_address | 输入验证 |
| size参数 | memory_allocation | 整数溢出 |
| Python bytes | bootstrap_uid | 绑定转换 |
| cipherText | decrypted_password | Python回调 |

---

## 5. 安全措施评估

### 5.1 已实施的安全措施

| 措施 | 位置 | 有效性 |
|------|------|--------|
| TLS1.3加密 | InitSSL() | **有效** - 强加密 |
| 强加密套件 | SslCtxSetCipherSuites() | **有效** |
| 安全编译选项 | CMakeLists.txt | **有效** |
| 证书过期检查 | CertExpiredCheck() | **有效** |
| 参数边界验证 | check_attr() | **部分有效** |
| Magic Number验证 | socket_finalize_accept() | **弱** - 可伪造 |
| 私钥擦除 | EraseDecryptData() | **有效** |

### 5.2 编译时安全选项

```
-D_FORTIFY_SOURCE=2
-O2 -std=c++17
-fstack-protector-strong
-Wl,-z,relro
-Wl,-z,now
```

### 5.3 加密配置

- TLS版本: TLS1.3 (强制)
- 加密套件:
  - TLS_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_CCM_SHA256
- 最小密钥长度: 2048位

---

## 6. 风险评分

| 模块 | 影响 | 可利用性 | 风险评分 |
|------|------|----------|----------|
| TLS安全模块 | Critical | Medium | **9.0/10** |
| 初始化模块 | Critical | High | **8.5/10** |
| Socket通信 | High | High | **7.5/10** |
| RDMA地址解析 | High | Medium | **6.5/10** |
| Python绑定 | High | Medium | **6.5/10** |
| 内存管理 | High | Medium | **6.0/10** |
| 远程内存访问 | High | Low | **5.5/10** |

---

## 7. 推荐扫描重点

### 7.1 必须扫描的模块

| 优先级 | 模块路径 | 关注点 |
|--------|----------|--------|
| P0 | src/host/bootstrap/config_store/acc_links/csrc/security/ | TLS/加密漏洞 |
| P0 | src/host/init/ | 参数验证、整数溢出 |
| P1 | src/host/bootstrap/socket/ | 网络输入验证 |
| P1 | src/host/transport/device_rdma/ | 地址解析 |
| P1 | src/host/python_wrapper/ | Python绑定安全 |
| P2 | src/host/mem/ | 内存操作 |
| P2 | src/host/data_plane/ | 远程内存访问 |

### 7.2 重点漏洞类型

1. **整数溢出**: `local_mem_size`, `elem_size`, `size` 参数
2. **输入验证**: 网络地址字符串、PE编号、Magic number
3. **加密问题**: 证书验证、私钥处理、密码泄露
4. **内存安全**: 远程内存访问、内存分配、指针转换
5. **注入风险**: Python回调函数、解密回调

---

## 8. 结论

SHMEM项目是一个功能完备的高性能共享内存通信库，但存在多个高风险攻击面。项目已实施多项安全措施(TLS加密、安全编译选项等)，但在以下方面仍需加强:

1. **用户回调函数安全**: 解密回调存在注入风险
2. **参数边界验证**: 整数溢出风险未被完全消除
3. **网络输入验证**: Socket通信缺乏深度验证
4. **Python绑定安全**: 类型转换和GIL处理需要更严格的检查

建议按照优先级对高风险模块进行深度漏洞扫描。

---

*报告生成时间: 2026-04-25*
*分析工具: OpenCode Architecture Analysis Agent*