# 威胁分析报告

**项目名称**: msPTI (MindStudio Profiling Tools Interface)  
**扫描时间**: 2026-04-20  
**项目类型**: library（华为昇腾NPU性能分析工具库）

---

## 1. 项目概述

msPTI 是华为昇腾AI处理器的性能分析工具接口库，提供C API和Python API供用户应用程序进行NPU性能分析。该库通过动态注入机制拦截ACL/HCCL/ProfAPI等库的函数调用，收集性能数据，并通过回调机制将数据传递给用户。

### 项目架构

```
mspti/
├── csrc/
│   ├── include/           # 公共API头文件 (mspti.h, mspti_callback.h, mspti_activity.h)
│   ├── callback/          # 回调管理 (callback_manager.cpp)
│   ├── activity/          # 活动记录管理
│   │   ├── activity_manager.cpp
│   │   └── ascend/
│   │       ├── channel/   # 驱动数据通道读取
│   │       ├── parser/    # 数据解析和计算
│   │       └── reporter/  # 报告生成
│   └── common/
│       ├── inject/        # 动态注入机制 (ACL/HCCL/Driver/Mstx/ProfAPI)
│       ├── function_loader.cpp  # dlopen/dlsym动态库加载
│       ├── utils.cpp      # 工具函数
│       └── context_manager.cpp
├── mspti/                 # Python API封装
│   ├── __init__.py
│   ├── monitor/           # 监控类
│   └── utils.py
```

---

## 2. 信任边界分析

### 2.1 边界定义

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| Library API Interface | User Application | msPTI Library | Medium |
| Dynamic Library Loading | msPTI Library | External Libraries (libascendcl.so, libhccl.so, libprofapi.so) | Critical |
| Driver Channel Data | msPTI Library | Device Driver/Kernel | High |
| Environment Variables | msPTI Library | System Environment (ASCEND_HOME_PATH) | High |
| User Callback Functions | msPTI Library | User-provided Callback Code | Medium |
| Marker/Domain Names | msPTI Library | User-provided Strings (msg, domain names) | Medium |

### 2.2 关键攻击面

1. **动态库加载机制**: dlopen/dlsym 加载外部库，路径由环境变量决定
2. **驱动数据通道**: ProfChannelRead 从设备驱动读取原始二进制数据
3. **用户回调机制**: msptiSubscribe/msptiActivityRegisterCallbacks 注册用户回调
4. **环境变量依赖**: ASCEND_HOME_PATH 控制动态库搜索路径
5. **字符串输入**: mstx标记函数接收用户字符串（msg、domain）
6. **结构体转换**: reinterpret_cast 直接转换驱动数据为内部结构体

---

## 3. STRIDE威胁建模

### 3.1 Spoofing（身份伪造）

| 威胁 | 描述 | 风险 | 影响文件 |
|------|------|------|----------|
| 库路径伪造 | ASCEND_HOME_PATH环境变量控制动态库路径，恶意用户可设置伪造路径加载恶意库 | Critical | function_loader.cpp:58 |
| Domain名伪造 | 用户提供的domain字符串可能包含恶意内容，仅做长度验证 | Medium | mstx_inject.cpp:66 |

**缓解建议**:
- 对动态库路径进行白名单验证，限制只能加载预定义的华为昇腾库
- 对domain/msg字符串进行内容验证，过滤危险字符

### 3.2 Tampering（数据篡改）

| 威胁 | 描述 | 风险 | 影响文件 |
|------|------|------|----------|
| 驱动数据篡改 | ProfChannelRead从驱动读取的数据可能被篡改，直接reinterpret_cast转换 | High | channel_reader.cpp:85 |
| 活动记录篡改 | 用户回调函数可能篡改活动记录缓冲区内容 | Medium | activity_manager.cpp:58 |
| 紧凑信息篡改 | profapi回调接收的数据可能包含异常结构 | High | profapi_inject.cpp:164 |

**缓解建议**:
- 对从驱动读取的数据进行结构验证和边界检查
- 在reinterpret_cast前验证数据长度和类型
- 对profapi回调数据进行字段验证

### 3.3 Repudiation（抵赖）

| 威胁 | 描述 | 风险 | 影响文件 |
|------|------|------|----------|
| 回调执行无日志 | 用户回调函数执行缺乏完整日志记录 | Low | callback_manager.cpp:195 |

**缓解建议**:
- 增加回调执行的详细日志记录，包括参数和返回值

### 3.4 Information Disclosure（信息泄露）

| 威胁 | 描述 | 风险 | 影响文件 |
|------|------|------|----------|
| 内核名称泄露 | 性能数据可能包含敏感的内核名称和参数 | Medium | kernel_parser.cpp:153 |
| 回调数据泄露 | 用户回调可能访问敏感性能数据 | Medium | callback_manager.cpp:209 |

**缓解建议**:
- 对敏感性能数据进行脱敏处理
- 限制回调函数对原始数据的访问权限

### 3.5 Denial of Service（拒绝服务）

| 威胁 | 描述 | 风险 | 影响文件 |
|------|------|------|----------|
| 长消息字符串 | 用户提供的msg字符串过长可能导致内存问题 | Medium | mstx_inject.cpp:186 |
| 缓冲区溢出 | 驱动数据超过缓冲区容量可能导致丢弃或崩溃 | Medium | channel_reader.cpp:93 |
| 回调阻塞 | 用户回调函数阻塞可能影响整个系统 | Medium | callback_manager.cpp:209 |

**缓解建议**:
- 严格限制msg/domain字符串长度（当前已有MAX_MARK_MSG_LEN=128限制）
- 增加驱动数据缓冲区边界检查
- 设置回调执行超时机制

### 3.6 Elevation of Privilege（权限提升）

| 威胁 | 描述 | 风险 | 影响文件 |
|------|------|------|----------|
| 库注入 | 通过伪造ASCEND_HOME_PATH加载恶意库，执行任意代码 | Critical | function_loader.cpp:74 |
| 回调代码执行 | 用户回调函数在库上下文中执行，可能进行特权操作 | High | callback_manager.cpp:209 |

**缓解建议**:
- 使用绝对路径白名单验证动态库路径
- 在沙箱环境中执行用户回调函数

---

## 4. 高风险文件分析

### 4.1 Critical风险文件

#### csrc/common/function_loader.cpp (Critical)

**风险点**: dlopen动态加载外部库

```cpp
// 第74行
auto handle = dlopen(soPath.c_str(), RTLD_LAZY);
```

**数据流**: 
```
getenv("ASCEND_HOME_PATH") → CanonicalSoPath → dlopen → dlsym
```

**漏洞场景**: 
1. 恶意用户设置ASCEND_HOME_PATH为恶意目录
2. 库加载恶意版本的libascendcl.so/libhccl.so
3. 恶意库执行任意代码，获取进程权限

**现有缓解措施**:
- 第47-53行有预定义的soNameList白名单
- 第64行使用Utils::RealPath进行路径规范化
- 第64行检查文件存在性和可读性

**不足之处**:
- 白名单仅限制库名，未限制库路径
- realpath规范化后未验证路径是否在合法范围内

#### csrc/common/inject/driver_inject.cpp (Critical)

**风险点**: ProfChannelRead从驱动读取数据

```cpp
// 第120行
int ProfChannelRead(unsigned int deviceId, unsigned int channelId, char *outBuf, unsigned int bufSize)
```

**数据流**: 
```
Device Driver → ProfChannelRead → ChannelReader::Execute → TransDataToActivityBuffer
```

**漏洞场景**: 
1. 恶意驱动返回超大数据或异常结构
2. 数据直接被reinterpret_cast转换
3. 可能导致内存越界或类型混淆

### 4.2 High风险文件

#### csrc/common/inject/profapi_inject.cpp (High)

**风险点**: 回调函数接收外部数据

```cpp
// 第127行 - MsptiApiReporterCallbackImpl
int32_t MsptiApiReporterCallbackImpl(uint32_t agingFlag, const MsprofApi * const data)

// 第164行 - MsptiCompactInfoReporterCallbackImpl  
int32_t MsptiCompactInfoReporterCallbackImpl(uint32_t agingFlag, CONST_VOID_PTR data, uint32_t length)
```

**漏洞场景**: 
1. libprofapi.so可能被替换或篡改
2. 回调数据结构可能包含异常字段
3. 未验证的数据直接传递给解析器

#### csrc/activity/ascend/channel/channel_reader.cpp (High)

**风险点**: 驱动数据转换

```cpp
// 第126-127行 - reinterpret_cast直接转换
TsTrackHead* tsHead = reinterpret_cast<TsTrackHead*>(buffer + pos);
```

**漏洞场景**: 
1. 驱动数据结构不符合预期
2. 直接类型转换可能导致内存访问错误
3. 缺少结构验证和边界检查

#### csrc/common/inject/acl_inject.cpp (High)

**风险点**: ACL函数注入

```cpp
// 第90-109行 - aclrtSetDevice
AclError aclrtSetDevice(int32_t deviceId) {
    pthread_once(&g_once, LoadAclFunction);
    // ...
    auto ret = func(deviceId);
    if (ret == MSPTI_SUCCESS) {
        // 直接使用用户传入的deviceId
        ActivityManager::GetInstance()->SetDevice(realDeviceId);
    }
}
```

**漏洞场景**: 
1. 恶意deviceId可能导致设备访问越界
2. 注入函数可能被劫持执行

#### csrc/common/inject/hccl_inject.cpp (High)

**风险点**: HCCL函数注入

```cpp
// 第70-91行 - HcclAllReduce
HcclResult HcclAllReduce(VOID_PTR sendBuf, VOID_PTR recvBuf, uint64_t count, 
    HcclDataType dataType, HcclReduceOp op, HcclComm comm, aclrtStream stream)
```

**漏洞场景**: 
1. 用户提供的缓冲区和参数直接传递
2. count参数可能导致整数溢出
3. 恶意comm/stream对象可能导致内存问题

---

## 5. 入口点分析

### 5.1 公共API入口点

| 函数 | 文件 | 行号 | 风险 | 说明 |
|------|------|------|------|------|
| msptiSubscribe | callback_manager.cpp | 226 | High | 接收用户回调函数和数据 |
| msptiUnsubscribe | callback_manager.cpp | 231 | Medium | 取消订阅 |
| msptiEnableCallback | callback_manager.cpp | 239 | Medium | 启用回调 |
| msptiEnableDomain | callback_manager.cpp | 245 | Medium | 启用域回调 |
| msptiActivityRegisterCallbacks | activity_manager.cpp | 388 | High | 注册缓冲区回调 |
| msptiActivityEnable | activity_manager.cpp | 394 | Medium | 启用活动类型 |
| msptiActivityDisable | activity_manager.cpp | 399 | Medium | 禁用活动类型 |
| msptiActivityFlushAll | activity_manager.cpp | 409 | Medium | 刷新缓冲区 |
| msptiActivityEnableMarkerDomain | mstx_inject.cpp | 443 | Medium | 启用标记域 |
| msptiActivityDisableMarkerDomain | mstx_inject.cpp | 453 | Medium | 禁用标记域 |

### 5.2 动态注入入口点

| 函数 | 文件 | 行号 | 风险 | 说明 |
|------|------|------|------|------|
| FunctionLoader::Get | function_loader.cpp | 67 | Critical | dlopen/dlsym加载 |
| CanonicalSoPath | function_loader.cpp | 45 | Critical | 环境变量路径 |
| ProfChannelRead | driver_inject.cpp | 120 | High | 驱动数据读取 |
| ProfDrvGetChannels | driver_inject.cpp | 55 | High | 获取通道列表 |
| ProfDrvStart | driver_inject.cpp | 94 | High | 启动profiling |

### 5.3 回调数据入口点

| 函数 | 文件 | 行号 | 风险 | 说明 |
|------|------|------|------|------|
| MsptiApiReporterCallbackImpl | profapi_inject.cpp | 127 | High | profapi API回调 |
| MsptiCompactInfoReporterCallbackImpl | profapi_inject.cpp | 164 | High | 紧凑信息回调 |
| MsptiGetHashIdImpl | profapi_inject.cpp | 111 | Medium | 哈希ID生成 |

### 5.4 Mstx标记入口点

| 函数 | 文件 | 行号 | 风险 | 说明 |
|------|------|------|------|------|
| MstxMarkAFunc | mstx_inject.cpp | 193 | Medium | 标记消息 |
| MstxRangeStartAFunc | mstx_inject.cpp | 210 | Medium | 范围开始 |
| MstxRangeEndFunc | mstx_inject.cpp | 230 | Low | 范围结束 |
| MstxDomainCreateAFunc | mstx_inject.cpp | 243 | Medium | 创建域 |

---

## 6. 数据流分析

### 6.1 高风险数据流

#### 数据流1: 环境变量 → 动态库加载

```
Source: getenv("ASCEND_HOME_PATH") @ function_loader.cpp:58
  ↓
CanonicalSoPath @ function_loader.cpp:45
  ↓ (路径拼接: ASCEND_HOME_PATH + "/lib64/" + soName)
Utils::RealPath @ utils.cpp:94
  ↓
Sink: dlopen(soPath.c_str(), RTLD_LAZY) @ function_loader.cpp:74
```

**风险**: 环境变量可被外部设置，导致加载恶意库

#### 数据流2: 驱动数据 → 类型转换

```
Source: ProfChannelRead(deviceId, channelId, buf, bufSize) @ driver_inject.cpp:120
  ↓
ChannelReader::Execute @ channel_reader.cpp:85
  ↓
TransDataToActivityBuffer @ channel_reader.cpp:108
  ↓
TransStarsLog @ channel_reader.cpp:140
  ↓
Sink: reinterpret_cast<TsTrackHead*>(buffer + pos) @ channel_reader.cpp:126
```

**风险**: 驱动数据未验证直接转换

#### 数据流3: 用户回调 → 代码执行

```
Source: msptiSubscribe(subscriber, callback, userdata) @ callback_manager.cpp:226
  ↓
CallbackManager::Init @ callback_manager.cpp:76
  ↓ (存储callback指针)
ExecuteCallback @ callback_manager.cpp:195
  ↓
Sink: subscriber_ptr_->handle(userdata, domain, cbid, &callbackData) @ callback_manager.cpp:209
```

**风险**: 用户回调函数直接执行

#### 数据流4: 用户消息 → 数据存储

```
Source: msg (const char*) @ mstx_inject.cpp:193
  ↓
IsMsgValid (strnlen检查) @ mstx_inject.cpp:180
  ↓ (仅检查长度<=128)
MstxParser::ReportMark @ mstx_parser.cpp:45
  ↓
Sink: ActivityManager::Record @ activity_manager.cpp:270
```

**风险**: 消息内容未验证

---

## 7. 安全建议

### 7.1 Critical优先级

1. **动态库路径验证**
   - 在CanonicalSoPath中增加路径白名单验证
   - 验证realpath结果是否在预定义的合法路径范围内
   - 考虑使用硬编码路径而非环境变量

2. **驱动数据验证**
   - 在ProfChannelRead返回后验证数据长度
   - 在reinterpret_cast前增加结构验证
   - 使用边界检查防止缓冲区溢出

### 7.2 High优先级

3. **回调数据验证**
   - 在MsptiApiReporterCallbackImpl中验证MsprofApi结构
   - 在MsptiCompactInfoReporterCallbackImpl中验证数据长度和类型

4. **注入函数参数验证**
   - 在aclrtSetDevice中验证deviceId范围
   - 在HCCL函数中验证count参数防止整数溢出

### 7.3 Medium优先级

5. **字符串验证**
   - 在IsMsgValid中增加内容验证，过滤危险字符
   - 对domain名称进行格式验证

6. **日志增强**
   - 增加回调执行日志记录
   - 记录动态库加载路径和函数调用

---

## 8. 总结

msPTI是一个华为昇腾NPU性能分析工具库，存在以下主要安全风险：

| 风险类型 | 数量 | 最高风险等级 |
|----------|------|--------------|
| 动态库加载漏洞 | 2 | Critical |
| 驱动数据篡改 | 3 | High |
| 回调代码执行 | 4 | High |
| 参数验证不足 | 6 | Medium |
| 信息泄露 | 2 | Medium |

**最关键的安全问题**: 动态库加载机制依赖环境变量ASCEND_HOME_PATH，可能导致恶意库注入。建议优先修复此问题，通过路径白名单或硬编码路径替代环境变量方式。

---

**报告生成时间**: 2026-04-20  
**分析工具**: Architecture Agent (Manual + LSP)