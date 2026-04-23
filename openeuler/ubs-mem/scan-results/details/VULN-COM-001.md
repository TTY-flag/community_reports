# VULN-COM-001：消息体长度整数溢出漏洞

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-COM-001 |
| 漏洞类型 | Integer Overflow (整数溢出) |
| CWE | CWE-190: Integer Overflow or Wraparound |
| 严重程度 | High |
| CVSS评分 | 7.5 (High) |
| 漏洞位置 | `src/communication/adapter/mxm_com_def.cpp:364-371` |
| 漏洞函数 | `CheckMessageBodyLen` |
| 攻击面 | TCP RPC / IPC 消息处理 |

## 漏洞描述

在 `CheckMessageBodyLen` 函数中，攻击者控制的消息头字段 `bodyLen` (uint32_t) 与 `sizeof(MxmComMessage)` 进行加法运算时，未进行溢出检查。当 `bodyLen` 被设置为接近 `UINT32_MAX` 的值时，加法运算会发生整数溢出回绕，导致验证检查错误通过。

### 漏洞代码

```cpp
// mxm_com_def.cpp:364-371
bool CheckMessageBodyLen(UBSHcomServiceContext& context, MxmComMessage& msg)
{
    return context.MessageDataLen() == (sizeof(MxmComMessage) + msg.GetMessageBodyLen());
}

bool CheckMessageBodyLen(UBSHcomRequest& netServiceMessage, MxmComMessage& msg)
{
    return netServiceMessage.size == (sizeof(MxmComMessage) + msg.GetMessageBodyLen());
}
```

### 相关数据类型

```cpp
// mxm_com_def.h:289-293
class MxmComMessageHead {
private:
    uint16_t opCode;       // 2 bytes
    uint16_t moduleCode;   // 2 bytes  
    uint32_t bodyLen;      // 4 bytes - 攻击者控制
    uint32_t crc;          // 4 bytes
};
// sizeof(MxmComMessageHead) = 16 bytes

// mxm_com_def.cpp:309
uint32_t MxmComMessage::GetMessageBodyLen() { return head.GetBodyLen(); }
```

## 攻击场景

### 场景1: 32位系统上的整数溢出绕过

在32位系统上，`size_t` 为32位，加法运算在32位空间内进行：

1. 攻击者构造恶意网络消息，设置 `bodyLen = 0xFFFFFFF0`
2. 计算: `sizeof(MxmComMessage) + bodyLen = 16 + 0xFFFFFFF0 = 0x100000000`
3. 在32位运算中，结果回绕为 `0`
4. 如果 `context.MessageDataLen()` 返回 `0`，验证检查通过
5. 后续代码使用原始 `bodyLen` 值 (`0xFFFFFFF0`)，导致缓冲区越界读取

### 场景2: 64位系统上的缓冲区越界读取

即使在64位系统上不会发生算术溢出，但攻击者可以：

1. 设置 `bodyLen` 为极大值（如 `0x7FFFFFFF`）
2. 分配小块内存的实际消息体
3. 验证检查失败，但攻击者可能利用竞争条件
4. 或者攻击者精心构造 `bodyLen` 使得溢出后等于实际小数据块大小

### 数据流

```
Network Message Header
       │
       ▼
head.bodyLen (uint32_t, 攻击者控制)
       │
       ▼
GetMessageBodyLen() 返回 bodyLen
       │
       ▼
CheckMessageBodyLen():
   sizeof(MxmComMessage) + bodyLen  ← 整数溢出点
       │
       ▼
验证通过后...
       │
       ▼
SoftCrc32(msg->GetMessageBody(), msg->GetMessageBodyLen(), ...)
       │
       ▼
越界读取 bodyLen 字节 (可能达 4GB)
```

## 利用步骤

1. **构造恶意消息**:
   ```cpp
   MxmComMessageHead maliciousHead;
   maliciousHead.opCode = SOME_OPCODE;
   maliciousHead.moduleCode = SOME_MODULE;
   maliciousHead.bodyLen = 0xFFFFFFF0;  // 接近 UINT32_MAX
   maliciousHead.crc = 0;  // CRC 会被忽略或绕过
   ```

2. **发送到目标服务**:
   - 通过 TCP RPC 端口
   - 通过 IPC Unix Domain Socket

3. **触发溢出**:
   - 32位系统: 加法溢出，验证可能通过
   - 64位系统: 如果服务有其他漏洞配合，仍可利用

4. **越界读取**:
   - `SoftCrc32` 循环读取 `bodyLen` 字节
   - 可能泄露敏感内存数据
   - 可能导致服务崩溃 (DoS)

## 影响范围

### 直接影响

1. **信息泄露**: 
   - `SoftCrc32` 函数会读取超出消息缓冲区的内存
   - 可能泄露相邻内存中的敏感数据（密钥、凭证、会话信息）

2. **拒绝服务 (DoS)**:
   - 如果读取未映射内存，导致 SIGSEGV 崩溃
   - 服务不可用

3. **内存耗尽**:
   ```cpp
   // mxm_com_base.h:356-357
   std::string reqStr = std::string(
       reinterpret_cast<char *>(ucMsg->GetMessageBody()),
       ucMsg->GetMessageBodyLen()  // 0xFFFFFFF0 字节!
   );
   ```
   - 尝试分配约 4GB 内存
   - 导致 OOM 或系统资源耗尽

### 受影响代码路径

1. `mxm_com_engine.cpp:784-800`: 消息接收处理
2. `mxm_com_base.h:356-357`: 消息反序列化
3. 所有调用 `GetMessageBodyLen()` 的位置

## 修复建议

### 方案1: 添加溢出检查

```cpp
bool CheckMessageBodyLen(UBSHcomServiceContext& context, MxmComMessage& msg)
{
    uint32_t bodyLen = msg.GetMessageBodyLen();
    size_t headerSize = sizeof(MxmComMessage);
    
    // 检查加法溢出
    if (bodyLen > SIZE_MAX - headerSize) {
        return false;  // 溢出，拒绝消息
    }
    
    size_t expectedSize = headerSize + bodyLen;
    size_t actualSize = context.MessageDataLen();
    
    // 额外检查: bodyLen 应该合理
    if (bodyLen > MAX_MESSAGE_BODY_SIZE) {  // 定义合理上限
        return false;
    }
    
    return actualSize == expectedSize;
}
```

### 方案2: 使用安全算术库

```cpp
#include <safeint.h>  // 或类似库

bool CheckMessageBodyLen(UBSHcomServiceContext& context, MxmComMessage& msg)
{
    uint32_t bodyLen = msg.GetMessageBodyLen();
    size_t headerSize = sizeof(MxmComMessage);
    size_t expectedSize;
    
    if (!SafeAdd(headerSize, bodyLen, expectedSize)) {
        return false;  // 溢出检测
    }
    
    return context.MessageDataLen() == expectedSize;
}
```

### 方案3: 定义最大消息大小常量

```cpp
// 在 mxm_com_def.h 或 mxm_com_constants.h 中添加
constexpr size_t MAX_MESSAGE_BODY_SIZE = 1024 * 1024 * 10;  // 10MB 上限

bool CheckMessageBodyLen(UBSHcomServiceContext& context, MxmComMessage& msg)
{
    uint32_t bodyLen = msg.GetMessageBodyLen();
    
    // 验证 bodyLen 在合理范围内
    if (bodyLen > MAX_MESSAGE_BODY_SIZE) {
        DBG_LOGERROR("Message body length exceeds maximum: " << bodyLen);
        return false;
    }
    
    return context.MessageDataLen() == (sizeof(MxmComMessage) + bodyLen);
}
```

## 检测方法

### 静态分析

- 使用 Clang Static Analyzer 检测整数溢出
- 启用 `-fsanitize=integer` 编译选项进行运行时检测

### 动态测试

```cpp
// 测试用例
void TestIntegerOverflow() {
    // 构造恶意消息
    uint8_t buffer[32] = {0};
    MxmComMessage* msg = reinterpret_cast<MxmComMessage*>(buffer);
    MxmComMessageHead head;
    head.SetBodyLen(0xFFFFFFF0);  // 接近 UINT32_MAX
    msg->SetMessageHead(head);
    
    // 应该返回 false，不应崩溃
    // 需要构造合适的 context 对象
}
```

## 参考资料

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-680: Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- [SEI CERT INT30-C: Ensure that unsigned integer operations do not wrap](https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap)

## 附录: 相关代码位置

| 文件 | 行号 | 描述 |
|------|------|------|
| `mxm_com_def.cpp` | 364-367 | 漏洞函数 (context版本) |
| `mxm_com_def.cpp` | 369-372 | 漏洞函数 (netServiceMessage版本) |
| `mxm_com_def.cpp` | 309 | GetMessageBodyLen 实现 |
| `mxm_com_def.h` | 292 | bodyLen 字段定义 |
| `mxm_com_engine.cpp` | 784 | 漏洞调用点 |
| `mxm_com_engine.cpp` | 791 | 越界读取点 (CRC计算) |
| `mxm_com_base.h` | 356-357 | 越界读取点 (字符串构造) |
| `dg_crc.h` | 231-234 | CRC循环实现 |
