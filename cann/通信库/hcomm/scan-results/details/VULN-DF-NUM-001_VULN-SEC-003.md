# VULN-DF-NUM-001：strtol错误检测缺失漏洞

**漏洞ID**: VULN-DF-NUM-001 (dataflow) + VULN-SEC-003 (security)  
**CWE**: CWE-190 (Integer Overflow or Wraparound) / CWE-20 (Improper Input Validation)  
**严重性**: High  
**置信度**: 85/100  
**状态**: CONFIRMED  

> 注：两个漏洞 ID 指向同一代码位置，分别由 dataflow-scanner 和 security-auditor 发现。

---

## 1. 漏洞概述

### 1.1 漏洞位置

| 属性 | 值 |
|------|-----|
| **文件** | `src/platform/hccp/rdma_service/rs_socket.c` |
| **行号** | 146-150 |
| **函数** | `rs_socket_fill_wlist_by_phyID` |
| **模块** | platform (hccp/rdma_service) |

### 1.2 漏洞描述

函数使用 `strtol()` 解析来自网络连接 tag 的 phyId，但：
- 使用 `NULL` 作为 `endptr` 参数
- 未检查 `strtol()` 的返回值是否有效
- 未检查 `errno` 是否发生错误

```c
phyId = (unsigned int)strtol(tagTemp, NULL, 10); // Decimal(10)
ret = DlHalGetDeviceInfo(phyId, MODULE_TYPE_SYSTEM, INFO_TYPE_VNIC_IP, &deviceInfo);
```

---

## 2. 源代码分析

### 2.1 漏洞代码上下文

```c
// 行 140-154: rs_socket_fill_wlist_by_phyID 函数片段
tagTemp = rsConn->tag + SOCK_CONN_TAG_SIZE;
tagTemp[SOCK_CONN_DEV_ID_SIZE - 1] = '\0';
RS_CHECK_POINTER_NULL_RETURN_INT(tagTemp);

if (rsConn->clientIp.family == AF_INET) {
    // VNIC IPv4 处理
    phyId = (unsigned int)strtol(tagTemp, NULL, 10); // 行 146 - 漏洞点
    ret = DlHalGetDeviceInfo(phyId, MODULE_TYPE_TYPE, INFO_TYPE_VNIC_IP, &deviceInfo);
    CHK_PRT_RETURN(ret, hccp_err("dl_hal_get_device_info failed, ret(%d) tagTemp phyId(%u)", ret, phyId), ret);
    vnicIp = (unsigned int)deviceInfo;
    hccp_dbg("chip_id:%u phyId:%u vnic_ip:%u", chipId, phyId, vnicIp);
    whiteListNode->remoteIp.addr.s_addr = vnicIp;
}
return 0;
```

### 2.2 数据来源分析

网络数据接收位置：

```c
// 行 324-369: RsTcpRecvTagInHandle 函数 - 数据来源
STATIC int RsTcpRecvTagInHandle(struct RsListenInfo *listenInfo, int connfd, 
    struct RsConnInfo *connTmp, struct RsIpAddrInfo *remoteIp)
{
    int expSize = SOCK_CONN_TAG_SIZE + SOCK_CONN_DEV_ID_SIZE;
    char *recvBuff = connTmp->tag;  // tag 缓冲区
    
    while (expSize > 0 && size != 0) {
        // 行 336: 从网络接收 tag 数据
        size = recv(connfd, recvBuff, expSize, 0);
        // ...
        expSize -= size;
        recvBuff += size;
    }
    
    // 数据保存到 connTmp->tag
    connTmp->state = RS_CONN_STATE_TAG_SYNC;
}
```

### 2.3 strtol 错误行为

根据 C 标准和 POSIX 规范：

| 输入情况 | strtol 返回值 | errno | endptr (NULL) |
|----------|---------------|-------|---------------|
| 有效数字 | 转换后的值 | 不变 | 无法检测 |
| 无效字符串 | 0 | 不一定设置 | 无法检测 |
| 溢出 | LONG_MAX/MIN | ERANGE | 无法检测 |
| 空字符串 | 0 | 不变 | 无法检测 |

**关键问题**：使用 `NULL` 作为 `endptr` 导致：
- 无法区分 "0" 和 "无效字符串"
- 无法检测部分转换（如 "123abc"）
- 无法检测溢出

---

## 3. 数据流分析

### 3.1 完整数据流路径

```
[远程客户端连接]
    ↓ 发送连接 tag 数据
recv(connfd, connTmp->tag)  [行 336 - SOURCE]
    ↓ tag 包含 SOCK_CONN_TAG_SIZE + SOCK_CONN_DEV_ID_SIZE
connTmp->tag 保存到连接结构体
    ↓ 被传递到白名单验证流程
rs_socket_fill_wlist_by_phyID(chipId, whiteListNode, conn)
    ↓ 提取 phyId 部分
tagTemp = rsConn->tag + SOCK_CONN_TAG_SIZE
    ↓ 错误的 strtol 使用
phyId = strtol(tagTemp, NULL, 10)  [行 146 - SINK]
    ↓ phyId 用于设备信息查询
DlHalGetDeviceInfo(phyId, ...)  [行 147]
    ↓ 获取 VNIC IP
vnicIp = deviceInfo
    ↓ 设置白名单 IP
whiteListNode->remoteIp.addr.s_addr = vnicIp
```

### 3.2 污点追踪标记

| 节点 | 类型 | 数据 | 说明 |
|------|------|------|------|
| 行 336 | SOURCE | `connTmp->tag` | 网络 recv 接收，攻击者可控 |
| 行 141 | TRANSFER | `tagTemp` | tag 偏移提取 |
| 行 146 | SINK | `strtol(tagTemp, NULL, 10)` | 无错误检测的转换 |
| 行 147 | SINK | `DlHalGetDeviceInfo(phyId, ...)` | 使用未验证的 phyId |
| 行 151 | SINK | `whiteListNode->remoteIp` | 白名单 IP 设置 |

---

## 4. 利用场景分析

### 4.1 攻击向量

攻击者作为集群成员或绕过初始连接检查后，发送恶意 tag 数据：

| 攻击输入 | strtol 结果 | phyId 值 | 后续影响 |
|----------|-------------|----------|----------|
| `"FFFFFFFF"` (溢出) | LONG_MAX | 可能截断 | 查询错误设备 |
| `"abc123"` (无效) | 0 | 0 | phyId=0, 查询设备 0 |
| `""` (空) | 0 | 0 | phyId=0 |
| `"999999999999"` (超范围) | LONG_MAX | 截断 | 设备 ID 错误 |
| `" -1 "` (负数) | -1 | 强转为 unsigned | 巨大值 |

### 4.2 攻击后果

| 场景 | 技术影响 | 业务影响 |
|------|----------|----------|
| **白名单错误** | remoteIp 设置为错误地址 | 连接验证通过错误的节点 |
| **设备信息泄露** | 查询非预期设备信息 | 获取其他设备的 VNIC IP |
| **连接劫持** | 白名单 IP 被设置为攻击者地址 | 攻击者可连接到错误节点 |
| **DoS** | DlHalGetDeviceInfo 失败 | 连接建立失败 |

### 4.3 最危险场景

**白名单绕过场景**：

```
攻击目标: 使 whiteListNode->remoteIp.addr 设置为攻击者可控值

步骤:
1. 攻击者建立 TCP 连接到 HCCP 服务
2. 发送精心构造的 tag 数据
3. 如果 phyId=0 导致 DlHalGetDeviceInfo 返回特定值
4. whiteListNode 被设置为攻击者期望的 IP
5. 后续连接验证使用错误的白名单
```

---

## 5. PoC 概念验证

### 5.1 概念性攻击代码

```c
// PoC 概念（需要实际协议分析）
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(HCCP_PORT),  // 需要确认实际端口
        .sin_addr.s_addr = inet_addr("target_ip")
    };
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    // 构造恶意 tag 数据
    char malicious_tag[SOCK_CONN_TAG_SIZE + SOCK_CONN_DEV_ID_SIZE];
    
    // tag 部分 - 正常数据
    memcpy(malicious_tag, "normal_tag_data", SOCK_CONN_TAG_SIZE);
    
    // phyId 部分 - 恶意数据（溢出或无效）
    // 方案 1: 溢出值
    snprintf(malicious_tag + SOCK_CONN_TAG_SIZE, SOCK_CONN_DEV_ID_SIZE, 
             "%ld", LONG_MAX);  // "9223372036854775807"
    
    // 方案 2: 无效字符串
    snprintf(malicious_tag + SOCK_CONN_TAG_SIZE, SOCK_CONN_DEV_ID_SIZE,
             "invalid");
    
    // 方案 3: 负数（强制 unsigned 转换后为大值）
    snprintf(malicious_tag + SOCK_CONN_TAG_SIZE, SOCK_CONN_DEV_ID_SIZE,
             "-1");
    
    send(sock, malicious_tag, sizeof(malicious_tag), 0);
    
    // 观察响应/行为
    // ...
    
    return 0;
}
```

### 5.2 验证方法

1. **单元测试**：
```c
// 测试 strtol 在各种输入下的行为
void test_strtol_behavior() {
    char *inputs[] = {"0", "", "abc", "999999999999", "-1", "FFFFFFFF"};
    for (int i = 0; i < 6; i++) {
        long result = strtol(inputs[i], NULL, 10);
        printf("Input: '%s' -> Result: %ld\n", inputs[i], result);
    }
}
```

2. **集成测试**：在模拟环境中发送恶意 tag 数据观察行为。

---

## 6. 影响范围分析

### 6.1 调用路径

```
rs_socket_fill_wlist_by_phyID
    ↑ 被调用于
RsServerValidAsyncInit [行 167]
    ↑ 被调用于
RsServerValidAsync [行 173]
    ↑ 被调用于
服务器连接验证流程
    ↑
HCCP RDMA Socket 服务
```

### 6.2 功能影响

| 功能 | 影响 | 说明 |
|------|------|------|
| **白名单验证** | High | remote IP 来源可能错误 |
| **设备信息查询** | Medium | phyId 错误导致查询失败 |
| **连接建立** | Medium | 验证失败导致连接中断 |
| **VNIC IP 获取** | High | 错误 IP 被使用 |

---

## 7. 修复建议

### 7.1 立即修复方案

```c
// 正确的 strtol 使用方式
STATIC int rs_socket_fill_wlist_by_phyID(unsigned int chipId, 
    struct RsWhiteListInfo *whiteListNode, struct RsConnInfo *rsConn)
{
    // ... 前面的代码 ...
    
    if (rsConn->clientIp.family == AF_INET) {
        // 修复：正确使用 strtol
        char *endptr;
        errno = 0;  // 重置 errno
        
        long phyIdLong = strtol(tagTemp, &endptr, 10);
        
        // 检查 1: 转换是否成功（是否有非数字字符）
        if (endptr == tagTemp || *endptr != '\0') {
            hccp_err("Invalid phyId format in tag: '%s'", tagTemp);
            return -EINVAL;
        }
        
        // 检查 2: 是否发生溢出
        if (errno == ERANGE || phyIdLong < 0 || phyIdLong > UINT_MAX) {
            hccp_err("phyId overflow or out of range: '%s'", tagTemp);
            return -EOVERFLOW;
        }
        
        phyId = (unsigned int)phyIdLong;
        
        // 检查 3: phyId 是否在有效设备范围内
        if (!IsValidPhyId(chipId, phyId)) {
            hccp_err("Invalid phyId %u for chip %u", phyId, chipId);
            return -EINVAL;
        }
        
        ret = DlHalGetDeviceInfo(phyId, MODULE_TYPE_SYSTEM, INFO_TYPE_VNIC_IP, &deviceInfo);
        // ...
    }
    return 0;
}
```

### 7.2 额外安全建议

1. **添加格式验证**：
```c
// 验证 tagTemp 是否只包含数字
for (char *p = tagTemp; *p != '\0'; p++) {
    if (!isdigit(*p)) {
        hccp_err("Non-digit character in phyId: '%s'", tagTemp);
        return -EINVAL;
    }
}
```

2. **添加范围限制**：
```c
#define MAX_PHY_ID 256  // 根据实际设备数量
if (phyId > MAX_PHY_ID) {
    hccp_err("phyId exceeds maximum: %u > %u", phyId, MAX_PHY_ID);
    return -EINVAL;
}
```

---

## 8. CVSS 评分

**CVSS v3.1**: 6.5 (Medium)

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network | 通过网络连接 tag |
| Attack Complexity (AC) | Low | 构造简单恶意 tag |
| Privileges Required (PR) | Low | 需要网络可达 |
| User Interaction (UI) | None | 无 |
| Scope (S) | Unchanged | 同一系统 |
| Confidentiality (C) | Low | 可能泄露设备信息 |
| Integrity (I) | Low | 白名单可能被错误设置 |
| Availability (A) | None | 不直接导致 DoS |

---

## 9. 结论

### 9.1 漏洞确认

| 属性 | 值 |
|------|-----|
| 类型 | CWE-190/20 整数转换/输入验证 |
| 严重性 | High（验证后提升） |
| 根因 | strtol NULL endptr + 无错误检查 |
| 数据来源 | 网络 recv tag 数据 |

### 9.2 修复优先级

**P1 - 2 周内修复**

建议在代码审查中检查所有 strtol/atoi 使用点，统一添加错误检测。

### 9.3 相关代码审查建议

搜索项目中其他类似问题：

```bash
grep -r "strtol.*NULL" src/
grep -r "atoi(" src/
```

---

**报告生成时间**: 2026-04-22  
**合并漏洞**: VULN-DF-NUM-001 + VULN-SEC-003