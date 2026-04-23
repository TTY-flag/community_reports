# CLUSTER-INPUTVAL-002: ZooKeeper节点数据输入验证逻辑错误致数据未校验直接使用

## 一、漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | CLUSTER-INPUTVAL-002 |
| 类型 | Improper Input Validation (CWE-20) |
| 严重性 | HIGH |
| 文件 | ubsio-boostio/src/cluster/common/cm_zkadapter.c |
| 影响行号 | 676, 805, 988 |
| CWE编号 | CWE-20: Improper Input Validation |
| 置信度 | 95% (已确认真实漏洞) |

## 二、漏洞确认分析

### 2.1 漏洞代码位置

漏洞存在于三个函数中，具有相同的逻辑错误模式：

**位置1: CmClientZkSubNodeList (行 675-680)**
```c
ret = CmZkWget(g_zh, zkPath, CmClientZkSubNodeListWatch, restore, (char *)nodeList, &len, NULL);
if (ret != ZOK && (CheckNodeDataFromZk(nodeList) != CM_OK)) {  // <-- 逻辑错误
    CM_LOGERROR("Get znode(%s) failed, ret(%d).", zkPath, ret);
    free(nodeList);
    return CM_ERR;
}
CmClientZkUpdateNodeList(nodeList);  // 未验证的数据直接被使用
```

**位置2: CmClientZkSubStateList (行 804-809)**
```c
ret = CmZkWget(g_zh, zkPath, CmClientZkSubStateListWatch, restore, (char *)stateList, &len, NULL);
if (ret != ZOK && (CheckStateDataFromZk(stateList) != CM_OK)) {  // <-- 逻辑错误
    CM_LOGERROR("Get znode(%s) failed, ret(%d).", zkPath, ret);
    free(stateList);
    return CM_ERR;
}
CmClientZkUpdateStateList(stateList);  // 未验证的数据直接被使用
```

**位置3: CmClientZkSubPtListChange (行 987-992)**
```c
ret = CmZkWget(g_zh, zkPath, CmClientZkPtWatchFunc, restore, (char *)ptList, &len, NULL);
if (ret != ZOK && (CheckPtDataFromZk(ptList) != CM_OK)) {  // <-- 逻辑错误
    CM_LOGERROR("Get znode(%s) failed, ret(%d).", zkPath, ret);
    free(ptList);
    return CM_ERR;
}
CmClientZkUpdatePtList(ptList);  // 未验证的数据直接被使用
```

### 2.2 逻辑错误分析

**问题核心：条件运算符 `&&` 的短路求值特性**

```c
if (ret != ZOK && (CheckNodeDataFromZk(nodeList) != CM_OK))
```

这个条件表达式的逻辑是：
- 当 `ret != ZOK` 为 **TRUE** 时，才会执行 `CheckNodeDataFromZk(nodeList)`
- 当 `ret == ZOK`（ZooKeeper读取成功）时，由于短路求值，`CheckNodeDataFromZk()` **永远不会被调用**

**逻辑真值表分析：**

| ret值 | ret != ZOK | 验证函数执行? | 最终结果 |
|-------|------------|--------------|----------|
| ZOK (成功) | FALSE | **跳过** | 条件为FALSE，继续执行 |
| !ZOK (失败) | TRUE | 执行 | 可能返回错误 |

**正确的逻辑应该是：**
```c
if (ret != ZOK || CheckNodeDataFromZk(nodeList) != CM_OK) {
    // 使用 || 确保两种情况都检查
}
```
或者：
```c
if (ret != ZOK) {
    // 处理ZK错误
    return CM_ERR;
}
if (CheckNodeDataFromZk(nodeList) != CM_OK) {
    // 处理验证失败
    return CM_ERR;
}
```

### 2.3 验证函数分析

**CheckNodeDataFromZk() (行 944-961)：**
```c
int32_t CheckNodeDataFromZk(NodeInfoList *nodeInfoList)
{
    if (nodeInfoList->nodeNum > MAX_NODE_NUM || nodeInfoList->poolId > MAX_POOL_NUM) {
        // nodeNum上限=256, poolId上限=512
        CM_LOGERROR("Node number or pool id check fail...");
        return CM_ERR;
    }

    for (uint16_t i = 0; i < nodeInfoList->nodeNum; ++i) {
        if (nodeInfoList->nodeList[i].nodeId > MAX_NODE_NUM || 
            nodeInfoList->nodeList[i].diskList.num > DISK_LIST_NUM) {
            // nodeId上限=256, diskList.num上限=16
            CM_LOGERROR("Node id or disk number check fail...");
            return CM_ERR;
        }
    }
    return CM_OK;
}
```

**CheckStateDataFromZk() (行 764-781)：**
```c
int32_t CheckStateDataFromZk(NodeStateList *nodeStateList)
{
    if (nodeStateList->nodeNum > MAX_NODE_NUM || nodeStateList->poolId > MAX_POOL_NUM) {
        return CM_ERR;
    }
    for (uint16_t i = 0; i < nodeStateList->nodeNum; ++i) {
        if (nodeStateList->nodeList[i].nodeId > MAX_NODE_NUM || 
            nodeStateList->nodeList[i].diskNum > DISK_LIST_NUM) {
            return CM_ERR;
        }
    }
    return CM_OK;
}
```

**CheckPtDataFromZk() (行 925-942)：**
```c
int32_t CheckPtDataFromZk(PtEntryList *ptEntryList)
{
    if (ptEntryList->maxCopyNum > PT_MAX_COPY_NUM || 
        ptEntryList->ptNum > MAX_PT_ENTRY || 
        ptEntryList->poolId > MAX_POOL_NUM) {
        return CM_ERR;
    }
    for (uint16_t i = 0; i < ptEntryList->ptNum; ++i) {
        if (ptEntryList->ptEntryList[i].copyNum > PT_MAX_COPY_NUM) {
            return CM_ERR;
        }
    }
    return CM_OK;
}
```

## 三、漏洞影响分析

### 3.1 直接影响：数组越界访问

当验证被绕过时，超大数值可能导致数组越界：

**NodeInfoList 数组越界：**
```c
// 在 CmClientZkUpdateNodeList() 中 (行 615)
for (nodeId = 0; nodeId < nodeList->nodeNum; nodeId++) {  // nodeNum可能 > 256
    nodeList->nodeList[nodeId] = changeList->nodeList[nodeId];  // 越界访问
}
```

**NodeStateList 数组越界：**
```c
// 在 CmClientZkUpdateStateList() 中 (行 711)
for (nodeId = 0; nodeId < stateList->nodeNum; nodeId++) {  // nodeNum可能 > 256
    stateList->nodeList[nodeId] = changeList->nodeList[nodeId];  // 越界访问
}
```

**PtEntryList 数组越界：**
```c
// 在 CmClientZkUpdatePtList() 中 (行 888)
for (ptId = 0; ptId < ptList->ptNum; ptId++) {  // ptNum可能 > 8192
    ptList->ptEntryList[ptId] = changeList->ptEntryList[ptId];  // 越界访问
}
```

### 3.2 内存分配不匹配

缓冲区分配大小基于配置的 `maxNodeNum/maxPtNum`，而非验证后的实际值：
```c
// 行 660: 分配基于配置值
int32_t len = (int32_t)(sizeof(NodeInfoList) + sizeof(NodeInfo) * restore->pool->maxNodeNum);

// 行 675: ZooKeeper写入的数据长度可能超过分配大小
ret = CmZkWget(g_zh, zkPath, ..., (char *)nodeList, &len, NULL);
```

### 3.3 数据流分析

```
ZooKeeper节点数据 → CmZkWget() → nodeList/stateList/ptList填充
                                           ↓
                          [ret == ZOK时验证被跳过]
                                           ↓
                          CmClientZkUpdateXXXList() 
                                           ↓
                          数组越界访问/内存破坏
                                           ↓
                          回调函数被调用(restore->nodeChange/stateChange/ptChange)
                                           ↓
                          业务层处理未验证数据
```

## 四、攻击场景分析

### 4.1 攻击前置条件

| 条件 | 可行性 | 说明 |
|------|--------|------|
| ZooKeeper服务器被攻陷 | 中等 | 攻击者需要控制至少一个ZK节点 |
| ZooKeeper网络被监听/篡改 | 中等 | 需要MITM攻击位置 |
| ZK客户端漏洞利用 | 低 | 比较复杂 |
| 集群内恶意节点 | 中等 | 如果有节点被攻陷，可写入恶意数据 |

### 4.2 攻击场景一：被攻陷的ZooKeeper节点

**攻击步骤：**
1. 攻击者攻陷ZooKeeper集群中的一个节点
2. 修改 `/cm/pool/{poolId}/node_list` znode数据
3. 将 `nodeNum` 设置为超大值（如 65535）
4. 将 `nodeList[300].nodeId` 设置为恶意值
5. 客户端通过 `CmClientZkSubNodeList()` 读取数据
6. ZooKeeper返回成功（ret == ZOK）
7. 验证函数被跳过
8. `CmClientZkUpdateNodeList()` 访问 `nodeList[300]` 越界
9. 触发内存访问违规或内存破坏

### 4.3 攻击场景二：恶意集群成员

**攻击步骤：**
1. 攻击者获得集群中一个计算节点的控制权
2. 该节点通过合法接口向ZooKeeper写入数据
3. 修改写入的数据包含超限的 nodeNum/poolId/nodeId
4. 其他节点通过订阅机制获取更新
5. ZOO_CHANGED_EVENT 触发重新订阅
6. 新数据读取成功，验证被绕过
7. 其他节点处理恶意数据时崩溃或被利用

### 4.4 攻击场景三：ZooKeeper会话劫持

**攻击步骤：**
1. 攻击者监听ZooKeeper网络通信
2. 劫持合法客户端会话
3. 发送伪造的 ZooKeeper 响应数据包
4. 响应包含 ret=ZOK 和恶意构造的节点数据
5. 客户端接收"成功"响应
6. 验证逻辑被短路
7. 未验证数据直接被使用

## 五、PoC 构造思路

### 5.1 PoC 概念设计

**方法A：修改ZooKeeper节点数据（需要ZK访问权限）**
```python
# 使用 zkCli.sh 或 Python kazoo 库
from kazoo.client import KazooClient

zk = KazooClient(hosts='zk_server:2181')
zk.start()

# 构造恶意 NodeInfoList 数据结构
malicious_data = struct.pack(
    '<HH',  # poolId, nodeNum
    0,      # poolId (合法)
    500     # nodeNum (超过 MAX_NODE_NUM=256)
)
# 添加越界的节点信息
for i in range(500):
    malicious_data += struct.pack('<HH...', i, ...)  # nodeId 等字段

# 写入恶意数据
zk.set('/cm/pool/1/node_list', malicious_data)
```

**方法B：触发订阅更新**
```c
// 等待 ZOO_CHANGED_EVENT 触发
// CmClientZkSubNodeListWatch() 被调用
// CmClientZkSubNodeList() 读取新数据
// ret == ZOK，验证被跳过
// CmClientZkUpdateNodeList() 访问 nodeList[500] 越界
```

### 5.2 验证PoC效果

**预期行为：**
- 程序崩溃（SIGSEGV/SIGBUS）
- 日志中无验证失败记录
- 内存访问违规日志

**观察方法：**
```bash
# 启用 core dump
ulimit -c unlimited

# 运行目标程序
./target_program

# 分析崩溃
gdb ./target_program core
# 查看 crash 位置是否在 CmClientZkUpdateNodeList 的循环中
```

## 六、实际可利用性评估

### 6.1 可利用性评级

| 因素 | 评级 | 说明 |
|------|------|------|
| 触发难度 | 中等 | 需要能够写入ZooKeeper数据 |
| 攻击复杂度 | 中等 | 需了解数据结构格式 |
| 稳定性 | 高 | 每次触发必绕过验证 |
| 影响范围 | 高 | 所有订阅该数据类型的节点 |
| 代码执行可能性 | 中等 | 可能通过堆溢出构造 |

### 6.2 综合评级：**高危**

**理由：**
1. **逻辑错误明确**：代码逻辑清晰可见错误
2. **绕过100%成功**：只要ZK读取成功，验证必然被绕过
3. **内存访问确定**：越界访问必然发生
4. **影响广泛**：三个函数共享同一错误模式
5. **集群场景放大**：一个恶意数据可影响整个集群

### 6.3 利用限制

- 需要ZooKeeper访问权限
- 需要了解内部数据结构格式
- 数据写入需要通过正常业务接口或直接操作ZK
- ZooKeeper通常有ACL保护

## 七、修复建议

### 7.1 正确的修复方案

**方案A：使用 `||` 替代 `&&`**

```c
// 修复位置：行 676, 805, 988
// 原代码：
if (ret != ZOK && (CheckNodeDataFromZk(nodeList) != CM_OK))

// 修复后：
if (ret != ZOK || (CheckNodeDataFromZk(nodeList) != CM_OK)) {
    CM_LOGERROR("Get znode(%s) failed or data invalid, ret(%d).", zkPath, ret);
    free(nodeList);
    return CM_ERR;
}
```

**方案B：分离错误处理和验证（推荐）**

```c
ret = CmZkWget(g_zh, zkPath, CmClientZkSubNodeListWatch, restore, (char *)nodeList, &len, NULL);
if (ret != ZOK) {
    CM_LOGERROR("Get znode(%s) failed, ret(%d).", zkPath, ret);
    free(nodeList);
    return CM_ERR;
}

// 成功后必须验证数据
if (CheckNodeDataFromZk(nodeList) != CM_OK) {
    CM_LOGERROR("Data validation failed for znode(%s).", zkPath);
    free(nodeList);
    return CM_ERR;
}

CmClientZkUpdateNodeList(nodeList);
```

### 7.2 修复影响范围

需要修改的三个位置：
| 函数 | 行号 | 修复内容 |
|------|------|----------|
| CmClientZkSubNodeList | 676 | `&&` → `||` 或分离验证 |
| CmClientZkSubStateList | 805 | `&&` → `||` 或分离验证 |
| CmClientZkSubPtListChange | 988 | `&&` → `||` 或分离验证 |

### 7.3 验证修复有效性

**测试代码：**
```c
// 模拟恶意数据
NodeInfoList maliciousList;
maliciousList.nodeNum = MAX_NODE_NUM + 100;  // 超限
maliciousList.poolId = 0;

// 测试修复后的代码
int ret = ZOK;  // 模拟成功读取
if (ret != ZOK || CheckNodeDataFromZk(&maliciousList) != CM_OK) {
    printf("Correctly rejected invalid data!\n");
}
```

## 八、缓解措施（临时）

### 8.1 ZooKeeper安全加固

1. **启用ZooKeeper ACL**：
   ```bash
   # zkCli.sh
   setAcl /cm/pool auth:user:crdwa
   ```

2. **网络隔离**：确保ZooKeeper仅在可信网络内可访问

3. **TLS加密**：启用ZooKeeper SSL/TLS通信

### 8.2 监控和检测

```bash
# 监控异常nodeNum值
grep "nodeNum" /var/log/cm.log | awk '{if($NF > 256) print "ALERT"}'
```

### 8.3 数据完整性校验

建议在业务层添加二次校验：
```c
// 在 CmClientZkUpdateNodeList 开头添加
if (changeList->nodeNum > restore->pool->maxNodeNum) {
    CM_LOGERROR("Unexpected nodeNum in update: %u > %u", 
                changeList->nodeNum, restore->pool->maxNodeNum);
    return;
}
```

## 九、相关代码参考

### 9.1 正确的条件使用示例（同一文件中）

在 `cm_zkadapter.c` 第 522-527 行有正确的模式：
```c
ret = CmZkExists(g_zh, zkPath, UNWATCH_ZNODE, NULL);
if (ret != ZOK && ret != ZNONODE) {  // 这里 && 是正确的
    CM_LOGERROR("Check znode(%s) exist failed, ret(%d).", zkPath, ret);
    return CM_ERR;
}
if (ret == ZNONODE) {
    return CM_NOT_EXIST;
}
return CM_OK;  // ret == ZOK 时继续正常流程
```

注意：此处的 `&&` 用于检查多种失败情况，而非跳过验证。

## 十、结论

**CLUSTER-INPUTVAL-002 是一个真实的高危漏洞。**

漏洞的根本原因是开发者误用了 `&&` 运算符进行条件判断，导致当 ZooKeeper 读取成功时，数据验证逻辑被完全跳过。这使得从 ZooKeeper 获取的任何数据（无论是正常数据还是恶意篡改的数据）在成功读取后都不会经过验证直接被使用。

该漏洞可导致：
1. 数组越界访问
2. 内存破坏
3. 程序崩溃
4. 潜在的任意代码执行

建议立即按照第七节的修复方案进行代码修改。

---

**分析完成日期：** 2026-04-20
**分析工具：** 人工代码审计 + 静态分析确认
