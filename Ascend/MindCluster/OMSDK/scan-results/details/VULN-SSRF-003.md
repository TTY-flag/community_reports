# VULN-SSRF-003: URL仅验证格式未限制目标地址致服务端请求伪造攻击

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SSRF-003 |
| **漏洞类型** | 服务端请求伪造 (Server-Side Request Forgery) |
| **CWE编号** | CWE-918 |
| **严重性** | High |
| **置信度** | 85% |
| **发现来源** | python-dataflow-module-scanner (om_event_subscription模块) |

## 2. 漏洞详情

### 2.1 位置信息
- **文件**: `src/om/src/app/sys_om/RedfishServer/om_event_subscription/param_checker.py`
- **类**: `DestinationChecker`
- **行号**: 77-96

### 2.2 代码片段
```python
class DestinationChecker(RegexStringChecker):
    def __init__(self, attr_name: str = None, min_len: int = 0, max_len: int = 2048, required: bool = True):
        # ⚠️ 只使用正则表达式验证URL格式
        super().__init__(attr_name, "(https|HTTPS)://[-A-Za-z0-9+&#/%?=~_|!:,.;]*[-A-Za-z0-9+&#/%=~_|]", 
                         min_len, max_len, required)

    def check_dict(self, data: dict) -> CheckResult:
        result = super().check_dict(data)
        if not result.success:
            return result
        value = self.raw_value(data)
        try:
            parse_ret = urlparse(value)
        except Exception:
            msg_format = "DestinationChecker: parse destination of {} failed."
            return CheckResult.make_failed(msg_format.format(self.name()))

        # ⚠️ 只检查用户名和密码，不检查主机地址是否为私有IP或云元数据端点
        if parse_ret.username or parse_ret.password:
            return CheckResult.make_failed("Destination is invalid")

        return CheckResult.make_success()  # ⚠️ 所有其他URL都通过
```

### 2.3 数据流
```
subscription_views.py:rf_create_subscriptions()
    -> CreateSubscriptionChecker.check(request_json)
    -> DestinationChecker.check({"Destination": url})
    -> regex检查 [只验证URL格式]
    -> urlparse检查 [只过滤username/password]
    -> CheckResult.make_success() [⚠️ 没有SSRF防护]
    -> subs_mgr.add_subscription()
    -> report_alarm_task.py:report_tasks()
    -> manager.request("POST", target) [⚠️ 发送请求到任意目标]
```

### 2.4 漏洞根因分析

**缺失的SSRF防护**:
- 未检查目标主机是否为私有IP地址
- 未检查目标主机是否为云元数据端点
- 未检查目标主机是否为内部服务地址
- 只依赖正则表达式验证URL格式，无法阻止SSRF攻击

### 2.5 调用链分析

**创建订阅入口** (subscription_views.py:95-158):
```python
@RedfishGlobals.redfish_operate_adapter(request, "Create Event Subscription")
def rf_create_subscriptions():
    # ...
    check_ret = RedfishGlobals.check_external_parameter(CreateSubscriptionChecker, request_json)
    if check_ret is not None:
        return check_ret, CommonConstants.ERR_GENERAL_INFO
    # DestinationChecker只做格式验证
    # ...
    subs_mgr.add_subscription(subscription_obj)
```

**发送请求入口** (report_alarm_task.py:79-112):
```python
@staticmethod
def report_tasks(subscriber: Subscription, manager: PoolManager, report_data: dict):
    target = subscriber.get_decrypt_destination()
    # 再次验证，但同样没有SSRF防护
    is_target_valid = DestinationChecker("target").check({"target": target})
    if not is_target_valid:
        return False

    try:
        resp = manager.request("POST", target, ...)  # ⚠️ 发送请求到任意目标
```

## 3. 利用条件分析

### 3.1 攻击者前置条件
| 条件 | 要求 | 说明 |
|------|------|------|
| **Redfish API访问权限** | 需要能调用Event Subscription API | 创建订阅需要认证 |
| **网络访问** | 需要访问Redfish服务端口 | 通常为HTTPS端口 |
| **任意用户** | 任何有订阅创建权限的用户 | 不需要特殊权限 |

### 3.2 SSRF可访问的目标

**私有IP地址范围**:
| CIDR | 描述 |
|------|------|
| `10.0.0.0/8` | 私有网络A类 |
| `172.16.0.0/12` | 私有网络B类 |
| `192.168.0.0/16` | 私有网络C类 |
| `127.0.0.0/8` | 本地回环 |
| `0.0.0.0/8` | 当前网络 |
| `169.254.0.0/16` | 链路本地 |

**云元数据端点**:
| 云平台 | 元数据URL |
|--------|-----------|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| Azure | `http://169.254.169.254/metadata/instance` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| OpenStack | `http://169.254.169.254/openstack/latest/meta_data.json` |

### 3.3 利用难度
- **难度**: Low
- **原因**: 只需合法API调用即可触发SSRF

## 4. 攻击场景描述

### 4.1 场景1: 云元数据泄露攻击

**攻击目标**: 获取云环境中的敏感元数据信息

**攻击步骤**:
1. 攻击者创建恶意订阅:
   ```json
   {
     "Destination": "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "EventTypes": ["Alert"],
     "Protocol": "Redfish",
     "HttpHeaders": {"X-Auth-Token": "valid_token"}
   }
   ```

2. DestinationChecker验证:
   - 正则匹配: `https://169.254.169.254/...` → 格式正确
   - urlparse: 无username/password → 通过
   - 返回: CheckResult.make_success()

3. 订阅创建成功

4. 当告警发生时，系统发送POST请求到AWS元数据端点

5. AWS元数据服务返回IAM凭证信息:
   ```json
   {
     "Code": "Success",
     "LastUpdated": "2024-01-01T00:00:00Z",
     "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
     "Token": "AQoDYXdzEJr..."
   }
   ```

6. **攻击者获得云服务凭证**

### 4.2 场景2: 内部服务探测攻击

**攻击目标**: 扫描内部网络中的服务

**攻击步骤**:
1. 攻击者创建多个订阅探测内部IP:
   ```json
   {"Destination": "https://192.168.1.1/admin", ...}
   {"Destination": "https://192.168.1.2/api", ...}
   {"Destination": "https://10.0.0.50/internal", ...}
   ```

2. 系统发送POST请求到这些内部地址

3. 根据响应判断内部服务存在:
   - 连接成功 → 服务存在
   - 超时 → 服务不存在
   - 特定错误码 → 服务信息泄露

4. **攻击者获得内部网络拓扑信息**

### 4.3 场景3: 本地服务攻击

**攻击目标**: 攻击本地运行的敏感服务

**攻击步骤**:
1. 创建指向本地服务的订阅:
   ```json
   {"Destination": "https://127.0.0.1:6443/api/v1/namespaces/default/secrets", ...}
   ```

2. 系统向Kubernetes API发送请求

3. 如果本地K8s配置不当，可能泄露secrets

4. **攻击者获得容器编排系统凭证**

### 4.4 场景4: DNS重绑定攻击

**攻击目标**: 绕过可能的IP检查

**攻击步骤**:
1. 攻击者注册域名 `evil-ssrf.com`
2. DNS服务器交替返回公网IP和私有IP:
   ```
   第一次查询: evil-ssrf.com → 203.0.113.1 (公网)
   第二次查询: evil-ssrf.com → 169.254.169.254 (私有)
   ```

3. 创建订阅: `{"Destination": "https://evil-ssrf.com/metadata", ...}`
4. 验证时DNS返回公网IP → 通过
5. 执行时DNS返回私有IP → SSRF成功

### 4.5 场景5: 端口扫描攻击

**攻击目标**: 扫描内部主机的开放端口

**攻击步骤**:
1. 创建订阅指向特定端口:
   ```json
   {"Destination": "https://192.168.1.100:22/", ...}  // SSH
   {"Destination": "https://192.168.1.100:3306/", ...}  // MySQL
   {"Destination": "https://192.168.1.100:6379/", ...}  // Redis
   ```

2. 根据响应时间判断端口状态

3. **攻击者获得内部服务端口信息**

## 5. 潜在影响评估

### 5.1 直接影响
| 影响 | 严重性 | 描述 |
|------|--------|------|
| **云凭证泄露** | Critical | AWS/Azure/GCP IAM凭证被窃取 |
| **内部服务暴露** | High | 内部网络拓扑和服务信息泄露 |
| **数据泄露** | High | 内部数据库/API可能被访问 |
| **横向移动** | High | 攻击者可利用泄露信息进行横向攻击 |

### 5.2 间接影响
- **集群接管**: 利用泄露凭证控制整个集群
- **数据窃取**: 访问内部数据库和存储系统
- **权限提升**: 利用内部服务漏洞提升权限

### 5.3 影响范围
- **影响组件**: om_event_subscription模块
- **影响服务**: Redfish Event Subscription服务
- **影响系统**: MindCluster集群 + 云环境

## 6. 修复建议

### 6.1 推荐修复方案: 完整的SSRF防护

```python
import ipaddress
import socket
import re

class DestinationChecker(RegexStringChecker):
    # 私有IP地址范围
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),  # 链路本地(云元数据)
        ipaddress.ip_network('192.0.2.0/24'),    # TEST-NET-1
        ipaddress.ip_network('198.51.100.0/24'), # TEST-NET-2
        ipaddress.ip_network('203.0.113.0/24'),  # TEST-NET-3
    ]
    
    # 云元数据主机名
    METADATA_HOSTS = [
        '169.254.169.254',
        'metadata.google.internal',
        'metadata',
        'kubernetes.default',
        'kubernetes.default.svc',
    ]
    
    def __init__(self, attr_name: str = None, min_len: int = 0, max_len: int = 2048, required: bool = True):
        super().__init__(attr_name, "(https|HTTPS)://[-A-Za-z0-9+&#/%?=~_|!:,.;]*[-A-Za-z0-9+&#/%=~_|]", 
                         min_len, max_len, required)

    def is_private_ip(self, host: str) -> bool:
        """检查主机是否为私有IP或云元数据端点"""
        # 检查是否为云元数据主机名
        if host in self.METADATA_HOSTS:
            return True
        
        # 尝试解析IP地址
        try:
            # 直接解析IP
            ip = ipaddress.ip_address(host)
            for network in self.PRIVATE_IP_RANGES:
                if ip in network:
                    return True
        except ValueError:
            pass
        
        # DNS解析并检查
        try:
            resolved_ips = socket.getaddrinfo(host, None)
            for family, _, _, _, sockaddr in resolved_ips:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                for network in self.PRIVATE_IP_RANGES:
                    if ip in network:
                        return True
        except socket.gaierror:
            pass
        
        return False

    def check_dict(self, data: dict) -> CheckResult:
        result = super().check_dict(data)
        if not result.success:
            return result
        
        value = self.raw_value(data)
        try:
            parse_ret = urlparse(value)
        except Exception:
            return CheckResult.make_failed("DestinationChecker: parse destination failed")

        # 检查用户名密码
        if parse_ret.username or parse_ret.password:
            return CheckResult.make_failed("Destination is invalid")

        # ✅ SSRF防护: 检查主机是否为私有IP
        host = parse_ret.hostname
        if host and self.is_private_ip(host):
            return CheckResult.make_failed("Destination points to private/internal address")

        # ✅ 检查端口是否为危险端口
        port = parse_ret.port
        DANGEROUS_PORTS = [22, 23, 25, 3306, 5432, 6379, 27017, 9200, 9300]
        if port and port in DANGEROUS_PORTS:
            return CheckResult.make_failed("Destination uses restricted port")

        return CheckResult.make_success()
```

### 6.2 增强防护: DNS缓存+重新验证

```python
def check_destination_with_dns_revalidation(url: str) -> bool:
    """DNS重绑定攻击防护"""
    parse_ret = urlparse(url)
    host = parse_ret.hostname
    
    # 第一次DNS查询
    first_ip = resolve_ip(host)
    if is_private_ip(first_ip):
        return False
    
    # 在实际发送请求前再次验证
    # (需要在report_tasks中实现)
    second_ip = resolve_ip(host)
    if first_ip != second_ip:
        # IP变化，可能为DNS重绑定攻击
        return False
    
    if is_private_ip(second_ip):
        return False
    
    return True
```

### 6.3 在report_tasks中增强防护

```python
@staticmethod
def report_tasks(subscriber: Subscription, manager: PoolManager, report_data: dict):
    target = subscriber.get_decrypt_destination()
    
    # ✅ 发送请求前再次验证IP
    host = urlparse(target).hostname
    if is_private_ip(host):
        run_log.error("Blocked SSRF attempt to private IP")
        return False
    
    try:
        # 设置超时和重定向限制
        resp = manager.request(
            "POST", target,
            body=json.dumps(report_data),
            timeout=5.0,  # 短超时防止长时间等待
            redirect=False,  # 禁止重定向
            headers={"X-Auth-Token": subscriber.get_decrypt_credential()}
        )
```

### 6.4 修复优先级
- **High**: 应尽快修复，云元数据泄露可导致整个云环境被接管

## 7. 参考资料

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [AWS SSRF Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [DNS Rebinding Attacks](https://en.wikipedia.org/wiki/DNS_rebinding)