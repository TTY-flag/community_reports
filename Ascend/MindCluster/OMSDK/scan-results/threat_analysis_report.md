# 威胁分析报告 - OMSDK

> 生成时间: 2026-04-21T06:30:00Z
> 项目路径: /home/pwn20tty/Desktop/opencode_project/shenteng/MindCluster/OMSDK
> 项目类型: 网络服务 (边缘管理系统 SDK)
> 扫描模式: 自主分析模式

## 项目概述

OM SDK 是华为边缘管理系统开发态组件，用于快速搭建智能边缘硬件管理平台。支持 RESTful 北向接口，可与 FusionDirector、SmartKit 等管理软件对接。

### 信任边界分析

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|-----|-------|---------|---------|
| REST API Interface | 边缘管理系统内部 | 远程管理客户端 (FusionDirector, SmartKit, Web UI) | Critical |
| Event Subscription | OM SDK 内部 | 外部 HTTPS 事件目标服务器 | High |
| Certificate Management | 系统证书存储 | 用户提供的证书内容 | High |

## 入口点分析

### 高风险入口点 (Critical)

| 入口点 | 类型 | 信任等级 | 风险描述 |
|-------|-----|---------|---------|
| `/redfish/v1/Systems/Actions/RestoreDefaults.Config` (POST) | web_route | untrusted_network | 远程客户端可触发恢复默认配置，涉及系统重启和配置重置 |
| `/redfish/v1/EventService/Subscriptions` (POST) | web_route | untrusted_network | 创建事件订阅，接收外部 URL 作为 Destination，存在 SSRF 风险 |
| 证书导入接口 (POST) | web_route | untrusted_network | 接收用户提供的证书内容字符串，存在证书验证绕过风险 |
| CRL 导入接口 (POST) | web_route | untrusted_network | 接收用户提供的吊销列表，存在 CRL 伪造风险 |

### 中高风险入口点 (High)

| 入口点 | 类型 | 信任等级 | 风险描述 |
|-------|-----|---------|---------|
| `ExecCmd.exec_cmd` (om_actions.py) | cmdline | semi_trusted | 系统重启命令执行，若参数控制不当可导致命令注入 |
| `subprocess.Popen` (recover_mini_os.py) | file | semi_trusted | Mini OS 恢复操作，执行外部命令 |
| FusionDirector 消息处理 | rpc | semi_trusted | 处理来自 FusionDirector 的 JSON 消息 |

## STRIDE 建模

### Spoofing (身份伪造)

- **风险点**: REST API 认证机制
- **入口**: `/redfish/v1/Systems/Actions/RestoreDefaults.Config` 需要二次认证
- **威胁**: 若认证实现不正确，攻击者可伪造合法用户身份

### Tampering (数据篡改)

- **风险点**: 证书/CRL 导入接口
- **入口**: `rf_import_root_cert`, `rf_import_root_crl`
- **威胁**: 恶意证书或 CRL 可被导入系统，破坏信任链

### Repudiation (抵赖)

- **风险点**: 操作日志记录
- **威胁**: 若日志记录不完整，攻击者可否认执行了敏感操作

### Information Disclosure (信息泄露)

- **风险点**: REST API 响应数据
- **威胁**: API 响应可能泄露系统内部信息（如设备信息、配置详情）

### Denial of Service (拒绝服务)

- **风险点**: 系统重启操作
- **入口**: `force_restart`, `cold_restart`
- **威胁**: 恶意调用重启接口可导致服务中断

### Elevation of Privilege (权限提升)

- **风险点**: 命令执行路径
- **入口**: `ExecCmd.exec_cmd`, `subprocess.Popen`
- **威胁**: 若参数由外部输入控制，可能执行任意命令

## 数据流风险分析

### 数据流 1: 恢复默认配置

```
request.get_data → json.loads → DefaultConfig.deal_request → ExecCmd.exec_cmd
```

**风险**: 若 `request_data_dict` 中的参数未充分校验，可能影响执行脚本的行为

### 数据流 2: 事件订阅创建

```
request.get_data → json.loads → Subscription.from_dict → subs_mgr.add_subscription
```

**风险**: Destination URL 由用户提供，存在 SSRF 风险；若 URL 验证不严格，可能导致内部资源访问

### 数据流 3: 证书导入

```
request.get_data → json.loads → check_multi_cert → subs_cert_mgr.overwrite_subs_cert
```

**风险**: 证书内容由用户提供，若校验逻辑存在缺陷，可能导入恶意证书

## 关键攻击面

1. **REST API 注入风险**: 多个 POST 接口接收 JSON 数据，需验证是否存在注入漏洞
2. **命令执行风险**: `ExecCmd.exec_cmd` 和 `subprocess.Popen` 调用外部命令
3. **SSRF 风险**: 事件订阅 Destination URL 由外部指定
4. **证书验证绕过**: 证书导入和 CRL 导入接口
5. **认证绕过**: REST API 认证机制（token_auth）

## 重点关注模块

- `om_system_service`: 系统操作 REST API (恢复默认配置、重启等)
- `om_event_subscription`: 事件订阅 REST API (SSRF、证书)
- `om_lib_systems`: 命令执行逻辑 (重启、恢复)
- `certmanage` (C/C++): 证书处理逻辑
- `fault_check` (C/C++): 故障检测逻辑

## 下一步扫描建议

1. 重点扫描 REST API 入口点的输入验证
2. 检查命令执行路径是否存在参数注入
3. 分析事件订阅 Destination URL 的 SSRF 风险
4. 验证证书/CRL 导入的校验逻辑完整性
5. 检查认证机制的实现安全性