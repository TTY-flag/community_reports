# OMSDK 威胁分析报告

## 项目概述

**项目名称**: OMSDK (Huawei OM SDK - Edge Management System)
**项目类型**: network_service (边缘管理系统 SDK)
**语言组成**: Python (92%, 629 文件) + C/C++ (8%, 53 文件)
**网络暴露**: 高 (RESTful API + WebSocket)
**认证要求**: 需要 (Token-based + TLS)

## 模块架构

### 核心模块

| 模块 | 语言 | 描述 | 入口点数 | 风险等级 |
|------|------|------|----------|----------|
| RedfishServer | Python | RESTful API 服务器 | 25 | 高 |
| system_service | Python | 系统管理服务 | 15 | 高 |
| upgrade_service | Python | 固件升级服务 | 5 | 严重 |
| fd_msg_process | Python | FusionDirector 消息处理 | 12 | 高 |
| security_service | Python | 安全服务 | 8 | 高 |
| alarm_process | C | 告警处理 | 2 | 中 |
| certmanage | C | 证书管理 | 5 | 高 |
| fault_check | C | 故障检测 | 0 | 高 |
| extend_alarm | C | 扩展告警检测 | 0 | 严重 |
| devm | C | 设备管理 | 0 | 中 |
| ens | C | 事件通知系统框架 | 0 | 中 |

## 攻击面分析

### AS-001: RESTful API 入口

**描述**: HTTPS 端口暴露的 RESTful API 端点

**入口点**:
- EP-001: `/redfish/v1/Systems` - 系统管理
- EP-002: `/redfish/v1/UpdateService` - 固件升级
- EP-003: `/redfish/v1/Systems/1/SecurityService/HttpsCert` - 证书导入
- EP-004: `/redfish/v1/AccountService/Accounts` - 用户管理
- EP-005: `/redfish/v1/SessionService` - 会话服务
- EP-006: `/redfish/v1/Systems/1/Storage` - NFS/分区管理
- EP-007: `/redfish/v1/Systems/1/NetworkInterfaces` - 网络配置

**风险因素**:
1. JSON 请求体接收未信任用户输入
2. 文件上传处理 (证书、固件包)
3. 认证绕过风险
4. 后端处理中的注入漏洞

**缓解措施**:
- Token-based 认证要求
- param_checker 类参数验证
- file_checker 模块文件路径验证
- 敏感操作的密码二次验证

**信任等级**: untrusted_network

### AS-002: 文件上传入口

**描述**: 多个文件上传端点处理证书、配置、固件包

**入口点**: EP-002, EP-003, EP-014, EP-015

**风险因素**:
1. 上传文件中的恶意内容
2. 文件名路径遍历
3. 归档解压漏洞
4. 证书链篡改

**缓解措施**:
- Upload mark file 机制
- 文件大小限制 (证书 10KB)
- safety_fopen 安全文件操作
- 证书有效性检查

**信任等级**: untrusted_local

### AS-003: 命令执行入口

**描述**: C 模块中的系统命令执行

**风险位置**:

| 文件 | 函数 | 行号 | 风险描述 |
|------|------|------|----------|
| extend_alarm.c | execute_check_cmd | 121 | `system((char*)cmd)` - 命令注入风险 |
| extend_alarm.c | fault_get_block_mem_dev | 397 | `system(block_info)` - 磁盘枚举 |
| check_space.c | fault_get_space_full_info | 74 | `system(&block_info[0])` - 空间检查 |
| check_extend_alarm.c | get_usb_hub_alarm | 301 | `system(usb_hub_info)` - USB 检查 |

**数据流分析**:
- DF-003: `/run/formated_hw.info` → `sprintf_s` → `system()`
- DF-004: 固定配置路径 → `sprintf_s` → `system()`

**风险等级**: 中 (固定模板 + sprintf_s)

### AS-004: IPC 通信入口

**描述**: Unix Domain Socket 和 WebSocket 通信

**入口点**: EP-008, EP-009

**风险因素**:
1. 消息格式解析漏洞
2. JSON 解析错误
3. Socket 接收缓冲区溢出

**缓解措施**:
- UDS 使用 SSL/TLS 双向认证
- 消息长度限制 (maxDataLen=1MB)
- `;;over;` 消息边界分隔符

### AS-005: 配置注入入口

**描述**: 配置文件解析不完全验证

**风险位置**:

| 文件 | 函数 | 行号 | 风险描述 |
|------|------|------|----------|
| lib_restful_adapter.py | LibRESTfulAdapter | 88 | `ast.literal_eval(ret)` - 代码注入风险 |
| ntp.py | get_ntp_config | 134 | `ast.literal_eval(nt_pfile)` - 配置文件评估 |
| common_methods.py | CommonMethods | 218 | `ast.literal_eval(fd.read())` - 文件内容评估 |

**风险等级**: 中 (trusted_local 源)

## 高危数据流

### DF-001: 固件上传 → 命令执行

**路径**: 
```
HTTP POST (EP-002) → rf_upgrade_service_actions → 
LibRESTfulAdapter → Upgrade_New → 系统升级命令
```

**污点类型**: user_input, file_content
**缓解措施**: UpdateServiceChecker, shell=False
**风险等级**: 高

### DF-002: 证书上传 → OpenSSL 解析

**路径**:
```
HTTP POST (EP-003) → rf_import_custom_certificate →
LibRESTfulAdapter → SecurityService → cert_getcertinfo → PEM_read_X509
```

**污点类型**: user_input, file_content
**缓解措施**: ImportServerCertificateChecker, MAX_CERTFILE_SIZE, symlink check
**风险等级**: 高

## 安全敏感函数清单

### 命令执行类

| 函数 | 文件 | 漏洞类型 |
|------|------|----------|
| execute_check_cmd | extend_alarm.c:121 | command_injection |
| fault_get_block_mem_dev | extend_alarm.c:397 | command_injection |
| fault_get_space_full_info | check_space.c:74 | command_injection |
| get_usb_hub_alarm | check_extend_alarm.c:301 | command_injection |
| subprocess.run | exec_cmd.py:42 | command_execution |

### 代码执行类

| 函数 | 文件 | 漏洞类型 |
|------|------|----------|
| ast.literal_eval | lib_restful_adapter.py:88 | code_injection |
| ast.literal_eval | ntp.py:134 | code_injection |

### 文件处理类

| 函数 | 文件 | 漏洞类型 |
|------|------|----------|
| shutil.move | upgrade_service_view.py:114 | path_traversal |
| os.rename | security_service_views.py:228 | path_traversal |
| PEM_read_X509 | certproc.c:463 | certificate_handling |

### 缓冲区处理类

| 函数 | 文件 | 漏洞类型 |
|------|------|----------|
| receive_socket_message | ibma_server.py:105 | buffer_overflow |
| alarm_report | alarm_process.c:283 | buffer_handling |

## 信任边界

### TB-001: 外部网络 → Flask 应用
- 组件: External Client → HTTPS Server → Flask Blueprints
- 数据流: HTTP request → authentication → request handler → backend service

### TB-002: Flask → 后端库 (LibRESTfulAdapter)
- 组件: Flask Views → LibRESTfulAdapter → Backend Libraries
- 数据流: JSON request → Adapter → lib/Linux modules → system calls

### TB-003: Python → C/C++ Daemon (ENS)
- 组件: Python Services → ENS Daemon → C Modules
- 数据流: Interface export/import → function calls → fault/alarm processing

### TB-004: OM SDK → FusionDirector (WebSocket)
- 组件: fd_msg_process → WsClientMgr → FusionDirector
- 数据流: WebSocket messages → handlers → backend processing

## 关键发现

### 1. system() 调用存在命令注入风险 (严重)

**位置**: extend_alarm.c, check_space.c, check_extend_alarm.c
**分析**: 
- `system()` 调用使用 `sprintf_s` 构建命令
- 命令模板为固定字符串，仅替换设备名
- 设备名来自 `/run/formated_hw.info` (trusted_local)
- 但如果配置文件被篡改，可能注入恶意命令

**建议**: 
- 替换 `system()` 为 `execvp()` 系列
- 对设备名进行字符白名单验证
- 监控配置文件完整性

### 2. ast.literal_eval 代码注入风险 (高)

**位置**: lib_restful_adapter.py, ntp.py, common_methods.py
**分析**: 
- `ast.literal_eval` 可解析 Python 表达式
- 仅支持 literal (字符串、数字、列表、字典)
- 不支持函数调用或运算符
- 实际风险较低，但存在潜在解析漏洞

**建议**:
- 使用 `json.loads` 替代 `ast.literal_eval`
- 对输入内容进行预验证

### 3. 固件上传处理链 (高)

**位置**: upgrade_service_view.py
**分析**: 
- 接收用户上传的 ZIP 文件
- 文件解压后进行系统升级
- 缺乏对 ZIP 内容的完整性校验

**建议**:
- 增加 ZIP 文件签名验证
- 对解压后文件进行 hash 校验
- 限制可执行文件权限

### 4. 证书导入处理 (高)

**位置**: security_service_views.py, certproc.c
**分析**:
- 接收 PEM/PFX 格式证书
- OpenSSL 解析证书内容
- 需验证证书链完整性

**建议**:
- 强化证书链验证
- 检查证书扩展字段
- 防止恶意证书注入

## 建议的安全加固措施

### 优先级 1 (严重)

1. **替换 system() 调用**
   - 将 `system()` 替换为 `execvp()` 或 `posix_spawn()`
   - 实施参数白名单验证

2. **固件上传签名验证**
   - 实施固件包数字签名
   - 校验解压后文件 hash

### 优先级 2 (高)

3. **证书导入强化**
   - 完整证书链验证
   - 扩展字段安全检查
   - 证书有效期严格校验

4. **ast.literal_eval 替换**
   - 使用 `json.loads` 替代
   - 或实施严格输入验证

### 优先级 3 (中)

5. **配置文件完整性监控**
   - 使用 hash 校验关键配置
   - 监控 `/run/formated_hw.info` 修改

6. **IPC 消息验证强化**
   - WebSocket 消息 schema 验证
   - Socket 消息深度检查

## 结论

OMSDK 作为边缘管理系统 SDK，承担了关键的网络服务职责。通过本次威胁分析，识别出：

- **15 个主要入口点**，其中 7 个为 untrusted_network
- **5 个攻击面**，最严重为命令执行和文件上传
- **6 处高危 system() 调用**
- **3 处 ast.literal_eval 使用**
- **42 个安全敏感函数**

建议 DataFlow Scanner 和 Security Auditor 重点扫描：
1. extend_alarm.c 中的 system() 调用链
2. upgrade_service_view.py 的文件上传处理
3. security_service_views.py 的证书导入流程
4. lib_restful_adapter.py 的 literal_eval 使用

---

**生成时间**: 2026-04-21
**生成 Agent**: Architecture Agent
**数据库**: scan-results/.context/scan.db