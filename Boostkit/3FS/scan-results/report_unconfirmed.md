# 漏洞扫描报告 — 待确认漏洞

**项目**: 3FS (Fire-Flyer File System)
**扫描时间**: 2026-04-22T12:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner

---

## 执行摘要

### 扫描概况

本次扫描在已确认的 2 个 Critical 漏洞之外，还发现了 5 个待进一步确认的漏洞。这些漏洞置信度在 40% 到 70% 之间，需要进一步的人工审核和验证。虽然不能立即确定其真实性和严重性，但建议安全团队对其进行评估。

### 关键发现

扫描发现 **5 个待确认漏洞**，包括 1 个 High、3 个 Medium 和 1 个 Low 级别：

| 漏洞ID | 类型 | 严重性 | 置信度 | 主要问题 |
|--------|------|--------|--------|----------|
| VULN-SEC-AUTH-002 | sensitive_info_exposure | High | 70% | 环境变量泄露认证令牌 |
| VULN-004 | buffer_overflow | Medium | 55% | FUSE API 缺少文件名长度检查 |
| VULN-SEC-AUTH-003 | authentication_bypass | Medium | 45% | 认证可通过配置关闭 |
| VULN-SEC-SESSION-001 | insufficient_session_expiration | Medium | 40% | Token 可设置为永不过期 |
| VULN-SEC-AUTH-001 | information_exposure | Low | 40% | CLI 输出打印完整 Token |

### 风险评级

**整体风险等级**: **Medium**

待确认漏洞主要涉及信息泄露、认证配置和会话管理问题。这些漏洞通常需要特定条件才能被利用，或者攻击面有限。建议安全团队评估这些漏洞在生产环境中的实际风险。

### 安全建议

1. **评估 VULN-SEC-AUTH-002**: 环境变量泄露 Token 的问题，考虑使用文件或密钥管理系统
2. **审核认证配置**: 确保 VULN-SEC-AUTH-003 中的 authenticate=false 仅在开发环境使用
3. **添加会话过期策略**: 针对 VULN-SEC-SESSION-001，建议设置强制 Token 过期时间
4. **修复防御性编码问题**: VULN-004 的文件名长度检查可增强防御深度
5. **减少敏感信息输出**: VULN-SEC-AUTH-001 可通过掩码处理 Token 输出

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 7 | 58.3% |
| FALSE_POSITIVE | 2 | 16.7% |
| CONFIRMED | 2 | 16.7% |
| LIKELY | 1 | 8.3% |
| **总计** | **12** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 20.0% |
| Medium | 3 | 60.0% |
| Low | 1 | 20.0% |
| **有效漏洞总计** | **5** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-AUTH-002]** sensitive_info_exposure (High) - `src/fuse/FuseClients.cc:68` @ `FuseClients::init` | 置信度: 70
2. **[VULN-004]** buffer_overflow (Medium) - `src/lib/api/UsrbIo.cc:784` @ `hf3fs_hardlink` | 置信度: 55
3. **[VULN-SEC-AUTH-003]** authentication_bypass (Medium) - `src/mgmtd/service/MgmtdState.cc:54` @ `validateAdmin` | 置信度: 45
4. **[VULN-SEC-SESSION-001]** insufficient_session_expiration (Medium) - `src/fbs/core/user/User.h:41` @ `TokenAttr` | 置信度: 40
5. **[VULN-SEC-AUTH-001]** information_exposure (Low) - `src/client/cli/admin/AdminUserCtrl.cc:53` @ `printUserAttr` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `IBSocket::accept@src/common/net/ib/IBSocket.cc` | network | untrusted_network | RDMA连接接受入口，接收远程客户端的连接请求，可能接收恶意构造的IBConnectReq | 接收RDMA连接请求 |
| `IBSocket::connect@src/common/net/ib/IBSocket.cc` | network | untrusted_network | RDMA连接发起，与远程服务建立连接，可能被恶意服务端攻击 | 发起RDMA连接 |
| `Listener::listen@src/common/net/Listener.cc` | network | untrusted_network | TCP/RDMA监听入口，监听指定端口等待远程连接 | 监听网络端口 |
| `Processor::unpackMsg@src/common/net/Processor.h` | network | untrusted_network | 网络消息解包入口，处理来自远程的网络数据包，包含checksum校验和反序列化 | 处理网络消息 |
| `fuse_operations@src/fuse/FuseOps.cc` | file | untrusted_local | FUSE文件系统操作入口，处理本地用户进程的文件系统请求 | FUSE操作回调 |
| `real_ino@src/fuse/FuseOps.cc` | file | untrusted_local | inode ID转换函数，处理来自FUSE的inode号 | inode转换 |
| `HeartbeatOperation@src/mgmtd/ops/HeartbeatOperation.cc` | network | untrusted_network | 心跳处理入口，接收远程节点的心跳信息 | 节点心跳处理 |
| `RegisterNodeOperation@src/mgmtd/ops/RegisterNodeOperation.cc` | network | untrusted_network | 节点注册入口，接收远程节点的注册请求 | 节点注册 |
| `AdminUserCtrl@src/client/cli/admin/AdminUserCtrl.cc` | cmdline | semi_trusted | 管理员CLI命令入口，处理管理员用户操作命令 | 管理员用户控制 |
| `hf3fs_open@src/lib/api/hf3fs.h` | file | untrusted_local | 用户态API入口，提供文件系统操作接口 | 用户态文件系统API |
| `pybind11_module@src/lib/py/binding.cc` | rpc | untrusted_local | Python绑定入口，暴露C++ API到Python环境 | Python API绑定 |
| `main@hf3fs_utils/cli.py` | cmdline | semi_trusted | Python CLI工具入口，处理用户命令行操作 | Python CLI入口 |

**其他攻击面**:
- RDMA Network: IBSocket accept/connect - InfiniBand/RoCE连接
- TCP Network: Listener listen - TCP端口监听
- RPC Protocol: Processor unpackMsg - 消息解包和反序列化
- FUSE Interface: FuseOps - 用户态文件系统操作
- Admin CLI: admin_cli.cc - 管理员命令处理
- Python Binding: binding.cc - Python模块绑定
- Storage RPC: StorageOperator - 存储服务操作
- Meta RPC: MetaOperator - 元数据服务操作

---

## 3. High 漏洞深度分析 (1)

### [VULN-SEC-AUTH-002] Sensitive Information Exposure via Environment Variable

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-SEC-AUTH-002 |
| **CWE** | CWE-214 (Invocation of Process Containing Visible Sensitive Information) |
| **类型** | sensitive_info_exposure |
| **严重性** | High |
| **置信度** | 70% |
| **状态** | LIKELY |
| **位置** | src/fuse/FuseClients.cc:68-76 |
| **函数** | FuseClients::init |
| **模块** | fuse |

#### 漏洞详情

**描述**: Authentication token is read from environment variable HF3FS_FUSE_TOKEN (FuseClients.cc:68-70). Environment variables are visible to other processes on the same system via /proc/[pid]/environ and can be leaked through process listings, debugging tools, or environment variable dumps. This allows attackers with local access to steal authentication tokens.

**漏洞代码** (`src/fuse/FuseClients.cc:68-76`)

```c
if (const char *env_p = std::getenv("HF3FS_FUSE_TOKEN")) {
  XLOGF(INFO, "Use token from env var");
  fuseToken = std::string(env_p);
} else {
  XLOGF(INFO, "Use token from config");
  auto tokenRes = loadFile(tokenFile);
  RETURN_ON_ERROR(tokenRes);
  fuseToken = folly::trimWhitespace(*tokenRes);
}
```

#### 攻击路径

**数据流**:

```
HF3FS_FUSE_TOKEN environment variable
  │
  ▼
std::getenv()  [读取环境变量]
  │
  ▼
fuseToken string  [存储认证令牌]
  │
  ▼
用于后续认证操作
```

#### 利用场景

**场景1：进程信息泄露**

本地攻击者可通过以下方式读取环境变量：
1. `/proc/[pid]/environ` 文件读取进程环境变量
2. `ps e` 命令显示进程环境变量
3. `cat /proc/[pid]/environ | tr '\0' '\n' | grep HF3FS_FUSE_TOKEN`
4. 调试工具如 gdb、strace 可捕获环境变量

**场景2：容器环境泄露**

在容器化部署中：
1. 容器间共享相同的环境变量配置
2. 容器运行时可能将环境变量暴露给日志系统
3. CI/CD 流程可能将环境变量泄露到构建日志

**场景3：恶意进程读取**

恶意进程在同一主机上运行时：
1. 扫描所有进程的环境变量
2. 寻找包含认证令牌的环境变量
3. 窃取令牌用于未授权访问

#### 影响评估

| 影响 | 描述 |
|------|------|
| Token 泄露 | 本地攻击者可读取 FUSE 认证令牌 |
| 未授权访问 | 窃取的 Token 可用于访问文件系统 |
| 权限提升 | 如果 Token 具有高权限，可提升攻击者权限 |

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-214 基础分 |
| reachability | 30 | 环境变量可见性高 |
| controllability | 10 | 需要本地访问权限 |
| mitigations | 0 | 无现有缓解措施 |
| context | 0 | 无特殊上下文加分 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **70** | |

**验证说明**: 环境变量 HF3FS_FUSE_TOKEN 确实泄露。本地攻击者可通过 /proc/[pid]/environ 读取 token。这是真实的信息泄露问题，但需要本地访问权限。

---

## 4. Medium 漏洞深度分析 (3)

### [VULN-004] Buffer Overflow in hf3fs_hardlink

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-004 |
| **CWE** | CWE-120 (Buffer Copy without Checking Size of Input) |
| **类型** | buffer_overflow |
| **严重性** | Medium |
| **置信度** | 55% |
| **状态** | POSSIBLE |
| **位置** | src/lib/api/UsrbIo.cc:784 |
| **函数** | hf3fs_hardlink |
| **模块** | lib/api |

#### 漏洞详情

**描述**: strcpy() in hf3fs_hardlink lacks length validation for filename. Target buffer arg.str is NAME_MAX (255 bytes). While filesystem typically limits filename length, explicit check missing for defense-in-depth.

**漏洞代码** (`src/lib/api/UsrbIo.cc:784`)

```c
strcpy(arg.str, link_path.filename().c_str())
```

#### 攻击路径

**数据流**:

```
API parameter link_name
  │
  ▼
link_path.filename().c_str()
  │
  ▼
strcpy(arg.str, ...)
  │
  ▼
arg.str[NAME_MAX]  [255字节缓冲区]
```

#### 影响评估

| 影响 | 描述 |
|------|------|
| 缓冲区溢出 | 超长文件名可能导致溢出 |
| 防御深度缺失 | 缺少显式边界检查 |

**缓解因素**: 文件系统通常限制文件名长度不超过 NAME_MAX (255)，但违反防御性编程原则。

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-120 基础分 |
| reachability | 30 | FUSE API 入口可达 |
| controllability | 10 | 文件名受文件系统限制 |
| mitigations | -15 | 文件系统已有限制 |
| context | 0 | 无特殊上下文加分 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **55** | |

**验证说明**: strcpy(arg.str, filename) 拷贝文件名到 NAME_MAX(255) 缓冲区。文件名长度由文件系统限制，通常不超过 NAME_MAX。但缺少显式边界检查，违反防御性编程原则。攻击面有限。

---

### [VULN-SEC-AUTH-003] Authentication Bypass via Configuration

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-SEC-AUTH-003 |
| **CWE** | CWE-287 (Improper Authentication) |
| **类型** | authentication_bypass |
| **严重性** | Medium (原评估: Critical → 验证后: Medium) |
| **置信度** | 45% |
| **状态** | POSSIBLE |
| **位置** | src/mgmtd/service/MgmtdState.cc:54-64 |
| **函数** | validateAdmin |
| **模块** | mgmtd |

#### 漏洞详情

**描述**: Authentication can be disabled via configuration. In MgmtdState.cc:55, validateAdmin() checks config_.authenticate() before performing authentication. If this config is set to false, no authentication is performed for admin operations. Similarly in MetaOperator.cc:60-65, the AUTHENTICATE macro allows bypassing authentication when config_.authenticate() is false. This allows complete authentication bypass if the configuration is misconfigured.

**漏洞代码** (`src/mgmtd/service/MgmtdState.cc:54-64`)

```c
CoTryTask<void> MgmtdState::validateAdmin(const core::ServiceOperation &ctx, const flat::UserInfo &userInfo) {
  if (config_.authenticate()) {
    auto ret = co_await userStore_.getUser(userInfo.token);
    CO_RETURN_ON_ERROR(ret);
    if (!ret->admin) {
      CO_RETURN_AND_LOG_OP_ERR(ctx, MgmtdCode::kNotAdmin, "");
    }
    LOG_OP_INFO(ctx, "Act as admin user {}({})", ret->name, ret->uid.toUnderType());
  }
  co_return Void{};
}
```

#### 攻击路径

**数据流**:

```
config_.authenticate() = false
  │
  ▼
validateAdmin() 跳过认证检查
  │
  ▼
允许任何用户执行管理员操作
```

#### 影响评估

| 影响 | 描述 |
|------|------|
| 认证绕过 | authenticate=false 时无认证 |
| 配置风险 | 不安全的默认配置 |

**缓解因素**: 这是配置层面问题，生产环境应开启认证。代码本身有认证机制。

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-287 基础分 |
| reachability | 20 | 需要配置错误 |
| controllability | 0 | 攻击者不能控制配置 |
| mitigations | 0 | 无现有缓解措施 |
| context | -5 | 配置问题而非代码缺陷 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **45** | |

**验证说明**: 认证可通过配置关闭。代码本身有认证机制（validateAdmin、AUTHENTICATE宏），但默认配置 authenticate=false。这是不安全的默认配置问题，属于部署配置层面风险。生产环境应开启认证。

---

### [VULN-SEC-SESSION-001] Insufficient Session Expiration

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-SEC-SESSION-001 |
| **CWE** | CWE-613 (Insufficient Session Expiration) |
| **类型** | insufficient_session_expiration |
| **严重性** | Medium (原评估: High → 验证后: Medium) |
| **置信度** | 40% |
| **状态** | POSSIBLE |
| **位置** | src/fbs/core/user/User.h:41-49 |
| **函数** | TokenAttr |
| **模块** | core/user |

#### 漏洞详情

**描述**: User tokens can be endless with no mandatory expiration. In User.h:43, TokenAttr.endTime being zero indicates an endless token (isEndless() returns true in User.cc:30). The validateToken() function (User.cc:33-46) only checks expiration if endTime is non-zero. Endless tokens persist indefinitely, allowing stolen tokens to be used forever without expiration.

**漏洞代码** (`src/fbs/core/user/User.h:41-49`)

```c
struct TokenAttr {
  SERDE_STRUCT_FIELD(token, Token{});
  SERDE_STRUCT_FIELD(endTime, UtcTime());  // 0 means endless
 public:
  bool active(UtcTime now) const;
  bool isEndless() const;

  bool operator==(const TokenAttr &other) const;
};
```

#### 攻击路径

**数据流**:

```
TokenAttr.endTime = 0
  │
  ▼
isEndless() = true
  │
  ▼
active() always returns true
  │
  ▼
token never expires
```

#### 影响评估

| 影响 | 描述 |
|------|------|
| 永不过期 | endTime=0 的 Token 无限期有效 |
| 会话劫持 | 窃取的 Token 可无限使用 |

**缓解因素**: 需要与其他漏洞组合（如环境变量泄露）才能被利用。

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-613 基础分 |
| reachability | 10 | 需要先获取 Token |
| controllability | 0 | 攻击者不能设置 Token |
| mitigations | 0 | 无现有缓解措施 |
| context | 0 | 无特殊上下文加分 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **40** | |

**验证说明**: endless token 确实存在（endTime=0表示永不过期）。这是会话管理设计问题。一旦 token 被窃取（通过其他漏洞如环境变量泄露），可无限期使用。需要与其他漏洞组合评估。

---

## 5. Low 漏洞深度分析 (1)

### [VULN-SEC-AUTH-001] Information Exposure in CLI Output

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-SEC-AUTH-001 |
| **CWE** | CWE-532 (Insertion of Sensitive Information into Log File) |
| **类型** | information_exposure |
| **严重性** | Low (原评估: Medium → 验证后: Low) |
| **置信度** | 40% |
| **状态** | POSSIBLE |
| **位置** | src/client/cli/admin/AdminUserCtrl.cc:53-63 |
| **函数** | printUserAttr |
| **模块** | core/user |

#### 漏洞详情

**描述**: User authentication tokens are exposed in CLI output. The printUserAttr() function (AdminUserCtrl.cc:53,56) and printUserInfo() function (AdminUserCtrl.cc:340) print full token strings to output tables. Additionally, user-list command outputs tokens in plain text (AdminUserCtrl.cc:322). This exposes sensitive authentication credentials to anyone with access to CLI output/logs.

**漏洞代码** (`src/client/cli/admin/AdminUserCtrl.cc:53-63`)

```c
table.push_back({"Token", fmt::format("{}(Expired at N/A)", attr.token)});
for (auto it = attr.tokens.rbegin(); it != attr.tokens.rend(); ++it) {
  const auto &sa = *it;
  table.push_back({"Token", fmt::format("{}(Expired at {})", sa.token, sa.endTime.YmdHMS())});
}
```

#### 攻击路径

**数据流**:

```
UserAttr.token
  │
  ▼
printUserAttr()
  │
  ▼
CLI output table
  │
  ▼
potential log file/user screen
```

#### 影响评估

| 影响 | 描述 |
|------|------|
| Token 泄露 | CLI 输出显示完整 Token |
| 日志泄露 | 输出可能被日志记录 |

**缓解因素**: 这是管理员 CLI 工具，需要管理员权限执行。攻击面有限。

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-532 基础分 |
| reachability | 10 | 需要管理员权限 |
| controllability | 0 | 攻击者不能触发 CLI |
| mitigations | 0 | 无现有缓解措施 |
| context | 0 | 无特殊上下文加分 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **40** | |

**验证说明**: CLI 输出确实打印完整 token (printUserAttr line 53,56)。但这是管理员 CLI 工具，需要管理员权限执行。输出可能被日志记录或屏幕截图捕获。属于信息泄露风险但攻击面有限。

---

## 6. 风险评估矩阵

### 漏洞风险矩阵

| 漏洞ID | 严重性 | 可达性 | 可控性 | 缓解措施 | 综合风险 |
|--------|--------|--------|--------|----------|----------|
| VULN-SEC-AUTH-002 | High | Local | Medium | None | **中等偏高** |
| VULN-004 | Medium | Local | Low | Filesystem | **中等** |
| VULN-SEC-AUTH-003 | Medium | Config | None | Config check | **低** |
| VULN-SEC-SESSION-001 | Medium | Token theft | None | None | **低** |
| VULN-SEC-AUTH-001 | Low | Admin CLI | None | None | **低** |

### 业务影响矩阵

| 漏洞ID | 服务可用性 | 数据完整性 | 系统安全 | 业务影响 |
|--------|------------|------------|----------|----------|
| VULN-SEC-AUTH-002 | 无直接影响 | 无直接影响 | Token泄露 | **中等** |
| VULN-004 | 无直接影响 | 无直接影响 | 内存破坏 | **低** |
| VULN-SEC-AUTH-003 | 无直接影响 | 可能未授权操作 | 认证绕过 | **中等** |
| VULN-SEC-SESSION-001 | 无直接影响 | 无直接影响 | 会话劫持 | **低** |
| VULN-SEC-AUTH-001 | 无直接影响 | 无直接影响 | 信息泄露 | **低** |

### 攻击复杂度矩阵

| 漏洞ID | 攻击复杂度 | 需要权限 | 攻击成本 | 检测难度 |
|--------|------------|----------|----------|----------|
| VULN-SEC-AUTH-002 | Low | Local Access | Low | Low |
| VULN-004 | Medium | Local Access + FS | Low | Low |
| VULN-SEC-AUTH-003 | Low | Config Access | Low | Medium |
| VULN-SEC-SESSION-001 | High | Token Theft | Medium | Low |
| VULN-SEC-AUTH-001 | Low | Admin CLI Access | Low | High |

---

## 7. 修复建议

### 优先级排序

| 优先级 | 漏洞ID | 修复方案 | 预估工作量 |
|--------|--------|----------|------------|
| **P1 高** | VULN-SEC-AUTH-002 | 使用文件或密钥管理系统替代环境变量 | 4 小时 |
| **P2 中** | VULN-004 | 添加文件名长度防御性检查 | 1 小时 |
| **P2 中** | VULN-SEC-AUTH-003 | 审核生产配置，确保认证开启 | 1 小时 |
| **P3 低** | VULN-SEC-SESSION-001 | 设置强制 Token 过期策略 | 2 小时 |
| **P3 低** | VULN-SEC-AUTH-001 | Token 输出掩码处理 | 1 小时 |

### VULN-SEC-AUTH-002 修复方案

**方案1：使用文件存储替代环境变量（推荐）**

```cpp
// 移除环境变量读取逻辑，仅使用文件
if (auto tokenRes = loadFile(tokenFile)) {
  fuseToken = folly::trimWhitespace(*tokenRes);
} else {
  XLOGF(ERR, "Failed to load token from file: {}", tokenRes.error());
  return tokenRes.error();
}
```

**方案2：使用密钥管理系统**

```cpp
// 从密钥管理系统获取 Token
auto tokenRes = keyManager.getToken("hf3fs_fuse_token");
RETURN_ON_ERROR(tokenRes);
fuseToken = *tokenRes;
```

**方案3：添加环境变量安全警告**

```cpp
if (const char *env_p = std::getenv("HF3FS_FUSE_TOKEN")) {
  XLOGF(WARN, "Using token from environment variable is insecure. Consider using file-based configuration.");
  // 检查环境变量是否被其他进程可见
  if (checkEnvVisibility()) {
    XLOGF(ERR, "Environment variable HF3FS_FUSE_TOKEN is visible to other processes!");
  }
  fuseToken = std::string(env_p);
}
```

### VULN-004 修复方案

**方案：添加防御性长度检查**

```cpp
// hf3fs_hardlink
const char* filename = link_path.filename().c_str();
size_t len = strlen(filename);
if (len >= NAME_MAX) {
  XLOGF(ERR, "Filename too long: {}", filename);
  return -ENAMETOOLONG;
}
strcpy(arg.str, filename);
```

### VULN-SEC-AUTH-003 修复方案

**方案：审核和强制生产配置**

```cpp
// 添加启动时配置检查
if (config_.authenticate() == false && !isDevelopmentMode()) {
  XLOGF(CRITICAL, "Authentication disabled in production mode! This is a security risk.");
  // 可选：强制要求开启认证
  throw std::runtime_error("Authentication must be enabled in production");
}
```

### VULN-SEC-SESSION-001 修复方案

**方案：强制 Token 过期策略**

```cpp
// 创建 Token 时强制设置过期时间
TokenAttr createToken(const Token& token, uint32_t maxAgeSeconds) {
  TokenAttr attr;
  attr.token = token;
  attr.endTime = UtcTime::now() + maxAgeSeconds;  // 强制过期
  return attr;
}

// 验证时检查过期
bool validateToken(const TokenAttr& attr) {
  if (attr.isEndless()) {
    XLOGF(WARN, "Endless token detected. Consider setting expiration.");
    // 可选：拒绝永不过期的 Token
    return false;
  }
  return attr.active(UtcTime::now());
}
```

### VULN-SEC-AUTH-001 修复方案

**方案：Token 输出掩码处理**

```cpp
// 修改 printUserAttr 函数
std::string maskToken(const Token& token) {
  // 显示前8字符，其余用掩码
  std::string str = token.toString();
  if (str.length() > 8) {
    return str.substr(0, 8) + "..." + "(" + std::to_string(str.length()) + " chars)";
  }
  return str;
}

table.push_back({"Token", maskToken(attr.token)});
```

---

## 8. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| core/user | 0 | 0 | 1 | 1 | 2 |
| fuse | 0 | 1 | 0 | 0 | 1 |
| lib/api | 0 | 0 | 1 | 0 | 1 |
| mgmtd | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **1** | **3** | **1** | **5** |

## 9. CWE 分布

| CWE | 数量 | 占比 | 描述 |
|-----|------|------|------|
| CWE-613 | 1 | 20.0% | Insufficient Session Expiration |
| CWE-532 | 1 | 20.0% | Insertion of Sensitive Information into Log File |
| CWE-287 | 1 | 20.0% | Improper Authentication |
| CWE-214 | 1 | 20.0% | Invocation of Process Containing Visible Sensitive Information |
| CWE-120 | 1 | 20.0% | Buffer Copy without Checking Size of Input |

## 10. 外部参考

### CWE 参考

| CWE | URL | 描述 |
|-----|-----|------|
| CWE-214 | https://cwe.mitre.org/data/definitions/214.html | Process Containing Visible Sensitive Information |
| CWE-120 | https://cwe.mitre.org/data/definitions/120.html | Classic Buffer Overflow |
| CWE-287 | https://cwe.mitre.org/data/definitions/287.html | Improper Authentication |
| CWE-613 | https://cwe.mitre.org/data/definitions/613.html | Insufficient Session Expiration |
| CWE-532 | https://cwe.mitre.org/data/definitions/532.html | Information Exposure Through Log Files |

---

## 11. 总结

本次扫描发现 5 个待确认漏洞，涵盖信息泄露、认证配置和会话管理问题：

1. **VULN-SEC-AUTH-002**: 环境变量泄露认证令牌，需要本地访问权限，建议使用文件或密钥管理系统替代
2. **VULN-004**: FUSE API 缺少防御性文件名长度检查，攻击面有限但违反防御性编程原则
3. **VULN-SEC-AUTH-003**: 认证可通过配置关闭，属于配置层面问题，生产环境应确保认证开启
4. **VULN-SEC-SESSION-001**: Token 可设置为永不过期，需要与其他漏洞组合才能被利用
5. **VULN-SEC-AUTH-001**: CLI 输出打印完整 Token，攻击面有限但建议掩码处理

这些漏洞的修复优先级低于已确认的 Critical 漏洞，但仍建议安全团队评估其在生产环境中的实际风险。修复方案相对简单，预估总工作量约 9 小时。

---

**报告生成时间**: 2026-04-22T12:00:00Z
**报告版本**: 1.0
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner v1.0