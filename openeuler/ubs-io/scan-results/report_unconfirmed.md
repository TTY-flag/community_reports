# 漏洞扫描报告 — 待确认漏洞

**项目**: ubs-io
**扫描时间**: 2026-04-20T12:02:30.045Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 106 | 51.7% |
| LIKELY | 68 | 33.2% |
| CONFIRMED | 23 | 11.2% |
| FALSE_POSITIVE | 8 | 3.9% |
| **总计** | **205** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **172** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[UNDERFS-001]** Path Traversal (HIGH) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio/src/underfs/local_system.cpp:68` @ `Put` | 置信度: 95
2. **[UNDERFS-003]** Path Traversal (HIGH) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio/src/underfs/local_system.cpp:140` @ `Delete` | 置信度: 95
3. **[DISK-004]** Integer Overflow in Allocation (HIGH) - `ubsio-boostio/src/disk/common/bdm_allocator.c:628` @ `BdmAllocatorCreate` | 置信度: 90
4. **[DISK-005]** Integer Overflow in Allocation (HIGH) - `ubsio-boostio/src/disk/common/bdm_allocator.c:643` @ `BdmAllocatorCreate` | 置信度: 90
5. **[SDK-002]** Insecure Dynamic Library Loading (Relative Path) (HIGH) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio/src/sdk/bio_client.cpp:302` @ `BioClientDiagnoseInit` | 置信度: 90
6. **[UNDERFS-002]** Path Traversal (HIGH) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio/src/underfs/local_system.cpp:105` @ `Get` | 置信度: 90
7. **[NET-001]** Integer Truncation (HIGH) - `ubsio-boostio/src/net/net_engine.cpp:189` @ `CreateShmFdWithName` | 置信度: 85
8. **[SEC-003]** Untrusted Search Path (HIGH) - `ubsio-boostio/src/common/bio_tls_util.h:41` @ `LoadDecryptFunction` | 置信度: 85
9. **[CLUSTER-DLOPEN-001]** Library Hijacking (HIGH) - `ubsio-boostio/src/cluster/common/cm_zk_api_dl.c:75` @ `ZookeeperApiLoad` | 置信度: 85
10. **[VULN-INTERCEPTOR-001]** Improper Input Validation (HIGH) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio/src/interceptor/server/interceptor_server.cpp:53` @ `CheckInterceptorReadReq` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `RequestReceived@undefined` | Network RPC | - | - | Handles incoming RPC requests with opCode dispatch |
| `RequestIPCReceived@undefined` | Network IPC | - | - | Handles incoming IPC requests via shared memory |
| `HookOpen/HookRead/HookWrite@undefined` | POSIX Hook | - | - | Intercepts POSIX file operations |
| `HandleInterceptorRead/HandleInterceptorWrite@undefined` | Interceptor Server | - | - | Handles remote file operation requests |
| `Initialize@undefined` | Configuration | - | - | Loads and validates configuration file |
| `CmClientZkInit/CmServerZkInit@undefined` | ZooKeeper | - | - | Initializes ZooKeeper connection and data handling |
| `LoadOpensslApiDl@undefined` | TLS | - | - | Loads OpenSSL libraries and initializes TLS |
| `Init/Get/Put@undefined` | Underlying FS | - | - | Operations on external Ceph storage |


---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cache | 0 | 0 | 0 | 0 | 0 |
| cluster | 0 | 0 | 0 | 0 | 0 |
| common | 0 | 0 | 0 | 0 | 0 |
| config | 0 | 0 | 0 | 0 | 0 |
| cross-module | 0 | 0 | 0 | 0 | 0 |
| daemon | 0 | 0 | 0 | 0 | 0 |
| disk | 0 | 0 | 0 | 0 | 0 |
| flow | 0 | 0 | 0 | 0 | 0 |
| htracer | 0 | 0 | 0 | 0 | 0 |
| interceptor | 0 | 0 | 0 | 0 | 0 |
| io_interceptor | 0 | 0 | 0 | 0 | 0 |
| message | 0 | 0 | 0 | 0 | 0 |
| net | 0 | 0 | 0 | 0 | 0 |
| sdk | 0 | 0 | 0 | 0 | 0 |
| security | 0 | 0 | 0 | 0 | 0 |
| server | 0 | 0 | 0 | 0 | 0 |
| underfs | 0 | 0 | 0 | 0 | 0 |
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 39 | 22.7% |
| CWE-190 | 24 | 14.0% |
| CWE-22 | 20 | 11.6% |
| CWE-426 | 7 | 4.1% |
| CWE-120 | 7 | 4.1% |
| CWE-367 | 6 | 3.5% |
| CWE-200 | 6 | 3.5% |
| CWE-476 | 4 | 2.3% |
| CWE-125 | 4 | 2.3% |
| CWE-732 | 3 | 1.7% |
| CWE-362 | 3 | 1.7% |
| CWE-129 | 3 | 1.7% |
| CWE-789 | 2 | 1.2% |
| CWE-787 | 2 | 1.2% |
| CWE-680 | 2 | 1.2% |
| CWE-416 | 2 | 1.2% |
| CWE-415 | 2 | 1.2% |
| CWE-401 | 2 | 1.2% |
| CWE-400 | 2 | 1.2% |
| CWE-347 | 2 | 1.2% |
| CWE-94 | 1 | 0.6% |
| CWE-908 | 1 | 0.6% |
| CWE-862 | 1 | 0.6% |
| CWE-829 | 1 | 0.6% |
| CWE-754 | 1 | 0.6% |
| CWE-74 | 1 | 0.6% |
| CWE-704 | 1 | 0.6% |
| CWE-676 | 1 | 0.6% |
| CWE-522 | 1 | 0.6% |
| CWE-502 | 1 | 0.6% |
| CWE-479 | 1 | 0.6% |
| CWE-473 | 1 | 0.6% |
| CWE-404 | 1 | 0.6% |
| CWE-306 | 1 | 0.6% |
| CWE-287 | 1 | 0.6% |
| CWE-280 | 1 | 0.6% |
| CWE-276 | 1 | 0.6% |
| CWE-269 | 1 | 0.6% |
| CWE-267 | 1 | 0.6% |
| CWE-252 | 1 | 0.6% |
| CWE-190/CWE-120 | 1 | 0.6% |
| CWE-170 | 1 | 0.6% |
| CWE-158 | 1 | 0.6% |
| CWE-15,CWE-94 | 1 | 0.6% |
| CWE-15 | 1 | 0.6% |
| CWE-128 | 1 | 0.6% |
| CWE-1238 | 1 | 0.6% |
| CWE-119 | 1 | 0.6% |
| CWE-114,CWE-426 | 1 | 0.6% |
| CWE-114 | 1 | 0.6% |
