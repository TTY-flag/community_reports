# VULN-DF-008：ASCEND_HOME_PATH控制AIV内核加载路径漏洞

> **合并说明**: 此漏洞与 VULN-SEC-BIN-001 为同一安全问题的不同发现点。
> 
> 详细分析请参考: **[VULN-SEC-BIN-001.md](./VULN-SEC-BIN-001.md)**

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-008 |
| **关联漏洞** | VULN-SEC-BIN-001 |
| **CWE** | CWE-426: Untrusted Search Path |
| **严重性** | High |
| **置信度** | 85 |

## 代码位置

**文件**: `src/ops/op_common/template/aiv/hccl_aiv_utils.cc`
**行号**: 145-156
**函数**: `GetAivOpBinaryPath()`

```cpp
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
if (getPath != nullptr) {
    libPath = getPath;
} else {
    libPath = "/usr/local/Ascend/cann";
}
binaryPath = libPath + "/lib64" + "/" + aivBinaryName;
```

## 关键发现

此漏洞点在 DataFlow 分析中独立发现，与 VULN-SEC-BIN-001 安全审计发现相同。两者指向同一代码位置的相同安全问题。

完整利用分析和修复建议请参阅主报告。