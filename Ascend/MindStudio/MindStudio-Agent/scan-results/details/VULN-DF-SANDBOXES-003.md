# VULN-DF-SANDBOXES-003 深度利用分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 缺失授权/功能缺失 (Missing Authorization/Implementation) |
| **CWE** | CWE-862: Missing Authorization |
| **严重性** | MEDIUM |
| **置信度** | 90% |
| **影响范围** | 所有使用沙箱配置的场景 |
| **漏洞文件** | `src/msagent/sandboxes/__init__.py:19-28` |

## 漏洞详情

### 技术分析

该漏洞存在于 `sandboxes` 模块中。系统定义了 SandboxType（seatbelt、bubblewrap）和 SandboxConfig 配置结构，但 `sandboxes/__init__.py` 仅从 `deepagents` 重新导出类型，没有实现任何实际的 OS 级沙箱功能。

**漏洞代码位置**:

```python
# src/msagent/sandboxes/__init__.py:19-28
"""Sandbox backends using deepagents."""

from deepagents.backends import LocalShellBackend
from deepagents.backends.protocol import SandboxBackendProtocol

# Re-export deepagents backend types  ← 仅重导出类型
BackendProtocol = SandboxBackendProtocol
SandboxBackend = SandboxBackendProtocol

__all__ = ["LocalShellBackend", "SandboxBackendProtocol", "BackendProtocol", "SandboxBackend"]
```

### 数据流分析

```
SandboxConfig 定义 (configs/sandbox.py)
    ↓
SandboxType.SEATBELT / BUBBLEWRAP 配置
    ↓
Registry.load_sandboxes() 加载配置
    ↓
sandboxes/__init__.py → 仅导出类型，无实现！
    ↓
工具执行时使用 LocalShellBackend（无沙箱）
    ↓
预期沙箱保护不存在
```

### 配置与实现对比

**配置定义存在**:

```python
# src/msagent/configs/sandbox.py
class SandboxType(StrEnum):
    SEATBELT = "seatbelt"      # macOS Seatbelt 沙箱
    BUBBLEWRAP = "bubblewrap"  # Linux Bubblewrap 沙箱

class SandboxConfig(VersionedConfig):
    type: SandboxType = Field(...)
    profile: str | None = Field(default=None)
    readonly_paths: list[str] | None = Field(default=None)
    writable_paths: list[str] | None = Field(default=None)
    network: bool | None = Field(default=True)
    # ...
```

**但实现缺失**:

```python
# src/msagent/sandboxes/__init__.py
# 没有 SeatbeltWrapper 类
# 没有 BubblewrapWrapper 类
# 没有 sandbox_execution 函数
# 仅导出类型定义，无实际功能
```

## 攻击场景

### 场景 1: 安全预期失效

**前提条件**:
1. 用户配置了 sandbox 配置文件
2. 用户相信工具在沙箱中执行
3. 实际上工具无任何隔离

**攻击路径**:
```yaml
# 用户安全配置
agent:
  sandboxes:
    production:
      type: bubblewrap
      readonly_paths: [/etc, /usr]
      writable_paths: [/app/data]
      network: false

# 用户预期：工具只能在 /app/data 写入，无法访问网络

# 实际执行：工具可访问整个文件系统和网络
# 因为 bubblewrap wrapper 未实现
```

### 场景 2: 配置验证缺失

**前提条件**:
1. SandboxType 包含 seatbelt/bubblewrap
2. 配置验证通过
3. 但运行时无对应实现

**攻击路径**:
```python
# 配置验证成功
config = SandboxConfig(
    type=SandboxType.SEATBELT,  # "seatbelt" 是有效值
    profile="strict"
)

# 但运行时查找沙箱实现...
# 没有 SeatbeltWrapper 类
# 没有 bubblewrap 执行代码
# 结果：回退到 LocalShellBackend（无沙箱）
```

### 场景 3: 沙箱配置被忽略

**前提条件**:
1. 多个沙箱配置定义
2. 配置已加载到 Registry
3. 但从未被应用到执行

**攻击路径**:
```python
# Registry 加载沙箱配置
registry.load_sandboxes(config_path)
# sandbox_configs 已加载

# AgentFactory.create() 调用
# sandbox_bindings 被删除 (VULN-DF-SANDBOXES-001)
# 即使有实现，也不会被调用

# 结果：所有沙箱配置被忽略
```

## PoC 构造

### 验证沙箱实现缺失

```python
# test_sandbox_missing.py
import msagent.sandboxes as sandboxes_module
import inspect

# 检查导出内容
print("Exported from sandboxes module:")
print(sandboxes_module.__all__)

# 检查是否有实际实现
members = inspect.getmembers(sandboxes_module)
implementations = [
    name for name, obj in members
    if inspect.isclass(obj) or inspect.isfunction(obj)
]

print(f"\nClasses/Functions found: {implementations}")

# 预期：应有 SeatbeltWrapper, BubblewrapWrapper 等
# 实际：仅有 LocalShellBackend, BackendProtocol（类型）
```

### 配置有效但无功能

```python
# test_config_valid_no_impl.py
from msagent.configs.sandbox import SandboxConfig, SandboxType

# 配置验证成功
try:
    config = SandboxConfig(
        type=SandboxType.BUBBLEWRAP,  # 有效类型
        profile="restricted",
        network=False
    )
    print(f"Config valid: {config}")
except Exception as e:
    print(f"Config invalid: {e}")

# 配置验证通过，但...
# 搜索 bubblewrap wrapper 实现
from msagent.sandboxes import __all__
print(f"Sandbox exports: {__all__}")
# 没有 BubblewrapWrapper！

# 实际执行会回退到无沙箱状态
```

### 模拟用户安全预期失效

```python
# simulate_security_expectation.py
"""模拟用户配置沙箱后的失望"""

# 用户配置文件
config_yaml = """
agent:
  name: secure-agent
  sandboxes:
    main:
      type: bubblewrap
      readonly_paths: [/etc, /usr, /bin]
      writable_paths: [/workspace]
      network: false
"""

# 用户期望：
# 1. 工具无法访问 /home
# 2. 工具无法访问网络
# 3. 工具只能写入 /workspace

# 实际执行：
# LocalShellBackend(inherit_env=True)
# 工具可访问整个文件系统
# 工具可访问网络
# 工具可写入任意位置

print("""
安全预期 vs 实际情况对比：
| 预期 | 实际 |
|------|------|
| 文件系统隔离 | 无隔离 |
| 网络隔离 | 无隔离 |
| 写入限制 | 无限制 |
| 环境变量隔离 | 继承所有 |
""")
```

## 影响评估

### 可能后果

| 食险类型 | 描述 | 严重程度 |
|----------|------|----------|
| **安全预期失效** | 用户误以为有沙箱保护 | 高（心理层面） |
| **配置无效** | 沙箱配置完全无作用 | 高 |
| **合规问题** | 安全承诺无法兑现 | 中 |
| **功能不完整** | 核心功能缺失 | 中 |
| **依赖 deepagents** | 沙箱功能依赖外部库 | 中 |

### 受影响资产

- 用户的安全预期
- 安全审计承诺
- 生产环境部署安全
- 沙箱配置文件（浪费）

### 功能缺失分析

| 功能 | 配置支持 | 实现状态 |
|------|----------|----------|
| Seatbelt 沙箱 | 有配置定义 | ❌ 无实现 |
| Bubblewrap 沙箱 | 有配置定义 | ❌ 无实现 |
| 文件系统隔离 | 有配置字段 | ❌ 无实现 |
| 网络隔离 | 有配置字段 | ❌ 无实现 |
| 环境变量隔离 | 有配置字段 | ❌ 无实现 |

## 修复建议

### 1. 实现 Seatbelt Wrapper

```python
# 建议新增：src/msagent/sandboxes/seatbelt.py
"""macOS Seatbelt sandbox wrapper."""

import subprocess
import sys
from pathlib import Path

class SeatbeltWrapper:
    """Wrap tool execution with macOS Seatbelt sandbox."""
    
    SEATBELT_PATH = "/usr/local/bin/seatbelt"  # 或从配置读取
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.profile = config.profile or "default"
    
    def wrap_command(self, command: list[str]) -> list[str]:
        """Wrap command with Seatbelt sandbox."""
        if sys.platform != "darwin":
            raise RuntimeError("Seatbelt only available on macOS")
        
        # 构建 Seatbelt 命令
        wrapped = [
            self.SEATBELT_PATH,
            "--profile", self.profile,
        ]
        
        # 添加路径限制
        if self.config.readonly_paths:
            for path in self.config.readonly_paths:
                wrapped.extend(["--readonly", path])
        
        if self.config.writable_paths:
            for path in self.config.writable_paths:
                wrapped.extend(["--writable", path])
        
        # 网络限制
        if not self.config.network:
            wrapped.append("--no-network")
        
        # 原始命令
        wrapped.extend(command)
        
        return wrapped
```

### 2. 实现 Bubblewrap Wrapper

```python
# 建议新增：src/msagent/sandboxes/bubblewrap.py
"""Linux Bubblewrap sandbox wrapper."""

import subprocess
import sys
from pathlib import Path

class BubblewrapWrapper:
    """Wrap tool execution with Linux Bubblewrap sandbox."""
    
    BWRAP_PATH = "bwrap"  # bubblewrap 命令
    
    def __init__(self, config: SandboxConfig):
        self.config = config
    
    def wrap_command(self, command: list[str], working_dir: str) -> list[str]:
        """Wrap command with Bubblewrap sandbox."""
        if not sys.platform.startswith("linux"):
            raise RuntimeError("Bubblewrap only available on Linux")
        
        # 构建 bwrap 命令
        wrapped = [self.BWRAP_PATH]
        
        # 文件系统限制
        # 只读挂载系统目录
        wrapped.extend([
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/etc", "/etc",
        ])
        
        # 可写目录
        if self.config.writable_paths:
            for path in self.config.writable_paths:
                wrapped.extend(["--bind", path, path])
        else:
            # 默认仅工作目录可写
            wrapped.extend(["--bind", working_dir, working_dir])
        
        # 设备和进程
        wrapped.extend([
            "--dev", "/dev",
            "--proc", "/proc",
        ])
        
        # 网络限制
        if not self.config.network:
            wrapped.append("--unshare-net")
        
        # 安全选项
        wrapped.extend([
            "--die-with-parent",  # 父进程退出时终止
            "--new-session",      # 新会话
        ])
        
        # 原始命令
        wrapped.extend(command)
        
        return wrapped
```

### 3. 更新 sandboxes/__init__.py

```python
# 建议修改：src/msagent/sandboxes/__init__.py
"""Sandbox backends with OS-specific implementations."""

from deepagents.backends import LocalShellBackend
from deepagents.backends.protocol import SandboxBackendProtocol

# 导入实际实现
from msagent.sandboxes.seatbelt import SeatbeltWrapper
from msagent.sandboxes.bubblewrap import BubblewrapWrapper

# 工厂函数：根据配置创建沙箱
def create_sandbox_wrapper(config: SandboxConfig) -> SeatbeltWrapper | BubblewrapWrapper | None:
    """Create sandbox wrapper based on configuration."""
    if config.type == SandboxType.SEATBELT:
        return SeatbeltWrapper(config)
    elif config.type == SandboxType.BUBBLEWRAP:
        return BubblewrapWrapper(config)
    else:
        return None  # 无沙箱

# 导出
BackendProtocol = SandboxBackendProtocol
SandboxBackend = SandboxBackendProtocol

__all__ = [
    "LocalShellBackend",
    "SandboxBackendProtocol",
    "BackendProtocol",
    "SandboxBackend",
    "SeatbeltWrapper",
    "BubblewrapWrapper",
    "create_sandbox_wrapper",
]
```

### 4. 验证沙箱可用性

```python
# 建议新增：沙箱可用性检查
def check_sandbox_available(sandbox_type: SandboxType) -> bool:
    """Check if sandbox tool is available on system."""
    if sandbox_type == SandboxType.SEATBELT:
        return sys.platform == "darwin" and Path("/usr/local/bin/seatbelt").exists()
    elif sandbox_type == SandboxType.BUBBLEWRAP:
        return sys.platform.startswith("linux") and subprocess.run(
            ["which", "bwrap"], capture_output=True
        ).returncode == 0
    return False

def validate_sandbox_config(config: SandboxConfig) -> None:
    """Validate that sandbox is actually available."""
    if not check_sandbox_available(config.type):
        raise ValueError(
            f"Sandbox type '{config.type}' is not available on this system. "
            f"Platform: {sys.platform}"
        )
```

### 5. 配置加载时警告

```python
# 建议在配置加载时添加警告
def load_sandboxes(self, config_path: Path) -> BatchSandboxConfig:
    config = BatchSandboxConfig.from_yaml(config_path)
    
    for name, sandbox in config.sandboxes.items():
        if not check_sandbox_available(sandbox.type):
            logger.warning(
                f"⚠️ Sandbox '{name}' configured with type '{sandbox.type}', "
                f"but this sandbox is not available on the current platform ({sys.platform}). "
                f"Tools will run without sandbox isolation."
            )
    
    return config
```

## 相关代码

### 当前 sandboxes 模块（仅导出）

```python
# src/msagent/sandboxes/__init__.py (当前状态)
"""Sandbox backends using deepagents."""

from deepagents.backends import LocalShellBackend
from deepagents.backends.protocol import SandboxBackendProtocol

# Re-export deepagents backend types
BackendProtocol = SandboxBackendProtocol
SandboxBackend = SandboxBackendProtocol

__all__ = ["LocalShellBackend", "SandboxBackendProtocol", "BackendProtocol", "SandboxBackend"]
```

### SandboxType 定义（存在）

```python
# src/msagent/configs/sandbox.py
class SandboxType(StrEnum):
    """Sandbox types supported by the system."""
    SEATBELT = "seatbelt"
    BUBBLEWRAP = "bubblewrap"
```

### SandboxConfig 定义（存在）

```python
# src/msagent/configs/sandbox.py (配置结构存在)
class SandboxConfig(VersionedConfig):
    type: SandboxType = Field(...)
    profile: str | None = Field(default=None)
    readonly_paths: list[str] | None = Field(default=None)
    writable_paths: list[str] | None = Field(default=None)
    network: bool | None = Field(default=True)
    # ... 其他字段

class BatchSandboxConfig(BaseModel):
    sandboxes: dict[str, SandboxConfig] = Field(...)
```

## 参考资料

- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [Bubblewrap GitHub](https://github.com/containers/bubblewrap)
- [Seatbelt (macOS Sandbox)](https://developer.apple.com/documentation/security/app_sandbox)
- [Process Isolation](https://en.wikipedia.org/wiki/Process_isolation)

## 结论

该漏洞是功能缺失问题：沙箱类型和配置结构已定义，但实际的 OS 级沙箱实现完全缺失。用户配置的沙箱设置无法生效，工具仍将在无隔离环境下执行。

**严重性评估**: MEDIUM

**关键风险点**:
1. SandboxType 定义存在但无实现
2. 配置验证通过但运行时无功能
3. 用户安全预期与实际不符
4. sandboxes 模块仅导出类型

**建议优先级**: 中等优先级修复

**修复方向**:
- 实现 SeatbeltWrapper（macOS）
- 实现 BubblewrapWrapper（Linux）
- 更新 sandboxes/__init__.py 导出实现
- 添加沙箱可用性检查

**相关漏洞**: 与 VULN-DF-SANDBOXES-001（沙箱配置未应用）相关，两者共同导致沙箱功能完全失效。