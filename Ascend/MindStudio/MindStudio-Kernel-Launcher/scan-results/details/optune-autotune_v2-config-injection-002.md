# 漏洞合并说明

## 合并状态

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | optune-autotune_v2-config-injection-002 |
| **漏洞类型** | Code Injection (CWE-94) |
| **严重程度** | High |
| **置信度** | 95% |
| **合并到** | cross-module-configs-to-command-exec |
| **关联漏洞** | 6c40d5f31c11 (compile_executable 命令执行) |

## 合并原因

`autotune_v2` 装饰器与 `autotune` 装饰器共享**完全相同的代码注入核心机制**，仅是同一漏洞的不同入口点。

---

## 漏洞位置对比

| 漏洞 ID | 装饰器 | 文件位置 | 编译函数 | 输出类型 |
|---------|--------|----------|----------|----------|
| cross-module-configs-to-command-exec | @autotune | tuner.py:251-279 | compile() | .so 共享库 |
| optune-autotune_v2-config-injection-002 | @autotune_v2 | tuner.py:557-578 | compile_executable() | .bin 可执行文件 |

---

## 核心共享机制分析

### 1. 共享验证缺陷

两者都调用 `check_configs()` 函数：

```python
# autotune_utils.py:34-36
def check_autotune_v2_params(configs, warmup_times):
    check_configs(configs)  # ← 与 autotune 使用相同验证函数
    check_warmup_times(warmup_times)

# autotune_utils.py:39-49
def check_configs(configs):
    ...
    for key, val in config.items():
        if not key or not isinstance(key, str):  # 仅检查类型
            raise ValueError(...)
        if not val or not isinstance(val, str):    # 仅检查类型
            raise ValueError(...)
    # 【关键缺陷】未验证字符串内容，可注入任意 C++ 代码
```

### 2. 共享注入核心

两者都使用 `kernel_modifier.py` 的 `_replace_param()` 方法：

**autotune 路径**:
```
tuner.py:189 → Replacer.replace_config(node, output_file_path)
    ↓
kernel_modifier.py:93-97 → self._replace_param(key, value, lines)
    ↓
kernel_modifier.py:63-91 → val 直接拼接到 C++ 源代码行
```

**autotune_v2 路径**:
```
tuner.py:432 → Replacer.replace_src_with_config(src_file, new_src_file, configs[index])
    ↓
kernel_modifier.py:30-35 → 遍历 config.items() 调用 _replace_param()
    ↓
kernel_modifier.py:63-91 → val 直接拼接到 C++ 源代码行
```

### 3. 注入点代码（相同）

```python
# kernel_modifier.py:38-50 - 两种替换方式
@staticmethod
def _replace_content_for_alias_name(line_index, line, replacement):
    # replacement = 用户提供的 val，直接拼接！
    index = len(line) - len(line.lstrip())
    new_line = line[:index] + replacement  # ← 注入发生
    ...

@staticmethod
def _replace_content_for_tunable_name(line_index, line, replacement):
    return line[:line.index('=') + 1] + ' ' + replacement + ';\n'  # ← 注入发生
```

---

## autotune_v2 独特调用链

虽然共享核心机制，autotune_v2 有独特的调度器架构：

### 完整调用流程

```
@autotune_v2(configs=[...], warmup_times=5)
    ↓
tuner.py:557-578 autotune_v2() 返回装饰器
    ↓
tuner.py:566-576 wrapper(*args, **kwargs)
    ├─ tuner.py:569 check_autotune_v2_params(configs, warmup_times)
    ├─ tuner.py:570 get_params_from_pre_launch(func, ...)  [prelaunch 模式]
    └─ tuner.py:571 AutotuneV2Scheduler(configs, warmup_times, launch_params)
    ↓
tuner.py:304-330 scheduler.execute()
    ├─ tuner.py:313 compile_pool.apply_async(_compile_task, (i,))
    └─ tuner.py:314 launch_thread = threading.Thread(target=_launch_task)
    ↓
tuner.py:332-343 _compile_task(index)
    ├─ tuner.py:334 new_src_file = gen_src_file(index)
    │   ↓
    │   tuner.py:432 Replacer.replace_src_with_config(src_file, new_src_file, configs[index])
    │   ↓                                           【代码注入发生】
    └─ tuner.py:336 executable = compile(new_src_file)
        ↓
        tuner.py:456-460 AutotunerV2.compile()
            ↓
            compile_executable(build_script, new_src_file, executable_file_path)
                ↓                【关联 6c40d5f31c11 命令执行漏洞】
```

### 与 autotune 的架构差异

| 组件 | autotune | autotune_v2 |
|------|----------|-------------|
| 调度器 | Executor | AutotuneV2Scheduler |
| 调优器 | Autotuner | AutotunerV2 |
| Replacer调用方式 | 实例方法 `replace_config()` | 静态方法 `replace_src_with_config()` |
| 编译函数 | compile() | compile_executable() |
| 输出类型 | CompiledKernel (.so) | CompiledExecutable (.bin) |
| 性能测量 | 自定义时间测量 | msprof op profiling |
| 执行方式 | importlib 加载共享库 | subprocess 执行可执行文件 |

---

## 与 6c40d5f31c11 的关联

autotune_v2 最终调用 `compile_executable()`，因此继承了 compile_executable 的漏洞风险：

| 漏洞类型 | 漏洞 ID | 注入点 | 最终执行 |
|----------|---------|--------|----------|
| 代码注入 | optune-autotune_v2-config-injection-002 | configs → C++ 源代码 | 编译后的恶意可执行文件 |
| 命令执行 | 6c40d5f31c11 | build_script → bash | subprocess.run(['bash', script, ...]) |

**双重攻击路径**:
- 通过 configs 注入恶意 C++ 代码（代码注入）
- 通过 build_script 注入恶意 bash 命令（命令执行）

---

## 攻击示例

### PoC: 通过 autotune_v2 注入恶意代码

```python
from mskl.optune.tuner import autotune_v2

# 恶意配置 - 注入 __attribute__((constructor)) 恶意函数
malicious_configs = [
    {
        "BLOCK_SIZE": "128; __attribute__((constructor)) void exploit() { "
                      "system(\"id > /tmp/pwned_autotune_v2\"); "
                      "} int _dummy = "
    }
]

@autotune_v2(configs=malicious_configs, warmup_times=1)
def my_kernel():
    """编译后的可执行文件在运行时触发 exploit() 函数"""
    from mskl.launcher.compiler import compile_executable
    compile_executable(
        build_script="/path/to/build.sh",
        src_file="/path/to/kernel.cpp",  # 需要 tunable:BLOCK_SIZE 标记
        output_bin_path="/tmp/kernel.bin"
    )

my_kernel()  # 触发攻击
```

---

## 结论

### 不需要独立分析的原因

1. **验证缺陷已覆盖**: `cross-module-configs-to-command-exec.md` 第67-81行详细分析了 `check_configs()` 的局限性
2. **注入机制已覆盖**: 第83-101行分析了 `_replace_param()` 的直接拼接
3. **攻击效果相同**: 两者都可注入任意 C++ 代码，如 `__attribute__((constructor))` 恶意函数
4. **修复方案相同**: 两者需要在同一位置（autotune_utils.py 和 kernel_modifier.py）添加内容验证

### 需要注意的差异

- autotune_v2 编译输出为可执行文件而非共享库
- autotune_v2 关联了 compile_executable 的命令执行漏洞 (6c40d5f31c11)
- prelaunch 模式下的特殊行为（保存 build_script 到 context）

---

## 修复建议

由于共享核心机制，修复方案与 cross-module-configs-to-command-exec 完全相同：

1. **在 `check_configs()` 中添加内容验证**（优先级: P0）
2. **在 `_replace_param()` 中添加安全替换**（优先级: P0）
3. **使用白名单机制验证配置值**（优先级: P1）

完整修复方案请参考：
- **[cross-module-configs-to-command-exec.md](./cross-module-configs-to-command-exec.md)** 第296-430行
- **[6c40d5f31c11.md](./6c40d5f31c11.md)** 第528-643行（针对 compile_executable）

---

## 相关 CWE 参考

- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-20**: Improper Input Validation
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code

---

**报告生成时间**: 2026-04-21
**合并判定**: autotune_v2 是 cross-module-configs-to-command-exec 的补充入口点，核心注入机制完全相同
