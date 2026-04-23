# ASC-Tools 威胁分析报告

## 项目概述

| 属性 | 值 |
|------|-----|
| 项目名称 | asc-tools |
| 语言组成 | C++ (80文件) + C (40文件) + Python (50文件) |
| 项目类型 | Ascend C 工具集 - CPU调试库、打包脚本、ELF解析工具 |
| 分析时间 | 2026-04-22 |

---

## 1. 攻击面分析

### 1.1 入口点类型分布

| 类型 | 数量 | 风险等级 |
|------|------|----------|
| CLI工具 | 14 | 高 |
| 库API | 6 | 高 |
| 文件输入 | 7种 | 中 |

### 1.2 主要入口点

#### Python CLI 工具
1. **package.py** - 打包工具，接收XML配置和多种CLI参数
2. **msobjdump_main.py** - ELF dump/提取工具
3. **dump_parser.py** - 调试数据解析器
4. **ascendc_npuchk_report.py** - NPU检查报告生成器
5. **ascendc_compile_kernel.py** - 内核编译工具
6. **install_dep_tar.py** - 依赖下载器

#### C/C++ 库API
1. **aclrtBinaryLoadFromData** - 从外部数据加载ELF二进制
2. **RegisterKernelElf** - 内核ELF注册
3. **StubInit** - Stub初始化（使用dlsym）
4. **aclrtMalloc/aclrtFree** - 内存分配/释放

#### 文件输入类型
- ELF文件 (.o, .a, .bin)
- Dump二进制文件 (*.bin)
- 日志文件 (*_npuchk.log)
- XML配置文件 (*.xml)
- INI配置文件 (*.ini)
- JSON文件 (*.json)
- CSV文件 (limit.csv)

---

## 2. 高风险模块分析

### 2.1 cpudebug 模块 (风险等级: 高)

**描述**: AscendC内核调试和模拟框架

**风险点**:
| 风险类型 | 文件 | 函数 | 描述 |
|----------|------|------|------|
| ELF解析 | kernel_elf_parser.h | RegisterKernelElf | 外部ELF二进制解析，缺乏完整性验证 |
| 动态加载 | stub_reg.cpp | StubInit | dlsym动态符号查找，RTLD_DEFAULT可能暴露全局符号 |
| 内存操作 | ascendc_acl_stub.cpp | aclrtMalloc/aclrtFree | 全局内存分配释放 |
| 二进制加载 | ascendc_acl_stub.cpp | aclrtBinaryLoadFromData | 从外部缓冲加载ELF，可被恶意利用 |

**数据流**:
```
外部二进制数据 → aclrtBinaryLoadFromData → RegisterKernelElf → 
ParseElfHeader → ParseKernelSections → KernelModeRegister
```

### 2.2 scripts/package 模块 (风险等级: 高)

**描述**: 打包构建和部署脚本

**风险点**:
| 风险类型 | 文件 | 行号 | 描述 |
|----------|------|------|------|
| 命令注入 | packer.py | 213 | `subprocess.run(cmd, shell=True)` - shell命令执行 |
| 文件操作 | package.py | 166-199 | 软链接创建、rm -f执行 |
| 权限修改 | package.py | 138-163 | chmod递归修改 |
| XML解析 | pkg_parser.py | 多处 | XML配置解析 |

**命令注入风险**:
```python
# packer.py:213
cmd = f'cd {delivery_dir} && {pack_cmd}'
result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```
- `delivery_dir` 和 `pack_cmd` 来自配置解析
- shell=True允许shell元字符解释
- 可能的攻击路径: 恶意XML配置 → 构造命令 → 命令注入

### 2.3 show_kernel_debug_data 模块 (风险等级: 高)

**描述**: 内核调试数据解析器

**风险点**:
| 风险类型 | 文件 | 行号 | 描述 |
|----------|------|------|------|
| 命令注入 | dump_parser.py | 875 | `subprocess.run(cmd, shell=True)` 执行msaccucmp.py |
| 二进制解析 | dump_parser.py | 70-73 | TLV结构解析，无长度验证 |
| 文件路径 | dump_parser.py | 1181 | 用户提供的文件路径直接使用 |

**高风险代码**:
```python
# dump_parser.py:875
cmd = f"python3 {msaccucmp_file} convert -d {dump_bin} -t bin -out {temp_dir}"
process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, shell=True, ...)
```

### 2.4 ascendc_compile_kernel 模块 (风险等级: 高)

**描述**: 内核编译工具

**风险点**:
| 风险类型 | 文件 | 行号 | 描述 |
|----------|------|------|------|
| 命令执行 | ascendc_compile_kernel.py | 161 | `os.system(cmd_str.format(...))` |
| 格式化字符串 | 多处 | | 参数直接格式化到shell命令 |

**高风险代码**:
```python
# ascendc_compile_kernel.py:161
cmd_str = ('export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH={} && make -f {} PY={} OUT={} CPP={}')
os.system(cmd_str.format(self.build_opp_path, mkfile, self.op_impl_py, op_bin_dir, self.op_cpp_file))
```

### 2.5 msobjdump 模块 (风险等级: 中)

**描述**: MSOBJ dump工具，解析Ascend C ELF文件

**风险点**:
| 风险类型 | 文件 | 行号 | 描述 |
|----------|------|------|------|
| 子进程执行 | utils.py | 47-67 | readelf, llvm-objcopy, ar执行 |
| 二进制解析 | msobjdump_main.py | 655-662 | mmap读取二进制内容 |
| 文件路径 | 多处 | | 用户提供的文件路径 |

### 2.6 npuchk 模块 (风险等级: 中)

**描述**: NPU检查错误报告生成器

**风险点**:
| 风险类型 | 文件 | 行号 | 描述 |
|----------|------|------|------|
| 子进程执行 | ascendc_npuchk_report.py | 74-85 | addr2line, c++filt执行 |
| 文件解析 | ascendc_npuchk_report.py | 33-70 | 日志文件解析 |
| 路径拼接 | ascendc_npuchk_report.py | 166 | cpu_bin_path与文件名拼接 |

### 2.7 install_dep_tar 模块 (风险等级: 中)

**描述**: 依赖下载器

**风险点**:
| 风险类型 | 文件 | 行号 | 描述 |
|----------|------|------|------|
| URL下载 | install_dep_tar.py | 31 | `urllib.request.urlretrieve` 无验证下载 |
| 文件写入 | install_dep_tar.py | 28 | 下载文件直接写入目标目录 |

---

## 3. 敏感操作分析

### 3.1 命令执行/注入

| 位置 | 代码模式 | 风险 |
|------|----------|------|
| packer.py:213 | `subprocess.run(cmd, shell=True)` | **高危** - shell注入 |
| dump_parser.py:875 | `subprocess.run(cmd, shell=True)` | **高危** - shell注入 |
| ascendc_compile_kernel.py:161 | `os.system(cmd_str.format(...))` | **高危** - 格式化注入 |
| package.py:151,181 | `subprocess.run(['chmod', '-R', ...])` | 中危 - 参数验证不足 |
| utils.py:47-67 | `subprocess.run(['readelf', ...])` | 低危 - 参数化执行 |

### 3.2 二进制解析

| 位置 | 解析类型 | 验证状态 |
|------|----------|----------|
| kernel_elf_parser.h | ELF header/section | 部分 - 长度检查 |
| kernel_elf_parser.h | TLV structure | 部分 - 类型/长度检查 |
| dump_parser.py | TLV/Block/DumpTensor | 部分 - magic number验证 |
| msobjdump_main.py | ELF sections | 无 - 直接mmap |

### 3.3 动态加载

| 位置 | 函数 | 风险 |
|------|------|------|
| stub_reg.cpp:62 | `dlsym(RTLD_DEFAULT, buf)` | **高危** - 全局符号查找 |
| stub_reg.cpp:48 | `open("stub_reg.log", ...)` | 低危 - 固定路径日志 |

### 3.4 文件操作

| 操作类型 | 模块 | 验证 |
|----------|------|------|
| 文件读取 | 所有模块 | 多数无路径验证 |
| 文件写入 | dump_parser.py, package.py | 权限设置(mode 640) |
| 目录创建 | 多处 | 存在性检查 |
| 软链接创建 | package.py:166-199 | 存在性检查 |
| chmod修改 | package.py:138-163 | 无权限边界检查 |

---

## 4. 数据流分析

### 4.1 外部输入到命令执行

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  XML配置文件     │ ──→ │  pkg_parser.py  │ ──→ │  package.py     │
│  CLI参数         │     │  parse_xml_config│    │  main()         │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ↓
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  delivery_dir   │ ──→ │  compose_cmd    │ ──→ │  packer.py      │
│  package_attr   │     │                 │     │  exec_pack_cmd  │
└─────────────────┘     └─────────────────┘     │  shell=True ★   │
                                                └─────────────────┘
```

### 4.2 ELF二进制加载

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  外部二进制数据   │ ──→ │ aclrtBinaryLoad │ ──→ │ RegisterKernelElf│
│  (uint8_t* data)│     │ FromData        │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ↓
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ ParseElfHeader  │ ──→ │ GetSectionHeader│ ──→ │ ParseKernelSections│
│ (大小验证)       │     │                 │     │ GetKernelInfo    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## 5. 建议的安全加固措施

### 5.1 命令注入防护 (优先级: 高)

1. **packer.py:213** - 移除shell=True，使用参数化执行:
```python
# 替换为
cmd_list = ['cd', delivery_dir, '&&', *pack_cmd.split()]
subprocess.run(cmd_list, capture_output=True)
```

2. **dump_parser.py:875** - 同样移除shell=True

3. **ascendc_compile_kernel.py:161** - 替换os.system为subprocess.run

### 5.2 二进制解析加固 (优先级: 高)

1. **kernel_elf_parser.h**:
   - 添加ELF magic number验证
   - 验证所有section偏移不超出数据范围
   - 添加最大section数量限制

2. **dump_parser.py**:
   - 添加文件大小上限检查
   - 验证TLV length不超出buffer范围

### 5.3 路径验证 (优先级: 中)

1. 所有用户提供的文件路径应验证:
   - 路径不包含路径遍历字符 (../)
   - 路径在预期目录范围内
   - 使用os.path.realpath()规范化

### 5.4 动态加载加固 (优先级: 中)

1. **stub_reg.cpp**:
   - 使用RTLD_NEXT而非RTLD_DEFAULT
   - 限制查找的符号名称范围

---

## 6. 风险评估总结

| 风险等级 | 数量 | 主要类型 |
|----------|------|----------|
| **高** | 4 | 命令注入、ELF加载、动态加载 |
| **中** | 3 | 子进程执行、二进制解析、路径操作 |
| **低** | 2 | 日志读取、参数化执行 |

### 优先修复项

1. ⚠️ **packer.py exec_pack_cmd** - shell=True命令注入
2. ⚠️ **dump_parser.py _pre_process** - shell=True命令注入  
3. ⚠️ **ascendc_compile_kernel.py os.system** - 格式化命令注入
4. ⚠️ **kernel_elf_parser.h RegisterKernelElf** - ELF解析加固

---

## 附录A: 子进程执行工具列表

| 工具 | 使用位置 | 参数来源 |
|------|----------|----------|
| readelf | utils.py:47-56 | 用户提供的文件路径 |
| llvm-objcopy | utils.py:63-67, pack_kernel.py | 用户文件路径 |
| ar | utils.py:59-60 | 用户文件路径 |
| addr2line | npuchk_report.py:88 | 用户提供的地址 |
| c++filt | npuchk_report.py:95 | 函数名 |
| makeself | packer.py | 配置构建 |
| make | compile_kernel.py | 配置构建 |
| chmod | package.py:151 | 配置路径 |
| rm | package.py:179 | 目标路径 |

## 附录B: 文件类型风险矩阵

| 文件类型 | 解析位置 | 验证 | 风险 |
|----------|----------|------|------|
| ELF (.o, .a) | msobjdump, kernel_elf_parser | 部分 | 中 |
| Dump binary (.bin) | dump_parser | magic验证 | 中 |
| XML (.xml) | pkg_parser | 无 | 低 |
| INI (.ini) | opdesc_parser | 无 | 低 |
| JSON (.json) | 多处 | json.load | 低 |
| CSV (.csv) | package.py | csv.reader | 低 |
| Log (.log) | npuchk_report.py | 无 | 低 |

---

*报告生成时间: 2026-04-22*
*分析范围: 全项目代码*
*检测方法: 静态分析 + 数据流追踪*