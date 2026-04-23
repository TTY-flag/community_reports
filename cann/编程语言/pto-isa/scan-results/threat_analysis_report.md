# PTO Tile Library 威胁分析报告

## 项目概述

**项目名称**: PTO Tile Library (pto-isa)
**项目类型**: 高性能计算库（Library）
**目标平台**: 华为 Ascend AI 加速器 (A2/A3/A5), CPU 模拟器
**文件总数**: 569 个（排除测试目录）
**扫描时间**: 2026-04-22

### 项目定位

Parallel Tile Operation (PTO) 是一个虚拟 ISA，为 Ascend CANN 定义了 90+ 标准 tile 指令。该项目：
- 提供统一的跨代 tile 抽象，降低不同 Ascend 代际之间的迁移成本
- 平衡可移植性和性能调优能力
- 服务于上层框架、operator 实现和编译器工具链

### 部署模型

作为 CANN 工具链的一部分，PTO Tile Library：
- 被上层框架（PyPTO、TileLang Ascend）集成使用
- 在本地或 Ascend 服务器上编译和运行
- 不直接暴露给外部用户，作为内部开发工具

---

## 信任边界分析

### 边界 1: Test Script Interface

| 属性 | 值 |
|------|-----|
| 边界名称 | Test Script Interface |
| 可信一侧 | Project Test Scripts (tests/run_cpu.py, tests/run_costmodel.py) |
| 不可信一侧 | Command Line Arguments, Environment Variables |
| 风险等级 | Medium |

**分析**:
- 测试脚本接收用户提供的命令行参数（如 `--testcase`, `--cxx`, `--build-dir`）
- 参数被传递给 `subprocess.run()` 执行 cmake/gtest 命令
- 虽然脚本有内部使用目的，但参数验证不足可能导致命令注入风险

### 边界 2: Network Download Interface

| 属性 | 值 |
|------|-----|
| 边界名称 | Network Download Interface |
| 可信一侧 | Install Scripts (scripts/install_pto.sh) |
| 不可信一侧 | Remote Package Servers, GitHub |
| 风险等级 | High |

**分析**:
- `scripts/install_pto.sh` 使用 `wget --no-check-certificate` 下载软件包
- 禁用 SSL 证书验证可能导致中间人攻击
- `git clone` 从 GitHub 克隆代码，依赖远程代码完整性

### 边界 3: Data File Interface

| 属性 | 值 |
|------|-----|
| 边界名称 | Data File Interface |
| 可信一侧 | CPU/NPU Simulator |
| 不可信一侧 | Test Data Files (numpy binary) |
| 风险等级 | Low |

**分析**:
- 测试数据文件为 numpy 二进制格式
- numpy 数据加载有相对安全的边界检查
- 数据文件由项目内部的 gen_data.py 生成

---

## 入口点分析

### Python 测试脚本入口点

| 入口点 | 文件 | 行号 | 信任等级 | 风险 |
|--------|------|------|----------|------|
| run_command | tests/run_cpu.py | 31 | semi_trusted | Medium |
| run_command | tests/run_costmodel.py | 40 | semi_trusted | Medium |
| parse_arguments | tests/run_cpu.py | 440 | semi_trusted | Medium |

### Shell 安装脚本入口点

| 入口点 | 文件 | 行号 | 信任等级 | 风险 |
|--------|------|------|----------|------|
| download_pto_isa_run | scripts/install_pto.sh | 96 | untrusted_network | High |
| install_gtest | scripts/install_pto.sh | 149 | untrusted_network | High |

---

## STRIDE 威胁建模

### Spoofing (身份伪造)

| 威胁 | 风险 |  mitigating措施 |
|------|------|------------------|
| 远程服务器伪装 - wget 从未验证证书的服务器下载 | High | 启用 SSL 证书验证，使用可信源 |
| GitHub 仓库伪装 - git clone 克隆可能被篡改的仓库 | Medium | 使用官方仓库，验证 commit hash |

### Tampering (数据篡改)

| 威胁 | 风险 | 缓解措施 |
|------|------|----------|
| 网络数据篡改 - wget --no-check-certificate 禁用 TLS | High | 移除 --no-check-certificate 选项 |
| 测试数据篡改 - 测试数据文件可能被外部修改 | Low | 数据由内部生成，限制文件权限 |

### Repudiation (否认)

| 威胁 | 风险 | 缓解措施 |
|------|------|----------|
| 缺乏操作日志 - 安装脚本操作缺乏审计日志 | Low | 增加操作日志记录 |

### Information Disclosure (信息泄露)

| 威胁 | 风险 | 缓解措施 |
|------|------|----------|
| 命令参数泄露 - 日志中可能包含敏感路径信息 | Low | 避免在日志中记录敏感信息 |
| 编译器版本泄露 - 获取编译器版本信息 | Low | 信息非敏感，风险可控 |

### Denial of Service (拒绝服务)

| 威胁 | 风险 | 缓解措施 |
|------|------|----------|
| 网络下载阻塞 - wget/git 操作可能超时 | Medium | 设置合理的超时时间 |
| 编译阻塞 - cmake/make 可能消耗大量资源 | Low | 限制并行编译数 |

### Elevation of Privilege (权限提升)

| 娃胁 | 风险 | 缓解措施 |
|------|------|----------|
| sudo make install - 安装脚本使用 sudo 执行 | High | 避免 sudo，使用用户级安装 |
| 命令注入 - 参数传递给 subprocess.run | Medium | 严格验证输入参数 |

---

## 高风险模块分析

### 1. scripts/install_pto.sh

**风险等级**: High

**问题点**:
1. `wget --no-check-certificate` 禁用 SSL 验证（行 123）
2. `sudo make install` 提升权限（行 164）
3. `git config --global http.sslverify false` 禁用 git SSL 验证（行 150）

**建议修复**:
- 移除 `--no-check-certificate` 选项
- 使用用户级安装而非 sudo
- 保持 git SSL 验证启用

### 2. tests/run_cpu.py

**风险等级**: Medium

**问题点**:
1. `subprocess.run()` 接收外部参数（行 47）
2. 编译器路径从环境变量获取（行 226-227）
3. 命令参数来自 argparse，缺乏严格验证

**建议修复**:
- 验证编译器路径是否在预期目录
- 限制可执行文件白名单（cmake, gtest, 编译器）
- 避免将用户输入直接拼接为命令

### 3. tests/run_costmodel.py

**风险等级**: Medium

**问题点**: 与 run_cpu.py 相同的 subprocess 执行模式

---

## 低风险模块分析

### C++ 核心库 (include/pto/)

**风险等级**: Low

**分析**:
- 纯计算逻辑，无外部输入处理
- 内存操作有边界检查（Shape, Stride 验证）
- 模板元编程确保编译时类型安全

### kernels/manual/

**风险等级**: Low

**分析**:
- 高性能 kernel 实现
- 仅在内部被调用
- 数据来源为上层框架，已通过框架验证

---

## 攻击面总结

| 攻击面 | 描述 | 风险等级 |
|--------|------|----------|
| Command Line Arguments | 测试脚本接收命令行参数 | Medium |
| Network Downloads | wget/git 从网络下载代码和软件包 | High |
| Subprocess Execution | subprocess.run 执行外部命令 | Medium |
| File I/O | numpy 二进制数据文件读写 | Low |
| Environment Variables | 编译器路径从环境变量获取 | Low |

---

## 安全建议

### 立即修复 (High Priority)

1. **移除 SSL 验证禁用选项**
   - 文件: scripts/install_pto.sh
   - 行: 123, 150
   - 操作: 移除 `--no-check-certificate` 和 `http.sslverify false`

2. **避免 sudo 权限提升**
   - 文件: scripts/install_pto.sh
   - 行: 164
   - 操作: 使用用户级安装或明确提示用户确认

### 建议修复 (Medium Priority)

3. **增强 subprocess 参数验证**
   - 文件: tests/run_cpu.py, tests/run_costmodel.py
   - 操作: 限制可执行文件白名单，验证路径合法性

4. **增强编译器路径验证**
   - 文件: tests/run_cpu.py
   - 行: 226-227
   - 操作: 验证编译器路径是否在预期目录

### 建议增强 (Low Priority)

5. **增加操作日志审计**
   - 文件: scripts/install_pto.sh
   - 操作: 记录关键操作到日志文件

---

## 结论

PTO Tile Library 是一个高性能计算库项目，整体安全风险较低。主要风险集中在：

1. **安装脚本的网络下载操作** - 禁用 SSL 验证和 sudo 权限提升是高风险点
2. **测试脚本的 subprocess 执行** - 命令参数缺乏严格验证

核心 C++ 库部分设计良好，采用模板元编程确保类型安全，内存操作有边界检查。

建议优先修复安装脚本中的 SSL 验证和权限提升问题，增强测试脚本的参数验证机制。

---

## 附录：模块分布

| 模块 | 文件数 | 语言 | 风险等级 |
|------|--------|------|----------|
| common | 15 | C++ | Low |
| cpu_simulator | 74 | C++ | Low |
| npu_a2a3 | 106 | C++ | Low |
| npu_a5 | 114 | C++ | Low |
| communication | 15 | C++ | Low |
| costmodel | 6 | C++ | Low |
| kernels_manual | 10+ | C++/混合 | Low |
| test_scripts | 5 | Python | Medium |
| install_scripts | 3 | Python/Shell | High |

---

**报告生成时间**: 2026-04-22
**分析工具**: Architecture Agent (自主分析模式)