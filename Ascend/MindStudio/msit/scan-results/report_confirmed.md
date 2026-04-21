# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio Inference Tools (msIT)
**扫描时间**: 2026-04-21T01:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 10 | 62.5% |
| POSSIBLE | 4 | 25.0% |
| LIKELY | 2 | 12.5% |
| **总计** | **16** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 10 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@msit/components/__main__.py` | cmdline | untrusted_local | CLI 入口点，通过 argparse 解析命令行参数，用户可以控制 --model_path、--output_path 等参数，这些参数直接影响文件读写操作 | msit 工具的主入口点，处理 debug、benchmark、analyze、convert 等子命令 |
| `main@msmodelslim/msmodelslim/cli/__main__.py` | cmdline | untrusted_local | CLI 入口点，用户通过 --model_path 和 --save_path 参数指定模型文件路径，直接影响模型加载和输出操作 | msmodelslim 工具的主入口点，处理 quant、analyze、tune 等子命令 |
| `main@msprechecker/msprechecker/cli.py` | cmdline | untrusted_local | CLI 入口点，用户可以控制预检参数和配置文件路径 | msprechecker 工具的主入口点，处理 precheck、dump、compare 等子命令 |
| `main@msserviceprofiler/msserviceprofiler/__main__.py` | cmdline | untrusted_local | CLI 入口点，用户可以控制分析参数和配置路径 | msserviceprofiler 工具的主入口点，处理 compare、split、analyze 等子命令 |
| `_run_cmd@msmodelslim/msmodelslim/utils/security/shell.py` | rpc | semi_trusted | 执行外部命令的内部函数，虽然参数经过验证，但如果验证存在缺陷可能导致命令注入 | ShellRunner 内部方法，执行 subprocess.run 命令 |
| `safe_get@msmodelslim/msmodelslim/utils/security/request.py` | network | semi_trusted | HTTP GET 请求函数，虽然限制了只能访问 localhost 或内网地址，但如果验证逻辑存在绕过可能导致 SSRF | 安全的 HTTP GET 请求函数 |
| `check_network@msprechecker/msprechecker/utils/network.py` | network | semi_trusted | 网络检查功能，可能涉及 socket 连接测试 | 网络连通性检查函数 |
| `main@msmodelslim/msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp` | cmdline | untrusted_local | C++ CLI 入口点，argv 参数直接用于文件路径，需要进行路径验证 | C++ 压缩图工具的主入口点 |

**其他攻击面**:
- 命令行参数: --model_path, --save_path, --output_path 等文件路径参数
- 配置文件: 用户提供的 JSON/YAML 配置文件
- 模型文件: 用户加载的模型文件（可能包含恶意代码）
- 外部命令执行: 通过 subprocess 调用 atc, msprof 等工具
- HTTP 请求: 向 vllm/MindIE 服务发送请求进行性能测试
- Pickle 反序列化: 加载校准数据或模型权重时可能涉及 pickle
- 网络检查: socket 连接测试功能

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
