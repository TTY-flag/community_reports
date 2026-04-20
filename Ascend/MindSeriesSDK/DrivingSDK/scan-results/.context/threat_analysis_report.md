# DrivingSDK 威胁分析报告

## 项目概述

- **项目名称**: DrivingSDK (MindSeries SDK)
- **项目类型**: Python库 + C/C++扩展
- **语言组成**: C/C++ 439个文件, Python 237个文件
- **代码规模**: 126,032 行
- **扫描模式**: 自主分析模式（无 threat.md 约束）

## 部署模型

本库作为 PyTorch 扩展模块，通过 pip 安装后使用。典型部署场景：
- 开发者导入 mx_driving 模块
- 调用 NPU 加速算子进行自动驾驶模型训练或推理
- 库包含 C/C++ 算子实现（通过 CMake 编译为 .so）和 Python API 封装

## 信任边界分析

| 边界 | 信任侧 | 非信任侧 | 风险等级 |
|------|--------|----------|----------|
| API Input | 应用代码（开发者控制） | 外部输入数据（模型文件、训练数据） | Medium |
| File System | 库安装路径 | 用户提供的文件路径（torch.load paths） | High |
| Dynamic Library Loading | 系统库路径 | LD_LIBRARY_PATH（可被操控） | Medium |
| Monkey Patching | 原实现（mmcv, mmdet, torch） | Patcher 替换代码 | Low |

## 高风险文件 (Top 10)

| 优先级 | 文件 | 语言 | 风险等级 | 原因 |
|--------|------|------|----------|------|
| 1 | mx_driving/patcher/patch.py | Python | High | eval() 表达式求值，潜在代码注入 |
| 2 | mx_driving/patcher/patcher.py | Python | Medium | 动态模块导入，Monkey Patching 框架 |
| 3 | tests/torch/data_cache.py | Python | High | torch.load() 无 weights_only=True，pickle 反序列化风险 |
| 4 | mx_driving/get_chip_info.py | Python | Medium | 从 LD_LIBRARY_PATH 加载共享库 |
| 5 | model_examples/DriverAgent/data.py | Python | High | torch.load() 加载 .pt 文件，pickle 反序列化风险 |
| 6 | model_examples/DriverAgent/train.py | Python | High | torch.load()/torch.save()，反序列化风险 |
| 7 | setup.py | Python | Medium | subprocess.check_call() 执行 cmake/git 命令 |
| 8 | cmake/util/ascendc_impl_build.py | Python | Medium | ctypes.CDLL() 加载共享库 |
| 9 | ci/access_control_test.py | Python | Medium | subprocess.Popen() 执行命令 |
| 10 | mx_driving/__init__.py | Python | Low | 修改 ASCEND_CUSTOM_OPP_PATH 环境变量 |

## 攻击面分析

### 1. Python API 输入验证
- **位置**: mx_driving/ops/sparse_functional.py, voxelization.py
- **风险**: Tensor 形状/类型验证不完整
- **影响**: 可能导致 NPU 算子崩溃或内存错误

### 2. 文件加载
- **位置**: model_examples/DriverAgent/data.py, tests/torch/data_cache.py
- **风险**: torch.load() 使用 pickle 反序列化，无 weights_only=True
- **影响**: 加载恶意 .pt 文件可能导致任意代码执行

### 3. 环境变量
- **位置**: mx_driving/get_chip_info.py, mx_driving/__init__.py
- **风险**: LD_LIBRARY_PATH 和 ASCEND_CUSTOM_OPP_PATH 可被操控
- **影响**: 可能加载恶意共享库

### 4. Monkey Patching
- **位置**: mx_driving/patcher/patcher.py, patch.py
- **风险**: 动态替换第三方库实现
- **影响**: Patch 定义不当可能破坏安全假设

### 5. Decorator 表达式求值
- **位置**: mx_driving/patcher/patch.py (line 790)
- **风险**: eval() 用于 decorator 表达式解析
- **影响**: 开发者创建恶意 patch 定义可能导致代码注入

### 6. C 扩展绑定
- **位置**: mx_driving/csrc/pybind.cpp
- **风险**: C++ 算子直接暴露给 Python 无验证
- **影响**: 输入验证依赖 Python 端，可能遗漏

### 7. 模型检查点加载
- **位置**: model_examples/DriverAgent/train.py
- **风险**: torch.load() 加载预训练权重
- **影响**: CLI 参数控制路径，可能加载恶意检查点

## 模块分布

| 模块 | 语言 | 组件数 | 风险评估 |
|------|------|--------|----------|
| kernels | C/C++ | 65 | 低（NPU算子实现） |
| mx_driving_ops | Python | 22 | 中（API 封装） |
| mx_driving_csrc | C/C++ | 27 | 低（Pybind 绑定） |
| mx_driving_patcher | Python | 13 | 高（动态替换） |
| mx_driving_modules | Python | 5 | 低（模块封装） |
| mx_driving_dataset | Python | 2 | 低（数据加载） |
| model_examples | Mixed | 61 | 高（示例代码含 torch.load） |
| tests | Mixed | 3 | 中（测试含 torch.load） |

## 建议扫描重点

1. **pickle 反序列化**: 检查所有 torch.load() 调用
2. **eval/exec 使用**: 检查 patch.py 中的动态代码执行
3. **动态库加载**: 检查 ctypes.CDLL() 和 LD_LIBRARY_PATH 使用
4. **输入验证**: 检查 C/C++ 算子的输入边界检查
5. **环境变量**: 检查 ASCEND_CUSTOM_OPP_PATH 和 LD_LIBRARY_PATH 使用