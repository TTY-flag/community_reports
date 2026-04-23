# VULN-SEC-GRAPH-001: Cypher查询字符串拼接未过滤用户输入致注入攻击

## Executive Summary

**Vulnerability Status**: CONFIRMED REAL VULNERABILITY

**Severity**: Medium-High (CWE-943: Improper Neutralization of Special Elements in Cypher Query)

**Vulnerability Type**: Cypher Injection

**Affected File**: `mx_rag/graphrag/graphs/opengauss_graph.py`

**Affected Function**: `_find_weakly_connected_components` (lines 904-930)

**Critical Code Location**: lines 919-923

---

## 1. Vulnerability Details

### 1.1 Vulnerable Code

```python
# File: mx_rag/graphrag/graphs/opengauss_graph.py
# Lines: 904-930 (specifically 919-923)

def _find_weakly_connected_components(self) -> List[Set[str]]:
    """
    Find all weakly connected components in the graph using Cypher queries.
    """
    all_nodes = list(dict.fromkeys(self.get_nodes(with_data=False)))
    visited = set()
    components = []

    for node in all_nodes:
        if node in visited:
            continue
        # VULNERABLE QUERY - node value directly embedded without sanitization
        query = (
            f"MATCH (start:Node {{id: \"{node}\"}}) "  # <-- INJECTION POINT
            f"MATCH p = (start)-[*]-(n) "
            f"RETURN DISTINCT n.text AS label"
        )
        result = self.graph_adapter.execute_cypher_query(query)
        ...
```

### 1.2 Root Cause Analysis

The vulnerability stems from **two compounding issues**:

1. **Injection Vector**: The `node` value is directly embedded into the Cypher query string using f-string interpolation without any sanitization via `cypher_value()` function.

2. **Logic Bug**: The query attempts to match by `{id: "{node}"}`, but:
   - `get_nodes(with_data=False)` returns `n.text` values (raw user document content)
   - The `id` field stores SHA256 hashes, NOT the text values
   - This mismatch creates an inconsistent query pattern

### 1.3 Comparison with Secure Code Patterns

The project has a proper sanitization function `cypher_value()` defined in `graph_util.py`:

```python
# Secure pattern used elsewhere in the same file (CypherQueryBuilder):
def match_node(label: str) -> str:
    return f"MATCH (n:Node {{id: {cypher_value(label)}}}) RETURN n LIMIT 1"

# Vulnerable pattern in _find_weakly_connected_components:
f"MATCH (start:Node {{id: \"{node}\"}})"  # Missing cypher_value()!
```

The `cypher_value()` function properly escapes:
- Single quotes: `'` → `\'`
- Backslashes: `\` → `\\`
- Parentheses: `(` → `\\(`, `)` → `\\)`

---

## 2. Complete Attack Path

### 2.1 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACK DATA FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────┘

[ATTACKER] uploads malicious document
    │
    ▼
┌──────────────────────────────────────────┐
│ GraphRAGPipeline.upload_files()          │
│ File: graphrag_pipeline.py:133           │
│ Input: file_list (user-uploaded files)   │
│ Check: SecFileCheck.check() - size/owner │
│ Note: NO content validation              │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ loader.load_and_split()                  │
│ Output: Document objects                 │
│ Content: page_content = raw file content │
│ Metadata: source = file path             │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ self.docs.extend(docs)                   │
│ Stores Document objects for processing   │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ GraphRAGPipeline.build_graph()           │
│ File: graphrag_pipeline.py:164           │
│ Condition: conceptualize=True required   │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ LLMRelationExtractor.query(docs)         │
│ File: relation_extraction.py:207         │
│ Output: List[dict] with raw_text field   │
│ raw_text = doc.page_content              │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ GraphMerger.merge(relations)             │
│ File: graph_merger.py:320                │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ merge_relations_into_graph()             │
│ File: graph_merger.py:270                │
│ graph.add_node(raw_text)                 │
│ ──────────────────────────────────────── │
│ OpenGaussGraph.add_node():               │
│   text: node (RAW USER CONTENT)          │
│   id: hashlib.sha256(node)               │
│ ★ MALICIOUS TEXT STORED IN DATABASE ★    │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ ConceptCluster.find_clusters()           │
│ File: concept_clustering.py:69           │
│ Call: graph.connected_components()       │
│ Triggered when: conceptualize=True       │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ OpenGaussGraph.connected_components()    │
│ File: opengauss_graph.py:692             │
│ Call: _find_weakly_connected_components()│
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ get_nodes(with_data=False)               │
│ Query: "MATCH (n:Node) RETURN n.text"    │
│ Returns: [n.text values] = user content  │
│ ★ MALICIOUS TEXT RETRIEVED ★             │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ _find_weakly_connected_components()      │
│ File: opengauss_graph.py:919-923         │
│ ★★★ INJECTION POINT ★★★                  │
│                                           │
│ query = f"MATCH (start:Node              │
│           {{id: \"{node}\"}})..."        │
│                                           │
│ node = malicious content                  │
│ NO cypher_value() sanitization            │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│ execute_cypher_query(query)              │
│ Cypher query sent to database            │
│ ★ ARBITRARY CYPHER EXECUTION ★           │
└──────────────────────────────────────────┘
```

### 2.2 Trigger Conditions

| Condition | Requirement | Default Value |
|-----------|-------------|---------------|
| Graph Type | `graph_type="opengauss"` | `"networkx"` |
| Conceptualize | `conceptualize=True` | `False` |
| User Upload | User can upload documents | N/A |
| Database | openGauss AGE graph connected | N/A |

**Attack Scenario**: An attacker who has legitimate access to upload documents to the GraphRAG system can exploit this vulnerability when:
1. The system is configured with `graph_type="opengauss"`
2. The system enables `conceptualize=True` for concept clustering
3. The attacker uploads a crafted document containing Cypher injection payload

---

## 3. PoC Construction Method

### 3.1 Basic Injection Payload

The malicious document content should contain characters that break the query structure:

```python
# Example malicious document content:
malicious_content = """
实体1 relates to 实体2.

This document contains a test node: "test\"}) RETURN 1 UNION MATCH (n) DELETE n //
"""
```

### 3.2 Injection Effect Analysis

When this content is processed:

**Original Query Intention**:
```cypher
MATCH (start:Node {id: "normal_text"}) MATCH p = (start)-[*]-(n) RETURN DISTINCT n.text AS label
```

**Injected Query** (if node contains `"test\"}) RETURN 1...`):
```cypher
MATCH (start:Node {id: "test"}) RETURN 1 UNION MATCH (n) DELETE n //"}) MATCH p = (start)-[*]-(n) RETURN DISTINCT n.text AS label
```

### 3.3 Key Injection Characters

| Character | Effect | Example |
|-----------|--------|---------|
| `"` | Closes string literal prematurely | `"test\"" → breaks at second quote |
| `\` | Escape character | `"test\\"` → escaped quote |
| `}` | Closes object literal | `{id: "test"}` → `{id: "test` + `}` |
| `UNION` | Query concatenation (if supported) | `... UNION MATCH ...` |

### 3.4 Potential Exploit Outcomes

1. **Denial of Service**: Query syntax errors crash the conceptualization process
2. **Data Exfiltration**: UNION-based injection to retrieve arbitrary node/edge data
3. **Data Deletion**: Injected `DELETE` or `DETACH DELETE` commands
4. **Data Modification**: Injected `SET` or `CREATE` commands

---

## 4. Impact Assessment

### 4.1 Affected Components

| Component | Impact Level | Description |
|-----------|-------------|-------------|
| OpenGauss AGE Graph Database | HIGH | Direct Cypher query execution |
| Knowledge Graph Integrity | HIGH | Potential data manipulation/deletion |
| Concept Clustering | MEDIUM | Process failure, incorrect results |
| GraphRAG Pipeline | MEDIUM | Availability impact when crash occurs |

### 4.2 Risk Matrix

| Dimension | Assessment | Justification |
|-----------|------------|---------------|
| **Exploitability** | Medium | Requires specific configuration (conceptualize=True, opengauss), but injection is straightforward |
| **Impact** | High | Direct database access, potential data manipulation |
| **Scope** | Medium | Affects conceptualization phase, not core retrieval |
| **Privilege Required** | Low | User-level document upload access |
| **User Interaction** | None | No additional interaction needed after upload |

### 4.3 Combined Logic Bug Impact

The logic bug (using text to match by hash) has additional security implications:
- The vulnerability might be overlooked during testing because the query "doesn't work anyway"
- This could delay vulnerability discovery
- However, the injection risk remains regardless of functional correctness

---

## 5. Exploit Conditions

### 5.1 Required Permissions

- Document upload access to GraphRAGPipeline
- No elevated privileges required
- Same user level as normal RAG operations

### 5.2 Environment Requirements

```python
# Required configuration:
pipeline = GraphRAGPipeline(
    work_dir="/path/to/work",
    llm=llm,
    embedding_model=embeddings,
    dim=768,
    graph_type="opengauss",  # REQUIRED
    conceptualize=True,      # REQUIRED (trigger)
    age_graph=opengauss_age_graph  # REQUIRED for opengauss
)

# Attack flow:
pipeline.upload_files(["malicious_document.txt"], loader_mng)
pipeline.build_graph(lang=Lang.EN)  # Triggers connected_components
```

### 5.3 Attack Feasibility

| Scenario | Feasible | Notes |
|----------|----------|-------|
| Document upload allowed | YES | Standard GraphRAG operation |
| conceptualize=True configured | PARTIAL | Default is False, but legitimate feature |
| OpenGauss backend | PARTIAL | Alternative is NetworkX (no injection risk) |
| Payload survives LLM extraction | PARTIAL | Depends on LLM behavior, but raw_text preserved |

---

## 6. Mitigation Recommendations

### 6.1 Primary Fix

Replace the vulnerable code with proper sanitization:

```python
# BEFORE (vulnerable):
query = (
    f"MATCH (start:Node {{id: \"{node}\"}}) "
    f"MATCH p = (start)-[*]-(n) "
    f"RETURN DISTINCT n.text AS label"
)

# AFTER (secure):
node_id = hashlib.sha256(node.encode("utf-8")).hexdigest()
query = (
    f"MATCH (start:Node {{id: {cypher_value(node_id)}}}) "
    f"MATCH p = (start)-[*]-(n) "
    f"RETURN DISTINCT n.text AS label"
)
```

### 6.2 Alternative Fix

Use CypherQueryBuilder pattern:

```python
# Create a new CypherQueryBuilder method:
@staticmethod
def weakly_connected_components_query(node_id: str) -> str:
    return (
        f"MATCH (start:Node {{id: {cypher_value(node_id)}}}) "
        f"MATCH p = (start)-[*]-(n) "
        f"RETURN DISTINCT n.text AS label"
    )
```

### 6.3 Fix Addresses Both Issues

The recommended fix addresses:
1. **Injection vulnerability**: Uses `cypher_value()` for proper escaping
2. **Logic bug**: Uses the hashed `id` instead of raw `text` for matching

---

## 7. Verification

### 7.1 Evidence of Vulnerability

**From source code analysis**:

1. `get_nodes(with_data=False)` returns text values:
   ```python
   # opengauss_graph.py:382-383
   return [row['label'] for row in result]  # row['label'] = n.text
   ```

2. `CypherQueryBuilder.match_nodes()` confirms this:
   ```python
   # graph_util.py:222
   return "MATCH (n:Node) RETURN n.text AS label"
   ```

3. Node text stored from user input:
   ```python
   # opengauss_graph.py:65
   attributes.update({"text": node, 'id': label})  # node = user input
   ```

4. Vulnerable query lacks sanitization:
   ```python
   # opengauss_graph.py:919-923
   f"MATCH (start:Node {{id: \"{node}\"}})..."  # Direct interpolation
   ```

**From test code confirmation**:

```python
# test_opengauss_graph.py:736-738
self.graph.get_nodes = MagicMock(return_value=["node1", "node2"])  # Returns text
self.mock_adapter.execute_cypher_query.side_effect = [
    [{"label": "node2"}],  # Query executed
```

### 7.2 Comparison with Similar Vulnerabilities

| CVE/Reference | Similar Pattern | This Vulnerability |
|---------------|-----------------|-------------------|
| CWE-943 | Improper neutralization in query | Direct Cypher injection |
| SQL Injection | String interpolation in SQL | String interpolation in Cypher |
| Neo4j Cypher Injection | UNION, WITH injection | Potential UNION injection |

---

## 8. Conclusion

This is a **confirmed real vulnerability** with the following characteristics:

- **Type**: Cypher Injection (CWE-943)
- **Severity**: Medium-High
- **Exploitability**: Requires specific configuration but straightforward to exploit
- **Impact**: Potential database manipulation, DoS
- **Root Cause**: Missing `cypher_value()` sanitization + logic bug

**Recommendation**: Apply immediate fix to use proper sanitization and correct the logic bug by using hashed IDs for matching.

---

## Appendix A: Related Code References

| File | Lines | Purpose |
|------|-------|---------|
| `opengauss_graph.py` | 904-930 | Vulnerable function |
| `opengauss_graph.py` | 58-67 | Node storage (stores text) |
| `opengauss_graph.py` | 369-383 | get_nodes (returns text) |
| `graph_util.py` | 29-79 | cypher_value() sanitization function |
| `graph_util.py` | 171-334 | CypherQueryBuilder (secure patterns) |
| `graph_merger.py` | 270 | Where user text enters graph |
| `graphrag_pipeline.py` | 133-152 | upload_files (entry point) |
| `graphrag_pipeline.py` | 164-206 | build_graph (processing) |
| `concept_clustering.py` | 92 | Where vulnerability is triggered |

---

**Report Generated**: 2026-04-20

**Classification**: CONFIRMED REAL VULNERABILITY - Requires Fix
