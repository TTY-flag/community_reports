# -*- coding: utf-8 -*-
filepath = r'D:\community_reports\Ascend\MindSeriesSDK\RAGSDK\scan-results\details\CROSS-MODULE-003.md'

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Section 5 translations
content = content.replace('## 5. Impact Scope', '## 5. 影响范围')
content = content.replace('### 5.1 Affected Components', '### 5.1 受影响组件')
content = content.replace('1. **BMRetriever** - Used for keyword-based document retrieval', '1. **BMRetriever** - 用于基于关键词的文档检索')
content = content.replace('2. **MultiQueryRetriever** - Used for multi-perspective query expansion', '2. **MultiQueryRetriever** - 用于多视角查询扩展')
content = content.replace('3. **SingleText2TextChain** - Main RAG pipeline entry point', '3. **SingleText2TextChain** - 主要 RAG 流程入口')
content = content.replace('4. **CacheChainChat** - Cached query wrapper', '4. **CacheChainChat** - 缓存查询包装器')
content = content.replace('### 5.2 Attack Impact Categories', '### 5.2 攻击影响类别')
content = content.replace('| Impact Type | Severity | Description |', '| 影响类型 | 严重程度 | 描述 |')
content = content.replace('| **Prompt Injection** | Critical | Complete control over LLM behavior |', '| **Prompt Injection** | Critical | 完全控制 LLM 行为 |')
content = content.replace('| **Data Exfiltration** | High | Retrieve sensitive documents via manipulated sub-queries |', '| **Data Exfiltration** | High | 通过操纵的子查询检索敏感文档 |')
content = content.replace('| **Context Leakage** | High | System prompts and configuration disclosure |', '| **Context Leakage** | High | 系统提示词和配置泄露 |')
content = content.replace('| **Denial of Service** | Medium | Token exhaustion, infinite loops |', '| **Denial of Service** | Medium | 令牌耗尽，无限循环 |')
content = content.replace('| **Response Manipulation** | High | Generate misleading or malicious content |', '| **Response Manipulation** | High | 生成误导性或恶意内容 |')
content = content.replace('### 5.3 Real-World Attack Scenario', '### 5.3 真实世界攻击场景')
content = content.replace('Attacker Query → RAG System', '攻击者查询 → RAG 系统')
content = content.replace('BMRetriever processes query with injected tokens', 'BMRetriever 处理带有注入令牌的查询')
content = content.replace('LLM receives manipulated prompt, ignores keyword extraction', 'LLM 接收被操纵的提示词，忽略关键词提取')
content = content.replace('LLM generates malicious keywords or returns manipulated content', 'LLM 生成恶意关键词或返回被操纵的内容')
content = content.replace('BM25Retriever searches using attacker-controlled keywords', 'BM25Retriever 使用攻击者控制的关键词搜索')
content = content.replace('Sensitive documents returned to attacker', '敏感文档返回给攻击者')

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print('Section 5 translated')
