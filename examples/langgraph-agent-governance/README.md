# LangGraph Agent Governance

This example shows how to use PolicyAware inside LangGraph-style agent nodes without adding LangGraph as a hard dependency.

LangGraph nodes are Python callables. `PolicyAwareNodeGuard` can:

- check graph state before a node runs
- block denied states
- pause high-risk states for approval
- evaluate MCP-style tool calls before execution
- attach policy decision metadata back into graph state

## Install

```bash
pip install policyaware
```

## Run

```bash
python langgraph_demo.py
```

## Expected Output

```text
safe_node_output= {'messages': [{'role': 'assistant', 'content': 'Customer record summarized safely.'}]}
blocked_node_output= {'policyaware': {'allowed': False, 'decision': 'deny', ...}, 'messages': [{'role': 'assistant', 'content': 'Request blocked by PolicyAware policy.'}]}
tool_decision= require_approval
tool_approval_required= True
```

## Use In A LangGraph Node

```python
from policyaware import PolicyAwareNodeGuard

guard = PolicyAwareNodeGuard(config="policyaware.yaml", tool_policy="tool-governance.yaml")

def my_node(state):
    return {"messages": [{"role": "assistant", "content": "node result"}]}

guarded_node = guard.guard_node(my_node)
```
