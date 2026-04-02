---
name: "🚨 False Negative (Missed Attack)"
about: "MCP-Fortress failed to detect an attack that it should have caught"
title: "[FN] "
labels: ["false-negative", "security"]
assignees: []
---

## Attack Description
What attack was performed that MCP-Fortress failed to detect?

## Attack Category
- [ ] Tool poisoning / description injection
- [ ] Prompt injection via tool arguments
- [ ] Path traversal
- [ ] SSRF
- [ ] Data exfiltration pattern
- [ ] Credential/PII exposure
- [ ] Supply chain (rug pull)
- [ ] Other: 

## Reproduction
Minimal code or request that demonstrates the missed detection:

```python
call = ToolCall(
    tool_name="...",
    arguments={...},
)
# MCP-Fortress should have flagged this but didn't
```

## Expected Behavior
Which detector should have caught this, and what alert should have been raised?

## MITRE ATT&CK Reference (if known)
e.g. T1041 (Exfiltration Over C2)

## Severity Assessment
Your assessment of how dangerous this miss is in production.

---
⚠️ If this involves an active exploit, please use [private security disclosure](../SECURITY.md) instead.
