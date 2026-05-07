<div align="center">

[![PyPI](https://img.shields.io/pypi/v/owasp-agentic-mcp)](https://pypi.org/project/owasp-agentic-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/owasp-agentic-mcp)](https://pypi.org/project/owasp-agentic-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/owasp-agentic-mcp)](https://github.com/CSOAI-ORG/owasp-agentic-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# OWASP Agentic AI MCP

**Security assessment against the OWASP Top 10 for Agentic AI (2025). Prompt injection detection, tool poisoning checks, excessive agency evaluation, and data leakage analysis.**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

The OWASP Top 10 for Agentic AI (released 2025) defines the ten most critical security risks for AI agents that can take actions, use tools, and operate autonomously. As organisations deploy MCP servers, LangChain agents, and autonomous AI workflows, these systems face attack vectors that traditional AppSec testing does not cover.

Prompt injection, tool poisoning, excessive agency, and cross-context data leakage are not theoretical: they are actively exploited. CISOs and security teams need a structured way to assess agentic AI deployments against the OWASP classification. This MCP evaluates your agent architecture against all 10 risk categories and produces actionable findings.

## Install

```bash
pip install owasp-agentic-mcp
```

## Tools

| Tool | OWASP Reference | What it does |
|------|----------------|--------------|
| `assess_agent_security` | All 10 risks | Full security posture assessment against OWASP Top 10 for Agentic AI |
| `check_prompt_injection` | Risk A01 | Detect prompt injection attack vectors in agent inputs |
| `check_tool_poisoning` | Risk A02 | Evaluate tool definitions and MCP configs for poisoning risks |
| `check_excessive_agency` | Risk A03 | Assess whether agent has more permissions than needed |
| `check_data_leakage` | Risk A06 | Identify cross-context data leakage paths in agent workflows |

## Example

```
Prompt: "Assess the security of our customer support AI agent.
It has access to 12 MCP tools including database queries, email
sending, and file system access. It operates on user prompts
with no input sanitisation."

Result: Assessment across all 10 OWASP Agentic AI risks with critical
findings: A01 prompt injection (no input sanitisation on user prompts),
A02 tool poisoning (3 MCP tools loaded without integrity checks),
A03 excessive agency (file system + email + database = over-privileged),
A06 data leakage (database query results passed through to email tool
without redaction). Remediation priorities and control recommendations
provided for each finding.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — agent security assessment |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

Every Pro/Enterprise audit produces a cryptographically signed certificate:

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
