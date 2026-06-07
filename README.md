<!-- mcp-name: CSOAI-ORG/owasp-agentic-mcp -->
[![MCP Scorecard: 86/100](https://img.shields.io/badge/proofof.ai-86%2F100-5b21b6)](https://proofof.ai/scorecard/owasp-agentic-mcp.html)

# Owasp Agentic MCP

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-22c55e)](https://councilof.ai)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/owasp_agentic_mcp/)

> OWASP Top 10 for Agentic AI security MCP server — prompt injection detection, tool poisoning, exc...

OWASP Top 10 for Agentic AI security MCP server — prompt injection detection, tool poisoning, excessive agency, data leakage assessment
<div align="center">

# OWASP Agentic MCP

**OWASP Top 10 for AI Agents Security Assessment — Prompt Injection, Tool Poisoning, Data Leakage**

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://github.com/CSOAI-ORG)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
</div>

---

## 🚀 Quick Start

```bash
# Install via pip
pip install owasp_agentic_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install owasp-agentic-mcp --client claude
```

## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/owasp-agentic-mcp)
- [API Reference](https://api.meok.ai)
- [EU AI Act Compliance Guide](https://councilof.ai/compliance)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](https://cal.com/csoai/august-audit)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** $99/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** $499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/pricing) | [Contact Sales →](mailto:sales@csoai.org)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 300+ MCP servers for sovereign AI governance.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>
Security assessment tools based on the OWASP Top 10 for AI Agents. Scan agent configurations for prompt injection vulnerabilities, tool poisoning risks, excessive agency, data leakage, and more.

## Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `full_agent_scan` | Full OWASP Agentic Top 10 security scan | `agent_config`, `tools`, `permissions` |
| `assess_agentic_security` | Assess against specific OWASP Agentic categories | `categories`, `agent_config` |
| `check_prompt_injection` | Test for prompt injection vulnerabilities | `system_prompt`, `user_input_template` |
| `check_tool_poisoning` | Check for tool poisoning risks | `tool_definitions`, `input_validation` |
| `check_excessive_agency` | Assess agency level vs minimum required | `allowed_tools`, `required_tools`, `permissions` |

## Installation

```bash
pip install mcp
```

### Claude Desktop / Cursor / VS Code / Windsurf
```json
{
  "mcpServers": {
    "owasp-agentic": {
      "command": "python",
      "args": ["path/to/server.py"]
    }
  }
}
```

## Usage Examples

### Full agent security scan
```json
{
  "agent_config": {
    "system_prompt": "You are a helpful assistant that can access email, calendar, and file system.",
    "allowed_tools": ["send_email", "read_calendar", "write_file"]
  },
  "permissions": ["email:send", "calendar:read", "files:write"]
}
```

### Check prompt injection
```json
{
  "system_prompt": "You are a financial advisor bot",
  "user_input_template": "{user_query} Please provide investment advice."
}
```

## Pricing

- **Free:** 10 scans/day
- **Pro:** $99/mo — unlimited scans + detailed reports
- **Enterprise:** $499/mo — continuous monitoring + custom rules

---

*Built by MEOK AI Labs | [meok.ai](https://meok.ai)*

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->

