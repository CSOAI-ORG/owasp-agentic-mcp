# OWASP Agentic AI Security MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

Security assessment based on OWASP Top 10 for Agentic AI (2025). Check for prompt injection, tool poisoning, excessive agency, and cross-context data leakage.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/owasp-agentic)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `assess_agent_security` | Full OWASP Agentic AI Top 10 security assessment |
| `check_prompt_injection` | Check text for prompt injection attack patterns |
| `check_tool_poisoning` | Check a tool for name/description manipulation |
| `check_excessive_agency` | Assess agent for excessive permissions (least privilege) |
| `check_data_leakage` | Assess cross-context data exposure risks |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/owasp-agentic-mcp.git
cd owasp-agentic-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "owasp-agentic": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/owasp-agentic-mcp"
    }
  }
}
```

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 10 requests/day |
| Pro | $29/mo | Unlimited |

## Authentication

Set `MEOK_API_KEY` environment variable. Get your key at [meok.ai/api-keys](https://meok.ai/api-keys).

## Links

- [MEOK AI Labs](https://meok.ai)
- [All MCP Servers](https://meok.ai/mcp)
- [GitHub](https://github.com/CSOAI-ORG/owasp-agentic-mcp)
