<div align="center">

# Owasp Agentic MCP

**MCP server for owasp agentic mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-owasp-agentic-mcp)](https://pypi.org/project/meok-owasp-agentic-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Owasp Agentic MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `assess_agent_security` | Full OWASP Agentic AI Top 10 security assessment. |
| `check_prompt_injection` | Check text for prompt injection attack patterns. |
| `check_tool_poisoning` | Check a tool for name/description manipulation (tool poisoning). |
| `check_excessive_agency` | Assess agent for excessive permissions (least privilege). |
| `check_data_leakage` | Assess cross-context data exposure risks. |

## Installation

```bash
pip install meok-owasp-agentic-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "owasp-agentic-mcp": {
      "command": "python",
      "args": ["-m", "meok_owasp_agentic_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
