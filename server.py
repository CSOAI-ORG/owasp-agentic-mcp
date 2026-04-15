#!/usr/bin/env python3
"""
OWASP Top 10 for AI Agents MCP Server
=======================================
By MEOK AI Labs | https://meok.ai

Security assessment based on the OWASP Top 10 for Agentic AI (2025).
Covers prompt injection, tool poisoning, excessive agency, data leakage,
and comprehensive agent security evaluation.

Install: pip install mcp
Run:     python server.py
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# ── Authentication ──────────────────────────────────────────────
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access

_MEOK_API_KEY = os.environ.get("MEOK_API_KEY", "")


def _check_auth(api_key: str = "") -> str | None:
    if _MEOK_API_KEY and api_key != _MEOK_API_KEY:
        return "Invalid API key. Get one at https://meok.ai/api-keys"
    return None


# ── Rate limiting ───────────────────────────────────────────────
FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _rl(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit ({FREE_DAILY_LIMIT}/day). "
            "Upgrade: https://meok.ai/mcp/owasp-agentic/pro"
        )
    _usage[caller].append(now)
    return None


# ── OWASP Top 10 for Agentic AI Knowledge Base ─────────────────

OWASP_AGENTIC_TOP_10 = {
    "A01": {"name": "Prompt Injection", "severity": "CRITICAL",
            "description": "Manipulation of agent behavior through crafted inputs that override system instructions.",
            "mitigations": ["Input validation and sanitization", "System prompt isolation",
                           "Output filtering", "Instruction hierarchy enforcement",
                           "Human-in-the-loop for sensitive operations"]},
    "A02": {"name": "Tool Poisoning", "severity": "CRITICAL",
            "description": "Malicious tool descriptions or names that manipulate agent behavior when tools are discovered or invoked.",
            "mitigations": ["Tool registry validation", "Tool description integrity checks",
                           "Allowlist-based tool selection", "Tool behavior monitoring",
                           "Cryptographic tool signing"]},
    "A03": {"name": "Excessive Agency", "severity": "HIGH",
            "description": "Agent granted more permissions, tools, or autonomy than needed for its task.",
            "mitigations": ["Least privilege principle", "Scope-limited tool access",
                           "Action approval gates", "Permission boundaries",
                           "Rate limiting on destructive actions"]},
    "A04": {"name": "Data Leakage", "severity": "HIGH",
            "description": "Sensitive information exposed across contexts, sessions, or to unauthorized parties.",
            "mitigations": ["Context isolation", "Output sanitization",
                           "PII/secret detection", "Session boundary enforcement",
                           "Data classification tagging"]},
    "A05": {"name": "Insecure Output Handling", "severity": "HIGH",
            "description": "Agent output used directly in downstream systems without validation.",
            "mitigations": ["Output validation", "Type checking", "Sandboxed execution",
                           "Content Security Policy", "Output encoding"]},
    "A06": {"name": "Insufficient Monitoring", "severity": "MEDIUM",
            "description": "Lack of logging, alerting, or audit trails for agent actions.",
            "mitigations": ["Comprehensive action logging", "Anomaly detection",
                           "Real-time alerting", "Audit trail retention",
                           "Action replay capability"]},
    "A07": {"name": "Broken Authentication", "severity": "HIGH",
            "description": "Weak or missing authentication for agent-to-agent or agent-to-tool communication.",
            "mitigations": ["Mutual TLS", "Token-based authentication",
                           "Identity verification", "Certificate pinning",
                           "Session management"]},
    "A08": {"name": "Uncontrolled Resource Consumption", "severity": "MEDIUM",
            "description": "Agent consuming excessive compute, tokens, or API calls without bounds.",
            "mitigations": ["Token budgets", "Execution timeouts",
                           "Rate limiting", "Cost caps",
                           "Resource quotas per task"]},
    "A09": {"name": "Supply Chain Vulnerabilities", "severity": "HIGH",
            "description": "Compromised tools, plugins, or model weights in the agent's dependency chain.",
            "mitigations": ["Dependency scanning", "SBOM generation",
                           "Signed artifacts", "Version pinning",
                           "Regular auditing"]},
    "A10": {"name": "Misaligned Goals", "severity": "MEDIUM",
            "description": "Agent optimizing for proxy metrics rather than intended outcomes.",
            "mitigations": ["Goal specification review", "Reward hacking detection",
                           "Human feedback loops", "Alignment testing",
                           "Objective function auditing"]},
}

INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+(instructions?|prompts?)",
    r"(you\s+are|act\s+as|pretend|roleplay|imagine)\s+.{0,30}(admin|root|system)",
    r"system\s*:\s*",
    r"<\|?(system|im_start|endoftext)\|?>",
    r"\\n\\nHuman:|\\n\\nAssistant:",
    r"IMPORTANT:\s*override",
    r"jailbreak|DAN\s*mode|developer\s*mode",
    r"base64_decode|eval\(|exec\(|__import__",
    r"\{\{.*\}\}",
    r"\\x[0-9a-fA-F]{2}",
]


# ── FastMCP Server ──────────────────────────────────────────────

mcp = FastMCP(
    "owasp-agentic-mcp",
    instructions=(
        "OWASP Agentic AI Security MCP Server by MEOK AI Labs. "
        "Assess AI agent security against the OWASP Top 10 for Agentic AI. "
        "Check for prompt injection vulnerabilities, tool poisoning, "
        "excessive agency, and cross-context data leakage."
    ),
)


@mcp.tool()
def assess_agent_security(
    agent_name: str,
    has_input_validation: bool = False,
    has_output_filtering: bool = False,
    has_tool_allowlist: bool = False,
    has_least_privilege: bool = False,
    has_context_isolation: bool = False,
    has_action_logging: bool = False,
    has_auth_between_agents: bool = False,
    has_resource_limits: bool = False,
    has_dependency_scanning: bool = False,
    has_alignment_testing: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Full OWASP Agentic AI Top 10 security assessment."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    control_map = {
        "A01": has_input_validation, "A02": has_tool_allowlist,
        "A03": has_least_privilege, "A04": has_context_isolation,
        "A05": has_output_filtering, "A06": has_action_logging,
        "A07": has_auth_between_agents, "A08": has_resource_limits,
        "A09": has_dependency_scanning, "A10": has_alignment_testing,
    }

    results = []
    for risk_id, mitigated in control_map.items():
        risk = OWASP_AGENTIC_TOP_10[risk_id]
        results.append({
            "id": risk_id,
            "name": risk["name"],
            "severity": risk["severity"],
            "mitigated": mitigated,
            "status": "PASS" if mitigated else "FAIL",
            "recommended_mitigations": risk["mitigations"] if not mitigated else [],
        })

    passed = sum(1 for r in results if r["status"] == "PASS")
    critical_passed = sum(1 for r in results if r["status"] == "PASS" and r["severity"] == "CRITICAL")
    critical_total = sum(1 for r in results if r["severity"] == "CRITICAL")

    if passed == 10:
        risk_rating = "LOW"
    elif critical_passed == critical_total and passed >= 7:
        risk_rating = "MEDIUM"
    elif critical_passed < critical_total:
        risk_rating = "CRITICAL"
    else:
        risk_rating = "HIGH"

    return json.dumps({
        "agent": agent_name,
        "framework": "OWASP Top 10 for Agentic AI (2025)",
        "assessment_date": datetime.now().isoformat(),
        "overall_risk": risk_rating,
        "score": round(passed / 10 * 100, 1),
        "risks_mitigated": passed,
        "risks_unmitigated": 10 - passed,
        "critical_risks_mitigated": f"{critical_passed}/{critical_total}",
        "results": results,
    }, indent=2)


@mcp.tool()
def check_prompt_injection(
    input_text: str,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Check text for prompt injection attack patterns."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    detections = []
    text_lower = input_text.lower()

    for i, pattern in enumerate(INJECTION_PATTERNS):
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            detections.append({
                "pattern_id": f"INJ-{i+1:03d}",
                "pattern": pattern,
                "matches": [str(m) if isinstance(m, str) else str(m) for m in matches[:3]],
                "severity": "CRITICAL" if i < 3 else "HIGH",
            })

    special_chars = sum(1 for c in input_text if ord(c) > 127 or c in '\x00\x01\x02\x03')
    if special_chars > len(input_text) * 0.1 and len(input_text) > 20:
        detections.append({
            "pattern_id": "INJ-SPECIAL",
            "description": "High ratio of special/unicode characters (possible encoding attack)",
            "severity": "MEDIUM",
        })

    if len(input_text) > 5000:
        detections.append({
            "pattern_id": "INJ-LENGTH",
            "description": f"Unusually long input ({len(input_text)} chars). May contain hidden instructions.",
            "severity": "LOW",
        })

    risk = "SAFE"
    if any(d.get("severity") == "CRITICAL" for d in detections):
        risk = "CRITICAL"
    elif any(d.get("severity") == "HIGH" for d in detections):
        risk = "HIGH"
    elif detections:
        risk = "MEDIUM"

    return json.dumps({
        "input_length": len(input_text),
        "risk_level": risk,
        "detections": detections,
        "detection_count": len(detections),
        "recommendation": "Block or sanitize this input before passing to agent."
            if risk in ("CRITICAL", "HIGH") else "Input appears safe.",
        "owasp_ref": "A01 - Prompt Injection",
    }, indent=2)


@mcp.tool()
def check_tool_poisoning(
    tool_name: str,
    tool_description: str,
    tool_source: str = "unknown",
    has_signature_verification: bool = False,
    has_description_hash: bool = False,
    from_trusted_registry: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Check a tool for name/description manipulation (tool poisoning)."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    issues = []

    suspicious_desc_patterns = [
        (r"ignore|override|bypass|instead", "Instruction override keywords in description"),
        (r"always\s+call\s+this|must\s+use\s+this|priority", "Coercive language in description"),
        (r"<[^>]+>|```|system:|Human:", "Markup or prompt markers in description"),
        (r"\\n|\\r|\\t|\\x", "Escape sequences in description"),
    ]
    for pattern, reason in suspicious_desc_patterns:
        if re.search(pattern, tool_description, re.IGNORECASE):
            issues.append({"issue": reason, "severity": "HIGH", "pattern": pattern})

    name_issues = []
    if re.search(r"[^a-zA-Z0-9_\-]", tool_name):
        name_issues.append("Tool name contains special characters")
    if len(tool_name) > 100:
        name_issues.append("Unusually long tool name")
    common_names = ["execute", "run_command", "eval", "shell", "admin", "sudo", "system"]
    if tool_name.lower() in common_names:
        name_issues.append(f"Tool name '{tool_name}' mimics system-level tools")
    for ni in name_issues:
        issues.append({"issue": ni, "severity": "MEDIUM"})

    trust_issues = []
    if not has_signature_verification:
        trust_issues.append("No cryptographic signature verification")
    if not has_description_hash:
        trust_issues.append("No description integrity hash")
    if not from_trusted_registry:
        trust_issues.append(f"Tool source '{tool_source}' not from trusted registry")
    for ti in trust_issues:
        issues.append({"issue": ti, "severity": "MEDIUM"})

    risk = "LOW"
    if any(i["severity"] == "HIGH" for i in issues):
        risk = "HIGH"
    elif any(i["severity"] == "MEDIUM" for i in issues):
        risk = "MEDIUM"

    return json.dumps({
        "tool_name": tool_name,
        "tool_source": tool_source,
        "risk_level": risk,
        "issues": issues,
        "trust_verification": {
            "signature_verified": has_signature_verification,
            "description_hash": has_description_hash,
            "trusted_registry": from_trusted_registry,
        },
        "owasp_ref": "A02 - Tool Poisoning",
    }, indent=2)


@mcp.tool()
def check_excessive_agency(
    agent_name: str,
    tools_available: int = 0,
    tools_used_in_task: int = 0,
    has_approval_gates: bool = False,
    has_scope_limits: bool = False,
    can_access_filesystem: bool = False,
    can_access_network: bool = False,
    can_execute_code: bool = False,
    can_modify_data: bool = False,
    can_send_communications: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Assess agent for excessive permissions (least privilege)."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    issues = []
    dangerous_caps = {
        "filesystem_access": can_access_filesystem,
        "network_access": can_access_network,
        "code_execution": can_execute_code,
        "data_modification": can_modify_data,
        "send_communications": can_send_communications,
    }

    active_dangerous = {k: v for k, v in dangerous_caps.items() if v}
    if len(active_dangerous) >= 3:
        issues.append({"issue": f"Agent has {len(active_dangerous)} dangerous capabilities active",
                        "severity": "CRITICAL", "capabilities": list(active_dangerous.keys())})

    if can_execute_code and not has_approval_gates:
        issues.append({"issue": "Code execution without approval gates", "severity": "CRITICAL"})
    if can_send_communications and not has_approval_gates:
        issues.append({"issue": "Can send communications without approval", "severity": "HIGH"})
    if not has_scope_limits:
        issues.append({"issue": "No scope limitations defined", "severity": "HIGH"})

    if tools_available > 0 and tools_used_in_task > 0:
        utilization = tools_used_in_task / tools_available * 100
        if utilization < 20 and tools_available > 10:
            issues.append({"issue": f"Only {tools_used_in_task}/{tools_available} tools used ({utilization:.0f}%). Over-provisioned.",
                            "severity": "MEDIUM"})

    risk = "LOW"
    if any(i["severity"] == "CRITICAL" for i in issues):
        risk = "CRITICAL"
    elif any(i["severity"] == "HIGH" for i in issues):
        risk = "HIGH"
    elif issues:
        risk = "MEDIUM"

    return json.dumps({
        "agent": agent_name,
        "risk_level": risk,
        "tools_available": tools_available,
        "tools_used": tools_used_in_task,
        "dangerous_capabilities": active_dangerous,
        "has_approval_gates": has_approval_gates,
        "has_scope_limits": has_scope_limits,
        "issues": issues,
        "owasp_ref": "A03 - Excessive Agency",
        "recommendation": "Apply least privilege: remove unused tools, add approval gates for dangerous actions."
            if risk != "LOW" else "Agent follows least privilege principles.",
    }, indent=2)


@mcp.tool()
def check_data_leakage(
    agent_name: str,
    has_context_isolation: bool = False,
    has_session_boundaries: bool = False,
    has_pii_detection: bool = False,
    has_output_sanitization: bool = False,
    shares_memory_across_users: bool = False,
    logs_contain_user_data: bool = False,
    third_party_data_sharing: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Assess cross-context data exposure risks."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    issues = []
    if shares_memory_across_users:
        issues.append({"issue": "Memory shared across users (cross-tenant leakage)",
                        "severity": "CRITICAL", "cwe": "CWE-200"})
    if not has_context_isolation:
        issues.append({"issue": "No context isolation between sessions",
                        "severity": "HIGH", "cwe": "CWE-668"})
    if not has_session_boundaries:
        issues.append({"issue": "Session boundaries not enforced",
                        "severity": "HIGH", "cwe": "CWE-488"})
    if not has_pii_detection:
        issues.append({"issue": "No PII/secret detection in agent outputs",
                        "severity": "HIGH", "cwe": "CWE-532"})
    if not has_output_sanitization:
        issues.append({"issue": "Agent outputs not sanitized before delivery",
                        "severity": "MEDIUM", "cwe": "CWE-116"})
    if logs_contain_user_data:
        issues.append({"issue": "Logs contain user data (potential data exposure)",
                        "severity": "MEDIUM", "cwe": "CWE-532"})
    if third_party_data_sharing:
        issues.append({"issue": "Data shared with third parties without explicit controls",
                        "severity": "HIGH", "cwe": "CWE-359"})

    risk = "LOW"
    if any(i["severity"] == "CRITICAL" for i in issues):
        risk = "CRITICAL"
    elif any(i["severity"] == "HIGH" for i in issues):
        risk = "HIGH"
    elif issues:
        risk = "MEDIUM"

    return json.dumps({
        "agent": agent_name,
        "risk_level": risk,
        "controls": {
            "context_isolation": has_context_isolation,
            "session_boundaries": has_session_boundaries,
            "pii_detection": has_pii_detection,
            "output_sanitization": has_output_sanitization,
        },
        "data_exposure_vectors": {
            "cross_user_memory": shares_memory_across_users,
            "log_leakage": logs_contain_user_data,
            "third_party_sharing": third_party_data_sharing,
        },
        "issues": issues,
        "owasp_ref": "A04 - Data Leakage",
    }, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
