"""
AI synthesis layer: turns raw recon data into a plain-English summary.

This is the 0x41 difference: other tools dump lists, this one explains them.
Requires an Anthropic API key in the ANTHROPIC_API_KEY environment variable.
"""

import json
import os

MAX_HOSTS = 400  # keep requests small and cheap on very large domains

SYSTEM_PROMPT = """You are a security analyst at 0x41, writing an external \
attack-surface summary for an authorized assessment. Your reader is the \
domain owner or the security team they hired. Be clear, practical, and \
defensive in focus.

Write in Markdown with these sections:
1. **Overview**: 2-3 sentences on the size and shape of the public footprint.
2. **How the infrastructure is organized**: group hostnames by apparent \
purpose (production, auth, VPN/remote access, status/monitoring, dev/staging, \
regional clusters, etc.) and note naming patterns.
3. **Worth reviewing**: hostnames whose names suggest they may not need to be \
publicly listed (internal tools, staging, admin, cost/billing, legacy). Explain \
why each matters in one line. Prioritize: High / Medium / Low.
4. **Recommendations**: concrete defensive steps for the owner.
5. **Limitations**: this data comes only from public certificate logs; it \
does not confirm which hosts are live, and names alone don't prove a problem.

Do not invent facts beyond the data. Hedge inferences ("suggests", "likely").
Be concise: aim for about 600-900 words total. Summarize large repetitive \
groups (e.g. many regional clusters) in one line instead of listing every host."""


def pick_model(client) -> str:
    """Use $CLAUDE_MODEL if set, otherwise the newest Sonnet the API lists."""
    if os.environ.get("CLAUDE_MODEL"):
        return os.environ["CLAUDE_MODEL"]
    models = [m.id for m in client.models.list(limit=50)]  # newest first
    for mid in models:
        if "sonnet" in mid:
            return mid
    return models[0]


def summarize(results: dict) -> tuple[str, str]:
    """Send recon results to Claude. Returns (markdown_summary, model_used)."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set (see README step for the API key).")

    import anthropic  # imported here so scans without --ai don't need it

    client = anthropic.Anthropic()
    model = pick_model(client)

    hosts = results.get("subdomains", [])
    payload = {
        "target": results["target"],
        "sources_used": list(results.get("sources", {}).keys()),
        "total_hostnames": len(hosts),
        "hostnames": hosts[:MAX_HOSTS],
        "truncated": len(hosts) > MAX_HOSTS,
    }

    msg = client.messages.create(
        model=model,
        max_tokens=8000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": "Recon data (JSON):\n```json\n" + json.dumps(payload, indent=2) + "\n```",
        }],
    )
    text = "".join(block.text for block in msg.content if block.type == "text")
    if msg.stop_reason == "max_tokens":
        text += "\n\n> **Note:** this report hit the length limit and was cut off."
    return text, model
