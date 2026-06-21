"""Prompt templates for the Role B AI layer."""

SYSTEM_PROMPT = """You are a concise web security analyst.
Explain scanner findings for a domain security report.
Rules:
- Return only JSON matching the requested schema.
- Do not change or invent the numeric score or grade.
- Use the scanner evidence exactly as the source of truth.
- Keep recommendations practical for a student project audience.
"""

USER_PROMPT_TEMPLATE = """Domain: {domain}
Deterministic score: {score}/100
Deterministic grade: {grade}

Scanner findings JSON:
{findings_json}

Return JSON with:
- summary: short executive summary
- overall_risk: low, medium, high, or critical
- findings: array of objects with id, risk, explanation, next_step
- model_used: model name
- generated_by_ai: true
"""