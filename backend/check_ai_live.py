"""
Quick live check for the AI Risk Analyzer.
Tests ONLY the OpenAI call (no DNS / network scan needed).

Run from the backend/ folder with the venv active:
    python check_ai_live.py

PASS  -> generated_by_ai = True,  model_used = gpt-4o-mini   (key works)
FAIL  -> generated_by_ai = False, model_used = local-fallback (key missing / package missing / call failed)
"""
import asyncio

from app.ai.service import explain_scan

SAMPLE_FINDINGS = [
    {"id": "tls.cert_valid", "category": "tls", "title": "TLS certificate valid",
     "passed": True, "severity": "info", "evidence": "Valid until 2027-01-01", "remediation": ""},
    {"id": "headers.hsts", "category": "headers", "title": "HSTS header missing",
     "passed": False, "severity": "high", "evidence": "No Strict-Transport-Security header",
     "remediation": "Add a Strict-Transport-Security header."},
    {"id": "email.dmarc", "category": "email", "title": "DMARC record missing",
     "passed": False, "severity": "medium", "evidence": "No DMARC TXT record found",
     "remediation": "Publish a DMARC policy."},
]


async def main():
    result = await explain_scan(
        domain="example.com", score=58, grade="D", findings=SAMPLE_FINDINGS,
    )
    print("=" * 50)
    print("generated_by_ai :", result.generated_by_ai)
    print("model_used      :", result.model_used)
    print("-" * 50)
    print("summary         :", result.summary)
    print("=" * 50)
    if result.generated_by_ai:
        print("PASS - OpenAI key works, AI is live.")
    else:
        print("FAIL - fell back to local. Check: .env key, langchain installed, or API call error.")


if __name__ == "__main__":
    asyncio.run(main())
