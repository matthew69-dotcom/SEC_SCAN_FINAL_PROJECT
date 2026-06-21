# Role B Writeup Draft: AI Integration & Validation

## Scope
Role B owns the AI explanation layer, prompt design, Markdown report support, and validation workflow for the AI-Assisted Lightweight Domain Security Checker. The AI layer explains scanner findings, but it does not calculate or modify the deterministic security score.

## Implementation Summary
The backend now includes an `app.ai` package with these responsibilities:

- `schemas.py`: Defines structured AI output using Pydantic models.
- `prompts.py`: Stores the system and user prompts used for LangChain/OpenAI.
- `service.py`: Runs the AI explanation pipeline and falls back to deterministic local explanations when OpenAI is unavailable.
- `report.py`: Renders scan results and AI/fallback explanations into Markdown.
- `validation.py`: Provides helper models and functions for accuracy, false positive, and false negative summaries.
- `validation_notes.md`: Tracks external validation results against SSL Labs, securityheaders.com, and MXToolbox.

The `/api/scan` route calls `explain_scan(...)` after scanner execution and deterministic scoring. The response summary now comes from the AI layer or fallback layer.

## LangChain Status
LangChain packages are installed and wired through `langchain-core` and `langchain-openai`. A real request reached OpenAI successfully, which confirms that the integration path is active. The account returned `insufficient_quota`, so paid model output cannot be fully evaluated yet.

The service handles this safely: if LangChain, OpenAI, quota, network, parsing, or API errors occur, `_call_langchain(...)` returns `None` and `explain_scan(...)` uses the local fallback explanation. This prevents `/api/scan` from crashing when the model is unavailable.

## Fallback Behavior
The fallback explanation is deterministic and uses only scanner findings, score, and grade. It reports:

- domain score and grade
- number of passed checks
- number of failed checks
- highest observed risk level
- per-finding explanation and next step for failed checks

This keeps the app usable without OpenAI credits and makes the behavior testable.

## Validation Plan
Validation compares this project's scanner results against external tools:

| Area | Our Scanner | External Reference |
|---|---|---|
| TLS certificate and protocol | `tls_scanner.py` | SSL Labs |
| HTTP security headers | `header_scanner.py` | securityheaders.com plus direct response headers |
| SPF, DMARC, DKIM | `email_scanner.py` | MXToolbox |
| DNSSEC, CAA, NS, wildcard DNS | `dns_scanner.py` | DNS provider/tool output where available |

Suggested test domains:

| Domain | Reason |
|---|---|
| google.com | Strong real-world baseline |
| example.com | Simple baseline domain |
| badssl.com | TLS edge cases |

## Validation Metrics
For each row in `validation_notes.md`:

- `Match`: our scanner agrees with the external reference.
- `False positive`: our scanner reports an issue but the external reference says it is OK.
- `False negative`: our scanner says OK but the external reference reports an issue.

Accuracy formula:

```text
accuracy = matches / total_compared_checks
```

## Current Limitations
- OpenAI model output cannot be fully evaluated until the account has quota.
- securityheaders.com may block automated requests, so header validation may need browser-based manual checking.
- SSL Labs can take time to finish scans and may blacklist some domains.
- DKIM detection is best effort because DKIM selectors cannot be exhaustively discovered without provider knowledge.
- The scanner checks a selected set of controls; it is not a replacement for a full commercial security assessment.

## Evidence To Add Later
After running `/api/scan`, add screenshots or copied results for:

1. Our scan result from Swagger UI.
2. SSL Labs result for TLS.
3. securityheaders.com result for headers.
4. MXToolbox result for SPF/DMARC/DKIM.
5. Completed `validation_notes.md` summary counts.
