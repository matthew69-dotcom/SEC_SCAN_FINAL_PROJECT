# Role B Validation Notes

## Goal
Compare scanner output against trusted external tools and record accuracy.

## Tools To Compare
- SSL Labs
- securityheaders.com
- MXToolbox

## Test Domains
| Domain | Expected Purpose | Notes |
|---|---|---|
| google.com | Strong baseline | Common secure domain |
| example.com | Simple baseline | Basic test domain |
| badssl.com | TLS edge cases | Useful for certificate testing |

## Accuracy Table
| Domain | Check | Our Result | External Tool Result | Match? | Notes |
|---|---|---|---|---|---|
| google.com | TLS certificate |  |  |  |  |
| google.com | Security headers |  |  |  |  |
| google.com | MX/SPF/DMARC |  |  |  |  |

## LangChain Status
LangChain packages are installed and wired into `backend/app/ai/service.py`.
A real API request reached OpenAI, but the account returned `insufficient_quota`.
Fallback mode works and `tests/test_ai.py` passes.

## Summary
- Total checks compared:
- Matches:
- Mismatches:
- False positives:
- False negatives:
- Accuracy: