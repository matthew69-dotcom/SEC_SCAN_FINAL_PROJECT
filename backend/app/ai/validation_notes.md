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
| google.com | TLS certificate |  |  |  | Pending manual comparison in SSL Labs |
| google.com | Security headers |  |  |  | Pending manual comparison in securityheaders.com |
| google.com | MX/SPF/DMARC |  |  |  | Pending manual comparison in MXToolbox |
| example.com | TLS certificate |  |  |  | Pending manual comparison in SSL Labs |
| example.com | Security headers |  |  |  | Pending manual comparison in securityheaders.com |
| example.com | MX/SPF/DMARC |  |  |  | Pending manual comparison in MXToolbox |
| badssl.com | TLS certificate |  |  |  | Pending manual comparison in SSL Labs |

## LangChain Status
LangChain packages are installed and wired into `backend/app/ai/service.py`.
A real API request reached OpenAI, but the account returned `insufficient_quota`.
The service catches model/API failures and falls back to deterministic local explanations.
Fallback mode works and the Role B tests pass.

## Implemented Role B Helpers
- `service.py`: AI explanation service with LangChain integration and fallback behavior.
- `report.py`: Markdown report renderer for scan findings plus AI/fallback explanation.
- `validation.py`: Validation row model, markdown table rendering, accuracy, false positive, and false negative summary helpers.

## Summary
- Total checks compared: pending
- Matches: pending
- Mismatches: pending
- False positives: pending
- False negatives: pending
- Accuracy: pending
