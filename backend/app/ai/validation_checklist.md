# Manual Validation Checklist

Use this checklist when finishing Role B validation.

## 1. Start Backend
```powershell
cd "C:\Users\ASUS\Documents\GitHub\SEC_SCAN_FINAL_PROJECT\backend"
python -m uvicorn app.main:app --reload --port 8000
```

Open:

```text
http://localhost:8000/docs
```

## 2. Run Our Scanner
Use `/api/scan` for each domain:

```json
{"domain": "google.com"}
```

```json
{"domain": "example.com"}
```

```json
{"domain": "badssl.com"}
```

Record:

- score
- grade
- summary
- failed TLS checks
- failed header checks
- failed email checks
- failed DNS checks

## 3. Compare TLS
Open SSL Labs:

```text
https://www.ssllabs.com/ssltest/
```

For each domain, compare:

- certificate valid/expired
- hostname match
- protocol support
- overall TLS grade

Fill TLS rows in `validation_notes.md`.

## 4. Compare Headers
Open securityheaders.com:

```text
https://securityheaders.com/
```

Compare:

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options / frame-ancestors
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Fill header rows in `validation_notes.md`.

## 5. Compare Email
Open MXToolbox:

```text
https://mxtoolbox.com/
```

Check:

- SPF
- DMARC
- DKIM if available
- MX records

Fill email rows in `validation_notes.md`.

## 6. Count Results
Update the summary:

```text
Total checks compared:
Matches:
Mismatches:
False positives:
False negatives:
Accuracy:
```

## 7. Final Report Notes
Use `role_b_writeup.md` as the starting draft for the final project report.
Replace pending validation placeholders with real results after manual comparison.
