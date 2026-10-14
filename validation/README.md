# Validation harness

ตอบคำถามกรรมการสองข้อด้วยข้อมูลจริง:

1. **ผลคงที่ไหม (repeatability)** — สแกนแต่ละโดเมนหลายรอบ ดูว่าเกรด/คะแนนเท่ากันทุกรอบหรือไม่ และ check ไหนผลกลับไปกลับมา
2. **ผลถูกไหม (accuracy)** — เทียบผล pass/fail ราย check กับเครื่องมืออ้างอิงอิสระ

| หมวด | เทียบกับ | วิธี |
| :-- | :-- | :-- |
| DNS + Email (SPF, DMARC, CAA, NS, DNSSEC) | Google DNS-over-HTTPS (`dns.google`) | อัตโนมัติ |
| TLS (cert valid, hostname, protocol) | Qualys SSL Labs API v4 | อัตโนมัติ (ต้องลงทะเบียนครั้งเดียว) หรือกรอกเอง |
| HTTP headers | securityheaders.com | กรอกเอง (API เสียเงิน) |

## วิธีใช้ (Windows, ที่ root ของ repo)

1. เปิด backend ก่อน: `cd backend` → activate venv → `uvicorn app.main:app`
2. เปิดอีก terminal ที่ root ของ repo แล้ว activate venv เดียวกัน (ต้องมี `httpx`)
3. รัน:

```
python validation/validate.py run --runs 3
```

ค่าเริ่มต้นใช้ `--mode single` (สแกนเฉพาะโดเมนหลัก ~10–20 วินาที/รอบ) โดเมน 14 ตัว × 3 รอบ ≈ 10–15 นาที
ถ้าอยากทดสอบความนิ่งของเกรดแบบ Full ด้วย: `--mode full` (ช้ากว่ามาก ~1 นาที/รอบ)

### SSL Labs (ไม่บังคับ แต่แนะนำ)

ลงทะเบียนครั้งเดียวด้วยอีเมลองค์กร (Gmail ใช้ไม่ได้):

```
python validation/validate.py register --first Muanmet --last Promchan --email 6631501118@lamduan.mfu.ac.th
python validation/validate.py run --runs 3 --ssllabs-email 6631501118@lamduan.mfu.ac.th
```

SSL Labs ใช้เวลา 1–3 นาทีต่อโดเมน (ใช้ผลแคช ≤24 ชม. ถ้ามี, ไม่ publish ผลขึ้นบอร์ด)
ข้อตกลงของ Qualys: ใช้ฟรี ไม่ใช่เชิงพาณิชย์ อย่ายิงพร้อมกันหลายตัว — สคริปต์ทำทีละโดเมนอยู่แล้ว

## ผลลัพธ์ — `validation/out/<เวลา>/`

- `summary.md` — ตารางพร้อมใส่เล่ม (repeatability, % agreement ราย check, รายการที่ไม่ตรง)
- `stability.csv` — 1 แถว/โดเมน
- `comparison.csv` — 1 แถว/(โดเมน, check): `ours`, `ref_auto`, `ref_manual`, `agree`, `reference_link`
- `raw_scans.json` — response ดิบทุกครั้ง (หลักฐาน)

## กรอกผลอ้างอิงเอง (headers / TLS ถ้าไม่ได้ใช้ SSL Labs API)

1. เปิด `comparison.csv` ใน Excel → คลิก `reference_link` ของแต่ละแถว
2. กรอกคอลัมน์ `ref_manual` เป็น `pass` หรือ `fail` **ตามเกณฑ์เดียวกับระบบเรา**:
   - `headers.hsts`: มี HSTS **และ** max-age ≥ 15552000 (180 วัน)
   - `headers.csp`: มี CSP และไม่ใช้ `'unsafe-inline'` ซ้ำหลาย directive
   - `headers.frame_protection`: มี X-Frame-Options **หรือ** CSP `frame-ancestors`
   - `headers.nosniff`: `X-Content-Type-Options: nosniff`
   - `headers.referrer_policy`: มี Referrer-Policy และไม่ใช่ `unsafe-url`
   - `headers.permissions_policy`: มี Permissions-Policy
3. Save เป็น **CSV UTF-8** แล้วรัน:

```
python validation/validate.py report validation/out/<เวลา>/comparison.csv
```

## อ่านผลอย่างระวัง

- **ทุกแถวที่ไม่ตรง ต้องอธิบายได้** — แยกเป็น (ก) บั๊กของเรา (ข) เกณฑ์ต่างกัน (ค) เว็บเปลี่ยนค่าระหว่างสแกน
- **DNSSEC**: ระบบเราดูแค่ "มี DNSKEY" แต่ reference ดู AD flag (resolver ตรวจ chain สำเร็จ) ถ้าโดเมนมี DNSKEY แต่ไม่มี DS ที่ parent จะไม่ตรงกัน — เป็นข้อค้นพบที่ดีสำหรับเล่ม
- **SPF**: เรา pass `spf_hardfail` เฉพาะ `-all`; `~all` (softfail) = fail ตามเกณฑ์เรา
- **DKIM** ไม่ได้เทียบ เพราะต้องรู้ selector (ทั้งเราและเครื่องมืออื่นต้องเดา)
- เว็บใหญ่ (google, youtube) อาจส่ง header ต่างกันตาม IP/ประเทศ — สแกนกับเปิดเว็บอ้างอิงให้ใกล้เวลากัน
- `badssl.com` ถูกออกแบบมาให้ TLS พังโดยตั้งใจ: `expired` → `tls.cert_valid` ต้อง fail, `wrong.host` → `tls.hostname_match` ต้อง fail
- **คาดว่าจะไม่ตรง: `self-signed.badssl.com`** — `tls.cert_valid` ของเราตรวจแค่ **วันหมดอายุ** (ต่อแบบ `CERT_NONE` เพื่อให้เห็นใบรับรองแม้ไม่ผ่าน) ไม่ได้ตรวจว่า CA น่าเชื่อถือ ใบ self-signed จึงน่าจะ pass ในระบบเรา แต่ SSL Labs ให้เกรด T → นี่คือช่องว่างจริงที่ควรแก้หรือเขียนเป็นข้อจำกัด

แก้รายชื่อโดเมนได้ใน `validation/domains.txt`
