# สรุปโปรเจกต์ + Timeline — สำหรับนำเสนอ

**โปรเจกต์:** AI-Assisted Lightweight Domain Security Checker
ระบบตรวจสอบความปลอดภัยของโดเมนแบบเบาด้วยปัญญาประดิษฐ์

**สถาบัน:** Mae Fah Luang University (MFU) · Senior Project (Computer Engineering) · ปี 2026
**อาจารย์ที่ปรึกษา:** Aj. Mahamah Sebakor
**ทีม:** Pheerathad (A) · Muanmet (B) · Pacharapol (C)
**อัปเดตเอกสาร:** 20 ต.ค. 2026

---

## 1. ระบบนี้คืออะไร (พูดสั้นๆ ตอนเปิด present)

เครื่องมือเว็บที่รับ "โดเมน" 1 ตัว (และ subdomain ทั้งหมดของมัน) แล้วให้ **เกรดความปลอดภัย A+ ถึง F**
ครอบคลุม DNS, HTTPS/TLS, HTTP security headers และ email auth (SPF/DKIM/DMARC)
โดย **AI ช่วยแปลผลทางเทคนิคให้เป็นภาษาคน แต่ AI ไม่เคยเป็นคนคิดคะแนน** — คะแนนคิดด้วยกฎตายตัวที่ตรวจสอบได้

---

## 2. หลักการสำคัญ (Non-negotiables) — อาจารย์มักถามจุดนี้

1. **Non-intrusive / lightweight** — สังเกตเหมือน client ปกติ ไม่โจมตี ไม่ยิง exploit
   (ห้ามเรียกว่า "passive" เพราะมีการต่อ TLS/HTTP, TCP connect 6 ports และ resolve wordlist ~120 ชื่อ)
2. **AI ไม่เคยให้คะแนน** — คะแนนมาจาก engine ที่ deterministic (กฎตายตัวใน `weights.yaml`) รันกี่ครั้งก็ได้ผลเท่าเดิม
3. ทุก scanner คืนค่า `CheckResult` เสมอ ไม่มีการ crash
4. scanner ทุกตัวรัน **ขนานกัน** ด้วย `asyncio.gather()`
5. ทุก API response แนบเลขเวอร์ชัน (app + model + rubric)
6. ทุกขั้นที่พึ่งบริการภายนอก **มีเวลาจำกัด** — สแกนไม่มีวันค้าง
7. **ไม่ต่อไปยัง IP ภายใน** (private/loopback ฯลฯ) — กัน SSRF
8. **ไม่สลับหรือแต่งผล** — ผลของโดเมนหลัก (apex) ไม่ถูกแทนด้วยของ subdomain; วัดไม่ได้ก็บอกว่าวัดไม่ได้

---

## 3. ระบบทำงานยังไง (Flow)

1. **Discovery** (เฉพาะโหมด Full scan) — หา subdomain จาก 3 แหล่ง: crt.sh (Certificate Transparency logs) + DNS mining + wordlist brute-force
2. **Scanners 4 ตัวรันพร้อมกัน** บนแต่ละ host:
   - DNS (DNSSEC, CAA, NS redundancy, wildcard)
   - TLS/HTTPS (cert ไม่หมดอายุ + CA น่าเชื่อถือ, protocol, hostname match, renewal buffer, cipher)
   - HTTP Security Headers (HSTS, CSP, X-Frame-Options, nosniff, referrer/permissions policy)
   - Email (SPF, DKIM, DMARC + ความเข้มของ policy)
3. **Geo-IP + Port scan** ต่อ host — หาตำแหน่ง / ISP / ASN และพอร์ตที่เปิด (80/443/8080/8443/8000/3000)
4. **Scoring Engine** — รวมผลตาม rubric ออกมาเป็นคะแนน + เกรด (กฎตายตัว ไม่ใช้ AI)
5. **AI Risk Analyzer** — GPT-4o-mini (ผ่าน LangChain, บังคับ JSON mode) **แปล** ผลทางเทคนิคให้เป็นภาษาคน: สรุปความเสี่ยง + ปัญหาหลัก (top issues) + สิ่งที่ทำได้ดี (positive findings)
6. **API** ส่ง response เป็น JSON มีโครงสร้างชัดเจน → **Frontend (React)** แสดงเป็น dashboard: เกรด, คะแนนแยกหมวด, ตาราง host, การ์ด AI

```
Domain
  │
  ▼
Discovery (crt.sh + DNS mining + wordlist)      ← Full scan เท่านั้น
  │
  ▼
[ DNS | TLS | Headers | Email ]  ← รันขนานกัน (asyncio.gather)
  │
  ▼
Geo-IP + Port scan (ต่อ host)
  │
  ▼
Scoring Engine (weights.yaml, deterministic)  →  คะแนน + เกรด A+..F
  │
  ▼
AI Risk Analyzer (GPT-4o-mini)  →  คำอธิบายภาษาคน (ไม่ยุ่งกับคะแนน)
  │
  ▼
API (JSON + version)  →  Frontend React Dashboard
```

---

## 4. Rubric คะแนน (เต็ม 100)

| หมวด | น้ำหนัก | รายละเอียดหลัก |
| :--- | :---: | :--- |
| TLS | 30 | cert_valid (10) + modern_protocol (8) + strong_ciphers (6) + cert_renewal_buffer (3) + hostname_match (3) |
| Headers | 25 | HSTS (6) + CSP (6) + frame_protection (4) + nosniff (3) + referrer_policy (3) + permissions_policy (3) |
| Email | 25 | SPF (8) + DMARC (7) + spf_hardfail (4) + dmarc_strict (4) + DKIM (2) |
| DNS | 20 | DNSSEC (8) + CAA (5) + ns_redundancy (4) + no wildcard (3) |

`tls.strong_ciphers` (check สุดท้าย) implement เสร็จแล้ว 14 ก.ค. 2026 — rubric ครบ 100 คะแนนทุก check

**เกณฑ์เกรด:** 95+ = A+ · 85+ = A · 75+ = B · 60+ = C · 40+ = D · ต่ำกว่านั้น = F

---

## 5. ประโยคตอบคำถามที่อาจารย์น่าจะถาม

**Q: ทำไมให้ AI แปลผล แต่ไม่ให้ AI คิดคะแนน?**
A: เพราะคะแนนต้อง reproducible และตรวจสอบได้ ถ้า AI คิดคะแนน รันสองครั้งอาจได้ไม่เท่ากันและอธิบายที่มาไม่ได้ เราจึงให้ engine ที่เป็นกฎตายตัวคิดคะแนน ส่วน AI ทำเฉพาะงานที่มันเก่งคือเปลี่ยนศัพท์เทคนิคให้คนทั่วไปเข้าใจ

**Q: ปลอดภัย/ถูกกฎหมายไหม จะโดนมองว่าโจมตีเว็บคนอื่นหรือเปล่า?**
A: ระบบเป็นแบบ non-intrusive ดูเฉพาะสิ่งที่ client ปกติเห็น (DNS, ใบ cert, HTTP headers ที่เซิร์ฟเวอร์ส่งมาเอง) + TCP connect 6 พอร์ตเว็บมาตรฐาน ไม่มีการยิง exploit หรือเจาะระบบ และจะไม่ต่อไปยัง IP ภายในของใคร

**Q: ถ้า AI ล่ม ระบบพังไหม?**
A: ไม่พัง ถ้าไม่ได้ตั้ง `OPENAI_API_KEY` ส่วน AI summary จะเป็น null และ UI ซ่อนการ์ด AI เอง คะแนนกับผล scan ยังทำงานปกติ

**Q: เชื่อถือผลได้แค่ไหน?**
A: วัด 2 แบบกับ 14 โดเมน (รวม badssl.com ที่ตั้งใจทำ TLS พัง):
(1) **สแกนซ้ำ 3 รอบได้เกรดเดิม 14/14 โดเมน** (2) **ผลราย check ตรงกับเครื่องมืออิสระ 198/203 = 97.5%**
(DNS/Email เทียบ Google DNS-over-HTTPS 98/98, TLS เทียบ SSL Labs 38/39, Headers เทียบ securityheaders.com 62/66)
แถวที่ไม่ตรงอธิบายได้ทุกแถว — ไม่ใช่การตีความผิด (ดู `validation/FINDINGS_2026-10-20.md`)

---

## 6. Stack ที่ใช้

| ส่วน | เทคโนโลยี |
| :--- | :--- |
| Backend | Python 3.12 + FastAPI (async ทั้งหมด, Pydantic v2) |
| Frontend | React 19 + Vite 8 + TypeScript (strict) + Tailwind 3 |
| Database | SQLite (dev) / PostgreSQL 16 (prod) — SQLAlchemy 2.0 async |
| AI | OpenAI GPT-4o-mini ผ่าน LangChain (บังคับ JSON) |
| DNS / TLS / HTTP | dnspython / ssl+cryptography / httpx |
| Scoring | pyyaml + custom engine (weights.yaml) |
| Deploy | Docker compose (dev/prod); Railway + Vercel ถ้าจำเป็น |

---

## 7. Timeline เดิม (แผน มิ.ย.–ก.ค. 2026 — เก็บไว้อ้างอิง)

> เส้นตายเดิม ~สิ้น ก.ค. ผ่านไปแล้ว วันสอบ/ส่งเล่มจริงต้องยืนยันกับอาจารย์ — สถานะล่าสุดดูหัวข้อ 8

ทำขนานกัน 3 คน — A = Pheerathad · B = Muanmet · C = Pacharapol

### สัปดาห์ที่ 1 · จ.29 มิ.ย. – อา.5 ก.ค. → ปิด W7

- **จ.29:** merge PR `feat/fe-be-integration` → `DEV` (frontend ที่เพิ่งเชื่อม Geo-IP / ports / AI summary เสร็จ)
- **C:** ตั้ง PostgreSQL — models + SQLAlchemy async + เก็บประวัติ scan + ต่อเข้า `/api/scan` (จ.–พฤ.)
- **B:** รัน scan domain ตัวอย่าง เทียบผลกับ SSL Labs / securityheaders / MXToolbox เก็บข้อมูล (จ.–พ.)
- **A:** เพิ่ม check สุดท้าย `tls.strong_ciphers` (weight 6) + เทสต์ แล้วช่วย review PR ของ C (จ.–อ.)

### สัปดาห์ที่ 2 · จ.6 – อา.12 ก.ค. → เริ่ม W8

- **A+C:** deploy backend ขึ้น Railway + frontend ขึ้น Vercel แก้ env / CORS / DB connection บน cloud (จ.–พ.)
- **B:** เขียนสรุปผล validation + ตารางความแม่นยำให้เสร็จ (จ.–อ.)
- **ทุกคน:** ทดสอบ end-to-end บนตัวที่ deploy จริง (พฤ.–ศ.)

### สัปดาห์ที่ 3 · จ.13 – ศ.17 ก.ค. → ปิดงาน

- **C+B:** เอกสารฉบับสมบูรณ์ + สไลด์ + รายงาน (จ.–พ.)
- **ทุกคน:** ซ้อม demo + buffer แก้บั๊ก (พฤ.–ศ.)
- **เป้าเสร็จ ~ศ.17 ก.ค.** เหลือ buffer ก่อนเส้นตาย ~สิ้นเดือน

**จุดเสี่ยงที่ต้องเผื่อเวลา:** การ deploy มักกินเวลากว่าที่คิด (DB บน cloud, CORS, ตัวแปร env) — กันเวลาช่วงสัปดาห์ที่ 2 ไว้เยอะหน่อย DB (Role C) กับ Validation (Role B) ทำขนานกันได้ ไม่ต้องรอกัน

---

## 8. สถานะปัจจุบัน (ณ 20 ต.ค. 2026)

- ✅ W1–W7: scanners + scoring + discovery + API + AI analyzer + Frontend + DB history
- ✅ W8: `tls.strong_ciphers` (TLS เต็ม 30/30)
- ✅ ต.ค. 2026 — ปรับความน่าเชื่อถือ (PR #5–#11 merge เข้า DEV แล้ว):
  - Full scan ไม่ค้าง: จำกัด 25 host + เวลาแต่ละขั้น
  - Email N/A สำหรับ host ที่ไม่มี MX (คิดคะแนนจาก 75)
  - กัน SSRF: ไม่ต่อไปยัง IP ภายใน
  - Apex ไม่ถูกแทนด้วยผลของ subdomain (40 วินาที + retry)
  - Validation harness + ผลเทียบ SSL Labs / securityheaders.com ครบ 14 โดเมน
  - TLS ตรวจ trust chain (self-signed = fail), header fetch retry 1 ครั้ง, header ซ้ำ, เวลาใน History เป็นเวลาไทย
- ✅ Tests: **143** · Validation: **14/14** repeatable, **97.5%** agreement
- ⬜ คุยอาจารย์: วันสอบ, template เล่ม, ต้อง deploy ไหม, คำถาม methodology 2 ข้อ
  (web checks N/A สำหรับ host ที่ไม่ใช่เว็บ? / การ์ดใหญ่โชว์เกรด apex แต่สรุปโชว์เกรด worst-host)
- ⬜ SSRF guard ยังไม่ตรวจ AAAA record (`mfu.ac.th` มี AAAA = `::1`)
- ⬜ อัปเดตเล่ม · เตรียม demo (Docker prod + สแกนล่วงหน้าเก็บใน History)
