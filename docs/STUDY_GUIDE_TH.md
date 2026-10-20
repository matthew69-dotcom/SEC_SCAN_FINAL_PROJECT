# คู่มือเข้าใจโปรเจกต์แบบลึก + เตรียมตอบกรรมการ (ภาษาไทย)

> สำหรับทีมใช้อ่านก่อน present. อิงจาก **โค้ดจริง** ณ ต.ค. 2026 (DEV หลัง PR #11) ไม่ใช่แค่เอกสาร
> คู่กับ `docs/ARCHITECTURE.md` (English) และ `PROJECT_MAP.md`

---

## 1. Elevator pitch (พูดได้ใน 30 วินาที)

> "ระบบของเราเป็นเว็บที่รับชื่อโดเมน 1 ชื่อ แล้วตรวจความปลอดภัยแบบ **non-intrusive / lightweight**
> (ดูเหมือน client ปกติ ไม่โจมตี ไม่ยิง exploit) ครอบคลุม 4 ด้าน: **DNS, TLS/HTTPS, HTTP security headers,
> และ email authentication (SPF/DKIM/DMARC)** จากนั้นให้เกรด A+ ถึง F
> ด้วย **rubric ที่ deterministic** — สแกนซ้ำได้ผลเท่าเดิมเสมอ
> ส่วน AI (GPT-4o-mini) ทำหน้าที่เดียวคือ **แปลผลเป็นภาษาคน** ไม่มีสิทธิ์ให้คะแนน
> โหมด full ยังค้นหา subdomain ทั้งหมดแล้วสแกนทุกตัว โดยเกรดของโดเมน =
> เกรดของ host ที่**แย่ที่สุด** เพราะ security พังที่จุดอ่อนที่สุดเสมอ"

---

## 2. เส้นทางของ 1 scan (ตามโค้ดจริงใน `routes.py`)

ผู้ใช้กด Scan → `POST /api/scan` `{domain, mode}` โดย `mode` มี 2 ค่า:
**`single`** (เฉพาะโดเมนที่พิมพ์) และ **`full`** (ค้นหา subdomain + Geo-IP + ports + AI)

### mode="single"
1. **SSRF guard** — ถ้าโดเมน resolve ไปที่ IP ภายใน (192.168.x, 127.x, 10.x ฯลฯ) จะไม่ต่อ TLS/headers เลย
   รายงานเป็น `dns.private_ip_exposed` แทน (DNS/email ยังตรวจได้เพราะถามแค่ resolver สาธารณะ)
2. `_scan_single_host()` ยิง scanner 4 ตัวพร้อมกันด้วย `asyncio.gather(..., return_exceptions=True)`
   — ถ้าตัวไหน crash จะกลายเป็น check `scan.error` ที่ fail ไม่ใช่ HTTP 500
3. รวม `CheckResult` ทั้งหมด → `score_checks()` ให้คะแนน+เกรด
4. ประกอบ `ScanResponse` (มี version info: app + AI model + rubric version)
5. `_save_scan()` บันทึกลง DB **ใน try/except** — DB ตายก็สแกนได้ (กฎข้อ 6)

### mode="full" (เพิ่มจาก single)
1. **Discovery** — `enumerate_hosts()` รวม 3 แหล่งพร้อมกัน:
   crt.sh (Certificate Transparency logs, จำกัดรวม 20s), DNS mining, wordlist ~120 ชื่อ
   → ตัด wildcard (`*.x.com`), dedup, แล้ว **resolve A record** เพื่อพิสูจน์ว่า host มีจริง
   (resolver ถูก pin ไว้ที่ 8.8.8.8 / 1.1.1.1, resolve พร้อมกันสูงสุด 20)
   ทั้งขั้นจำกัด **45 วินาที** — เกินก็สแกน apex อย่างเดียว
2. **จำกัด 25 host** (`MAX_HOSTS`) — เลือก apex, www, แล้วชื่อที่สั้น/ตื้นที่สุดก่อน
   (crt.sh โตขึ้นเรื่อยๆ เช่น mfu.ac.th เจอ 223 host — ไม่จำกัดคือสแกนค้าง)
3. **SSRF guard** — host ที่ A record ตัวใดตัวหนึ่งเป็น IP ภายใน ถูกตัดออก ไม่ต่อ ไม่ port scan
   (mfu.ac.th: ns1/ns2 → 192.168.x ถูกข้าม 4 host) แล้วรายงานรวมใน `dns.private_ip_exposed`
4. สแกนทุก host พร้อมกัน แต่คุมด้วย `Semaphore(5)` + timeout ต่อ host **20 วินาที**
   — **apex ได้ 40 วินาที + retry 1 ครั้ง**; host ที่ timeout/พังนับเป็น `hosts_failed` และชื่ออยู่ใน summary
   — **Email N/A:** SPF/DMARC/DKIM ตรวจเฉพาะ apex และ host ที่มี MX ของตัวเอง
     host อื่น (www, api …) ไม่รับเมล จึงตัดหมวด email ออก คิดคะแนนจาก 75 แล้วสเกลเป็น 100
     + info finding `email.not_applicable`
5. **Geo-IP** ทุก IP พร้อมกัน (ip-api.com, จำกัด 10s) → location(≈), ISP, ASN
6. **Port scan** — TCP connect ธรรมดา (`asyncio.open_connection`) ไปที่ **IP ที่ตรวจแล้ว** (ไม่ใช่ชื่อ)
   เช็คแค่ 6 ports: 80, 443, 8080, 8443, 8000, 3000 (concurrency 10, จำกัดรวม 20s, ไม่ต้อง root)
7. **Aggregate:** `domain_score = คะแนน host ที่แย่ที่สุด (min)` + average ให้ดูด้วย
   ส่วนการ์ดหลักแสดงผลของ **apex** — **ไม่มีวันเอาผลของ host อื่นมาแทน**
   (เคยเกิด: youtube.com timeout แล้วระบบโชว์ผลของ subdomain เป็น youtube.com → A89 vs D48 ห่างกัน 2 นาที)
   ถ้า apex สแกนไม่ได้จริง → finding `scan.apex_unavailable` + หมายเหตุใน summary + ไม่มี AI summary
8. **AI** — `analyze_findings()` วิเคราะห์ findings ของ apex host เท่านั้น (จำกัด 30s)
   ห่อด้วย try/except: AI พังก็ได้ผลสแกนปกติ (`ai_summary = null`)

### History (Week 7)
`GET /api/scans` (list ใหม่→เก่า) · `GET /api/scans/{id}` (ผลเต็มจาก `result_json`)
· `DELETE /api/scans/{id}` — ทุก scan ถูกเก็บอัตโนมัติ

---

## 3. เจาะลึกทีละส่วน

### 3.1 Scanners — สัญญาเดียวกันทุกตัว (`scanners/base.py`)

ทุก scanner คืน `list[CheckResult]`:
`{id, category, title, passed, severity, evidence, remediation}`
และ**ห้าม raise เด็ดขาด** — connection fail = check ที่ fail พร้อม evidence อธิบายว่าทำไม
ผลคือ orchestrator ใน routes.py "โง่" ได้ (แค่เก็บผล) และระบบไม่มีวันล่มเพราะ scanner

| Scanner | ตรวจอะไร | เทคนิค |
| :--- | :--- | :--- |
| `dns_scanner` | DNSSEC (DNSKEY/RRSIG), CAA, NS ≥2 ตัว, wildcard exposure | dnspython, pin resolver 8.8.8.8/1.1.1.1 |
| `tls_scanner` | cert ไม่หมดอายุ **และ chain ไปถึง CA ที่เชื่อถือได้**, เหลือ ≥30 วัน, hostname ตรง SAN/CN, protocol ≥ TLS 1.2, cipher แข็งแรง | **2 handshake:** (1) `CERT_NONE` เพื่อ "ดู" cert แม้เสีย (expiry, hostname, protocol, cipher) (2) `create_default_context()` ตรวจ trust chain (ปิด hostname check เพราะตัดสินแยก) — self-signed/CA ไม่รู้จัก = fail พร้อมเหตุผลจาก OpenSSL; blocking I/O โยนเข้า `asyncio.to_thread` |
| `header_scanner` | HSTS, CSP (มี+ไม่ unsafe-inline ล้วน), X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy | `httpx.AsyncClient` + follow_redirects, **อ่านแค่ header ไม่โหลด body**, retry 1 ครั้งเมื่อ ConnectTimeout/ConnectError (ไม่ retry ถ้า cert เสีย), header ซ้ำ (`nosniff, nosniff`) นับตามความหมาย, check ที่ fail แนบ HTTP status + URL ปลายทาง |
| `email_scanner` | SPF (v=spf1), SPF hardfail (-all), DMARC (_dmarc TXT), DMARC p=quarantine/reject, DKIM ตาม common selectors | DNS TXT queries |
| `port_scanner` | ports เปิดจาก 6 ตัวข้างต้น (โหมด full เท่านั้น, ไม่มีผลต่อคะแนน — info only) | TCP connect, timeout 3s |

### 3.2 Scoring engine (`scoring/engine.py`) — หัวใจของ "AI ไม่ให้คะแนน"

- **Pure function:** input เดิม → output เดิมเสมอ ไม่มี network ไม่มี random
- โหลด `weights.yaml` ครั้งเดียว (lru_cache) แล้ว **validate เข้ม**:
  ผลรวม weight ทุก category ต้อง = 100 เป๊ะ, check ห้ามซ้ำข้าม category,
  grade ห้ามซ้ำ — YAML ผิดคือ app ไม่ยอมทำงาน
- check ที่ scanner ส่งมาแต่**ไม่อยู่ใน rubric** = info-only (ไม่มีผลต่อคะแนน)
- check ที่**อยู่ใน rubric แต่ไม่มีใครส่งมา** = ได้ 0 และ flag `present: false`
  → ช่องโหว่ของ coverage **มองเห็นได้** ไม่ใช่แอบเนียนได้คะแนนฟรี
  (กลไกนี้เคยทำให้เห็นชัดว่า `tls.strong_ciphers` ยังไม่ implement — ตอนนี้
  implement แล้ว ทุก check ใน rubric มี scanner ส่งมาครบ)
- check id ซ้ำ (scanner glitch) → **last-wins** (deterministic)
- breakdown ต่อ category ถูกส่งกลับให้ UI แสดง "ทำไมได้เกรดนี้" ทุกแถว

**Rubric (จำให้ได้):** TLS 30 · Headers 25 · Email 25 · DNS 20 (รวม 100)
**Grade:** ≥95 A+ · ≥85 A · ≥75 B · ≥60 C · ≥40 D · ต่ำกว่านั้น F

### 3.3 AI layer (`ai/`) — ของ Role B แต่ต้องอธิบายได้

- Flow: `routes.py` → `analyzer.analyze_findings(apex findings, context)` →
  `service.explain_scan()` → LangChain + GPT-4o-mini (JSON mode + PydanticOutputParser)
  → output ถูก validate เป็น schema (`AIExplanation`) เสมอ
- **ไม่มี key / ไม่มี langchain / API พัง** → `_fallback_explanation()` สร้างสรุปจาก
  template ในเครื่อง: เรียง findings ที่ fail ตาม severity, หยิบ 8 อันแรก,
  ตั้ง `generated_by_ai: false`, `model_used: "local-fallback"` — ผู้ใช้ได้ผลเสมอ
- `overall_risk` มาจาก **rule-based** (`_risk_from_findings`: มี critical→critical,
  มี high→high, ...) ไม่ใช่ AI ตัดสิน
- ผลที่ UI แสดง: `risk_summary`, `top_issues`, `positive_findings` (สูงสุด 5),
  พร้อม flag ว่า AI จริงหรือ fallback

### 3.4 Database (Week 7 — `db/`)

- `ScanRecord`: scan_id (PK), domain, mode, score, grade, findings_count,
  created_at, **`result_json`** = ScanResponse ทั้งก้อนเก็บเป็น JSON
  → เปิดประวัติย้อนหลังได้ "เหมือนเพิ่งสแกนเสร็จ" โดยไม่ต้อง normalize schema
- codebase เดียวใช้ได้ 2 DB: `DATABASE_URL` ขึ้นต้น `sqlite:///` → aiosqlite,
  `postgresql://`/`postgres://` → asyncpg (rewrite อัตโนมัติ)
- ตารางถูก `create_all` ตอน startup ผ่าน FastAPI lifespan — ยังไม่มี Alembic
  (limitation ที่ยอมรับและ document ไว้)
- ทุกจุดที่แตะ DB ห่อ try/except → **DB ล่ม สแกนไม่ล่ม**

### 3.5 Frontend

React 19 + Vite 8 + TypeScript (strict) + Tailwind — `src/App.tsx` (~1,339 บรรทัด)
คือทั้ง UI: ฟอร์มสแกน (สลับ single/full), หน้า result (การ์ดเกรด, breakdown
ต่อ category, Geo-IP ที่ marked "≈", open ports, การ์ด AI), หน้า History อ่านจาก server
`src/api.ts` = typed client. Dev ใช้ Vite proxy `/api` → backend:8000 (ไม่มีปัญหา CORS)

---

## 4. Design decisions — "ทำไม" ที่กรรมการชอบถาม

1. **ทำไม AI ห้ามให้คะแนน?** — (1) reproducibility: LLM ตอบไม่เท่าเดิม สอบซ้ำไม่ได้
   (2) hallucination: อาจให้เหตุผลมั่ว (3) accountability: rubric ใน YAML ตรวจสอบ/
   อ้างอิงได้ ชี้ได้ว่าคะแนนแต่ละแต้มมาจากไหน (4) cost/latency. AI เก่งสุดที่การ "อธิบาย"
2. **ทำไม worst-host?** — security คือ weakest link: subdomain เก่าๆ ที่ลืมไว้
   คือช่องทางเจาะยอดนิยม ถ้าใช้ average คะแนนจะหลอกว่าปลอดภัย (เรายังโชว์ average คู่กัน)
3. **ทำไม non-intrusive เท่านั้น?** — จริยธรรม+กฎหมาย: เราอ่านเฉพาะสิ่งที่ public
   (DNS records, TLS handshake ปกติ, HTTP headers, CT logs) เหมือน browser ทั่วไปทำ
   ไม่ยิง payload ไม่ brute-force auth (ระวังคำ: **ไม่ใช่ "passive"** เพราะเรามีการ
   connect จริง — TLS/HTTP, TCP 6 ports, resolve wordlist ~120 ชื่อ)
4. **ทำไม rubric เป็น YAML?** — ปรับ weight ได้โดยไม่แตะ Python, มี version ติดไปกับ
   ทุก response, กรรมการ/อาจารย์ตรวจ rubric ได้ตรงๆ
5. **ทำไม async ทั้งระบบ?** — งานคือ network I/O เกือบล้วน: สแกน 4 ด้าน × N hosts
   ถ้า sequential จะช้ามาก; `asyncio.gather` + Semaphore(5) + timeout 20s/host
   ทำให้เร็วแต่ไม่ DoS เป้าหมายและไม่โดน rate-limit
6. **ทำไมไม่ใช้ nmap/sslyze?** — โจทย์คือ "lightweight": pure Python, ไม่ต้อง root,
   deploy ที่ไหนก็ได้ และเราต้องการควบคุม CheckResult contract เองทั้งหมด
7. **ทำไม TLS scanner ทำ 2 handshake?** — handshake แรกตั้ง `CERT_NONE` เพราะถ้าให้ ssl
   validate เอง cert ที่เสียจะ connect ไม่ได้เลย เราต้อง "เห็น" cert เสียเพื่อรายงาน
   (วันหมดอายุ, ชื่อ, protocol, cipher) แต่แบบนี้อย่างเดียวจะไม่รู้ว่า **CA น่าเชื่อถือไหม**
   — validation จับได้ว่า self-signed.badssl.com เคย pass ผิด จึงเพิ่ม handshake ที่ 2
   แบบ verify เพื่อตัดสิน trust (ปิด hostname check เพราะ `hostname_match` ตัดสินแยกแล้ว
   ไม่หักคะแนนซ้ำ)
9. **ทำไมตัดหมวด email ของ subdomain ที่ไม่มี MX?** — www/api ไม่รับเมล การหักคะแนนเพราะไม่มี
   SPF/DMARC ไม่ยุติธรรม จึงคิดคะแนนจากหมวดที่เกี่ยวข้อง (75) แล้วสเกล — แบบเดียวกับที่
   rubric อื่นๆ ใช้ "N/A" แทนการให้ 0
10. **ทำไมจำกัดเวลาทุกขั้น + 25 host?** — ข้อมูลภายนอกโตเรื่อยๆ (crt.sh) และบริการภายนอก
    ช้าได้ (crt.sh, ip-api, OpenAI) ถ้าไม่จำกัด สแกนเดียวค้างได้เป็นนาที — เคยเกิดจริง
8. **ทำไม SQLite+Postgres คู่?** — dev ไม่ต้อง setup อะไรเลย (ไฟล์เดียว auto-create),
   prod ได้ concurrent writes + managed backup; async SQLAlchemy ทำให้สลับด้วย
   env var เดียว

---

## 5. คำถามกรรมการที่น่าจะโดน + แนวตอบ

**Q: ระบบนี้ต่างจาก SSL Labs / securityheaders.com ยังไง?**
A: เครื่องมือพวกนั้นเก่งด้านเดียวและดูทีละ host — ของเรารวม 4 ด้าน + ค้นหา
subdomain อัตโนมัติ + ให้เกรดเดียวที่อธิบายได้ + AI สรุปเป็นภาษาคนสำหรับคนไม่ technical
และเราใช้เครื่องมือพวกนั้นเป็น **baseline validate ความถูกต้อง** — ผลราย check ตรงกัน 97.5%
(เกรดรวมเทียบตรงๆ ไม่ได้เพราะ rubric ต่างกัน เช่น SSL Labs ให้ google.com เกรด B เพราะยังเปิด TLS 1.0/1.1)

**Q: เชื่อคะแนนได้แค่ไหน? วัดความถูกต้องยังไง?**
A: (1) engine deterministic 100% (pure function + rubric versioned) มี test **142 ตัว**
(2) **Repeatability:** สแกน 14 โดเมน × 3 รอบ ได้เกรดเดิม **14/14** (youtube.com full scan ×3 = A/89 ทุกรอบ)
(3) **Accuracy:** เทียบราย check กับเครื่องมืออิสระ **198/203 = 97.5%** — DNS/Email กับ Google DoH 98/98,
TLS กับ SSL Labs 38/39, Headers กับ securityheaders.com 62/66 — แถวที่ไม่ตรงอธิบายได้ทุกแถว
(เว็บส่ง header ต่างกันตามผู้ขอ / SSL Labs ได้ cert คนละใบ) ข้อควรพูดเอง: DNS reference ใช้ข้อมูล
resolver ของ Google เหมือนเรา จึงพิสูจน์ว่า "โค้ดตีความถูก" ไม่ใช่ข้อมูลอิสระ 100%
(4) validation จับบั๊กจริงได้ 2 ตัว (self-signed ผ่านผิด, header ซ้ำ) และแก้แล้วพร้อม regression test

**Q: สแกนโดเมนของคนอื่นถูกกฎหมายไหม?**
A: เราอ่านเฉพาะข้อมูล public ที่ server ยินดีบอกทุกคนอยู่แล้ว (DNS, cert, headers)
ไม่มี exploitation, ไม่ brute-force รหัสผ่าน, port scan เป็นแค่ TCP connect 6 ports
มาตรฐาน + มี concurrency cap + **ไม่ต่อไปยัง IP ภายในเด็ดขาด** — เทียบเท่าที่ browser และ search engine ทำทุกวัน

**Q: ถ้ามีคนใส่โดเมนที่ชี้ไป 192.168.x / 127.0.0.1 เพื่อให้ระบบเราไปสแกนเครือข่ายภายใน (SSRF)?**
A: ทุก host ถูกเช็ค A record ทุกตัวก่อนต่อ ถ้าเป็น IP ภายใน (RFC 1918, loopback, link-local,
CGNAT, multicast) จะไม่ต่อเลย รายงานเป็น `dns.private_ip_exposed` แทน และ port scan ยิงไปที่ IP
ที่ตรวจแล้ว ไม่ใช่ชื่อ (ข้อจำกัดที่พูดตรงๆ: ยังไม่เช็ค AAAA/IPv6 — mfu.ac.th มี AAAA เป็น `::1`)

**Q: ถ้า OpenAI ล่มหรือ key หมดโควต้า?**
A: ระบบไม่สนใจเลย — AI ถูกห่อ try/except และมี local fallback template ที่สร้างสรุป
จาก findings ตรงๆ พร้อม flag `generated_by_ai: false` ให้ผู้ใช้รู้ว่าอันไหนคือ AI จริง

**Q: AI hallucinate ผลตรวจได้ไหม?**
A: input ของ AI คือ findings ที่ตรวจเสร็จแล้วเท่านั้น (JSON) และ output ถูกบังคับ
ผ่าน Pydantic schema + JSON mode — AI เรียบเรียงได้อย่างเดียว สร้างข้อเท็จจริงใหม่
เข้าระบบคะแนนไม่ได้เพราะคะแนนถูกคำนวณจบก่อน AI ทำงานเสมอ

**Q: DKIM ตรวจยังไงในเมื่อไม่รู้ selector?**
A: DKIM ต้องรู้ selector ถึงจะ query ได้ เราจึงลอง common selectors
(default, google, selector1 ฯลฯ) — เจอ = ผ่าน ไม่เจอ = อาจมีแต่เราไม่เห็น
นี่คือเหตุผลที่ DKIM มี weight แค่ 2 จาก 25 ของ email (ยอมรับ limitation ตรงๆ)

**Q: ถ้าโดเมนมี subdomain เป็นพันตัว?**
A: สแกนสูงสุด **25 host** (apex, www, แล้วชื่อสั้นที่สุด) + Semaphore 5 host พร้อมกัน
+ timeout 20s/host + discovery จำกัด 45s — งานถูก bound เสมอ เช่น mfu.ac.th เจอ 223 host
ก็สแกน 25 และ summary บอกว่าเจอเท่าไร สแกนเท่าไร ข้ามเท่าไร timeout ตัวไหน

**Q: เว็บอยู่หลัง Cloudflare/CDN ผลจะเพี้ยนไหม?**
A: TLS/headers ที่เห็นคือของ edge ซึ่งก็คือสิ่งที่ผู้ใช้จริงเจอ จึงถือว่าถูกต้อง
ส่วน Geo-IP จะชี้ตำแหน่ง CDN — UI จึง mark "≈ approximate" และเราบอกว่า
country/ISP/ASN เท่านั้นที่เชื่อถือได้

**Q: สแกนซ้ำได้เกรดต่างกันได้ไหม?**
A: engine ให้ผลเท่าเดิมเสมอกับ input เดิม และเราวัดจริงแล้ว 14/14 โดเมนได้เกรดเดิมทุกรอบ
สิ่งที่เคยทำให้เปลี่ยนคือ network ชั่วคราว (thaigov.go.th เคยได้ C73, C73, D51 เพราะดึง header
timeout ครั้งเดียว) — แก้ด้วย retry 1 ครั้งแล้ว ที่เหลือคือสถานะจริงของเป้าหมายเปลี่ยน ซึ่ง "ควร" สะท้อนในคะแนน

**Q: ทำไมแค่ 6 ports?**
A: ขอบเขตคือ web-facing security posture ไม่ใช่ network audit — 6 ports คือ
พอร์ต HTTP/HTTPS มาตรฐาน+ทางเลือกยอดนิยม และ open ports เป็น **info-only**
ไม่กระทบคะแนน (rubric ไม่มี port checks)

**Q: ข้อจำกัดของระบบมีอะไรบ้าง?** *(ตอบเองก่อนโดนถามจะดูดี)*
A: (1) `tls.strong_ciphers` ตัดสินจาก cipher ที่ negotiate ได้จริงใน handshake
เดียว — ไม่ได้ไล่ probe ทุก suite (2) trust check ไม่ดึง intermediate cert เองแบบ browser
— server ที่ส่ง chain ไม่ครบจะ fail (ถูกสำหรับ client ทั่วไป) (3) SSRF guard ยังไม่ตรวจ AAAA
และ TLS/headers ต่อด้วยชื่อ (ต้องใช้ SNI) จึงมี DNS-rebinding race ในทางทฤษฎี (4) full scan
จำกัด 25 host + ใช้ worst-host (5) host ที่ไม่ใช่เว็บ (ns, ftp) โดนหัก TLS+headers จนคะแนนต่ำ
(6) DKIM เจอเฉพาะ common selectors (7) ไม่มี Alembic (8) Geo-IP location ประมาณการ
(9) บางเว็บส่ง header ต่างกันตามผู้ขอ/ภูมิภาค ผลคือสิ่งที่ scanner ของเราได้รับ

**Q: แผน deploy คืออะไร ทำไมยังไม่ deploy?**
A: architecture ถูกออกแบบให้ deploy-ready แล้ว: Docker images + compose ทั้ง
dev/prod ใน repo, `DATABASE_URL`/CORS สลับด้วย env var, target คือ Railway
(backend+Postgres) + Vercel (frontend) — เรา demo ผ่าน Docker prod stack
บนเครื่องเดียว ซึ่งพฤติกรรมเหมือน production ทุกอย่างยกเว้น domain จริง

**Q: แบ่งงานกันยังไง?**
A: Role A (Pheerathad) — scanners, scoring engine, discovery, DB, FE↔BE integration
· Role B (Muanmet) — AI layer + validation · Role C (Pacharapol) — frontend
dashboard + W7 database ร่วม (ปรับตามจริงก่อนพูด)

---

## 6. ศัพท์ที่ต้องอธิบายได้ใน 1 ประโยค

| ศัพท์ | อธิบาย |
| :--- | :--- |
| **DNSSEC** | ลายเซ็นดิจิทัลบน DNS records กัน DNS spoofing/cache poisoning |
| **CAA** | DNS record ที่ประกาศว่า CA ไหนออก cert ให้โดเมนนี้ได้บ้าง |
| **SPF** | TXT record บอกว่า server ไหนส่งเมลในนามโดเมนนี้ได้; `-all` = hardfail ปฏิเสธที่เหลือ |
| **DKIM** | ลายเซ็นในหัวเมล ตรวจกับ public key ใน DNS (ต้องรู้ selector) |
| **DMARC** | นโยบายว่าถ้า SPF/DKIM ไม่ผ่านให้ทำอะไร; p=reject/quarantine = เข้ม |
| **HSTS** | header บังคับ browser ใช้ HTTPS เท่านั้น กัน SSL-strip |
| **CSP** | header จำกัดแหล่ง script/resource กัน XSS |
| **X-Frame-Options / frame-ancestors** | ห้ามเว็บอื่น iframe เรา กัน clickjacking |
| **Certificate Transparency (crt.sh)** | log สาธารณะของ cert ทุกใบที่ CA ออก — เราใช้หา subdomain แบบ passive |
| **SAN** | รายชื่อ hostname ใน cert ที่ cert ใบนี้คุ้มครอง |
| **TLS 1.2/1.3** | เวอร์ชันโปรโตคอล; 1.0/1.1 ถูก deprecate แล้ว = fail check |
| **asyncio.gather** | รัน coroutine หลายตัวพร้อมกันแล้วรอครบ — หัวใจความเร็วของระบบ |

## 7. ตัวเลขที่ควรจำขึ้นใจ

- Rubric: **TLS 30 / Headers 25 / Email 25 / DNS 20** · Grade: **95 / 85 / 75 / 60 / 40**
- TLS เต็ม **30/30** แล้ว (strong_ciphers implement เสร็จ W8: AEAD + forward
  secrecy, ไม่มี legacy algo เช่น RC4/3DES/MD5, key ≥128 bits; TLS 1.3 ผ่านเสมอ)
- Tests: **142** (offline ยกเว้น 4 live tests ที่ยิง google.com)
- Validation: **14/14** repeatable · **198/203 = 97.5%** agreement (DNS/Email 98/98, TLS 38/39, Headers 62/66)
- Full scan: สูงสุด **25** host, concurrency **5**, timeout **20s**/host (apex **40s + retry**),
  discovery **45s**, Geo-IP **10s**, ports **20s**, AI **30s**, ports **80/443/8080/8443/8000/3000**
- Email N/A → คิดคะแนนจาก **75**
- Resolver pin: **8.8.8.8 / 1.1.1.1** · TLS ขั้นต่ำ **1.2** · cert renewal buffer **30 วัน**
- Stack: Python **3.12** + FastAPI · React **19** + Vite **8** · SQLAlchemy **2.0** async
  · Postgres **16** · GPT-**4o-mini** ผ่าน LangChain **0.3**

## 8. Demo plan โดยไม่ต้อง deploy จริง

1. `docker compose -f docker-compose.prod.yml up --build -d` → เปิด `http://localhost:8080`
   (nginx + built frontend + Postgres — topology เดียวกับ production)
2. เตรียมโดเมนตัวอย่าง 3 ระดับ: เกรดดี (เช่น google.com), กลางๆ (เว็บมหาลัย),
   แย่ (เว็บเก่าที่ไม่มี HSTS/DMARC) — **สแกนล่วงหน้า**เก็บใน History กันเน็ตหอพักพัง
3. โชว์ breakdown ว่าคะแนนโปร่งใสทุกแต้ม → โชว์การ์ด AI → ปิด `OPENAI_API_KEY`
   แล้วสแกนใหม่ให้เห็น fallback ทำงาน (ขายกฎ "ระบบไม่พึ่ง AI")
4. ถ้าโดนถามเรื่อง production จริง: ชี้ compose file + ตาราง env var ใน `docs/DOCKER.md`
   ว่า "เปลี่ยนแค่ URL 2 ตัว"
