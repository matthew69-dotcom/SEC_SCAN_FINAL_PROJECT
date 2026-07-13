# คู่มือเข้าใจโปรเจกต์แบบลึก + เตรียมตอบกรรมการ (ภาษาไทย)

> สำหรับทีมใช้อ่านก่อน present. อิงจาก **โค้ดจริง** ณ ก.ค. 2026 ไม่ใช่แค่เอกสาร
> คู่กับ `docs/ARCHITECTURE.md` (English) และ `PROJECT_MAP.md`

---

## 1. Elevator pitch (พูดได้ใน 30 วินาที)

> "ระบบของเราเป็นเว็บที่รับชื่อโดเมน 1 ชื่อ แล้วตรวจความปลอดภัยแบบ **passive**
> (ไม่โจมตี ไม่ยิง exploit) ครอบคลุม 4 ด้าน: **DNS, TLS/HTTPS, HTTP security headers,
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
1. `_scan_single_host()` ยิง scanner 4 ตัวพร้อมกันด้วย `asyncio.gather(..., return_exceptions=True)`
   — ถ้าตัวไหน crash จะกลายเป็น check `scan.error` ที่ fail ไม่ใช่ HTTP 500
2. รวม `CheckResult` ทั้งหมด → `score_checks()` ให้คะแนน+เกรด
3. ประกอบ `ScanResponse` (มี version info: app + AI model + rubric version)
4. `_save_scan()` บันทึกลง DB **ใน try/except** — DB ตายก็สแกนได้ (กฎข้อ 6)

### mode="full" (เพิ่มจาก single)
1. **Discovery** — `enumerate_hosts()` รวม 3 แหล่งพร้อมกัน:
   crt.sh (Certificate Transparency logs), DNS mining, wordlist
   → ตัด wildcard (`*.x.com`), dedup, แล้ว **resolve A record** เพื่อพิสูจน์ว่า host มีจริง
   (resolver ถูก pin ไว้ที่ 8.8.8.8 / 1.1.1.1, resolve พร้อมกันสูงสุด 20)
2. สแกนทุก host พร้อมกัน แต่คุมด้วย `Semaphore(5)` (MAX_HOST_CONCURRENCY)
   + timeout ต่อ host 20 วินาที — host ที่ timeout/พังจะถูกนับเป็น `hosts_failed`
3. **Geo-IP** ทุก IP พร้อมกัน (ip-api.com) → location(≈), ISP, ASN
4. **Port scan** ทุก host พร้อมกัน — TCP connect ธรรมดา (`asyncio.open_connection`)
   เช็คแค่ 6 ports: 80, 443, 8080, 8443, 8000, 3000 (ไม่ใช้ raw socket ไม่ต้อง root)
5. **Aggregate:** `domain_score = คะแนน host ที่แย่ที่สุด (min)` + คำนวณ average ให้ดูด้วย
   ส่วนหน้า result หลักแสดงผลของ **apex domain** (โดเมนที่ผู้ใช้พิมพ์)
6. **AI** — `analyze_findings()` วิเคราะห์ findings ของ apex host เท่านั้น
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
| `tls_scanner` | cert มีจริง+ไม่หมดอายุ, เหลือ ≥30 วัน, hostname ตรง SAN/CN, protocol ≥ TLS 1.2 | manual handshake ด้วย `ssl`+`socket` (ตั้ง `CERT_NONE` เพื่อ "ดู" cert ที่เสียได้ — **scanner เป็นคนตัดสิน ไม่ใช่ ssl library**), parse ด้วย `cryptography.x509`, blocking I/O โยนเข้า `asyncio.to_thread` |
| `header_scanner` | HSTS, CSP (มี+ไม่ unsafe-inline ล้วน), X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy | `httpx.AsyncClient` + follow_redirects |
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
  (นี่คือเหตุผลที่ `tls.strong_ciphers` ที่ยังไม่ implement ทำให้ TLS เต็มแค่ 24/30)
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
3. **ทำไม passive เท่านั้น?** — จริยธรรม+กฎหมาย: เราอ่านเฉพาะสิ่งที่ public
   (DNS records, TLS handshake ปกติ, HTTP headers, CT logs) เหมือน browser ทั่วไปทำ
   ไม่ยิง payload ไม่ brute-force auth — สแกนโดเมนคนอื่นได้โดยไม่ผิด
4. **ทำไม rubric เป็น YAML?** — ปรับ weight ได้โดยไม่แตะ Python, มี version ติดไปกับ
   ทุก response, กรรมการ/อาจารย์ตรวจ rubric ได้ตรงๆ
5. **ทำไม async ทั้งระบบ?** — งานคือ network I/O เกือบล้วน: สแกน 4 ด้าน × N hosts
   ถ้า sequential จะช้ามาก; `asyncio.gather` + Semaphore(5) + timeout 20s/host
   ทำให้เร็วแต่ไม่ DoS เป้าหมายและไม่โดน rate-limit
6. **ทำไมไม่ใช้ nmap/sslyze?** — โจทย์คือ "lightweight": pure Python, ไม่ต้อง root,
   deploy ที่ไหนก็ได้ และเราต้องการควบคุม CheckResult contract เองทั้งหมด
7. **ทำไม TLS scanner ตั้ง CERT_NONE?** — ไม่ใช่ความประมาท: ถ้าให้ ssl validate เอง
   cert ที่หมดอายุจะ connect ไม่ได้เลย เราต้อง "เห็น" cert เสียเพื่อรายงานมันเป็น finding
   (scanner เป็นผู้ตัดสิน ไม่ใช่ library)
8. **ทำไม SQLite+Postgres คู่?** — dev ไม่ต้อง setup อะไรเลย (ไฟล์เดียว auto-create),
   prod ได้ concurrent writes + managed backup; async SQLAlchemy ทำให้สลับด้วย
   env var เดียว

---

## 5. คำถามกรรมการที่น่าจะโดน + แนวตอบ

**Q: ระบบนี้ต่างจาก SSL Labs / securityheaders.com ยังไง?**
A: เครื่องมือพวกนั้นเก่งด้านเดียวและดูทีละ host — ของเรารวม 4 ด้าน + ค้นหา
subdomain อัตโนมัติ + ให้เกรดเดียวที่อธิบายได้ + AI สรุปเป็นภาษาคนสำหรับคนไม่ technical
และเราใช้เครื่องมือพวกนั้นเป็น **baseline validate ความถูกต้อง** ของเราใน W8

**Q: เชื่อคะแนนได้แค่ไหน? วัดความถูกต้องยังไง?**
A: คะแนน deterministic 100% (pure function + rubric versioned) มี unit test 56 ตัว
ครอบคลุม engine และ scanner ทุกตัวแบบ offline และแผน W8 คือเทียบผลกับ SSL Labs /
securityheaders.com / MXToolbox เป็น external validation

**Q: สแกนโดเมนของคนอื่นถูกกฎหมายไหม?**
A: เราอ่านเฉพาะข้อมูล public ที่ server ยินดีบอกทุกคนอยู่แล้ว (DNS, cert, headers)
ไม่มี exploitation, ไม่ brute-force รหัสผ่าน, port scan เป็นแค่ TCP connect 6 ports
มาตรฐาน + มี concurrency cap — เทียบเท่าที่ browser และ search engine ทำทุกวัน

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
A: Semaphore จำกัด 5 host พร้อมกัน + timeout 20s/host + dedup + ตัด host
ที่ resolve ไม่ได้ตั้งแต่ discovery — งานถูก bound เสมอ host ที่พังนับเป็น hosts_failed
และรายงานให้เห็น

**Q: เว็บอยู่หลัง Cloudflare/CDN ผลจะเพี้ยนไหม?**
A: TLS/headers ที่เห็นคือของ edge ซึ่งก็คือสิ่งที่ผู้ใช้จริงเจอ จึงถือว่าถูกต้อง
ส่วน Geo-IP จะชี้ตำแหน่ง CDN — UI จึง mark "≈ approximate" และเราบอกว่า
country/ISP/ASN เท่านั้นที่เชื่อถือได้

**Q: สแกนซ้ำได้เกรดต่างกันได้ไหม?**
A: engine ให้ผลเท่าเดิมเสมอกับ input เดิม สิ่งเดียวที่เปลี่ยนได้คือสถานะจริงของ
เป้าหมาย (เช่น cert เพิ่งต่ออายุ) ซึ่งเป็นการเปลี่ยนที่ "ควร" สะท้อนในคะแนน

**Q: ทำไมแค่ 6 ports?**
A: ขอบเขตคือ web-facing security posture ไม่ใช่ network audit — 6 ports คือ
พอร์ต HTTP/HTTPS มาตรฐาน+ทางเลือกยอดนิยม และ open ports เป็น **info-only**
ไม่กระทบคะแนน (rubric ไม่มี port checks)

**Q: ข้อจำกัดของระบบมีอะไรบ้าง?** *(ตอบเองก่อนโดนถามจะดูดี)*
A: (1) `tls.strong_ciphers` ยังไม่ implement — TLS เต็มแค่ 24/30 (แผน W8)
(2) ไม่มี Alembic — schema เปลี่ยนต้องสร้าง DB ใหม่ (3) DKIM เจอเฉพาะ common
selectors (4) Geo-IP location ประมาณการ (5) ผล external validation อยู่ระหว่าง W8

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
- TLS ตอนนี้เต็ม **24/30** (strong_ciphers 6 ยังไม่ implement)
- Tests: **56/56 ผ่าน แบบ offline ทั้งหมด**
- Full scan: concurrency **5** hosts, timeout **20s**/host, ports **80/443/8080/8443/8000/3000**
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
