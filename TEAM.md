# Team Roles & Work Split

แบ่งงาน 3 คน สำหรับโปรเจค **AI-Assisted Lightweight Domain Security Checker**

> โครงสร้างของระบบแบ่งเป็น 3 ก้อนที่ทำงานขนานกันได้: **Scanners** (รวบรวมข้อมูลดิบ), **AI + Scoring** (วิเคราะห์ + ให้คะแนน), และ **Frontend + DevOps** (แสดงผล + deploy) เลือกคนละก้อนแล้วเดินคู่ขนาน

---

## 3 บทบาทหลัก

### 👤 Role A — Backend Scanners & Scoring
**เจ้าของ:** Pheerathad Pangputhipong (6631501086)

**ดูแล:**
- ทุก scanner ใน `backend/app/scanners/` (DNS, TLS, Headers, Email)
- Scoring engine ใน `backend/app/scoring/`
- API endpoints ใน `backend/app/api/`
- Unit tests สำหรับ scanner ทุกตัว

**ทักษะที่ใช้:** Python, async/await, network protocols (DNS, TLS, HTTP)

---

### 👤 Role B — AI Integration & Validation
**เจ้าของ:** _____________

**ดูแล:**
- LangChain + OpenAI integration ใน `backend/app/ai/`
- Prompt engineering (ทำให้ AI ตอบแม่นและตามรูปแบบ)
- Markdown report rendering
- Validation testing (เทียบกับ SSL Labs, securityheaders.com, MXToolbox)
- ตาราง accuracy / FP / FN

**ทักษะที่ใช้:** Python, prompt design, ความเข้าใจ security (เพื่อ tune AI)

---

### 👤 Role C — Frontend & DevOps
**เจ้าของ:** _____________

**ดูแล:**
- React UI ใน `frontend/src/`
- Tailwind styling, responsive design
- Database layer (PostgreSQL + SQLAlchemy) ใน `backend/app/db/`
- Docker setup
- Cloud deployment (Railway สำหรับ backend, Vercel สำหรับ frontend)
- เอกสาร: README, User Manual, Final Report, Slides

**ทักษะที่ใช้:** React, TypeScript, Tailwind, Docker, deployment basics

---

## แผนรายสัปดาห์ (ขนานกัน 3 ช่อง)

| สัปดาห์ | 👤 A — Scanners | 👤 B — AI | 👤 C — Frontend & DevOps |
|:---:|---|---|---|
| **W3** | Header Scanner + Email Scanner | อ่าน LangChain docs / ออกแบบ prompt ใน Notion | ปรับ UI ให้สวยขึ้น + แยก component |
| **W4** | Scoring Engine (rule-based) + `weights.yaml` | สร้าง prompt v1 + ทดลองรันด้วย mock data | สร้าง History page (mockup, ใช้ dummy data) |
| **W5** | refactor + tests | LangChain pipeline + JSON output parser + wiring เข้า routes | Docker Compose + ไฟล์ env สำหรับ team |
| **W6** | เพิ่ม checks ที่ขาด + improve evidence text | tune prompt จนได้ output คุณภาพ | Render markdown ใน UI สวยๆ + responsive |
| **W7** | optimize parallel scanning | finalize prompt + handle error / timeout | PostgreSQL integration + History endpoint + UI |
| **W8** | run scans 10 โดเมน → ส่งให้ B ทำ validation | สร้างตาราง validation + เขียน Final Report ส่วน Results | Deploy backend (Railway) + frontend (Vercel) + เขียน User Manual |

---

## Git Workflow (สำคัญที่สุดเพื่อไม่ทับงานกัน)

### Branch strategy

```
main                           ← code ที่ใช้ได้แน่ๆ (deploy ได้)
├── feat/scanner-headers       ← A กำลังทำ Header scanner
├── feat/ai-langchain          ← B กำลังทำ AI
└── feat/frontend-results-ui   ← C กำลังปรับ UI
```

### กฎข้อตกลง

1. **ห้าม commit ลง `main` ตรงๆ** ทุกอย่างผ่าน Pull Request
2. **ตั้งชื่อ branch:** `feat/<สิ่งที่ทำ>` หรือ `fix/<bug>` หรือ `docs/<doc>`
3. **Commit message ใช้ Conventional Commits:**
   - `feat: add HSTS header check`
   - `fix: handle expired cert without raising`
   - `docs: update ROADMAP for Week 4`
   - `test: add fixture for dns_scanner`
4. **PR ต้องให้อีกคนหนึ่ง review ก่อน merge** (อย่างน้อย 1 approve)
5. **Pull จาก `main` มา rebase บน branch ตัวเองทุกวัน** ก่อนเริ่มทำงาน:
   ```cmd
   git checkout main
   git pull
   git checkout feat/your-branch
   git rebase main
   ```

### Daily flow

```cmd
# เช้า — เริ่มทำงาน
git checkout main
git pull
git checkout -b feat/whatever-im-doing-today

# เขียนโค้ด, test...

# เย็น — push
git add .
git commit -m "feat: ..."
git push -u origin feat/whatever-im-doing-today
# แล้วเปิด Pull Request บน GitHub
```

---

## Sync Routine (เพื่อไม่ให้หลงทาง)

### Daily — แชต Discord/Line สั้นๆ (5 นาที)
- เมื่อวาน: ทำอะไรเสร็จ
- วันนี้: จะทำอะไร
- ติด: มีอะไรค้างไหม

### Weekly — ประชุมจริง 30 นาที (วันอาทิตย์เย็น)
- demo ที่ทำในสัปดาห์
- ดู ROADMAP สัปดาห์ถัดไป
- decide ว่าใครรับงานไหน

---

## Interface Contracts (สิ่งที่ทุกคนต้องเคารพ)

เพื่อให้ทำขนานกันได้ ทุกคน **ต้องเคารพ interface** เหล่านี้:

### 1. Scanner output (Role A → Role B + scoring)
ทุก scanner คืน `list[CheckResult]` ที่มี keys ตามนี้เสมอ (อยู่ใน `scanners/base.py`):
```python
{
  "id": "tls.cert_valid",
  "category": "tls" | "dns" | "headers" | "email",
  "title": "...",
  "passed": bool,
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "evidence": "...",
  "remediation": "...",
}
```

### 2. AI input/output (Role B)
- **Input:** rawJSON ของ scanner findings
- **Output:** JSON ตาม `Pydantic` schema (มี summary + per-finding explanation)
- AI **ห้าม** แตะ `score` (คะแนนคำนวณ deterministic)

### 3. API response (Role A + B → Role C)
หน้าตา response ของ `/api/scan` อยู่ใน `backend/app/api/schemas.py` คลาส `ScanResponse` — ห้ามเปลี่ยน fields โดยไม่บอก Role C ก่อน

---

## ของที่ต้องตั้งก่อนเริ่มทำงาน

ทำ **ครั้งเดียวร่วมกัน:**

1. **สร้าง GitHub repo** (private หรือ public ก็ได้)
2. **Push code ปัจจุบันขึ้น:**
   ```cmd
   cd "D:\FINAL PROJECT SEC SCAN"
   git init
   git add .
   git commit -m "feat: Week 1+2 scaffold + DNS/TLS scanners"
   git branch -M main
   git remote add origin <your-github-url>
   git push -u origin main
   ```
3. **เพิ่มเพื่อนเป็น Collaborator** (Settings → Collaborators → Add)
4. **เปิด Branch Protection** บน `main` (Settings → Branches → require PR review)
5. **สร้าง Discord/Line group** สำหรับ daily sync
6. **เลือกบทบาท** ใส่ชื่อในตารางด้านบน
