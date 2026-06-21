# 8-Week Roadmap

| Week | Goal | Deliverable |
|---|---|---|
| **1** | Foundation | Repo + FastAPI + React+Vite รันได้ `/api/scan` คืน mock JSON |
| **2** | DNS + TLS scanners | สอง scanner ทำงานได้จริง + unit tests |
| **3** | Header + Email scanners | ครบทั้ง 4 scanner + parallel `asyncio.gather()` |
| **4** | Scoring Engine | คะแนน 0-100 + grade A-F จาก rules ใน `weights.yaml` |
| **5** | AI Risk Analyzer | LangChain + GPT-4o-mini สรุป finding + แนะนำวิธีแก้ |
| **6** | Frontend Dashboard | หน้า Scan + หน้า Results สวยๆ ด้วย Tailwind |
| **7** | Database + History | PostgreSQL เก็บ scan history + หน้า History |
| **8** | Validate + Deploy | เทียบ 10 โดเมน + deploy ขึ้น Railway/Vercel + เขียน Final Report |

## Buffer
มี ~2 สัปดาห์ buffer ก่อน defense — ใช้สำหรับ bug fix, slide, ซ้อม present

## ขั้นต่อไป (Week 1 — เริ่มทันที)
1. `cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload`
2. `cd frontend && npm install && npm run dev`
3. กรอกโดเมนใน UI → ควรเห็น JSON mock กลับมา
4. Commit แรก: `git init && git add . && git commit -m "feat: Week 1 scaffold"`
