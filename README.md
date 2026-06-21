# Domain Security Checker

AI-Assisted Lightweight Domain Security Checker — senior project, MFU 2026.

## Stack
- **Backend:** FastAPI (Python 3.11+), LangChain + OpenAI
- **Frontend:** React 18 + Vite + TypeScript + Tailwind CSS
- **DB:** PostgreSQL (added in Week 7)
- **Deploy:** Railway (backend) + Vercel (frontend)

## Quick Start

### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    |    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env             # ใส่ OPENAI_API_KEY ของคุณ
uvicorn app.main:app --reload --port 8000
```

เปิด http://localhost:8000/docs จะเห็น Swagger UI

### Frontend
```bash
cd frontend
npm install
npm run dev
```

เปิด http://localhost:5173

## Project Structure
```
backend/
  app/
    main.py            # FastAPI entry
    config.py          # env vars
    api/
      routes.py        # /api/scan, /api/health
      schemas.py       # Pydantic models
    scanners/          # Week 2-3
    scoring/           # Week 4
    ai/                # Week 5
    db/                # Week 7
  tests/

frontend/
  src/
    App.tsx
    api.ts
    main.tsx
```

ดู [ROADMAP.md](./ROADMAP.md) สำหรับแผน 8 สัปดาห์
