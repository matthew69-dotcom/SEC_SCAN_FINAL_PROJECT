# สรุประบบ Database (W7) — สำหรับตอบอาจารย์

**โปรเจกต์:** AI-Assisted Lightweight Domain Security Checker · MFU Senior Project 2026
**ส่วนงาน:** W7 — Scan-history persistence
**Branch:** `feat/scan-history-db`
**อัปเดต:** 6 ก.ค. 2026

---

## 1. Database ในระบบนี้ทำหน้าที่อะไร (พูดสั้นๆ)

เก็บ **ประวัติการสแกน** ไว้ฝั่ง server ทุกครั้งที่มีคนสแกนโดเมน ผลลัพธ์จะถูกบันทึกลงฐานข้อมูล
ทำให้เปิดดูผลเก่าย้อนหลังได้ และประวัติไม่หายแม้ปิดเบราว์เซอร์หรือเปลี่ยนเครื่อง

**ก่อนหน้านี้:** ประวัติเก็บใน localStorage ของเบราว์เซอร์ (หายเมื่อล้าง cache, ดูข้ามเครื่องไม่ได้)
**ตอนนี้:** เก็บใน database ฝั่ง server → ถาวร, เรียกผ่าน API ได้

---

## 2. เทคโนโลยีที่ใช้

| ส่วน | เทคโนโลยี | เหตุผล |
| :--- | :--- | :--- |
| ORM | SQLAlchemy 2.0 (async) | มาตรฐาน Python, async เข้ากับ FastAPI |
| Dev DB | SQLite (ผ่าน `aiosqlite`) | ไม่ต้องติดตั้งอะไร ไฟล์เดียวจบ เหมาะกับพัฒนา/เทสต์ |
| Prod DB | PostgreSQL (ผ่าน `asyncpg`) | ทนโหลด รองรับหลาย connection ตอน deploy จริง |

**จุดสำคัญ:** โค้ดชุดเดียวใช้ได้ทั้งสอง DB — สลับด้วยตัวแปร `DATABASE_URL` เท่านั้น ไม่ต้องแก้โค้ด

---

## 3. โครงสร้างไฟล์ (`backend/app/db/`)

```
app/db/
├── database.py   # async engine + session, เลือก driver อัตโนมัติจาก DATABASE_URL
├── models.py     # ตาราง ScanRecord
├── crud.py       # ฟังก์ชัน create / list / get / delete
└── __init__.py
```

---

## 4. ตารางเก็บอะไรบ้าง (model `ScanRecord`)

| คอลัมน์ | ชนิด | ความหมาย |
| :--- | :--- | :--- |
| `scan_id` | String (PK) | รหัสสแกน (UUID) |
| `domain` | String | โดเมนที่สแกน |
| `mode` | String | single / full |
| `score` | Integer | คะแนน 0-100 |
| `grade` | String | เกรด A+ ถึง F |
| `findings_count` | Integer | จำนวนข้อค้นพบ |
| `created_at` | DateTime | เวลาที่สแกน |
| `result_json` | JSON | **ผลลัพธ์เต็มทั้งก้อน** (เก็บเป็น JSON) |

**ทำไมเก็บ `result_json` ทั้งก้อน:** เวลาเปิดดูรายงานเก่า จะได้ข้อมูลครบเหมือนตอนสแกนจริง (findings, breakdown, hosts, AI summary) โดยไม่ต้องแตกเป็นหลายตาราง — เรียบง่ายและใช้ได้ทั้ง SQLite/Postgres

---

## 5. API ที่เพิ่มเข้ามา

| Method | Endpoint | หน้าที่ |
| :--- | :--- | :--- |
| POST | `/api/scan` | สแกน + **บันทึกลง DB อัตโนมัติ** |
| GET | `/api/scans` | ดึงประวัติล่าสุด (ใหม่สุดก่อน) |
| GET | `/api/scans/{id}` | ดึงผลเต็มของสแกนหนึ่งรายการ |
| DELETE | `/api/scans/{id}` | ลบประวัติหนึ่งรายการ |

Frontend หน้า History เรียก 3 endpoint นี้แทนการอ่าน localStorage

---

## 6. หลักการออกแบบสำคัญ (อาจารย์มักถามจุดนี้)

1. **การสแกนต้องไม่ล้มเพราะ DB** — การบันทึกลง DB ถูกหุ้มด้วย `try/except` ทั้งหมด ถ้า DB ล่ม ระบบจะ log ไว้แล้วสแกนต่อได้ปกติ (แค่ไม่บันทึกประวัติ) การสแกนคืองานหลัก ห้ามพังเพราะงานรอง
2. **สร้างตารางอัตโนมัติ** — ตอน start server จะเช็คและสร้างตารางให้เอง (`create_all`) ผู้ใช้ไม่ต้องรันคำสั่งสร้าง DB เอง
3. **Dev/Prod ใช้โค้ดเดียวกัน** — แยกด้วย `DATABASE_URL` ลดความต่างระหว่างเครื่องพัฒนากับ production
4. **ประวัติของใครของมัน** — ไฟล์ `dev.db` ไม่ขึ้น git (อยู่ใน .gitignore) แต่ละคนมี DB ของตัวเอง ข้อมูลไม่ปนกัน

---

## 7. ประโยคตอบคำถามที่อาจารย์น่าจะถาม

**Q: ทำไมใช้ SQLite ตอนพัฒนา แต่ PostgreSQL ตอน deploy?**
A: SQLite เป็นไฟล์เดียว ไม่ต้องติดตั้ง server เหมาะกับพัฒนา/เทสต์ให้เร็ว ส่วน PostgreSQL ทนหลาย connection พร้อมกันได้ เหมาะกับใช้งานจริงบน cloud เราออกแบบให้โค้ดรองรับทั้งคู่ สลับด้วย config ตัวเดียว ไม่ต้องแก้โค้ด

**Q: ถ้า database ล่ม ระบบพังไหม?**
A: ไม่พัง การบันทึกลง DB หุ้ม try/except ไว้ ถ้าเชื่อม DB ไม่ได้ ระบบจะ log แล้วสแกนต่อได้ปกติ แค่ไม่มีประวัติเก็บไว้

**Q: ทำไมเก็บผลเป็น JSON ทั้งก้อน ไม่แยกตาราง?**
A: เพื่อให้เปิดดูรายงานเก่าได้ครบเหมือนเดิม และรองรับทั้ง SQLite/Postgres ง่าย สำหรับสเกลของโปรเจกต์นี้ (เก็บประวัติเพื่อเรียกดู ไม่ได้ query ลึกในแต่ละ finding) การเก็บ JSON เหมาะสมและเรียบง่ายกว่า

**Q: ใช้ async ทำไม?**
A: FastAPI และ scanner ทั้งหมดเป็น async อยู่แล้ว การใช้ async DB (SQLAlchemy async + asyncpg/aiosqlite) ทำให้ไม่มีการ block ระหว่างรอ DB สอดคล้องกับสถาปัตยกรรมทั้งระบบ

**Q: มี migration ไหม (เวลาแก้โครงสร้างตาราง)?**
A: ตอนนี้ใช้ `create_all` สร้างตารางตอน start ซึ่งพอสำหรับสเกลนี้ ถ้าต่อยอดในอนาคตสามารถเพิ่ม Alembic เพื่อจัดการ migration ได้ (บันทึกไว้เป็น known limitation)

---

## 8. การทดสอบ

- ไฟล์เทสต์ใหม่ `tests/test_db.py` — 5 เทสต์: create, list (เรียงใหม่สุดก่อน), get ที่ไม่มี, delete, delete ที่ไม่มี
- ใช้ SQLite ชั่วคราวแยกต่อเทสต์ ไม่แตะ `dev.db` จริง
- รวมทั้ง backend **56/56 เทสต์ผ่าน** (51 เดิม + 5 ใหม่)
- ทดสอบ endpoint `GET`/`DELETE /api/scans` ผ่าน TestClient แล้ว

---

## 9. วิธีรัน (สรุปสั้น)

```
cd backend
pip install -r requirements.txt      # เพิ่ม sqlalchemy, aiosqlite, asyncpg, greenlet
uvicorn app.main:app --reload        # dev.db สร้างอัตโนมัติตอน start
```

ตอน deploy บน Railway: ตั้งตัวแปร `DATABASE_URL` เป็น PostgreSQL connection string ก็ใช้ได้ทันที ไม่ต้องแก้โค้ด

---

## 10. Known limitations

1. ยังไม่ผูก Alembic migration — ใช้ `create_all` ตอน startup (พอสำหรับสเกลปัจจุบัน)
2. เก็บผลเป็น JSON ทั้งก้อน — ไม่เหมาะถ้าต้อง query เจาะลึกในแต่ละ finding (ไม่ใช่ use case ของโปรเจกต์นี้)
3. ยังไม่มีระบบ auth — ประวัติทุกคนอยู่รวมกันในฐานเดียว (ตรงกับ design "open access" ของโปรเจกต์)
