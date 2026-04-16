# IT Automated System

ระบบ IT Operations อัตโนมัติสำหรับองค์กร รองรับหลาย VLAN  
Built with **FastAPI + SQLite + HTMX + Tailwind CSS**

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **Network Scanner** — Auto-discover Windows PCs ในทุก VLAN ผ่าน NetBIOS/SMB
- **Agent** — เก็บข้อมูล hardware, software, checklist, metrics จากแต่ละเครื่อง
- **Analysis Engine** — วิเคราะห์ compliance score, security risks, performance issues
- **Help Desk** — Ticket system พร้อม auto-enrich ข้อมูลเครื่องอัตโนมัติ
- **Remote Actions** — สั่ง clear_temp, check_software, kill_process ผ่าน UI
- **WMI Collect** — ดึงข้อมูลเครื่องที่ไม่มี agent ผ่าน PowerShell remoting
- **PDF Report** — Generate รายงานตรวจสอบเครื่อง (KKS-FP-PD02-06)
- **Web UI** — Dashboard, Machines, Tickets, Scan, Settings ผ่าน browser

---

## โครงสร้าง

```
itops/
├── server/         # FastAPI server + Web UI
│   ├── app.py      # API endpoints
│   ├── ui.py       # UI routes (HTMX)
│   ├── db.py       # SQLite store
│   └── templates/  # HTML templates
├── agent/          # Agent รันบนแต่ละเครื่อง
│   ├── collector.py  # เก็บข้อมูล hardware/software
│   ├── actions.py    # รัน remote actions
│   └── run.py        # Entry point
├── scanner/        # Network scanner
│   ├── scanner.py    # Ping + NetBIOS scan
│   └── wmi_collector.py  # Agentless WMI collect
├── analysis/       # Analysis engine
│   └── engine.py   # Rule-based compliance check
├── helpdesk/       # Help desk logic
└── report/         # PDF report generator
config/
├── server.env.example
├── agent.yml.example
├── network_segments.yml.example
├── scanner.yml.example
└── policies.yml
```

---

## Quick Start

### Requirements
- Python 3.10+
- Windows (agent/scanner ใช้ WMI/NetBIOS)

### 1. Clone & Install

```powershell
git clone https://github.com/<your-username>/it-automated-system.git
cd "it-automated-system"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. ตั้งค่า

```powershell
# Server config
Copy-Item config\server.env.example config\server.env
# แก้ API_KEY ใน config\server.env

# Agent config
Copy-Item config\agent.yml.example config\agent.yml
# แก้ api.api_key ให้ตรงกับ API_KEY

# Network segments
Copy-Item config\network_segments.yml.example config\network_segments.yml
# แก้ CIDR ให้ตรงกับ network จริง

# Scanner config
Copy-Item config\scanner.yml.example config\scanner.yml
```

### 3. รัน Server

```powershell
python -m itops.server.run --env-file config\server.env
```

เปิด browser: **http://127.0.0.1:8800**

### 4. รัน Agent (แต่ละเครื่อง)

```powershell
python -m itops.agent.run --config config\agent.yml --policies config\policies.yml --no-jitter --verbose
```

### 5. Scan Network

```powershell
python -m itops.scanner.run --config config\scanner.yml --verbose
```

หรือกดปุ่ม **Scan Network** ใน Web UI

---

## Web UI

| หน้า | URL | คำอธิบาย |
|------|-----|-----------|
| Dashboard | `/` | ภาพรวม segments, tickets, compliance |
| Machines | `/ui/machines` | รายชื่อเครื่องทั้งหมด + compliance score |
| Machine Detail | `/ui/machines/{hostname}` | ข้อมูลเครื่อง + remote actions |
| Help Desk | `/ui/tickets` | Ticket management |
| Network Scan | `/ui/scan` | ผล scan แต่ละ VLAN |
| Settings | `/ui/settings` | แก้ config ทั้งหมดผ่าน UI |

---

## API Endpoints

```
POST /api/v1/ingest                          # Agent ส่งข้อมูล
GET  /api/v1/machine/{hostname}/latest       # ข้อมูลล่าสุด
GET  /api/v1/machine/{hostname}/analyze      # วิเคราะห์ compliance
GET  /api/v1/machine/{hostname}/report       # PDF report
POST /api/v1/machine/{hostname}/command      # สั่ง remote action
POST /api/v1/scan/start                      # เริ่ม network scan
GET  /api/v1/scan/status                     # สถานะ scan
POST /api/v1/tickets                         # สร้าง ticket
GET  /api/v1/tickets                         # รายการ tickets
```

---

## Role-based Software Policy

แก้ได้ที่ `config/policies.yml`:

```yaml
roles:
  office_user:
    required: ["Microsoft Office", "Antivirus", "VPN Client"]
    forbidden: ["uTorrent", "TeamViewer", "AnyDesk"]
  developer:
    required: ["Git", "VS Code"]
    forbidden: ["Pirated Software"]
```

---

## Deploy Agent ด้วย Task Scheduler

```powershell
schtasks /Create /TN "IT_Agent" /TR "python -m itops.agent.run --config C:\agent\config\agent.yml --policies C:\agent\config\policies.yml" /SC HOURLY /MO 4 /F
```

---

## License

MIT — ใช้งานได้อิสระ ยินดีรับ contribution
