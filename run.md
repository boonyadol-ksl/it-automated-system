ติดตั้ง dependency
cd "d:\python\KSL IT Automated System"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

ตั้งค่า Server (.env)
Copy-Item config\server.env.example config\server.env -Force
notepad config\server.env
แก้ KSL_API_KEY=change-me เป็นค่าเช่น KSL_API_KEY=ksl-dev-123

รัน Server
python -m itops.server.run --env-file config\server.env
เช็คว่า server ขึ้น:
เปิด http://127.0.0.1:8800/health (ควรได้ {"status":"ok"})

ตั้งค่า Agent (YAML)
Copy-Item config\agent.yml.example config\agent.yml -Force
notepad config\agent.yml
แก้ api.api_key: ให้ "ตรงกับ" KSL_API_KEY ใน config\server.env

รัน Agent (ส่งข้อมูลเข้า server 1 ครั้ง)
python -m itops.agent.run --config config\agent.yml --policies config\policies.yml --no-jitter --verbose

รัน Scanner
python -m itops.scanner.run --config config\scanner.yml --verbose

ดูข้อมูลที่ถูกเก็บ
http://127.0.0.1:8800
http://127.0.0.1:8800/api/v1/segments
http://127.0.0.1:8800/api/v1/machine/<hostname>/latest
