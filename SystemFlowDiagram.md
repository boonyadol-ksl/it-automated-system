┌─────────────────────────────────────────────────────────────────┐
│                         AGENT LAYER                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Collect   │───►│   Compile   │───►│  Submit with Jitter │  │
│  │   Data      │    │   Payload   │    │  (Randomized Delay) │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         API LAYER                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Receive   │───►│   Store     │───►│   AI Analysis       │  │
│  │   Payload   │    │   Raw Data  │    │   Engine            │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│                                               │                 │
│                                               ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │  Trigger    │◄───│   Decision  │◄───│   Pattern Detection │  │
│  │  Automation │    │   Engine    │    │   (Segment-wide)    │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AUTOMATION LAYER                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Queue     │───►│   Execute   │───►│   Verify Result     │  │
│  │   Actions   │    │   Remotely  │    │   (Pull Model)      │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │  Real-time  │    │  Executive  │    │   Alerting          │  │ 
│  │  Dashboard  │    │  Reports    │    │   (Email/Slack)     │  │ 
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

| Layer          | Security Measure                                     |
| -------------- | ---------------------------------------------------- |
| **Agent**      | Code signing, obfuscation, tamper detection          |
| **Transport**  | mTLS 1.3, certificate pinning                        |
| **API**        | JWT tokens, rate limiting, IP whitelist              |
| **Database**   | Encryption at rest, row-level security               |
| **Automation** | Pull model (no inbound), signed commands, audit logs |

ผมจะออกแบบระบบ IT Asset Management & Self-Healing Infrastructure ที่ครอบคลุมทั้งหมดตามข้อกำหนดที่คุณให้มา โดยแบ่งเป็น 5 ส่วนหลัก:

---

## 🏗️ System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CENTRAL INFRASTRUCTURE                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   FastAPI   │  │ PostgreSQL  │  │   Redis     │  │   Web Dashboard     │ │
│  │   Server    │◄─┤  (Primary)  │◄─┤  (Cache/   │  │   (React/Vue)       │ │
│  │             │  │             │  │  Queue)     │  │                     │ │
│  └──────┬──────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                                                                   │
│         ▼                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    AI Analysis Engine (Python)                       │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │  Anomaly    │  │  Policy     │  │   Threat    │  │ Automation │  │    │
│  │  │  Detection  │  │  Engine     │  │   Intel     │  │ Decision   │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ▲
                                      │ HTTPS/MTLS
┌─────────────────────────────────────┼─────────────────────────────────────┐
│                         NETWORK SEGMENTS (VLANs)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│  │ 10.7.30.x   │  │ 10.8.10.x   │  │ 10.9.20.x   │  │   ...       │      │
│  │ (Office)    │  │(Accounting) │  │(Production) │  │             │      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘      │
│         │                │                │                │              │
│    ┌────┴────┐      ┌────┴────┐      ┌────┴────┐      ┌────┴────┐        │
│    │ Agent x │      │ Agent x │      │ Agent x │      │ Agent x │        │
│    │ Agent y │      │ Agent y │      │ Agent y │      │ Agent y │        │
│    │ Agent z │      │ Agent z │      │ Agent z │      │ Agent z │        │
│    └─────────┘      └─────────┘      └─────────┘      └─────────┘        │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 1️⃣ Data Collection Layer (Python Agent)

### Agent Architecture (Per Machine)

```python
# agent/core/collector.py
import psutil
import wmi
import winreg
import requests
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import random
import time

@dataclass
class AssetData:
    hostname: str
    ip: str
    network_segment: str
    role: str  # office_user, accounting, production_pc, developer
    os: str
    cpu: str
    ram_gb: float
    disk_total_gb: float
    disk_free_gb: float
    bios_date: str
    last_seen: str

@dataclass
class ChecklistData:
    antivirus: str  # installed/not_installed/outdated
    admin_rights: bool
    internet_access: bool
    wmi_service: str
    vnc_status: str
    disk_cleanup: bool

@dataclass
class MetricsData:
    cpu_usage: float
    ram_usage: float
    disk_usage_percent: float

class SystemCollector:
    def __init__(self, config_path: str = "agent_config.json"):
        self.config = self._load_config(config_path)
        self.role = self.config.get("role", "office_user")
        self.api_endpoint = self.config.get("api_url")
        self.api_key = self.config.get("api_key")
        
    def _load_config(self, path: str) -> dict:
        """Load role-based configuration from GPO or local file"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            # Fallback: detect role from AD group or hostname pattern
            return self._detect_role_from_environment()
    
    def _detect_role_from_environment(self) -> dict:
        """Auto-detect machine role from Active Directory or naming convention"""
        import socket
        hostname = socket.gethostname().lower()
        
        role_map = {
            'acc': 'accounting',
            'fin': 'accounting', 
            'dev': 'developer',
            'prd': 'production_pc',
            'prod': 'production_pc',
            'off': 'office_user'
        }
        
        detected_role = 'office_user'  # default
        for key, role in role_map.items():
            if key in hostname:
                detected_role = role
                break
                
        return {
            "role": detected_role,
            "api_url": "https://itops.company.com/api/v1/assets",
            "api_key": None  # Will be injected by GPO
        }
    
    def collect_asset_info(self) -> AssetData:
        """Collect hardware and system information"""
        import socket
        import platform
        
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        
        # Calculate network segment
        ip_parts = ip.split('.')
        network_segment = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        # Get BIOS date using WMI
        c = wmi.WMI()
        bios_date = "unknown"
        try:
            for bios in c.Win32_BIOS():
                bios_date = bios.ReleaseDate[:8] if bios.ReleaseDate else "unknown"
        except:
            pass
            
        # Memory in GB
        ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
        
        # Disk info
        disk = psutil.disk_usage('/')
        disk_total = round(disk.total / (1024**3), 2)
        disk_free = round(disk.free / (1024**3), 2)
        
        return AssetData(
            hostname=hostname,
            ip=ip,
            network_segment=network_segment,
            role=self.role,
            os=f"{platform.system()} {platform.release()}",
            cpu=platform.processor(),
            ram_gb=ram_gb,
            disk_total_gb=disk_total,
            disk_free_gb=disk_free,
            bios_date=bios_date,
            last_seen=datetime.utcnow().isoformat()
        )
    
    def collect_checklist(self) -> ChecklistData:
        """Security and compliance checklist"""
        # Check antivirus (Windows Defender or third-party)
        antivirus_status = self._check_antivirus()
        
        # Check admin rights
        admin_rights = self._check_admin_rights()
        
        # Check internet
        internet = self._check_internet()
        
        # WMI service status
        wmi_status = self._check_wmi_service()
        
        # VNC status
        vnc_status = self._check_vnc()
        
        # Disk cleanup needed
        needs_cleanup = self._check_disk_cleanup_needed()
        
        return ChecklistData(
            antivirus=antivirus_status,
            admin_rights=admin_rights,
            internet_access=internet,
            wmi_service=wmi_status,
            vnc_status=vnc_status,
            disk_cleanup=needs_cleanup
        )
    
    def _check_antivirus(self) -> str:
        """Check Windows Defender or installed AV status"""
        try:
            c = wmi.WMI(namespace="root\\SecurityCenter2")
            av_products = c.query("SELECT * FROM AntiVirusProduct")
            
            if not av_products:
                return "not_installed"
            
            for av in av_products:
                # Check if real-time protection enabled
                if av.productState:
                    state = hex(av.productState)
                    if state[-2:] == '00':  # Simplified check
                        return "outdated"
            return "installed"
        except:
            return "unknown"
    
    def _check_admin_rights(self) -> bool:
        """Check if current user has admin privileges"""
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def _check_internet(self) -> bool:
        """Check internet connectivity"""
        import urllib.request
        try:
            urllib.request.urlopen('https://8.8.8.8', timeout=3)
            return True
        except:
            return False
    
    def _check_wmi_service(self) -> str:
        """Check if WMI service is running"""
        try:
            service = psutil.win_service_get('winmgmt')
            return "running" if service.status() == 'running' else "stopped"
        except:
            return "unknown"
    
    def _check_vnc(self) -> str:
        """Check VNC installation and status"""
        vnc_services = ['tvnserver', 'vncserver', 'uvnc_service']
        for service_name in vnc_services:
            try:
                service = psutil.win_service_get(service_name)
                return "running" if service.status() == 'running' else "stopped"
            except:
                continue
        return "not_installed"
    
    def _check_disk_cleanup_needed(self) -> bool:
        """Check if disk cleanup is recommended (>10% temp files)"""
        import tempfile
        import os
        
        temp_size = 0
        temp_dirs = [tempfile.gettempdir(), os.environ.get('TEMP'), r'C:\Windows\Temp']
        
        for temp_dir in temp_dirs:
            if temp_dir and os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir):
                    for f in files:
                        try:
                            temp_size += os.path.getsize(os.path.join(root, f))
                        except:
                            pass
        
        disk_total = psutil.disk_usage('/').total
        return (temp_size / disk_total) > 0.10
    
    def collect_metrics(self) -> MetricsData:
        """Collect real-time performance metrics"""
        return MetricsData(
            cpu_usage=psutil.cpu_percent(interval=1),
            ram_usage=psutil.virtual_memory().percent,
            disk_usage_percent=psutil.disk_usage('/').percent
        )
    
    def collect_installed_software(self) -> List[Dict]:
        """Collect installed software from registry"""
        software_list = []
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for reg_path in registry_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                        
                        software_list.append({
                            "name": name,
                            "version": version,
                            "publisher": publisher,
                            "hash": hashlib.md5(f"{name}{version}".encode()).hexdigest()[:8]
                        })
                        winreg.CloseKey(subkey)
                    except:
                        continue
                winreg.CloseKey(key)
            except:
                continue
                
        return software_list
    
    def get_software_policy(self) -> Dict:
        """Fetch software policy for this role from API"""
        try:
            response = requests.get(
                f"{self.api_endpoint}/policy/{self.role}",
                headers={"X-API-Key": self.api_key},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        # Fallback default policies
        default_policies = {
            "office_user": {
                "required": ["Microsoft Office", "Antivirus", "VPN Client"],
                "optional": ["Adobe Reader", "Chrome", "Firefox"],
                "forbidden": ["uTorrent", "TeamViewer", "AnyDesk"]
            },
            "accounting": {
                "required": ["Microsoft Office", "Antivirus", "ERP Client", "VPN Client"],
                "optional": ["Adobe Reader"],
                "forbidden": ["Games", "Social Media Apps", "USB Tools"]
            },
            "developer": {
                "required": ["Git", "VS Code", "Docker Desktop"],
                "optional": ["Postman", "Node.js", "Python"],
                "forbidden": ["Pirated Software", "Keygens"]
            },
            "production_pc": {
                "required": ["SCADA Client", "Antivirus"],
                "optional": [],
                "forbidden": ["Games", "Social Media", "USB Tools", "Remote Desktop"]
            }
        }
        return default_policies.get(self.role, default_policies["office_user"])
    
    def compile_payload(self) -> Dict:
        """Compile full payload for API submission"""
        asset = self.collect_asset_info()
        checklist = self.collect_checklist()
        metrics = self.collect_metrics()
        software = self.collect_installed_software()
        policy = self.get_software_policy()
        
        return {
            "asset": asdict(asset),
            "checklist": asdict(checklist),
            "metrics": asdict(metrics),
            "installed_software": software,
            "software_policy": policy,
            "agent_version": "2.1.0",
            "collection_timestamp": datetime.utcnow().isoformat()
        }
    
    def submit_with_jitter(self, payload: Dict):
        """Submit data with randomized delay to prevent API spikes"""
        jitter = random.randint(0, 300)  # 0-5 minutes
        time.sleep(jitter)
        
        try:
            response = requests.post(
                self.api_endpoint,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                    "X-Machine-Hash": hashlib.sha256(
                        payload['asset']['hostname'].encode()
                    ).hexdigest()[:16]
                },
                timeout=30
            )
            return response.status_code == 200
        except Exception as e:
            # Queue for retry (local SQLite)
            self._queue_for_retry(payload)
            return False
    
    def _queue_for_retry(self, payload: Dict):
        """Store failed submission for later retry"""
        import sqlite3
        conn = sqlite3.connect('agent_queue.db')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY,
                payload TEXT,
                timestamp TEXT,
                retry_count INTEGER DEFAULT 0
            )
        ''')
        conn.execute(
            "INSERT INTO queue (payload, timestamp) VALUES (?, ?)",
            (json.dumps(payload), datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()


# agent/scheduler.py
from apscheduler.schedulers.background import BackgroundScheduler
from collector import SystemCollector
import logging

class AgentScheduler:
    def __init__(self):
        self.collector = SystemCollector()
        self.scheduler = BackgroundScheduler()
        
    def start(self):
        """Start the agent with randomized scheduling"""
        import random
        
        # Random start time to prevent thundering herd
        initial_delay = random.randint(0, 3600)
        
        # Schedule every 4 hours with jitter
        self.scheduler.add_job(
            self._collection_job,
            'interval',
            hours=4,
            jitter=600,  # ±10 minutes
            max_instances=1
        )
        
        self.scheduler.start()
        logging.info(f"Agent started. Initial delay: {initial_delay}s")
        
    def _collection_job(self):
        """Main collection job"""
        try:
            payload = self.collector.compile_payload()
            success = self.collector.submit_with_jitter(payload)
            logging.info(f"Data submission: {'success' if success else 'queued'}")
        except Exception as e:
            logging.error(f"Collection failed: {e}")


if __name__ == "__main__":
    scheduler = AgentScheduler()
    scheduler.start()
    
    # Keep alive
    import signal
    signal.pause()
```

---

## 2️⃣ Central API Layer (FastAPI)

```python
# api/main.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Literal
from datetime import datetime, timedelta
import asyncpg
import redis.asyncio as redis
from contextlib import asynccontextmanager
import json
import hashlib
from enum import Enum

# Models
class Asset(BaseModel):
    hostname: str
    ip: str
    network_segment: str
    role: Literal["office_user", "accounting", "production_pc", "developer"]
    os: str
    cpu: str
    ram_gb: float
    disk_total_gb: float
    disk_free_gb: float
    bios_date: str
    last_seen: datetime

class Checklist(BaseModel):
    antivirus: Literal["installed", "not_installed", "outdated", "unknown"]
    admin_rights: bool
    internet_access: bool
    wmi_service: Literal["running", "stopped", "unknown"]
    vnc_status: Literal["running", "stopped", "not_installed", "unknown"]
    disk_cleanup: bool

class Metrics(BaseModel):
    cpu_usage: float = Field(ge=0, le=100)
    ram_usage: float = Field(ge=0, le=100)
    disk_usage_percent: float = Field(ge=0, le=100)

class SoftwareItem(BaseModel):
    name: str
    version: str
    publisher: str
    hash: str

class SoftwarePolicy(BaseModel):
    required: List[str]
    optional: List[str]
    forbidden: List[str]

class AssetPayload(BaseModel):
    asset: Asset
    checklist: Checklist
    metrics: Metrics
    installed_software: List[SoftwareItem]
    software_policy: SoftwarePolicy
    agent_version: str
    collection_timestamp: datetime

class AnalysisResult(BaseModel):
    status: Literal["healthy", "warning", "critical"]
    scope: Literal["device", "network"]
    network_segment: str
    compliance_score: int = Field(ge=0, le=100)
    issues: List[Dict]
    insight: str
    summary: str
    recommended_actions: List[str]

# Database & Cache
class Database:
    def __init__(self):
        self.pool = None
        self.redis = None
        
    async def connect(self):
        self.pool = await asyncpg.create_pool(
            "postgresql://itops:secure_pass@db/itops",
            min_size=10, max_size=50
        )
        self.redis = await redis.from_url("redis://redis:6379")
        
    async def close(self):
        await self.pool.close()
        await self.redis.close()

db = Database()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    await db.close()

app = FastAPI(title="IT Ops Central API", lifespan=lifespan)
security = HTTPBearer()

# Authentication
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Validate JWT or API Key
    token = credentials.credentials
    if not token or len(token) < 32:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token

# Endpoints
@app.post("/api/v1/assets", response_model=AnalysisResult)
async def receive_asset_data(
    payload: AssetPayload,
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_token)
):
    """
    Receive asset data from agent, store it, and trigger AI analysis
    """
    # 1. Store raw data
    await store_asset_data(payload)
    
    # 2. Get historical context for this segment
    segment_history = await get_segment_history(payload.asset.network_segment)
    
    # 3. Trigger AI analysis
    analysis = await analyze_asset(payload, segment_history)
    
    # 4. Store analysis results
    await store_analysis_result(payload.asset.hostname, analysis)
    
    # 5. If critical, trigger immediate automation
    if analysis.status == "critical":
        background_tasks.add_task(
            trigger_automation,
            payload.asset.hostname,
            analysis.recommended_actions
        )
    
    # 6. Update segment-wide statistics
    background_tasks.add_task(
        update_segment_stats,
        payload.asset.network_segment
    )
    
    return analysis

@app.get("/api/v1/policy/{role}")
async def get_policy(role: str, token: str = Depends(verify_token)):
    """Return software policy for specific role"""
    policies = {
        "office_user": {
            "required": ["Microsoft Office 365", "Windows Defender", "Company VPN"],
            "optional": ["Adobe Acrobat Reader", "Google Chrome", "7-Zip"],
            "forbidden": ["uTorrent", "TeamViewer", "AnyDesk", "Baidu Software", "360 Safe"]
        },
        "accounting": {
            "required": ["Microsoft Office 365", "Windows Defender", "SAP Client", "Company VPN"],
            "optional": ["Adobe Acrobat Reader"],
            "forbidden": ["Games", "Social Media Apps", "USB Writing Tools", "Remote Desktop Tools"]
        },
        "developer": {
            "required": ["Git", "Visual Studio Code", "Docker Desktop", "Windows Terminal"],
            "optional": ["Postman", "Node.js", "Python 3.x", "JetBrains Tools"],
            "forbidden": ["Pirated Software", "Keygens", "Cracking Tools"]
        },
        "production_pc": {
            "required": ["SCADA Client", "Windows Defender", "Industrial Antivirus"],
            "optional": [],
            "forbidden": ["Games", "Social Media", "USB Tools", "Remote Desktop", "Development Tools"]
        }
    }
    
    if role not in policies:
        raise HTTPException(status_code=404, detail="Role not found")
    
    return policies[role]

@app.get("/api/v1/segment/{segment}/status")
async def get_segment_status(segment: str, token: str = Depends(verify_token)):
    """Get aggregated status for entire network segment"""
    query = """
    SELECT 
        COUNT(*) as total_machines,
        COUNT(CASE WHEN last_analysis->>'status' = 'critical' THEN 1 END) as critical_count,
        COUNT(CASE WHEN last_analysis->>'status' = 'warning' THEN 1 END) as warning_count,
        AVG((last_analysis->>'compliance_score')::int) as avg_compliance,
        mode() WITHIN GROUP (ORDER BY role) as dominant_role
    FROM assets 
    WHERE network_segment = $1
    AND last_seen > NOW() - INTERVAL '24 hours'
    """
    
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(query, segment)
        
    return {
        "network_segment": segment,
        "total_machines": row["total_machines"],
        "health_summary": {
            "critical": row["critical_count"],
            "warning": row["warning_count"],
            "healthy": row["total_machines"] - row["critical_count"] - row["warning_count"]
        },
        "average_compliance": round(row["avg_compliance"], 1),
        "dominant_role": row["dominant_role"],
        "trend": await get_segment_trend(segment)
    }

# Helper functions
async def store_asset_data(payload: AssetPayload):
    """Store or update asset information"""
    query = """
    INSERT INTO assets (
        hostname, ip, network_segment, role, os, hardware_info,
        checklist, metrics, installed_software, software_policy,
        last_seen, raw_data
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (hostname) DO UPDATE SET
        ip = EXCLUDED.ip,
        network_segment = EXCLUDED.network_segment,
        checklist = EXCLUDED.checklist,
        metrics = EXCLUDED.metrics,
        installed_software = EXCLUDED.installed_software,
        last_seen = EXCLUDED.last_seen,
        raw_data = EXCLUDED.raw_data
    """
    
    async with db.pool.acquire() as conn:
        await conn.execute(
            query,
            payload.asset.hostname,
            payload.asset.ip,
            payload.asset.network_segment,
            payload.asset.role,
            payload.asset.os,
            json.dumps({
                "cpu": payload.asset.cpu,
                "ram_gb": payload.asset.ram_gb,
                "disk_total_gb": payload.asset.disk_total_gb,
                "disk_free_gb": payload.asset.disk_free_gb,
                "bios_date": payload.asset.bios_date
            }),
            json.dumps(payload.checklist.dict()),
            json.dumps(payload.metrics.dict()),
            json.dumps([s.dict() for s in payload.installed_software]),
            json.dumps(payload.software_policy.dict()),
            payload.asset.last_seen,
            json.dumps(payload.dict())
        )

async def get_segment_history(segment: str, hours: int = 24) -> List[Dict]:
    """Get recent data from same network segment for pattern detection"""
    query = """
    SELECT hostname, checklist, metrics, installed_software, last_analysis
    FROM assets
    WHERE network_segment = $1
    AND last_seen > NOW() - INTERVAL '%s hours'
    ORDER BY last_seen DESC
    """ % hours
    
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(query, segment)
        
    return [dict(row) for row in rows]

async def analyze_asset(payload: AssetPayload, segment_history: List[Dict]) -> AnalysisResult:
    """
    AI Analysis Engine - implements the analysis logic from requirements
    """
    issues = []
    compliance_score = 100
    critical_count = 0
    warning_count = 0
    
    # 1. Software Policy Validation
    installed_names = [s.name.lower() for s in payload.installed_software]
    
    # Check required software
    for required in payload.software_policy.required:
        if not any(required.lower() in name for name in installed_names):
            issues.append({
                "type": "software",
                "scope": "device_issue",
                "severity": "high",
                "description": f"Required software '{required}' not found",
                "root_cause": "Software deployment failure or policy violation",
                "recommendation": f"Deploy {required} via SCCM or GPO immediately"
            })
            compliance_score -= 15
            critical_count += 1
    
    # Check forbidden software
    forbidden_patterns = {
        "baidu": ["baidu", "百度"],
        "torrent": ["utorrent", "bittorrent", "qbittorrent"],
        "remote_unauthorized": ["teamviewer", "anydesk", "chrome remote"],
        "gaming": ["steam", "epic games", "origin"],
        "cracking": ["keygen", "crack", "patch", "activator"]
    }
    
    for software in payload.installed_software:
        software_lower = software.name.lower()
        for category, patterns in forbidden_patterns.items():
            if any(pattern in software_lower for pattern in patterns):
                severity = "critical" if category in ["cracking", "remote_unauthorized"] else "high"
                issues.append({
                    "type": "security",
                    "scope": "device_issue",
                    "severity": severity,
                    "description": f"Forbidden software detected: {software.name}",
                    "root_cause": "Unauthorized software installation",
                    "recommendation": f"Uninstall {software.name} immediately and audit installation source"
                })
                compliance_score -= 20 if severity == "critical" else 10
                critical_count += 1
    
    # 2. Security Checklist Analysis
    if payload.checklist.antivirus in ["not_installed", "outdated"]:
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "critical",
            "description": f"Antivirus {payload.checklist.antivirus}",
            "root_cause": "Security baseline violation",
            "recommendation": "Install/Update antivirus definitions immediately"
        })
        compliance_score -= 25
        critical_count += 1
    
    if payload.checklist.admin_rights and payload.asset.role in ["office_user", "accounting"]:
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "high",
            "description": "Admin rights enabled for standard user role",
            "root_cause": "Privilege escalation risk",
            "recommendation": "Remove user from Administrators group via GPO"
        })
        compliance_score -= 15
        critical_count += 1
    
    if payload.checklist.vnc_status == "running" and payload.asset.role == "production_pc":
        issues.append({
            "type": "security",
            "scope": "device_issue",
            "severity": "critical",
            "description": "VNC running on production machine",
            "root_cause": "Unauthorized remote access on critical system",
            "recommendation": "Stop and disable VNC service immediately"
        })
        compliance_score -= 20
        critical_count += 1
    
    # 3. Performance Analysis
    if payload.metrics.disk_usage_percent > 90:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "high",
            "description": f"Disk usage at {payload.metrics.disk_usage_percent}%",
            "root_cause": "Insufficient storage space",
            "recommendation": "Run disk cleanup, move data to network storage, or expand disk"
        })
        compliance_score -= 10
        warning_count += 1
    elif payload.metrics.disk_usage_percent > 80:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "medium",
            "description": f"Disk usage at {payload.metrics.disk_usage_percent}%",
            "root_cause": "Storage approaching capacity",
            "recommendation": "Schedule disk cleanup and review large files"
        })
        compliance_score -= 5
        warning_count += 1
    
    if payload.metrics.ram_usage > 90:
        issues.append({
            "type": "performance",
            "scope": "device_issue",
            "severity": "high",
            "description": f"RAM usage at {payload.metrics.ram_usage}%",
            "root_cause": "Memory pressure - possible memory leak or insufficient RAM",
            "recommendation": "Identify memory-hungry processes, consider RAM upgrade if persistent"
        })
        compliance_score -= 10
        warning_count += 1
    
    # 4. Hardware Age Analysis
    try:
        bios_year = int(payload.asset.bios_date[:4])
        current_year = datetime.now().year
        if current_year - bios_year > 5:
            issues.append({
                "type": "config",
                "scope": "device_issue",
                "severity": "medium",
                "description": f"BIOS from {bios_year} ({current_year - bios_year} years old)",
                "root_cause": "Outdated hardware firmware",
                "recommendation": "Schedule hardware refresh or BIOS update"
            })
            compliance_score -= 5
            warning_count += 1
    except:
        pass
    
    # 5. Network Segment Pattern Analysis
    segment_issues = detect_segment_patterns(payload, segment_history)
    issues.extend(segment_issues)
    
    # Adjust compliance for network-wide issues
    network_critical = sum(1 for i in segment_issues if i["severity"] == "critical")
    compliance_score -= network_critical * 10
    
    # Determine status
    if critical_count > 0 or network_critical > 0 or compliance_score < 60:
        status = "critical"
    elif warning_count > 2 or compliance_score < 80:
        status = "warning"
    else:
        status = "healthy"
    
    # Generate insight
    insight = generate_insight(payload, segment_history, issues)
    
    # Generate summary
    summary = f"Machine {payload.asset.hostname} ({payload.asset.role}): "
    if status == "healthy":
        summary += "All systems operational. Compliance excellent."
    elif status == "critical":
        summary += f"{critical_count} critical issues require immediate attention."
    else:
        summary += f"{warning_count} warnings detected. Review recommended."
    
    # Recommended actions for automation
    recommended_actions = [
        issue["recommendation"] for issue in issues 
        if issue["severity"] in ["high", "critical"]
    ]
    
    return AnalysisResult(
        status=status,
        scope="network" if segment_issues else "device",
        network_segment=payload.asset.network_segment,
        compliance_score=max(0, compliance_score),
        issues=issues,
        insight=insight,
        summary=summary,
        recommended_actions=recommended_actions
    )

def detect_segment_patterns(payload: AssetPayload, history: List[Dict]) -> List[Dict]:
    """Detect if issues are systemic across network segment"""
    segment_issues = []
    
    if len(history) < 3:
        return segment_issues
    
    # Check for common antivirus issues
    av_issues = sum(1 for h in history if h["checklist"]["antivirus"] != "installed")
    if av_issues > len(history) * 0.5:  # >50% of segment
        segment_issues.append({
            "type": "security",
            "scope": "network_issue",
            "severity": "critical",
            "description": f"Antivirus issues detected on {av_issues}/{len(history)} machines in segment",
            "root_cause": "Possible GPO failure or network-wide AV deployment issue",
            "recommendation": "Audit GPO settings and AV management server immediately"
        })
    
    # Check for internet connectivity issues
    inet_issues = sum(1 for h in history if not h["checklist"]["internet_access"])
    if inet_issues > len(history) * 0.3:  # >30% of segment
        segment_issues.append({
            "type": "config",
            "scope": "network_issue",
            "severity": "high",
            "description": f"Internet connectivity issues on {inet_issues}/{len(history)} machines",
            "root_cause": "Possible firewall, proxy, or network infrastructure issue",
            "recommendation": "Check network gateway, DNS, and proxy configuration"
        })
    
    # Check for common forbidden software
    forbidden_counts = {}
    for h in history:
        for sw in h["installed_software"]:
            name = sw["name"].lower()
            if any(f in name for f in ["baidu", "360", "teamviewer"]):
                forbidden_counts[name] = forbidden_counts.get(name, 0) + 1
    
    for sw_name, count in forbidden_counts.items():
        if count > 2:  # Found on multiple machines
            segment_issues.append({
                "type": "security",
                "scope": "network_issue",
                "severity": "critical",
                "description": f"'{sw_name}' found on {count} machines in segment",
                "root_cause": "Possible software distribution from internal source or compromised installer",
                "recommendation": f"Emergency removal of {sw_name} across entire segment via SCCM"
            })
    
    return segment_issues

def generate_insight(payload: AssetPayload, history: List[Dict], issues: List[Dict]) -> str:
    """Generate pattern insight"""
    if not history:
        return "Insufficient data for trend analysis"
    
    # Compare metrics to segment average
    avg_cpu = sum(h["metrics"]["cpu_usage"] for h in history) / len(history)
    avg_ram = sum(h["metrics"]["ram_usage"] for h in history) / len(history)
    
    insights = []
    
    if payload.metrics.cpu_usage > avg_cpu * 1.5:
        insights.append(f"CPU usage ({payload.metrics.cpu_usage}%) significantly above segment average ({avg_cpu:.1f}%)")
    
    if payload.metrics.ram_usage > avg_ram * 1.3:
        insights.append(f"Memory pressure higher than typical for {payload.asset.role} machines")
    
    # Check for degradation trend
    same_machine_history = [h for h in history if h["hostname"] == payload.asset.hostname]
    if len(same_machine_history) >= 3:
        disk_trend = [h["metrics"]["disk_usage_percent"] for h in same_machine_history[:3]]
        if disk_trend[0] > disk_trend[1] > disk_trend[2]:
            insights.append("Disk usage trending upward - predict full disk in ~7 days")
    
    if insights:
        return " | ".join(insights)
    return "Performance within normal parameters for role"

async def store_analysis_result(hostname: str, analysis: AnalysisResult):
    """Store analysis results"""
    query = """
    UPDATE assets 
    SET last_analysis = $1, 
        status = $2,
        compliance_score = $3,
        updated_at = NOW()
    WHERE hostname = $4
    """
    async with db.pool.acquire() as conn:
        await conn.execute(
            query,
            json.dumps(analysis.dict()),
            analysis.status,
            analysis.compliance_score,
            hostname
        )

async def trigger_automation(hostname: str, actions: List[str]):
    """Queue automated remediation actions"""
    async with db.redis.pipeline() as pipe:
        for action in actions:
            await pipe.lpush(
                "automation_queue",
                json.dumps({
                    "hostname": hostname,
                    "action": action,
                    "queued_at": datetime.utcnow().isoformat(),
                    "priority": "critical"
                })
            )
        await pipe.execute()

async def update_segment_stats(segment: str):
    """Update cached segment statistics"""
    # Implementation for caching segment stats
    pass

async def get_segment_trend(segment: str) -> str:
    """Calculate trend direction for segment health"""
    return "stable"  # Placeholder
```

---

## 3️⃣ Database Schema (PostgreSQL)

```sql
-- Database: itops
-- Schema: enterprise asset management with time-series support

-- Main assets table
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    ip INET NOT NULL,
    network_segment CIDR NOT NULL,
    role VARCHAR(50) NOT NULL,
    os VARCHAR(255),
    
    -- Hardware info as JSONB for flexibility
    hardware_info JSONB,
    
    -- Compliance & security data
    checklist JSONB NOT NULL,
    metrics JSONB NOT NULL,
    installed_software JSONB,
    software_policy JSONB,
    
    -- Analysis results
    status VARCHAR(20) DEFAULT 'unknown',
    compliance_score INTEGER CHECK (compliance_score BETWEEN 0 AND 100),
    last_analysis JSONB,
    
    -- Timestamps
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Raw data for audit
    raw_data JSONB,
    
    -- Indexes
    CONSTRAINT valid_role CHECK (role IN ('office_user', 'accounting', 'production_pc', 'developer'))
);

-- Indexes for performance
CREATE INDEX idx_assets_network_segment ON assets(network_segment);
CREATE INDEX idx_assets_role ON assets(role);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_last_seen ON assets(last_seen);
CREATE INDEX idx_assets_compliance ON assets(compliance_score);

-- GIN indexes for JSONB queries
CREATE INDEX idx_assets_checklist ON assets USING GIN(checklist);
CREATE INDEX idx_assets_software ON assets USING GIN(installed_software jsonb_path_ops);

-- Time-series table for metrics history
CREATE TABLE metrics_history (
    id BIGSERIAL PRIMARY KEY,
    hostname VARCHAR(255) REFERENCES assets(hostname) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    cpu_usage DECIMAL(5,2),
    ram_usage DECIMAL(5,2),
    disk_usage_percent DECIMAL(5,2),
    
    -- Partition by month for performance
) PARTITION BY RANGE (timestamp);

-- Create partitions for next 12 months
-- (Automated via cron job)

-- Software inventory tracking
CREATE TABLE software_inventory (
    id SERIAL PRIMARY KEY,
    software_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    publisher VARCHAR(255),
    hash VARCHAR(32),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    machine_count INTEGER DEFAULT 1,
    UNIQUE(software_name, version, hash)
);

-- Link table: which machines have which software
CREATE TABLE machine_software (
    hostname VARCHAR(255) REFERENCES assets(hostname) ON DELETE CASCADE,
    software_id INTEGER REFERENCES software_inventory(id) ON DELETE CASCADE,
    installed_date TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (hostname, software_id)
);

-- Policy definitions
CREATE TABLE role_policies (
    id SERIAL PRIMARY KEY,
    role VARCHAR(50) UNIQUE NOT NULL,
    policy_definition JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(100)
);

-- Automation action log
CREATE TABLE automation_log (
    id BIGSERIAL PRIMARY KEY,
    hostname VARCHAR(255) REFERENCES assets(hostname),
    action_type VARCHAR(100) NOT NULL,
    description TEXT,
    triggered_by VARCHAR(100),  -- AI system or manual
    status VARCHAR(50),  -- pending, running, completed, failed
    result JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Alert/Notification table
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,  -- security, performance, compliance
    severity VARCHAR(20) NOT NULL,    -- low, medium, high, critical
    scope VARCHAR(20) NOT NULL,       -- device, network
    network_segment CIDR,
    hostname VARCHAR(255),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    recommendation TEXT,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for alerts
CREATE INDEX idx_alerts_unack ON alerts(acknowledged) WHERE acknowledged = FALSE;
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created ON alerts(created_at);

-- Network segments configuration
CREATE TABLE network_segments (
    cidr CIDR PRIMARY KEY,
    segment_name VARCHAR(100),
    location VARCHAR(100),
    responsible_team VARCHAR(100),
    criticality VARCHAR(20),  -- low, medium, high, critical
    compliance_requirements JSONB
);

-- Audit log for all changes
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100),
    record_id VARCHAR(255),
    action VARCHAR(20),  -- INSERT, UPDATE, DELETE
    old_values JSONB,
    new_values JSONB,
    changed_by VARCHAR(100),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Triggers for audit logging
CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO audit_log (table_name, record_id, action, old_values)
        VALUES (TG_TABLE_NAME, OLD.id, TG_OP, row_to_json(OLD));
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO audit_log (table_name, record_id, action, old_values, new_values)
        VALUES (TG_TABLE_NAME, NEW.id, TG_OP, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO audit_log (table_name, record_id, action, new_values)
        VALUES (TG_TABLE_NAME, NEW.id, TG_OP, row_to_json(NEW));
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Apply audit trigger to critical tables
CREATE TRIGGER assets_audit AFTER INSERT OR UPDATE OR DELETE ON assets
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();

-- Materialized view for dashboard
CREATE MATERIALIZED VIEW dashboard_summary AS
SELECT 
    network_segment,
    role,
    COUNT(*) as machine_count,
    COUNT(*) FILTER (WHERE status = 'healthy') as healthy_count,
    COUNT(*) FILTER (WHERE status = 'warning') as warning_count,
    COUNT(*) FILTER (WHERE status = 'critical') as critical_count,
    AVG(compliance_score) as avg_compliance,
    MAX(last_seen) as last_checkin
FROM assets
WHERE last_seen > NOW() - INTERVAL '24 hours'
GROUP BY network_segment, role;

-- Refresh concurrently every 5 minutes
CREATE UNIQUE INDEX idx_dashboard_summary ON dashboard_summary(network_segment, role);
```

---

## 4️⃣ Automation & Self-Healing System

```python
# automation/engine.py
import asyncio
import json
import subprocess
import paramiko
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import logging

class ActionType(Enum):
    SOFTWARE_INSTALL = "software_install"
    SOFTWARE_REMOVE = "software_remove"
    SERVICE_STOP = "service_stop"
    SERVICE_START = "service_start"
    REGISTRY_FIX = "registry_fix"
    DISK_CLEANUP = "disk_cleanup"
    REBOOT = "reboot"
    GPO_UPDATE = "gpo_update"
    ADMIN_RIGHTS_REVOKE = "admin_rights_revoke"

@dataclass
class AutomationAction:
    hostname: str
    action_type: ActionType
    parameters: Dict
    priority: str  # low, medium, high, critical
    retry_count: int = 0
    max_retries: int = 3

class SelfHealingEngine:
    def __init__(self):
        self.ssh_key_path = "/secrets/automation_key"
        self.api_endpoint = "https://itops.company.com/api/v1"
        
    async def process_queue(self):
        """Main loop processing automation queue"""
        while True:
            try:
                # Fetch pending actions from Redis
                action_data = await self._fetch_next_action()
                if action_data:
                    action = self._parse_action(action_data)
                    await self._execute_action(action)
                else:
                    await asyncio.sleep(5)
            except Exception as e:
                logging.error(f"Automation engine error: {e}")
                await asyncio.sleep(10)
    
    async def _fetch_next_action(self) -> Optional[Dict]:
        """Fetch highest priority action from queue"""
        # Implementation using Redis BLPOP
        pass
    
    def _parse_action(self, data: Dict) -> AutomationAction:
        """Parse action from queue"""
        return AutomationAction(
            hostname=data["hostname"],
            action_type=ActionType(data["action_type"]),
            parameters=data.get("parameters", {}),
            priority=data.get("priority", "medium")
        )
    
    async def _execute_action(self, action: AutomationAction):
        """Execute automation action on remote machine"""
        try:
            if action.action_type == ActionType.SOFTWARE_REMOVE:
                await self._remove_software(action)
            elif action.action_type == ActionType.SERVICE_STOP:
                await self._stop_service(action)
            elif action.action_type == ActionType.ADMIN_RIGHTS_REVOKE:
                await self._revoke_admin_rights(action)
            elif action.action_type == ActionType.DISK_CLEANUP:
                await self._run_disk_cleanup(action)
            elif action.action_type == ActionType.GPO_UPDATE:
                await self._force_gpo_update(action)
            
            await self._log_success(action)
            
        except Exception as e:
            await self._handle_failure(action, str(e))
    
    async def _remove_software(self, action: AutomationAction):
        """Uninstall software silently"""
        software_name = action.parameters.get("software_name")
        
        # Method 1: WMI uninstall
        ps_script = f'''
        $app = Get-WmiObject -Class Win32_Product | Where-Object {{ $_.Name -like "*{software_name}*" }}
        if ($app) {{
            $app.Uninstall()
            Write-Output "Uninstalled: $($app.Name)"
        }}
        '''
        
        # Method 2: If WMI fails, try registry uninstall string
        # Method 3: Direct MSIExec
        
        await self._run_remote_powershell(action.hostname, ps_script)
    
    async def _stop_service(self, action: AutomationAction):
        """Stop and disable a service"""
        service_name = action.parameters.get("service_name")
        
        ps_script = f'''
        Stop-Service -Name "{service_name}" -Force
        Set-Service -Name "{service_name}" -StartupType Disabled
        Write-Output "Service {service_name} stopped and disabled"
        '''
        
        await self._run_remote_powershell(action.hostname, ps_script)
    
    async def _revoke_admin_rights(self, action: AutomationAction):
        """Remove user from Administrators group"""
        ps_script = '''
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $adminGroup = [ADSI]"WinNT://./Administrators,group"
        $adminGroup.Remove("WinNT://$user,user")
        Write-Output "Admin rights revoked for $user"
        '''
        
        await self._run_remote_powershell(action.hostname, ps_script)
    
    async def _run_disk_cleanup(self, action: AutomationAction):
        """Execute disk cleanup"""
        ps_script = '''
        # Clean temp directories
        Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        
        # Run Disk Cleanup (cleanmgr) with specific flags
        # Or use Dism for component cleanup
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
        
        Write-Output "Disk cleanup completed"
        '''
        
        await self._run_remote_powershell(action.hostname, ps_script)
    
    async def _force_gpo_update(self, action: AutomationAction):
        """Force Group Policy update"""
        ps_script = '''
        gpupdate /force
        Write-Output "GPO update completed"
        '''
        
        await self._run_remote_powershell(action.hostname, ps_script)
    
    async def _run_remote_powershell(self, hostname: str, script: str):
        """Execute PowerShell script on remote machine via WinRM/SSH"""
        # Option 1: WinRM (Requires proper setup)
        # Option 2: SSH with key auth
        # Option 3: Agent pulls command from API (pull model - most secure)
        
        # Using pull model: Store command in DB, agent picks it up
        await self._queue_command_for_agent(hostname, script)
    
    async def _queue_command_for_agent(self, hostname: str, script: str):
        """Store command for agent to pull (secure, no inbound required)"""
        # Store in Redis with TTL
        command_id = hashlib.sha256(f"{hostname}{time.time()}".encode()).hexdigest()[:16]
        
        await redis.setex(
            f"cmd:{hostname}:{command_id}",
            3600,  # 1 hour TTL
            json.dumps({
                "command_id": command_id,
                "script": script,
                "issued_at": datetime.utcnow().isoformat()
            })
        )
    
    async def _log_success(self, action: AutomationAction):
        """Log successful automation"""
        query = """
        INSERT INTO automation_log 
        (hostname, action_type, description, status, completed_at)
        VALUES ($1, $2, $3, 'completed', NOW())
        """
        await db.execute(query, action.hostname, action.action_type.value, 
                        json.dumps(action.parameters))
    
    async def _handle_failure(self, action: AutomationAction, error: str):
        """Handle failed automation"""
        action.retry_count += 1
        
        if action.retry_count < action.max_retries:
            # Re-queue with delay
            await self._requeue_with_backoff(action)
        else:
            # Alert human operator
            await self._create_alert(action, error)
    
    async def _requeue_with_backoff(self, action: AutomationAction):
        """Re-queue with exponential backoff"""
        delay = 2 ** action.retry_count * 60  # 2, 4, 8 minutes
        await asyncio.sleep(delay)
        await self._queue_action(action)
    
    async def _create_alert(self, action: AutomationAction, error: str):
        """Create alert for manual intervention"""
        query = """
        INSERT INTO alerts 
        (alert_type, severity, scope, hostname, title, description)
        VALUES ('automation', 'high', 'device', $1, $2, $3)
        """
        await db.execute(
            query,
            action.hostname,
            f"Automation failed: {action.action_type.value}",
            f"Action failed after {action.max_retries} retries. Error: {error}"
        )


# automation/remediation_rules.py
# Predefined remediation mappings

REMEDIATION_MAP = {
    # Security issues
    "forbidden_software_baidu": {
        "action": ActionType.SOFTWARE_REMOVE,
        "parameters": {"software_name": "Baidu"},
        "auto_execute": True,
        "requires_approval": False
    },
    "forbidden_software_teamviewer": {
        "action": ActionType.SOFTWARE_REMOVE,
        "parameters": {"software_name": "TeamViewer"},
        "auto_execute": False,  # Requires approval - might be legitimate use
        "requires_approval": True
    },
    "admin_rights_standard_user": {
        "action": ActionType.ADMIN_RIGHTS_REVOKE,
        "parameters": {},
        "auto_execute": True,
        "requires_approval": False
    },
    "vnc_on_production": {
        "action": ActionType.SERVICE_STOP,
        "parameters": {"service_name": "tvnserver"},
        "auto_execute": True,
        "requires_approval": False
    },
    
    # Performance issues
    "disk_cleanup_needed": {
        "action": ActionType.DISK_CLEANUP,
        "parameters": {},
        "auto_execute": True,
        "requires_approval": False
    },
    "high_disk_usage": {
        "action": ActionType.DISK_CLEANUP,
        "parameters": {"aggressive": True},
        "auto_execute": False,
        "requires_approval": True
    }
}
```

---

## 5️⃣ Web Dashboard (React + TypeScript)

```typescript
// dashboard/src/components/Dashboard.tsx
import React, { useEffect, useState } from 'react';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import { io } from 'socket.io-client';

interface AssetStatus {
  network_segment: string;
  total_machines: number;
  health_summary: {
    healthy: number;
    warning: number;
    critical: number;
  };
  average_compliance: number;
}

const Dashboard: React.FC = () => {
  const [segments, setSegments] = useState<AssetStatus[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selectedSegment, setSelectedSegment] = useState<string | null>(null);

  useEffect(() => {
    // WebSocket for real-time updates
    const socket = io('wss://itops.company.com');
    
    socket.on('asset-update', (data) => {
      updateSegmentData(data);
    });
    
    socket.on('new-alert', (alert) => {
      setAlerts(prev => [alert, ...prev]);
    });

    // Initial data fetch
    fetchSegments();
    
    return () => { socket.disconnect(); };
  }, []);

  const fetchSegments = async () => {
    const response = await fetch('/api/v1/segments');
    const data = await response.json();
    setSegments(data);
  };

  const healthChartData = {
    labels: segments.map(s => s.network_segment),
    datasets: [
      {
        label: 'Healthy',
        data: segments.map(s => s.health_summary.healthy),
        backgroundColor: '#10b981',
      },
      {
        label: 'Warning',
        data: segments.map(s => s.health_summary.warning),
        backgroundColor: '#f59e0b',
      },
      {
        label: 'Critical',
        data: segments.map(s => s.health_summary.critical),
        backgroundColor: '#ef4444',
      }
    ]
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>IT Operations Command Center</h1>
        <div className="global-stats">
          <StatCard 
            title="Total Assets" 
            value={segments.reduce((acc, s) => acc + s.total_machines, 0)} 
            icon="server"
          />
          <StatCard 
            title="Critical Issues" 
            value={segments.reduce((acc, s) => acc + s.health_summary.critical, 0)}
            alert={true}
          />
          <StatCard 
            title="Avg Compliance" 
            value={`${Math.round(segments.reduce((acc, s) => acc + s.average_compliance, 0) / segments.length)}%`}
          />
        </div>
      </header>

      <div className="dashboard-grid">
        <div className="chart-container">
          <h2>Network Segment Health</h2>
          <Bar data={healthChartData} options={{ responsive: true }} />
        </div>

        <div className="alerts-panel">
          <h2>Active Alerts</h2>
          <div className="alerts-list">
            {alerts.map(alert => (
              <AlertCard 
                key={alert.id}
                severity={alert.severity}
                title={alert.title}
                description={alert.description}
                scope={alert.scope}
                onAcknowledge={() => acknowledgeAlert(alert.id)}
              />
            ))}
          </div>
        </div>

        <div className="segment-detail">
          <h2>Segment Explorer</h2>
          {selectedSegment ? (
            <SegmentDetail segment={selectedSegment} />
          ) : (
            <p>Select a segment to view details</p>
          )}
        </div>

        <div className="automation-queue">
          <h2>Self-Healing Queue</h2>
          <AutomationQueue />
        </div>
      </div>
    </div>
  );
};

// Component: AlertCard
const AlertCard: React.FC<{
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  scope: 'device' | 'network';
  onAcknowledge: () => void;
}> = ({ severity, title, description, scope, onAcknowledge }) => {
  const severityColors = {
    low: '#6b7280',
    medium: '#f59e0b',
    high: '#ef4444',
    critical: '#dc2626'
  };

  return (
    <div className={`alert-card severity-${severity}`} style={{ borderLeftColor: severityColors[severity] }}>
      <div className="alert-header">
        <span className="badge">{scope}</span>
        <span className="badge" style={{ background: severityColors[severity] }}>{severity}</span>
        <h4>{title}</h4>
      </div>
      <p>{description}</p>
      <button onClick={onAcknowledge}>Acknowledge</button>
    </div>
  );
};

// Component: SegmentDetail
const SegmentDetail: React.FC<{ segment: string }> = ({ segment }) => {
  const [machines, setMachines] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/v1/segment/${segment}/machines`)
      .then(r => r.json())
      .then(setMachines);
  }, [segment]);

  return (
    <div className="segment-detail-view">
      <h3>Segment: {segment}</h3>
      <table className="machines-table">
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Role</th>
            <th>Status</th>
            <th>Compliance</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {machines.map(m => (
            <tr key={m.hostname} className={`status-${m.status}`}>
              <td>{m.hostname}</td>
              <td>{m.role}</td>
              <td>
                <StatusBadge status={m.status} />
              </td>
              <td>
                <ComplianceBar score={m.compliance_score} />
              </td>
              <td>{new Date(m.last_seen).toLocaleString()}</td>
              <td>
                <button onClick={() => viewDetails(m.hostname)}>Details</button>
                <button onClick={() => triggerRemediation(m.hostname)}>
                  Remediate
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// Component: ComplianceBar
const ComplianceBar: React.FC<{ score: number }> = ({ score }) => {
  const color = score >= 90 ? '#10b981' : score >= 70 ? '#f59e0b' : '#ef4444';
  
  return (
    <div className="compliance-bar">
      <div 
        className="compliance-fill" 
        style={{ width: `${score}%`, backgroundColor: color }}
      />
      <span>{score}%</span>
    </div>
  );
};

export default Dashboard;
```

---

## 📊 System Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         AGENT LAYER                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Collect   │───►│   Compile   │───►│  Submit with Jitter │ │
│  │   Data      │    │   Payload   │    │  (Randomized Delay) │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         API LAYER                                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Receive   │───►│   Store     │───►│   AI Analysis       │ │
│  │   Payload   │    │   Raw Data  │    │   Engine            │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│                                               │                 │
│                                               ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  Trigger    │◄───│   Decision  │◄───│   Pattern Detection │ │
│  │  Automation │    │   Engine    │    │   (Segment-wide)    │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AUTOMATION LAYER                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Queue     │───►│   Execute   │───►│   Verify Result     │ │
│  │   Actions   │    │   Remotely  │    │   (Pull Model)      │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  Real-time  │    │  Executive  │    │   Alerting          │ │
│  │  Dashboard  │    │  Reports    │    │   (Email/Slack)     │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Considerations

| Layer | Security Measure |
|-------|-----------------|
| **Agent** | Code signing, obfuscation, tamper detection |
| **Transport** | mTLS 1.3, certificate pinning |
| **API** | JWT tokens, rate limiting, IP whitelist |
| **Database** | Encryption at rest, row-level security |
| **Automation** | Pull model (no inbound), signed commands, audit logs |

---

## 📈 Scaling Strategy

1. **Horizontal Scaling**: API servers behind load balancer
2. **Database**: Read replicas for dashboard queries, connection pooling
3. **Caching**: Redis for real-time data, segment statistics
4. **Partitioning**: Time-series data partitioned by month
5. **Queue**: Redis Streams or RabbitMQ for automation queue

ระบบนี้รองรับ **10,000+ machines** กระจายอยู่หลาย network segments พร้อม capability ในการ self-healing และ policy enforcement อัตโนมัติ