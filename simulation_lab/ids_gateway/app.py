import os
import sys
import json
import urllib.request
import urllib.error
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import engine

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

app = FastAPI(title="Smart NIDS Botnet Detection Dashboard")

# Start background network inspection proxy
engine.start_proxy_servers()

@app.get("/api/stats")
async def get_stats():
    import time
    threat = "LOW"
    risk_score = 10
    now_t = time.time()
    
    is_blocked = len(engine.blocked_ips) > 0
    active_mode = engine.stats_counter.get('active_mode', 'normal')
    
    recent_attack = (now_t - engine.last_attack_time) < 8.0 and active_mode == 'attack'
    recent_beacon = (now_t - engine.last_beacon_time) < 10.0 and active_mode in ['beacon', 'attack']

    if is_blocked:
        threat = "DEFENDED (THREAT MITIGATED & ISOLATED)"
        risk_score = 5
    elif recent_attack:
        threat = "CRITICAL (ATTACK CONFIRMED)"
        risk_score = 98
    elif recent_beacon or active_mode == 'beacon':
        threat = "SUSPICIOUS (C2 BEACON DETECTED)"
        risk_score = 72
        
    return {
        'total_flows': engine.stats_counter['total_flows'],
        'botnet_flows': engine.stats_counter['botnet_flows'],
        'normal_flows': engine.stats_counter['normal_flows'],
        'threat_level': threat,
        'risk_score': risk_score,
        'active_mode': active_mode,
        'blocked_ips': list(engine.blocked_ips),
        'flows': list(engine.flow_history)[:35]
    }

@app.get("/api/logs")
async def get_logs():
    return {
        'logs': list(engine.system_logs)
    }

@app.post("/api/control/mode")
async def change_scenario_mode(request: Request):
    """Coordinates mode change synchronously across victim-zombie and c2-server."""
    data = await request.json()
    mode = data.get('mode', 'normal')
    engine.stats_counter['active_mode'] = mode
    
    c2_cmd = 'sleep'
    if mode == 'normal':
        c2_cmd = 'sleep'
        engine.stats_counter['attack_in_progress'] = False
        engine.stats_counter['active_c2_channel'] = False
        engine.last_attack_time = 0
        engine.last_beacon_time = 0
        engine.add_log("DASHBOARD", "SCENARIO", "Kích hoạt Hồi 1: Máy Nạn nhân chỉ lướt web bình thường (Sạch)", "green")
    elif mode == 'beacon':
        c2_cmd = 'sleep'
        engine.stats_counter['active_c2_channel'] = True
        engine.stats_counter['attack_in_progress'] = False
        engine.add_log("DASHBOARD", "SCENARIO", "Kích hoạt Hồi 2: Bật liên lạc ngầm Botnet C2 Heartbeat (5.0s/lần)", "orange")
    elif mode == 'attack':
        c2_cmd = 'scan'
        engine.stats_counter['attack_in_progress'] = True
        engine.add_log("DASHBOARD", "SCENARIO", "Kích hoạt Hồi 3: Phát động tấn công Botnet SYN Scan bùng nổ!", "red")

    # 1. Notify Victim Zombie directly via port 5000
    try:
        req_zombie = urllib.request.Request(
            "http://victim-zombie:5000/mode",
            data=json.dumps({"mode": mode}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req_zombie, timeout=2) as resp:
            pass
    except Exception as e:
        print(f"[DASHBOARD] Không gửi được lệnh tới victim-zombie:5000: {e}", flush=True)

    # 2. Notify C2 Server
    try:
        req_c2 = urllib.request.Request(
            "http://c2-server:8443/api/command",
            data=json.dumps({"command": c2_cmd}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req_c2, timeout=2) as resp:
            pass
    except Exception as e:
        print(f"[DASHBOARD] Lỗi gửi lệnh sang C2: {e}", flush=True)

    return {"status": "ok", "mode": mode, "c2_command": c2_cmd}

@app.post("/api/control/block")
async def block_ip(request: Request):
    data = await request.json()
    ip = data.get('ip', '172.28.0.20')
    engine.blocked_ips.add(ip)
    engine.stats_counter['attack_in_progress'] = False
    engine.stats_counter['active_c2_channel'] = False
    engine.add_log("GATEWAY-IPS", "ISOLATE", f"ĐÃ KÍCH HOẠT CÁCH LY: IP {ip} bị ngắt hoàn toàn mọi luồng mạng!", "purple")
    return {"status": "ok", "blocked": list(engine.blocked_ips)}

@app.post("/api/control/unblock")
async def unblock_ip():
    engine.blocked_ips.clear()
    engine.stats_counter['attack_in_progress'] = False
    engine.stats_counter['active_c2_channel'] = False
    engine.stats_counter['active_mode'] = 'normal'
    
    # Reset victim mode to normal
    try:
        req_zombie = urllib.request.Request(
            "http://victim-zombie:5000/mode",
            data=json.dumps({"mode": "normal"}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req_zombie, timeout=2) as resp:
            pass
    except Exception:
        pass
        
    engine.add_log("GATEWAY-IPS", "UNBLOCK", "Khôi phục mạng: Đã mở chặn cho IP và đưa về trạng thái bình thường", "blue")
    return {"status": "ok", "blocked": []}

@app.post("/api/control/clear")
async def clear_counters():
    engine.flow_history.clear()
    engine.system_logs.clear()
    engine.stats_counter['total_flows'] = 0
    engine.stats_counter['botnet_flows'] = 0
    engine.stats_counter['normal_flows'] = 0
    engine.stats_counter['attack_in_progress'] = False
    engine.stats_counter['active_c2_channel'] = False
    engine.add_log("DASHBOARD", "RESET", "Đã làm sạch lịch sử luồng mạng và bộ đếm thống kê", "blue")
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def dashboard_page():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard template not found</h1>"

if __name__ == '__main__':
    print("==================================================", flush=True)
    print("  🛡️ SMART NIDS GATEWAY & DASHBOARD ĐANG KHỞI CHẠY", flush=True)
    print("  Giao diện Web: http://localhost:8501", flush=True)
    print("==================================================", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=8501)
