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

app = FastAPI(title="Smart NIDS Botnet Detection Dashboard - Lateral Movement Edition")

# Start background network inspection proxy
engine.start_proxy_servers()

WORKER_HOSTS = {
    'f0': 'victim-f0',
    'f1_1': 'victim-f1-1',
    'f1_2': 'victim-f1-2',
    'f1_3': 'victim-f1-3'
}

def notify_workstation(bot_id, endpoint, payload=None):
    host = WORKER_HOSTS.get(bot_id, f"victim-{bot_id}")
    url = f"http://{host}:5000/{endpoint}"
    try:
        data_bytes = json.dumps(payload or {}).encode('utf-8')
        req = urllib.request.Request(url, data=data_bytes, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        # print(f"[APP] Không kết nối được tới {host}: {e}", flush=True)
        return None

@app.get("/api/stats")
async def get_stats():
    import time
    threat = "LOW"
    risk_score = 10
    now_t = time.time()
    
    is_blocked = len(engine.blocked_ips) > 0
    active_mode = engine.stats_counter.get('active_mode', 'normal')
    
    recent_attack = (now_t - engine.last_attack_time) < 8.0 and active_mode == 'attack'
    recent_beacon = (now_t - engine.last_beacon_time) < 10.0 and active_mode in ['f0_c2', 'spread', 'attack']

    # Count infected bots
    infected_count = sum(1 for w in engine.workstations.values() if w['status'] == 'infected')

    if is_blocked:
        if '172.28.0.20' in engine.blocked_ips and len(engine.blocked_ips) == 1:
            threat = "DEFENDED (TƯỜNG LỬA NIDS CHẶN SỚM F0 - 3 MÁY F1 AN TOÀN 100%)"
            risk_score = 5
        else:
            threat = "DEFENDED (ĐÃ CÔ LẬP TOÀN BỘ 4 MÁY ZOMBIE TẠI GATEWAY)"
            risk_score = 5
    elif engine.defense_engine == 'legacy':
        if recent_attack:
            threat = "CRITICAL (KHÔNG TƯỜNG LỬA: NGHẼN MẠNG DO BÃO GÓI DoS)"
            risk_score = 98
        elif active_mode in ['f0_c2', 'spread']:
            threat = "HIGH (BẢN KHÔNG TƯỜNG LỬA: BỎ LỌT C2 & F0 GỌI P0 TỰ DO)"
            risk_score = 65
    else:
        # AI NIDS Engine (Bản chứa tường lửa)
        if recent_attack:
            threat = "CRITICAL (TẤN CÔNG TỔNG LỰC 4 ZOMBIE CONFIRMED)"
            risk_score = 99
        elif active_mode == 'spread':
            threat = "CRITICAL (PHÁT HIỆN LÂY NHIỄM NỘI BỘ LATERAL MOVEMENT!)"
            risk_score = 92
        elif recent_beacon or active_mode == 'f0_c2':
            threat = "DEFENDED (TƯỜNG LỬA NIDS ĐÃ CHẶN SỚM F0)"
            risk_score = 10
        
    return {
        'total_flows': engine.stats_counter['total_flows'],
        'botnet_flows': engine.stats_counter['botnet_flows'],
        'normal_flows': engine.stats_counter['normal_flows'],
        'threat_level': threat,
        'risk_score': risk_score,
        'active_mode': active_mode,
        'defense_engine': engine.defense_engine,
        'workstations': engine.workstations,
        'infected_count': infected_count,
        'blocked_ips': list(engine.blocked_ips),
        'flows': list(engine.flow_history)[:40]
    }

@app.post("/api/control/engine")
async def toggle_defense_engine(request: Request):
    data = await request.json()
    new_engine = data.get('engine', 'ai')
    engine.defense_engine = new_engine
    active_mode = engine.stats_counter.get('active_mode', 'normal')

    if new_engine == 'legacy':
        engine.add_log("HỆ THỐNG", "CONFIG", "Đã chuyển sang: 🌐 BẢN KHÔNG CHỨA TƯỜNG LỬA (Không phát hiện C2 & Không bảo vệ LAN)", "orange")
        # If currently in Step 2, remove early block because there is no firewall!
        if active_mode == 'f0_c2':
            engine.blocked_ips.discard('172.28.0.20')
            engine.workstations['f0']['status'] = 'infected'
            engine.stats_counter['active_c2_channel'] = True
            engine.add_log("KHÔNG TƯỜNG LỬA", "UNPROTECTED", "⚠️ Không có tường lửa: F0 tự do kết nối P0 C2 Master!", "orange")
    else:
        engine.add_log("HỆ THỐNG", "CONFIG", "Đã chuyển sang: 🛡️ TƯỜNG LỬA NIDS HỌC MÁY (Phát hiện C2 & Chặn đứng F0 bảo vệ F1)", "green")
        # In AI Firewall mode, steps 3, 4, 5 do not exist because F0 is blocked early!
        if active_mode in ['f0_c2', 'spread', 'attack', 'block_f0', 'block_all']:
            engine.stats_counter['active_mode'] = 'f0_c2'
            engine.blocked_ips.clear()
            engine.blocked_ips.add('172.28.0.20')
            engine.workstations['f0']['status'] = 'blocked'
            for b_id in ['f1_1', 'f1_2', 'f1_3']:
                engine.workstations[b_id]['status'] = 'clean'
            engine.stats_counter['active_c2_channel'] = False
            engine.stats_counter['attack_in_progress'] = False
            engine.add_log("TƯỜNG LỬA AI", "IPS-BLOCK", "🛡️ TƯỜNG LỬA NIDS ĐÃ CHẶN ĐỨNG F0! 3 máy F1 an toàn 100% (Các bước 3, 4, 5 bị triệt tiêu).", "green")
    return {"status": "ok", "defense_engine": engine.defense_engine}

@app.post("/api/control/scenario")
async def handle_scenario(request: Request):
    data = await request.json()
    mode = data.get('scenario', 'normal')
    engine.stats_counter['active_mode'] = mode

    if mode == 'normal':
        # 1. Disinfect all 4 workstations
        for b_id in ['f0', 'f1_1', 'f1_2', 'f1_3']:
            notify_workstation(b_id, 'disinfect')
            engine.workstations[b_id]['status'] = 'clean'
        
        # 2. Reset P0 C2 server
        try:
            req = urllib.request.Request("http://c2-server:8443/api/clear", data=b'{}', headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

        # 3. Clear Gateway state
        engine.blocked_ips.clear()
        engine.stats_counter['attack_in_progress'] = False
        engine.stats_counter['active_c2_channel'] = False
        engine.last_attack_time = 0
        engine.last_beacon_time = 0
        engine.add_log("KỊCH BẢN", "STEP-1", "Hồi 1: Toàn bộ mạng nội bộ an toàn. Cả 4 máy phòng ban F0 (Kinh Doanh), F1-1 (Kế toán), F1-2 (Nhân sự), F1-3 (Kỹ thuật) đều sạch.", "green")

    elif mode == 'f0_c2':
        # F0 gets infected by malware and tries to call P0 C2 Server
        notify_workstation('f0', 'status', {'status': 'beaconing'})
        engine.stats_counter['attack_in_progress'] = False

        if engine.defense_engine == 'ai':
            # TƯỜNG LỬA NIDS HỌC MÁY (Bản chứa tường lửa):
            # Tường lửa phát hiện chu kỳ 5.0s -> Chặn sớm F0 & bảo vệ 3 máy F1 an toàn!
            engine.blocked_ips.add('172.28.0.20')
            engine.workstations['f0']['status'] = 'blocked'
            for b_id in ['f1_1', 'f1_2', 'f1_3']:
                engine.workstations[b_id]['status'] = 'clean'
            engine.stats_counter['active_c2_channel'] = False
            engine.add_log("TƯỜNG LỬA AI", "STEP-2", "Hồi 2: F0 dính mã độc gọi C2 -> TƯỜNG LỬA NIDS PHÁT HIỆN & CHẶN SỚM F0! 3 máy F1 an toàn 100%.", "green")
        else:
            # BẢN KHÔNG CHỨA TƯỜNG LỬA:
            # Không có tường lửa bảo vệ -> F0 tự do gửi Heartbeat về P0 mà không bị chặn!
            engine.blocked_ips.discard('172.28.0.20')
            engine.workstations['f0']['status'] = 'infected'
            for b_id in ['f1_1', 'f1_2', 'f1_3']:
                engine.workstations[b_id]['status'] = 'clean'
            engine.stats_counter['active_c2_channel'] = True
            engine.add_log("KỊCH BẢN", "STEP-2", "Hồi 2: Bản không chứa tường lửa: F0 dính mã độc và tự do gọi C2 về P0 mà không bị phát hiện hay ngăn chặn!", "orange")

    elif mode == 'spread':
        # Instruct P0 to issue spread command
        try:
            req = urllib.request.Request("http://c2-server:8443/api/command", data=json.dumps({"command": "spread"}).encode('utf-8'), headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

        # F0 initiates lateral movement to infect F1-1, F1-2, F1-3
        notify_workstation('f0', 'spread')
        # Mark all as infected in gateway
        for b_id in ['f0', 'f1_1', 'f1_2', 'f1_3']:
            engine.workstations[b_id]['status'] = 'infected'
        engine.stats_counter['active_c2_channel'] = True
        engine.add_log("KỊCH BẢN", "STEP-3", "Hồi 3: F0 (Kinh Doanh) quét mạng LAN nội bộ và lây nhiễm sang 3 máy phòng ban F1! Đội quân 4 Zombie hình thành.", "purple")

    elif mode == 'attack':
        # Instruct P0 to issue attack command
        try:
            req = urllib.request.Request("http://c2-server:8443/api/command", data=json.dumps({"command": "scan"}).encode('utf-8'), headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

        # All 4 bots attack simultaneously
        for b_id in ['f0', 'f1_1', 'f1_2', 'f1_3']:
            notify_workstation(b_id, 'status', {'status': 'attack'})
            engine.workstations[b_id]['status'] = 'infected'

        engine.stats_counter['attack_in_progress'] = True
        engine.add_log("KỊCH BẢN", "STEP-4", "Hồi 4: P0 phát lệnh tổng tấn công! Cả 4 Zombie (F0 + 3xF1) đồng loạt xả bão gói DoS!", "red")

    elif mode == 'block_f0':
        # Early Defense: Block only F0 (172.28.0.20)
        engine.blocked_ips.clear()
        engine.blocked_ips.add('172.28.0.20')
        engine.workstations['f0']['status'] = 'blocked'
        # Disinfect all F1s so they are 100% clean and safe
        for b_id in ['f1_1', 'f1_2', 'f1_3']:
            notify_workstation(b_id, 'disinfect')
            engine.workstations[b_id]['status'] = 'clean'
        engine.stats_counter['attack_in_progress'] = False
        engine.stats_counter['active_c2_channel'] = False
        engine.stats_counter['active_mode'] = 'block_f0'
        engine.add_log("PHÒNG THỦ AI", "EARLY-BLOCK", "🛡️ KÍCH HOẠT PHÒNG THỦ SỚM: Đã cô lập F0 (NV Kinh Doanh - 172.28.0.20) tại Gateway! 3 máy phòng ban F1 được bảo vệ an toàn 100%.", "green")

    elif mode == 'block_all':
        # Full containment: Block all 4 machines
        engine.blocked_ips.clear()
        for ip in ['172.28.0.20', '172.28.0.21', '172.28.0.22', '172.28.0.23']:
            engine.blocked_ips.add(ip)
        for b_id in ['f0', 'f1_1', 'f1_2', 'f1_3']:
            engine.workstations[b_id]['status'] = 'blocked'
        engine.stats_counter['attack_in_progress'] = False
        engine.stats_counter['active_c2_channel'] = False
        engine.stats_counter['active_mode'] = 'block_all'
        engine.add_log("PHÒNG THỦ IPS", "CONTAINMENT", "🛑 ĐÃ CÔ LẬP TOÀN BỘ 4 MÁY ZOMBIE NỘI BỘ TẠI GATEWAY!", "purple")

    elif mode == 'unblock':
        engine.blocked_ips.clear()
        for b_id in ['f0', 'f1_1', 'f1_2', 'f1_3']:
            notify_workstation(b_id, 'disinfect')
            engine.workstations[b_id]['status'] = 'clean'
        engine.stats_counter['active_mode'] = 'normal'
        engine.stats_counter['attack_in_progress'] = False
        engine.stats_counter['active_c2_channel'] = False
        engine.add_log("GATEWAY-IPS", "UNBLOCK", "Đã mở chặn toàn bộ IP và khôi phục mạng công ty.", "blue")

    return {"status": "ok", "scenario": mode, "workstations": engine.workstations}

@app.get("/api/logs")
async def get_logs():
    return {
        'logs': list(engine.system_logs)
    }

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
    print("  🛡️ SMART NIDS GATEWAY ĐANG KHỞI CHẠY", flush=True)
    print("  Giao diện Web: http://localhost:8501", flush=True)
    print("==================================================", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=8501)
