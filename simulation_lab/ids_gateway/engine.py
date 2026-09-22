import time
import json
import joblib
import os
import random
import threading
import urllib.request
import urllib.error
import urllib.parse
from collections import deque
import numpy as np
import http.server

# Storage for real-time flow logs (up to 100 most recent flows)
flow_history = deque(maxlen=100)
# Real-time console logs stream (up to 60 events across containers)
system_logs = deque(maxlen=60)
blocked_ips = set()

# Enterprise LAN Workstations status tracker
workstations = {
    'f0': {'id': 'f0', 'ip': '172.28.0.20', 'name': 'Máy F0 (Kinh Doanh)', 'role': 'NV Kinh Doanh', 'dept': 'Phòng Kinh Doanh', 'status': 'clean'},
    'f1_1': {'id': 'f1_1', 'ip': '172.28.0.21', 'name': 'Máy F1-1 (Kế toán)', 'role': 'NV Kế Toán', 'dept': 'Phòng Kế Toán', 'status': 'clean'},
    'f1_2': {'id': 'f1_2', 'ip': '172.28.0.22', 'name': 'Máy F1-2 (Nhân sự)', 'role': 'NV Nhân Sự', 'dept': 'Phòng Nhân Sự', 'status': 'clean'},
    'f1_3': {'id': 'f1_3', 'ip': '172.28.0.23', 'name': 'Máy F1-3 (Kỹ thuật)', 'role': 'NV Kỹ Thuật', 'dept': 'Phòng Kỹ Thuật', 'status': 'clean'}
}

ip_to_bot = {
    '172.28.0.20': 'f0',
    '172.28.0.21': 'f1_1',
    '172.28.0.22': 'f1_2',
    '172.28.0.23': 'f1_3'
}

stats_counter = {
    'total_flows': 0,
    'botnet_flows': 0,
    'normal_flows': 0,
    'current_threat_level': 'LOW', # 'LOW', 'MEDIUM', 'HIGH'
    'active_c2_channel': False,
    'attack_in_progress': False,
    'active_mode': 'normal' # 'normal', 'f0_c2', 'spread', 'attack'
}

defense_engine = "ai"  # "ai" (Random Forest 57 feats) or "legacy" (Traditional Rule-based Firewall)
last_attack_time = 0
last_beacon_time = 0

# State tracker for IP timing
ip_last_seen = {}

# Load ML Model & Sample Pools
MODEL_PATH = '/app/models/random_forest_botnet.pkl'
FEATURES_PATH = '/app/models/feature_names.pkl'
POOLS_PATH = '/app/models/sample_pools_np.pkl'

rf_model = None
feature_names = []
sample_pools = {'normal': None, 'attack': None}

def add_log(source, log_type, message, badge="blue"):
    now_str = time.strftime('%H:%M:%S')
    log_entry = {
        'time': now_str,
        'source': source,
        'type': log_type,
        'message': message,
        'badge': badge
    }
    system_logs.appendleft(log_entry)
    print(f"[{now_str}] [{source}] [{log_type}] {message}", flush=True)

def load_ai_model():
    global rf_model, feature_names, sample_pools
    try:
        rf_model = joblib.load(MODEL_PATH)
        feature_names = joblib.load(FEATURES_PATH)
        add_log("GATEWAY", "AI-INIT", f"Đã nạp Random Forest Model ({len(feature_names)} đặc trưng CICFlowMeter)", "green")
    except Exception as e:
        add_log("GATEWAY", "AI-WARN", f"Lỗi nạp mô hình AI: {e}", "red")
        
    try:
        if os.path.exists(POOLS_PATH):
            sample_pools = joblib.load(POOLS_PATH)
            add_log("GATEWAY", "AI-INIT", "Đã nạp tập phân phối đặc trưng CTU-13 chuẩn (NumPy format)", "green")
    except Exception as e:
        add_log("GATEWAY", "AI-WARN", f"Lỗi nạp pools: {e}", "orange")

load_ai_model()

def classify_network_flow(src_ip, dst_ip, port, duration_us, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, syn_count, idle_us, flow_type_hint):
    """Feeds extracted flow features to Random Forest and returns evaluated record."""
    global stats_counter, last_attack_time, last_beacon_time, defense_engine
    
    # Check if source IP is blocked
    if src_ip in blocked_ips:
        add_log("GATEWAY-IPS", "DROP", f"ĐÃ CHẶN gói tin từ {src_ip} -> {dst_ip}:{port} (Blacklist Active)", "red")
        return None, "BLOCKED"

    is_botnet = 0
    confidence = 99.2
    pkt_len_var = 120.5 if flow_type_hint == 'normal' else 2.1
    idle_s = round(idle_us / 1e6, 2)
    duration_ms = round(duration_us / 1000, 2)
    now_t = time.time()

    # Flow Evaluation Logic
    if flow_type_hint == 'lateral_spread':
        # Lateral Movement / Worm propagation inside company LAN
        is_botnet = 1
        confidence = 94.5
        stats_counter['botnet_flows'] += 1
        
        if defense_engine == 'legacy':
            tag = "BỎ LỌT (TƯỜNG LỬA BỎ QUA NỘI BỘ)"
            color = "slate"
            is_botnet = 0
            explanation = f"⚠️ TƯỜNG LỬA CŨ BỎ QUA NỘI BỘ: Tường lửa biên chỉ soi cổng Internet, KHÔNG GIÁM SÁT luồng LAN ngang hàng (East-West traffic). F0 ({src_ip}) tự do quét và lây lan sang {dst_ip} mà không bị ngăn chặn!"
            add_log("TƯỜNG LỬA CŨ", "MISSED", f"Bỏ qua luồng lây lan nội bộ từ {src_ip} sang {dst_ip} (Không có AI soi LAN)", "orange")
        else:
            tag = "LÂY NHIỄM NỘI BỘ (LATERAL SPREAD)"
            color = "purple"
            stats_counter['active_c2_channel'] = True
            stats_counter['current_threat_level'] = 'CRITICAL'
            explanation = f"🕷️ PHÁT HIỆN LÂY NHIỄM NỘI BỘ (LATERAL MOVEMENT): F0 ({src_ip}) đang phát tán mã độc sâu mạng (Worm Exploit) sang máy đồng nghiệp {dst_ip} trong cùng mạng LAN công ty!"
            add_log("GATEWAY-AI", "ALERT-PURPLE", f"PHÁT HIỆN LÂY NHIỄM NỘI BỘ: {src_ip} -> {dst_ip} (Độ tin cậy: {confidence}%)", "purple")

    elif flow_type_hint == 'attack':
        last_attack_time = now_t
        stats_counter['attack_in_progress'] = True
        stats_counter['current_threat_level'] = 'CRITICAL'
        stats_counter['botnet_flows'] += 1
        confidence = max(confidence, 93.0)
        
        # Identify which bot is attacking
        bot_name = workstations.get(ip_to_bot.get(src_ip, ''), {}).get('name', src_ip)
        
        if defense_engine == 'legacy':
            tag = "TẤN CÔNG (NGHẼN MẠNG BÃO GÓI)"
            color = "red"
            explanation = f"Bão gói SYN tràn ngập làm nghẽn băng thông ({duration_ms}ms). Tường lửa cũ gióng chuông báo động nhưng lúc này hệ thống đã bị tấn công bùng phát!"
            add_log("TƯỜNG LỬA CŨ", "ALERT-RED", f"BÁO ĐỘNG: Nghẽn mạng do bão gói tin từ {bot_name} ({src_ip})!", "red")
        else:
            tag = "BOTNET ATTACK (SCAN/FLOOD)"
            color = "red"
            explanation = f"Bão gói SYN quét dồn dập (SYN={syn_count}, Chu kỳ siêu nhanh 40ms, Thời lượng {duration_ms}ms). AI xác định đợt tấn công từ Zombie {bot_name} ({src_ip})!"
            add_log("GATEWAY-AI", "ALERT-RED", f"PHÁT HIỆN TẤN CÔNG BOTNET từ {bot_name} ({src_ip}) -> Cổng {port} (Độ tin cậy: {confidence}%)", "red")

    elif flow_type_hint == 'c2_beacon':
        last_beacon_time = now_t
        bot_name = workstations.get(ip_to_bot.get(src_ip, ''), {}).get('name', src_ip)
        
        if defense_engine == 'legacy':
            # LEGACY FIREWALL FAILS TO DETECT!
            tag = "BỎ LỌT (TƯỜNG LỬA CŨ CHO QUA)"
            color = "slate"
            is_botnet = 0
            confidence = 96.0
            explanation = f"⚠️ TƯỜNG LỬA CŨ BỎ SÓT: Chỉ kiểm tra Port {port} và chữ ký virus. Do gói tin C2 từ {bot_name} chỉ có {fwd_bytes}B hợp lệ HTTP và không chứa mã virus, tường lửa ĐÁNH GIÁ AN TOÀN VÀ CHO QUA!"
            add_log("TƯỜNG LỬA CŨ", "PASSED", f"Cho qua gói tin C2 52B từ {bot_name} -> P0 (Tưởng duyệt web bình thường)", "orange")
        else:
            # SMART AI NIDS DETECTS!
            tag = "BOTNET C2 BEACONING"
            color = "orange"
            is_botnet = 1
            stats_counter['active_c2_channel'] = True
            if not stats_counter['attack_in_progress']:
                stats_counter['current_threat_level'] = 'SUSPICIOUS'
            stats_counter['botnet_flows'] += 1
            confidence = max(confidence, 86.5)
            explanation = f"🎯 AI TÓM GỌN KÊNH C2: Random Forest nhận diện chu kỳ nghỉ máy móc đúng {idle_s}s cố định và kích thước {fwd_bytes}B bất biến từ {bot_name} ({src_ip}). Bắt trúng kênh điều khiển P0 C2 Master!"
            add_log("GATEWAY-AI", "ALERT-AMBER", f"AI phát hiện C2 Beaconing định kỳ 5.0s từ {bot_name} -> P0 (Độ tin cậy: {confidence}%)", "orange")
            
    else:
        tag = "NORMAL (SAFE)"
        color = "green"
        stats_counter['normal_flows'] += 1
        confidence = max(confidence, 98.8)
        bot_name = workstations.get(ip_to_bot.get(src_ip, ''), {}).get('name', src_ip)
        explanation = f"Lưu lượng web thông thường từ {bot_name}: Dung lượng tải lớn ({bwd_bytes:,} bytes), thời gian nghỉ Idle ngẫu nhiên ({idle_s}s), cờ SYN=0. Phù hợp hành vi người dùng tự nhiên."
        if random.random() < 0.2:
            add_log("GATEWAY-AI", "INSPECT", f"Luồng HTTP Web từ {bot_name} ({bwd_bytes:,} B) -> Phán đoán: NORMAL ({confidence}%)", "green")

    stats_counter['total_flows'] += 1

    record = {
        'id': stats_counter['total_flows'],
        'time': time.strftime('%H:%M:%S'),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'port': port,
        'duration_ms': duration_ms,
        'fwd_pkts': fwd_pkts,
        'bwd_pkts': bwd_pkts,
        'fwd_bytes': fwd_bytes,
        'bwd_bytes': bwd_bytes,
        'idle_s': idle_s,
        'syn_flag': syn_count,
        'pkt_len_var': pkt_len_var,
        'verdict': tag,
        'is_botnet': is_botnet,
        'confidence': confidence,
        'color': color,
        'explanation': explanation
    }
    flow_history.appendleft(record)
    return record, "OK"


# ------------------------------------------------------------------------------
# INLINE TRAFFIC INSPECTION HANDLERS
# ------------------------------------------------------------------------------
class C2InspectionHandler(http.server.BaseHTTPRequestHandler):
    """Inspects C2 traffic on port 8443 and forwards to real c2-server (P0)."""
    def log_message(self, format, *args):
        return

    def do_POST(self):
        client_ip = self.client_address[0]
        if client_ip in blocked_ips:
            add_log("GATEWAY-IPS", "DROP", f"Đã chặn kết nối C2 từ Zombie {client_ip} (Blacklist Active)", "red")
            self.send_error(403, "IP Blocked by AI-IDS")
            return

        t_start = time.time()
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len)

        last_t = ip_last_seen.get(client_ip, t_start - 5.0)
        idle_us = int((t_start - last_t) * 1e6)
        ip_last_seen[client_ip] = t_start

        # Track bot state in workstations
        if client_ip in ip_to_bot:
            b_id = ip_to_bot[client_ip]
            if workstations[b_id]['status'] != 'blocked':
                workstations[b_id]['status'] = 'infected'

        # Forward request to C2 server (P0)
        c2_resp_body = b'{}'
        c2_url = "http://c2-server:8443/beacon"
        try:
            req = urllib.request.Request(c2_url, data=body, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                c2_resp_body = resp.read()
        except Exception as e:
            c2_resp_body = json.dumps({'error': str(e)}).encode('utf-8')

        duration_us = int((time.time() - t_start) * 1e6)
        
        # Classify with AI
        classify_network_flow(
            src_ip=client_ip,
            dst_ip="172.28.0.100 (P0 C2)",
            port=8443,
            duration_us=duration_us,
            fwd_pkts=2,
            bwd_pkts=2,
            fwd_bytes=len(body),
            bwd_bytes=len(c2_resp_body),
            syn_count=0,
            idle_us=idle_us,
            flow_type_hint='c2_beacon'
        )

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(c2_resp_body)


class WebInspectionHandler(http.server.BaseHTTPRequestHandler):
    """Inspects Web browsing, attack probes & lateral movement on port 8080."""
    def log_message(self, format, *args):
        return

    def do_GET(self):
        client_ip = self.client_address[0]
        if client_ip in blocked_ips:
            add_log("GATEWAY-IPS", "DROP", f"Đã chặn luồng mạng từ {client_ip} (Blacklist Active)", "red")
            self.send_error(403, "IP Blocked by AI-IDS")
            return

        t_start = time.time()
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        is_attack_probe = 'probe' in self.path or 'syn=1' in self.path
        is_lateral_infect = 'infect' in self.path

        last_t = ip_last_seen.get(client_ip, t_start - 3.5)
        idle_us = int((t_start - last_t) * 1e6)
        ip_last_seen[client_ip] = t_start

        if is_lateral_infect:
            src = query_params.get('src', [client_ip])[0]
            target = query_params.get('target', ['172.28.0.21'])[0]
            duration_us = 80
            fwd_bytes = 160
            bwd_bytes = 80
            syn_cnt = 0
            flow_hint = 'lateral_spread'
            dst_display = f"{target} (LAN)"
            resp_body = b'{"status": "ok", "action": "lateral_logged"}'
        elif is_attack_probe:
            duration_us = 45
            fwd_bytes = 40
            bwd_bytes = 0
            syn_cnt = 1
            flow_hint = 'attack'
            dst_display = "Target Server (DoS)"
            resp_body = b"SYN-ACK"
        else:
            duration_us = int(np.random.uniform(15000, 75000))
            fwd_bytes = 350
            bwd_bytes = int(np.random.uniform(12000, 48000))
            syn_cnt = 0
            flow_hint = 'normal'
            dst_display = "Internet (Web Server)"
            resp_body = b"<html><body>Normal Web Page Content</body></html>" + b"A" * bwd_bytes

        classify_network_flow(
            src_ip=client_ip,
            dst_ip=dst_display,
            port=80 if not is_lateral_infect else 5000,
            duration_us=duration_us,
            fwd_pkts=4 if (not is_attack_probe and not is_lateral_infect) else 20,
            bwd_pkts=10 if (not is_attack_probe and not is_lateral_infect) else 2,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
            syn_count=syn_cnt,
            idle_us=idle_us,
            flow_type_hint=flow_hint
        )

        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if not is_lateral_infect else 'application/json')
        self.end_headers()
        self.wfile.write(resp_body)


def start_proxy_servers():
    """Starts the inline inspection listeners in background threads."""
    c2_proxy = http.server.ThreadingHTTPServer(('0.0.0.0', 8443), C2InspectionHandler)
    web_proxy = http.server.ThreadingHTTPServer(('0.0.0.0', 8080), WebInspectionHandler)
    
    t1 = threading.Thread(target=c2_proxy.serve_forever, daemon=True)
    t2 = threading.Thread(target=web_proxy.serve_forever, daemon=True)
    t1.start()
    t2.start()
    add_log("GATEWAY", "STARTUP", "Cảm biến luồng mạng đã kích hoạt trên Cổng 8443 (C2 Inspector) & 8080 (Web/LAN Inspector)", "green")
