import os
import time
import json
import random
import threading
import sys
import http.server
import urllib.request
import urllib.error

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

NODE_ID = os.environ.get("NODE_ID", "f0")
ROLE = os.environ.get("ROLE", "PatientZero")
DEVICE_NAME = os.environ.get("DEVICE_NAME", "Máy F0 (Nạn nhân gốc)")
IP_ADDRESS = os.environ.get("IP_ADDRESS", "172.28.0.20")

# Gateway endpoints (All external traffic routes through ids-gateway)
GATEWAY_HOST = "ids-gateway"
C2_PROXY_URL = f"http://{GATEWAY_HOST}:8443/beacon"
WEB_PROXY_URL = f"http://{GATEWAY_HOST}:8080/web"
LATERAL_INSPECT_URL = f"http://{GATEWAY_HOST}:8080/infect"

# Operational status: 'clean', 'beaconing', 'infected', 'attack'
# Starts in 'clean' state (uninfected employee browsing normal web)
current_status = "clean"
active_command = "sleep"
is_running = True

def log(tag, message):
    now_str = time.strftime('%H:%M:%S')
    print(f"[{now_str}] [{DEVICE_NAME}] {tag} {message}", flush=True)

def normal_user_traffic():
    """Simulates an employee browsing company intranet & internet news."""
    log("🌐 [USER]", "Tiến trình nhân viên văn phòng: Lướt web, tra cứu tài liệu...")
    sites = ["intranet.html", "news.html", "dashboard.html", "docs.pdf", "api/data"]
    
    while is_running:
        try:
            target_page = random.choice(sites)
            req_url = f"{WEB_PROXY_URL}?page={target_page}&client={NODE_ID}"
            req = urllib.request.Request(req_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            
            with urllib.request.urlopen(req, timeout=4) as response:
                content_len = len(response.read())
                if random.random() < 0.25:
                    log("🌐 [USER]", f"Đã tải {target_page} ({content_len:,} bytes) - Trạng thái bình thường")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                log("🛑 [MẠNG]", "Mạng bị ngắt! Gặp mã 403 Forbidden (Gateway đã cô lập IP)")
        except Exception:
            pass
            
        time.sleep(random.uniform(3.5, 6.5))

def malware_c2_beaconing():
    """Simulates botnet heartbeat communication to C2 Master (P0)."""
    global active_command
    
    while is_running:
        if current_status in ['beaconing', 'infected', 'attack']:
            try:
                payload = json.dumps({
                    "bot_id": NODE_ID,
                    "role": ROLE,
                    "device_name": DEVICE_NAME,
                    "ip": IP_ADDRESS,
                    "status": "online",
                    "current_action": active_command
                }).encode('utf-8')

                req = urllib.request.Request(
                    C2_PROXY_URL, 
                    data=payload,
                    headers={'Content-Type': 'application/json'}
                )
                
                with urllib.request.urlopen(req, timeout=4) as response:
                    res_data = json.loads(response.read().decode('utf-8'))
                    active_command = res_data.get('command', 'sleep')
                    log("🦠 [BEACON]", f"Gửi Heartbeat 5.0s tới P0 (C2 Server) | Lệnh C2: [{active_command.upper()}]")
                    
                    if current_status == 'attack' or active_command in ['scan', 'flood']:
                        execute_attack(active_command)

            except urllib.error.HTTPError as e:
                if e.code == 403:
                    log("🛑 [BEACON]", "Mất kết nối P0 C2! 403 Forbidden (Gateway đã chặn)")
            except Exception:
                pass

            time.sleep(5.0)
        else:
            time.sleep(1.0)

def execute_attack(mode):
    """Fires burst of SYN scan / DoS packets when instructed."""
    log("🚨 [TẤN CÔNG]", f"ĐỒNG LOẠT TẤN CÔNG: Lệnh [{mode.upper()}]! Bắt đầu xả gói tin...")
    attack_url = f"http://{GATEWAY_HOST}:8080/probe"
    
    for i in range(20):
        try:
            req = urllib.request.Request(
                f"{attack_url}?target_port={random.randint(20, 1000)}&syn=1&bot={NODE_ID}",
                headers={'X-Botnet-Attack': 'SYN-Scan'}
            )
            with urllib.request.urlopen(req, timeout=1) as res:
                res.read()
        except urllib.error.HTTPError as e:
            if e.code == 403:
                log("🛑 [TẤN CÔNG]", "Tấn công bị chặn bởi Gateway IPS!")
                break
        except Exception:
            pass
        time.sleep(0.04)

def execute_lateral_spread():
    """F0 scans and infects internal company workstations F1-1, F1-2, F1-3."""
    log("🕷️ [LÂY LAN NỘI BỘ]", "F0 bắt đầu quét dải mạng LAN và phát tán mã độc sang các máy F1...")
    targets = [
        {"ip": "172.28.0.21", "name": "F1-1 (Kế toán)"},
        {"ip": "172.28.0.22", "name": "F1-2 (Nhân sự)"},
        {"ip": "172.28.0.23", "name": "F1-3 (Kỹ thuật)"}
    ]

    for t in targets:
        time.sleep(1.2) # Brief propagation delay for realism
        target_ip = t['ip']
        target_name = t['name']
        
        # 1. Notify Gateway of lateral movement flow so AI detects it
        try:
            probe_url = f"{LATERAL_INSPECT_URL}?src={IP_ADDRESS}&target={target_ip}"
            urllib.request.urlopen(probe_url, timeout=2).read()
        except Exception:
            pass

        # 2. Infect the target F1 machine via port 5000
        try:
            infect_url = f"http://{target_ip}:5000/infect"
            req = urllib.request.Request(
                infect_url,
                data=json.dumps({"source": IP_ADDRESS, "payload": "worm_exploit"}).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                log("💥 [LÂY LAN THÀNH CÔNG]", f"Đã xâm nhập & lây nhiễm thành công sang {target_name} ({target_ip})!")
        except Exception as e:
            log("⚠️ [LÂY LAN THẤT BẠI]", f"Không kết nối được tới {target_name}: {e}")

    log("💀 [HOÀN TẤT LÂY LAN]", "Toàn bộ mạng nội bộ đã bị biến thành mạng lưới Botnet 4 Zombie!")

class WorkstationControlHandler(http.server.BaseHTTPRequestHandler):
    """Port 5000 control & infection listener for this workstation."""
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == '/status':
            resp = {
                'node_id': NODE_ID,
                'role': ROLE,
                'device_name': DEVICE_NAME,
                'ip': IP_ADDRESS,
                'status': current_status,
                'active_command': active_command
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global current_status, active_command
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        if self.path == '/status':
            new_status = data.get('status', 'clean')
            current_status = new_status
            if new_status == 'attack':
                active_command = 'scan'
                threading.Thread(target=execute_attack, args=('scan',), daemon=True).start()
            elif new_status == 'clean':
                active_command = 'sleep'
            log("⚙️ [TRẠNG THÁI]", f"Đã chuyển sang: >>> {current_status.upper()} <<<")
            resp = {'status': 'ok', 'current_status': current_status}

        elif self.path == '/infect':
            # F1 machine receiving infection payload from F0
            src = data.get('source', 'unknown')
            current_status = "infected"
            log("🦠 [BỊ LÂY NHIỄM]", f"⚠️ ĐÃ BỊ LÂY NHIỄM MÃ ĐỘC TỪ {src}! Bắt đầu kết nối về P0 C2 Master...")
            resp = {'status': 'ok', 'node_id': NODE_ID, 'current_status': current_status}

        elif self.path == '/disinfect':
            current_status = "clean"
            active_command = "sleep"
            log("🟢 [KHỬ ĐỘC]", "Đã dọn sạch mã độc khỏi bộ nhớ. Máy đã an toàn!")
            resp = {'status': 'ok', 'current_status': 'clean'}

        elif self.path == '/spread':
            # F0 initiating lateral spreading
            if NODE_ID == 'f0':
                threading.Thread(target=execute_lateral_spread, daemon=True).start()
                resp = {'status': 'ok', 'action': 'spreading_started'}
            else:
                resp = {'status': 'error', 'message': 'Only F0 can initiate lateral spread'}

        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode('utf-8'))

def start_server():
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 5000), WorkstationControlHandler)
    server.serve_forever()

if __name__ == '__main__':
    print("==================================================", flush=True)
    print(f"  💻 {DEVICE_NAME} ĐANG KHỞI CHẠY", flush=True)
    print(f"  ID: {NODE_ID} | Role: {ROLE} | IP: {IP_ADDRESS}", flush=True)
    print("==================================================", flush=True)
    
    t_ctrl = threading.Thread(target=start_server, daemon=True)
    t_ctrl.start()

    t_user = threading.Thread(target=normal_user_traffic, daemon=True)
    t_user.start()

    t_bot = threading.Thread(target=malware_c2_beaconing, daemon=True)
    t_bot.start()

    while True:
        time.sleep(1)
