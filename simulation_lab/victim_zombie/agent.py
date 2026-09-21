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

# Gateway endpoints (Traffic passes through ids-gateway)
GATEWAY_HOST = "ids-gateway"
C2_PROXY_URL = f"http://{GATEWAY_HOST}:8443/beacon"
WEB_PROXY_URL = f"http://{GATEWAY_HOST}:8080/web"

# Current operational mode: 'normal', 'beacon', 'attack'
# Starts in 'normal' mode (clean machine browsing web)
current_mode = "normal"
active_command = "sleep"
is_running = True

def log(tag, message):
    now_str = time.strftime('%H:%M:%S')
    print(f"[{now_str}] {tag} {message}", flush=True)

def normal_user_traffic():
    """Simulates an employee browsing websites naturally."""
    log("🌐 [USER DUYỆT WEB]", "Bắt đầu tiến trình người dùng lướt web bình thường...")
    sites = ["news.html", "dashboard.html", "docs.pdf", "image.png", "api/data"]
    
    while is_running:
        try:
            target_page = random.choice(sites)
            req_url = f"{WEB_PROXY_URL}?page={target_page}"
            req = urllib.request.Request(req_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            
            with urllib.request.urlopen(req, timeout=5) as response:
                content_len = len(response.read())
                if random.random() < 0.4:
                    log("🌐 [USER DUYỆT WEB]", f"Đã tải {target_page} ({content_len:,} bytes) - Trạng thái bình thường")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                log("🛑 [USER DUYỆT WEB]", "Mạng bị ngắt! Gặp lỗi 403 Forbidden (Gateway đã chặn IP)")
            else:
                pass
        except Exception:
            pass
            
        # Natural human pauses: 3 to 6 seconds
        time.sleep(random.uniform(3.0, 6.0))

def malware_c2_beaconing():
    """Simulates the stealthy Botnet agent beaconing to C2."""
    global active_command
    log("🦠 [MÃ ĐỘC BOTNET]", "Tiến trình mã độc đã nạp. Chờ trạng thái kích hoạt...")
    
    while is_running:
        if current_mode in ['beacon', 'attack']:
            try:
                payload = json.dumps({
                    "bot_id": "zombie-machine-01",
                    "ip": "172.28.0.20",
                    "status": "ready",
                    "current_action": active_command
                }).encode('utf-8')

                req = urllib.request.Request(
                    C2_PROXY_URL, 
                    data=payload,
                    headers={'Content-Type': 'application/json'}
                )
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    res_data = json.loads(response.read().decode('utf-8'))
                    active_command = res_data.get('command', 'sleep')
                    log("🦠 [MÃ ĐỘC BEACON]", f"Gửi heartbeat 5.0s tới C2 Server (52 bytes) | Lệnh C2: [{active_command.upper()}]")
                    
                    if current_mode == 'attack' or active_command in ['scan', 'flood']:
                        execute_attack(active_command)

            except urllib.error.HTTPError as e:
                if e.code == 403:
                    log("🛑 [MÃ ĐỘC BEACON]", "Kết nối C2 thất bại! 403 Forbidden (Gateway đã ngắt kênh)")
                else:
                    pass
            except Exception as e:
                pass

            # Strict periodic heartbeat: exactly 5.0 seconds
            time.sleep(5.0)
        else:
            # In normal mode, malware is completely dormant
            time.sleep(1.0)

def execute_attack(mode):
    """Executes attack traffic when instructed."""
    log("🚨 [MÃ ĐỘC TẤN CÔNG]", f"PHÁT ĐỘNG TẤN CÔNG: Lệnh [{mode.upper()}]! Bắt đầu xả bão gói tin...")
    attack_url = f"http://{GATEWAY_HOST}:8080/probe"
    
    for i in range(25):
        try:
            req = urllib.request.Request(
                f"{attack_url}?target_port={random.randint(20, 1000)}&syn=1",
                headers={'X-Botnet-Attack': 'SYN-Scan'}
            )
            with urllib.request.urlopen(req, timeout=1) as res:
                res.read()
        except urllib.error.HTTPError as e:
            if e.code == 403:
                log("🛑 [MÃ ĐỘC TẤN CÔNG]", "Tấn công bị dập tắt! Gặp mã chặn 403 Forbidden.")
                break
        except Exception:
            pass
        time.sleep(0.04) # 40ms machine rate
        
    log("💥 [MÃ ĐỘC TẤN CÔNG]", f"Đã hoàn thành xả đợt gói tin quét cổng ({mode.upper()})")


class VictimControlHandler(http.server.BaseHTTPRequestHandler):
    """Lightweight control HTTP server on port 5000 to dynamically toggle states."""
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == '/status':
            resp = {
                'status': 'ok',
                'mode': current_mode,
                'ip': '172.28.0.20',
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
        global current_mode, active_command
        if self.path == '/mode':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body)
                new_mode = data.get('mode', 'normal')
                current_mode = new_mode
                if new_mode == 'attack':
                    active_command = 'scan'
                    # Immediately trigger an attack burst
                    threading.Thread(target=execute_attack, args=('scan',), daemon=True).start()
                elif new_mode == 'beacon':
                    active_command = 'sleep'
                elif new_mode == 'normal':
                    active_command = 'sleep'
                    
                log("⚙️ [ĐIỀU KHIỂN LAB]", f"Chuyển chế độ thành công: >>> {current_mode.upper()} <<<")
                resp = {'status': 'ok', 'mode': current_mode}
            except Exception as e:
                resp = {'status': 'error', 'message': str(e)}

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def start_control_server():
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 5000), VictimControlHandler)
    server.serve_forever()

if __name__ == '__main__':
    print("==================================================", flush=True)
    print("  💻 MÁY NẠN NHÂN (VICTIM WORKSTATION) ĐANG CHẠY", flush=True)
    print("  IP: 172.28.0.20 | Cổng điều khiển: 5000", flush=True)
    print("==================================================", flush=True)
    
    # 1. Start Control API thread
    t_ctrl = threading.Thread(target=start_control_server, daemon=True)
    t_ctrl.start()

    # 2. Start User Browsing thread
    t_user = threading.Thread(target=normal_user_traffic, daemon=True)
    t_user.start()
    
    # 3. Start Malware Beaconing thread (dormant if mode is 'normal')
    t_bot = threading.Thread(target=malware_c2_beaconing, daemon=True)
    t_bot.start()
    
    while True:
        time.sleep(1)
