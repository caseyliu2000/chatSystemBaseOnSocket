# server_json.py
import socket
import threading
import json
from datetime import datetime
import re

#server IP and port
HOST = '127.0.0.1'
PORT = 65432

# 客户端 IP 分配范围
CLIENT_IP_BASE = '127.0.0.'
CLIENT_IP_START = 2
CLIENT_IP_END = 255 * 1 + 254  # 127.0.0.2 - 127.0.0.254

# 本地 client_ip 分配表 {name: client_ip} 保存本地client和client_ip的对应关系
client_ip_table = {}
# 已分配的 client_ip set
allocated_client_ips = set()

# {name: conn} #conn 是socket connection object
clients = {}

def allocate_client_ip():
    for i in range(CLIENT_IP_START, CLIENT_IP_END + 1):
        ip = f'{CLIENT_IP_BASE}{i}'
        # 如果该ip 没有被分配，则分配给client
        if ip not in allocated_client_ips:
            allocated_client_ips.add(ip)
            return ip
    return None  # 没有可用 IP

def release_client_ip(ip):
    allocated_client_ips.discard(ip)

# 其他 server 上 client 信息表（预留，暂不自动同步）
# {client_name: {"server_ip": ..., "client_ip": ...}}
external_clients = {}

def handle_client(conn, addr, name):
    print(f"{name} connected from {addr}")
    # 分配 client_ip
    client_ip = allocate_client_ip()
    if not client_ip:
        response = {
            "type": "system",
            "from": "server",
            "to": name,
            "to_type": "user",
            "payload": "No available client IPs. Connection refused.",
            "payload_type": "text",
            "timestamp": datetime.now().isoformat()
        }
        conn.sendall(json.dumps(response).encode())
        conn.close()
        return
    client_ip_table[name] = client_ip
    try:
        response = {
            "type": "system",
            "from": "server",
            "to": name,
            "to_type": "user",
            "payload": f"Your assigned client_ip: {client_ip}",
            "payload_type": "text",
            "timestamp": datetime.now().isoformat()
        }
        conn.sendall(json.dumps(response).encode())
    except:
        pass
    print(f"[Server] Assigned {name} client_ip: {client_ip}")
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            try:
                msg = json.loads(data.decode())
                payload = msg.get('payload', '')
                payload_type = msg.get('payload_type', '')

                # 命令处理
                if payload_type == 'command':
                    #显示当前所有online 用户
                    if payload.startswith('/list'):
                        # 除自己外的在线用户
                        online_users = [u for u in clients.keys() if u != name]
                        response = {
                            "type": "message",
                            "from": "server",
                            "to": name,
                            "to_type": "user",
                            "payload": f"Online users: {', '.join(online_users) if online_users else 'None'}",
                            "payload_type": "text",
                            "timestamp": datetime.now().isoformat()
                        }
                        conn.sendall(json.dumps(response).encode())
                        continue
                    #实现clientA 向clientB 发送消息 格式：/msg clientB 信息内容
                    elif payload.startswith('/msg '):
                        # 支持 /msg <user> 内容 格式
                        match = re.match(r'/msg\s+(\S+)\s+(.+)', payload)
                        if match:
                            target = match.group(1)
                            content = match.group(2)
                            if not target or target == name:
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": "Invalid target user.",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(json.dumps(response).encode())
                                continue
                            if target not in clients:
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": f"User {target} is not online.",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(json.dumps(response).encode())
                                continue
                            # 直接转发消息
                            out_msg = {
                                "type": "message",
                                "from": name,
                                "to": target,
                                "to_type": "user",
                                "payload": content,
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            clients[target].sendall(json.dumps(out_msg).encode())
                            continue
                    #实现clientA 向clientB 发送文件 格式：/msg_file clientB 文件路径
                    elif payload.startswith('/msg_file '):
                        # 支持 /msg_file <user> <文件路径> 格式
                        match = re.match(r'/msg_file\s+(\S+)\s+(.+)', payload)
                        if match:
                            target = match.group(1)
                            file_path = match.group(2)
                            if not target or target == name:
                                # 如果target 是当前用户，则提示错误
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": "Invalid target user.",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(json.dumps(response).encode())
                                continue
                            # 如果target 不在线，则提示错误
                            if target not in clients:
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": f"User {target} is not online.",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(json.dumps(response).encode())
                                continue
                            # 发送文件传输请求
                            file_request = {
                                "type": "message_file",
                                "from": name,
                                "to": target,
                                "to_type": "user",
                                "payload": f"File transfer request: {file_path}",
                                "payload_type": "file",
                                "timestamp": datetime.now().isoformat(),
                                "payload_id": str(hash(datetime.now())),
                                "file_path": file_path
                            }
                            # 发送文件传输 数据
                            clients[target].sendall(json.dumps(file_request).encode())
                            continue
                # 普通消息
                print(f"[{msg['from']}] ➜ [{msg['to']}] : {msg['payload']}")
                recipient = msg["to"]
                if recipient in clients:
                    clients[recipient].sendall(json.dumps(msg).encode())
                else:
                    warning = {
                        "type": "message",
                        "from": "server",
                        "to": msg["from"],
                        "to_type": "user",
                        "payload": f"User {recipient} is not online.",
                        "payload_type": "text",
                        "timestamp": datetime.now().isoformat()
                    }
                    conn.sendall(json.dumps(warning).encode())
            except Exception as e:
                print("JSON decode failed:", e)
                continue
        except:
            break

    print(f"{name} disconnected")
    conn.close()
    if name in clients:
        del clients[name]
    if name in client_ip_table:
        release_client_ip(client_ip_table[name])
        del client_ip_table[name]
    print(f"[Server] Current client_ip_table: {client_ip_table}")


# 主线程监听
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[Server] Listening on {HOST}:{PORT}...")

    while True:
        conn, addr = s.accept()
        conn.sendall("Enter your name:".encode())
        name = conn.recv(1024).decode().strip()
        clients[name] = conn
        threading.Thread(target=handle_client, args=(conn, addr, name), daemon=True).start()
        # 打印当前所有 client_ip
        print(f"[Server] Current client_ip_table: {client_ip_table}")
        print(f"[Server] External clients (other servers): {external_clients}")