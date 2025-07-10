# server_json.py
import socket
import threading
import json
from datetime import datetime
import re

#server IP and port
HOST = '127.0.0.1'
PORT = 65432

#之后会修改成username 和server IP 信息。
clients = {}  # {name: conn} #conn 是socket connection object

def handle_client(conn, addr, name):
    print(f"{name} connected from {addr}")
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