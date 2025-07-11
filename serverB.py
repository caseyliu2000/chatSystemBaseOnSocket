# server_json.py
import socket
import threading
import json
from datetime import datetime
import re
import base64


#server IP and port
HOST = '127.0.0.1'
PORT = 65433
SERVER_PORT=65001

# 客户端 IP 分配范围
CLIENT_IP_BASE = '127.0.0.'
CLIENT_IP_START = 2
CLIENT_IP_END = 255 * 1 + 254  # 127.0.0.2 - 127.0.0.254


# 已连接的其他 server {addr: conn}
server_peers = {}

# 本地 client_ip 分配表 {name: client_ip} 保存本地client和client_ip的对应关系
client_ip_table = {}
# 已分配的 client_ip set
allocated_client_ips = set()

# {name: conn} #conn 是socket connection object
clients = {}

# ==== 本 Server 配置信息 ====
SERVER_ID = "serverB"  # 启动时可手动修改为 serverB
SERVER_IP = "127.0.0.1"
# SERVER_PORT_CLIENT = 65000  # 本 server 的 client 端口
# SERVER_PORT_SERVER = 65001  # 本 server 的 server-to-server 端口

# 其他 server 的信息（假设只与 serverB 通信）
PEER_SERVER_ID = "serverA" # (注意修改)
PEER_SERVER_IP = "127.0.0.1"# (注意修改)
PEER_SERVER_PORT = 65000 # (注意修改)

# external_clients 结构: {client_name: {"server_ip": ..., "server_port": ...}}
external_clients = {}

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

'''
将消息转发到其他 server（短连接）
1. 连接其他server
2. 发送消息
3. 关闭连接
'''
def forward_message_to_peer(target_server_ip, target_server_port, msg):
    """将消息转发到其他 server（短连接）"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
            peer_sock.connect((target_server_ip, target_server_port))
            peer_sock.sendall(json.dumps(msg).encode())
    except Exception as e:
        print(f"[Server] Failed to forward message to peer: {e}")

'''
当local client 输入/list 命令时，会请求其他server 获得其在线用户   
1. 主动连接其他server
2. 发送握手信息
3. 发送在线用户请求
4. 等待回复
5. 更新 external_clients
6. 返回在线用户列表
'''
def request_peer_online_users():
    """主动连接 serverB，请求其在线用户列表"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
            peer_sock.connect((PEER_SERVER_IP, PEER_SERVER_PORT))
            # 只发一条消息，包含身份和请求
            req = {"type": "online_user_request", "server_id": SERVER_ID}
            peer_sock.sendall(json.dumps(req).encode())
            # 等待回复
            data = peer_sock.recv(4096)
            msg = json.loads(data.decode())
            if msg.get("type") == "online_user_response":
                peer_id = msg.get("server_id", "unknown")
                online_users = msg.get("online_users", [])
                # 更新 external_clients
                for uname in online_users:
                    external_clients[uname] = {"server_ip": PEER_SERVER_IP, "server_port": PEER_SERVER_PORT}
                return online_users
    except Exception as e:
        print(f"[Server] Failed to request peer online users: {e}")
    return []

'''
处理client 连接
1. 给新client分配 client_ip
2. 发送系统消息，告知client 其client_ip
3. 启动client-to-server 处理线程
5. 打印当前所有 client_ip
6. 打印当前所有 external_clients
'''
def handle_client(conn, addr, name):
    print(f"{name} connected from {addr}")
    # 给新client分配 client_ip
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
                        # 本地在线用户（除自己外）
                        online_users = [u for u in clients.keys() if u != name]
                        # 请求 serverB 的在线用户
                        peer_users = request_peer_online_users()
                        # 合并所有用户
                        all_users = online_users + peer_users
                        response = {
                            "type": "message",
                            "from": "server",
                            "to": name,
                            "to_type": "user",
                            "payload": f"Online users: {', '.join(all_users) if all_users else 'None'}",
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
                            #如果target client 在local
                            if target in clients:
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
                            #如果target client在其他server
                            elif target in external_clients:
                                peer_info = external_clients[target]
                                out_msg = {
                                    "type": "message",
                                    "from": name,
                                    "to": target,
                                    "to_type": "user",
                                    "payload": content,
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                forward_message_to_peer(peer_info["server_ip"], peer_info["server_port"], out_msg)
                                continue
                            else:
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
                    #实现clientA 向clientB 发送文件 格式：/msg_file clientB 文件路径
                    elif payload.startswith('/msg_file '):
                        # 支持 /msg_file <user> <文件路径> 格式
                        match = re.match(r'/msg_file\s+(\S+)\s+(.+)', payload)
                        if match:
                            target = match.group(1)
                            file_path = match.group(2)
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
                            # 读取文件内容并 base64 编码
                            try:
                                with open(file_path, 'rb') as f:
                                    file_bytes = f.read(10 * 1024 * 1024 + 1)
                                if len(file_bytes) > 10 * 1024 * 1024:
                                    raise Exception("File too large (max 10MB)")
                                file_b64 = base64.b64encode(file_bytes).decode()
                            except Exception as e:
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": f"File error: {e}",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(json.dumps(response).encode())
                                continue
                            file_request = {
                                "type": "message_file",
                                "from": name,
                                "to": target,
                                "to_type": "user",
                                "payload": file_b64,
                                "payload_type": "file",
                                "timestamp": datetime.now().isoformat(),
                                "payload_id": str(hash(datetime.now())),
                                "file_path": file_path
                            }
                            if target in clients:
                                clients[target].sendall(json.dumps(file_request).encode())
                                continue
                            elif target in external_clients:
                                peer_info = external_clients[target]
                                forward_message_to_peer(peer_info["server_ip"], peer_info["server_port"], file_request)
                                continue
                            else:
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
                # 普通消息
                print(f"[{msg['from']}] ➜ [{msg['to']}] : {msg['payload']}")
                recipient = msg["to"]
                if recipient in clients:
                    clients[recipient].sendall(json.dumps(msg).encode())
                elif recipient in external_clients:
                    # 跨服务器转发
                    peer_info = external_clients[recipient]
                    forward_message_to_peer(peer_info["server_ip"], peer_info["server_port"], msg)
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

'''
处理其他server 发来的消息
1. 如果消息是普通消息，则转发到本地client
2. 如果消息是文件传输请求，则转发到本地client
'''
def receive_message_from_peer(msg):
    if msg.get("type") == "message":
        recipient = msg["to"]
        if recipient in clients:
            clients[recipient].sendall(json.dumps(msg).encode())
            print(f"[Server] Forwarded message to local client {recipient}")
        else:
            print(f"[Server] Received message for unknown client {recipient}")
    # 未来可扩展更多 type
    elif msg.get("type") == "message_file":
        recipient = msg["to"]
        if recipient in clients:
            clients[recipient].sendall(json.dumps(msg).encode())
            print(f"[Server] Forwarded file to local client {recipient}")
        else:
            print(f"[Server] Received file for unknown client {recipient}")

# 处理server 连接
def server_peer_listener():
    """监听其他 server 的连接"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, SERVER_PORT))
        s.listen()
        print(f"[Server] Listening for server peers on {HOST}:{SERVER_PORT}...")
        while True:
            conn, addr = s.accept()
            try:
                data = conn.recv(4096)
                msg = json.loads(data.decode())
                if msg.get("type") == "online_user_request":
                    # 回复本地在线用户
                    user_list = list(clients.keys())
                    resp = {
                        "type": "online_user_response",
                        "server_id": SERVER_ID,
                        "online_users": user_list
                    }
                    conn.sendall(json.dumps(resp).encode())
                else:
                    # 统一交给 receive_message_from_peer 处理
                    receive_message_from_peer(msg)
            except Exception as e:
                print(f"[Server] Peer handshake failed: {e}")
                conn.close()


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
        # 启动 client-to-server 处理线程
        threading.Thread(target=handle_client, args=(conn, addr, name), daemon=True).start()

        # 启动 server-to-server 监听线程
        threading.Thread(target=server_peer_listener, daemon=True).start()
        # 打印当前所有 client_ip
        print(f"[Server] Current client_ip_table: {client_ip_table}")
        print(f"[Server] External clients (other servers): {external_clients}")