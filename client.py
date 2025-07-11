# client_json.py
import socket
import json
import threading
from datetime import datetime
import re
import base64
import os

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
                elif reply.get('payload_type') == 'file':
                    print(f"\n[{reply['from']}] wants to send you a file: {reply.get('file_path', 'unknown')}")
                else:
                    print(f"\n[{reply['from']}] ➜ You: {reply['payload']}")
                print("Command (/list, /msg <user> content, /msg_file <user> <file>, /quit): ", end="", flush=True)
            except Exception as e:
                print(f"\nError receiving message: {e}")
                break
        except Exception as e:
            print(f"\nError receiving message: {e}")
            break
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
'''
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    name_prompt = s.recv(1024).decode()
    name = input(name_prompt).strip()
    s.sendall(name.encode())

    print("You are connected. Use /list to see users, /msg <user> content to chat, /msg_file <user> <file> to send files, /quit to exit.")
    receive_thread = threading.Thread(target=receive_messages, args=(s,), daemon=True)
    receive_thread.start()

    while True:
        try:
            cmd = input("Command (/list, /msg <user> content, /msg_file <user> <file>, /quit): ").strip()
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
            print("Unknown command. Use /list, /msg <user> content, /msg_file <user> <file>, or /quit.")
        except KeyboardInterrupt:
            print("\nDisconnecting...")
            break
        except Exception as e:
            print(f"Error: {e}")
            break