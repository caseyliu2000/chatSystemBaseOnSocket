# Chat System Basic (Socket Version)

本项目是一个基于 Python socket 的简易聊天系统，包含 server.py（服务器端）和 client.py（客户端）。支持多客户端连接、消息收发、用户列表、点对点消息和文件传输命令。

## 主要功能

### server.py
- 监听指定 IP 和端口，等待客户端连接。
- 为每个新连接的 client 分配唯一的 client_ip（127.0.0.2 ~ 127.0.0.254），并记录在 `client_ip_table`。
- 为每个 client 创建独立的 socket 连接对象（conn），通过该对象与 client 通信。
- 所有 server 与 client 的消息均采用 JSON 格式，便于解析。
- 支持命令：
  - `/list` 查看在线用户
  - `/msg <user> <content>` 点对点消息
  - `/msg_file <user> <file>` 点对点文件传输请求
- 客户端断开时，自动回收 client_ip 并清理资源。
- 预留 `external_clients` 字典，用于后续扩展跨服务器 client 信息同步。

### client.py
- 连接到指定的 server（IP 和端口）。
- 输入用户名后，接收 server 分配的 client_ip。
- 支持命令行交互：
  - `/list` 查看在线用户
  - `/msg <user> <content>` 发送消息给指定用户
  - `/msg_file <user> <file>` 发送文件请求给指定用户
  - `/quit` 退出
- 所有与 server 的通信均通过 socket 进行，消息采用 JSON 格式。
- 能正确解析 server 返回的 JSON 消息。

## 运行方式

1. 启动一个或多个 server：
   ```bash
   python server.py
   ```
2. 启动一个或多个 client，连接到 server：
   ```bash
   python client.py
   ```
3. 按提示输入用户名，使用命令进行聊天。

## 注意事项
- server.py 和 client.py 需在 Python 3 环境下运行。
- 多个 server 可以在不同终端/窗口运行，模拟分布式场景。
- 当前版本未实现服务器间的自动同步和转发，仅支持单 server 内部通信。
- 所有消息均为 JSON 格式，client 需正确解析。

---
如需扩展跨服务器通信或有其他需求，请参考代码中的 `external_clients` 相关注释。 