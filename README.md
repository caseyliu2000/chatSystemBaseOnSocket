#当前分支，已整合功能
 - backdoor_admin 绕滚登入机制
 - Client.py加入sqlite database，保存该用户的sent/received 信息
 - 根目录中，加入wg.env文件，设置好了server.py的ip,port参数，用于部署wireguard的配置。

# Chat System with Group Messaging

A multi-server chat system with group messaging capabilities, built with Python sockets and JSON messaging.

## System Architecture

The system consists of multiple servers that can communicate with each other:
- **server.py** (serverA) - Runs on port 65432, server-to-server port 65000
- **serverB.py** (serverB) - Runs on port 65433, server-to-server port 65001
- **client.py** - Connects to serverA (port 65432)
- **clientB.py** - Connects to serverB (port 65433)

## Features

### 1. User Management
- **User Registration**: Users connect with a unique username
- **Client IP Assignment**: Each user gets assigned a unique client IP (127.0.0.x)
- **Online User Discovery**: `/list` command shows all online users across servers
- **Cross-Server Communication**: Users can send messages to users on other servers

### 2. Private Messaging
- **Direct Messages**: `/msg <user> <message>` - Send private message to specific user
- **File Sharing**: `/msg_file <user> <file_path>` - Send files up to 10MB
- **Cross-Server Support**: Messages and files can be sent between users on different servers

### 3. Group Messaging System

#### Group Management Commands
- **Create Group**: `/create_group <group_name>` - Create a new group (creator automatically joins)
- **Join Group**: `/join_group <group_name>` - Join an existing group
- **List Groups**: `/list_group` - Show all groups on current server with member count and creator
- **Delete Group**: `/delete_group <group_name>` - Delete group (creator only)
- **Group Messages**: `/msg_group <group_name> <message>` - Send message to all group members

#### Group Features
- **Server-Local Groups**: Groups exist only on the server where they were created
- **Creator Permissions**: Only group creators can delete groups
- **Automatic Cleanup**: Users are removed from groups when they disconnect
- **Member Validation**: Only group members can send messages to the group

### 4. Server-to-Server Communication
- **Peer Discovery**: Servers can discover online users on other servers
- **Message Forwarding**: Messages are automatically forwarded between servers
- **File Transfer**: Files can be transferred across server boundaries

## Message Formats

### Private Messages
```json
{
    "type": "message",
    "from": "userA",
    "to": "userB",
    "to_type": "user",
    "payload": "Hello!",
    "payload_type": "text",
    "timestamp": "2025-01-01T00:00:00Z"
}
```

### Group Messages
```json
{
    "type": "group_message",
    "from": "userA",
    "to": "GroupName",
    "to_type": "group",
    "content": "Hello everyone!",
    "content_type": "text",
    "timestamp": "2025-01-01T00:00:00Z"
}
```

### File Messages
```json
{
    "type": "message_file",
    "from": "userA",
    "to": "userB",
    "to_type": "user",
    "payload": "base64_encoded_file_content",
    "payload_type": "file",
    "timestamp": "2025-01-01T00:00:00Z",
    "payload_id": "unique_id",
    "file_path": "filename.txt"
}
```

## Data Structures

### Server-Side Storage
- `clients`: `{user_name: connection_object}` - Active user connections
- `client_ip_table`: `{user_name: client_ip}` - User to IP mapping
- `external_clients`: `{user_name: {"server_ip": ..., "server_port": ...}}` - Users on other servers
- `groups`: `{group_name: {"members": [user_names], "creator": creator_name}}` - Group information
- `user_groups`: `{user_name: [group_names]}` - User's group memberships

## Usage

### Starting the System

1. **Start serverA**:
   ```bash
   python server.py
   ```

2. **Start serverB** (optional, for multi-server setup):
   ```bash
   python serverB.py
   ```

3. **Connect clients**:
   ```bash
   python client.py    # Connects to serverA
   python clientB.py   # Connects to serverB
   ```

### Available Commands

#### User Commands
- `/list` - List all online users across servers
- `/msg <user> <message>` - Send private message
- `/msg_file <user> <file_path>` - Send file to user
- `/quit` - Disconnect from server

#### Group Commands
- `/create_group <name>` - Create new group
- `/join_group <name>` - Join existing group
- `/list_group` - List all groups on current server
- `/msg_group <group> <message>` - Send message to group
- `/delete_group <name>` - Delete group (creator only)

### Example Session

```
Enter your name: Alice
You are connected. Available commands:
  /list - List online users
  /msg <user> <content> - Send message to user
  /msg_file <user> <file> - Send file to user
  /create_group <name> - Create a new group
  /join_group <name> - Join an existing group
  /list_group - List all groups
  /msg_group <group> <message> - Send message to group
  /delete_group <name> - Delete a group (creator only)
  /quit - Exit

Command: /create_group TeamA
[server] ➜ You: Group 'TeamA' created successfully

Command: /list_group
[server] ➜ You: Groups: 'TeamA' (members: 1, creator: Alice)

Command: /msg_group TeamA Hello everyone!
[Group:TeamA] Alice: Hello everyone!

Command: /list
[server] ➜ You: Online users: Bob, Charlie
```

## Technical Details

### Network Configuration
- **Client Ports**: 65432 (serverA), 65433 (serverB)
- **Server-to-Server Ports**: 65000 (serverA), 65001 (serverB)
- **Client IP Range**: 127.0.0.2 - 127.0.0.254

### Error Handling
- **Connection Refusal**: When no client IPs are available
- **Invalid Commands**: Helpful error messages for malformed commands
- **File Validation**: File size limits (10MB) and existence checks
- **Group Validation**: Permission checks for group operations

### Security Features
- **Input Validation**: All commands are validated before processing
- **Permission Control**: Group deletion restricted to creators
- **Resource Management**: Automatic cleanup of disconnected users

## Limitations

1. **Server-Local Groups**: Groups are not shared across servers
2. **No Persistence**: All data is lost on server restart
3. **No Authentication**: No user authentication or authorization
4. **Limited File Types**: No file type validation
5. **Single Thread per Client**: Each client connection uses one thread

## Future Enhancements

- Cross-server group messaging
- Persistent storage for groups and user data
- User authentication and authorization
- File type validation and virus scanning
- Real-time notifications
- Message history and search
- User profiles and avatars 
