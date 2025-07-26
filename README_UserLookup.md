# 聊天系统用户查找功能

## 概述

这个增强的聊天系统添加了用户查找功能，允许服务器之间相互查找用户信息。当clientA想要向clientB发送消息时，如果serverA没有clientB的信息，系统会自动发起用户查找请求。

## 新增功能

### 1. 数据库管理
- 支持SQLite本地数据库和CockroachDB远程数据库
- 创建了`server_info_table`和`user_info_table`
- 支持用户注册、查询和状态更新
- 使用UUID作为用户主键（CockroachDB版本）

### 2. 用户管理
- 自动注册新连接的用户
- 更新用户最后上线时间
- 管理用户在线状态

### 3. 用户查找协议
- `user_lookup_request`: 用户查找请求
- `user_lookup_response`: 用户查找响应
- 支持跨服务器用户查找

### 4. 增强的群组消息功能
- 支持向群组内所有在线成员发送消息
- 自动处理跨服务器群组成员
- 智能用户查找和external_clients更新
- 只发送给在线用户，不考虑离线用户

## 文件结构

```
chatSystemBasicCursor/
├── server.py                 # 主服务器文件（已增强）
├── server_crdb_wg.py         # CockroachDB版本的服务器文件
├── database_manager.py       # SQLite数据库管理模块
├── database_manager_cockroachdb.py  # CockroachDB数据库管理模块
├── user_manager.py          # 用户管理模块
├── test_group_message.py    # 群组消息测试脚本
├── test_cockroachdb_connection.py  # CockroachDB连接测试脚本
└── README_UserLookup.md     # 本文档
```

## 使用方法

### 1. 启动服务器

**SQLite版本（本地数据库）**：
```bash
python server.py
```

**CockroachDB版本（远程数据库）**：
```bash
python server_crdb_wg.py
```

### 2. 配置环境变量
确保`wg.env`文件包含以下配置：
```
SERVER_ID=serverA
HOST_IP=127.0.0.1
PORT_CLIENT=65432
PORT_SERVER=65000
```

### 3. 用户连接流程
1. 客户端连接到服务器
2. 服务器分配client_ip
3. 用户信息自动注册到数据库
4. 用户可以使用`/msg <username> <message>`发送消息

### 4. 用户查找流程
1. 当用户发送消息给未知用户时
2. 系统自动创建`user_lookup_request`
3. 发送请求到其他服务器
4. 其他服务器检查本地用户并回复
5. 如果找到用户，添加到`external_clients`并转发消息

### 5. 群组消息流程
1. 用户发送群组消息
2. 系统遍历群组内所有成员
3. 向本地在线成员直接发送消息
4. 向external_clients中的成员转发消息
5. 对未知成员执行lookup_request查找
6. 找到后更新external_clients并发送消息

## 消息格式

### user_lookup_request
```json
{
   "type": "user_lookup_request",
   "request_id": "uuid_1234",
   "from_server": "serverA",
   "target_user_id": "clientB",
   "timestamp": "2025-06-19T21:30:00Z"
}
```

### user_lookup_response
```json
{
   "type": "user_lookup_response",
   "request_id": "uuid_1234",
   "user_id": "clientB",
   "online": true,
   "response_server": "serverB",
   "timestamp": "2025-06-19T21:30:00Z"
}
```

## 数据库表结构

### user_info_table
- `user_id`: 用户ID（自增）
- `username`: 用户名（唯一）
- `display_name`: 显示名称
- `last_seen`: 最后上线时间
- `user_pubkey`: 用户公钥
- `invite_history`: 邀请历史
- `latest_ip`: 最新IP地址

### server_info_table
- `server_id`: 服务器ID
- `server_name`: 服务器名称
- `server_pubip`: 公网IP
- `server_port`: 服务器端口
- `server_privip`: 内网IP
- `server_pubkey`: 服务器公钥
- `server_presharedkey`: 预共享密钥

## 测试

运行群组消息测试脚本：
```bash
python test_group_message.py
```

运行CockroachDB连接测试脚本：
```bash
python test_cockroachdb_connection.py
```

## 注意事项

1. 确保服务器端口配置正确
2. 用户查找请求有30秒超时时间
3. SQLite数据库文件会自动创建在项目根目录
4. CockroachDB版本需要网络连接和有效的数据库凭据
5. 所有用户信息都会持久化保存
6. CockroachDB版本使用UUID作为用户主键，SQLite版本使用自增整数

## 扩展功能

- 支持多服务器架构
- 用户状态同步
- 消息历史记录
- 群组消息支持 