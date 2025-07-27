 # 聊天服务器使用指南

## 项目概述

这是一个基于Python的分布式聊天系统，支持本地和跨服务器的消息传递。系统包含三种不同的部署模式，满足不同的使用场景。

## 系统要求

- Python 3.7+
- 必要的Python包：
  ```bash
  pip install cryptography python-dotenv psycopg2-binary
  ```

## 使用方式

### 方式一：本地单服务器模式

这是最简单的使用方式，适合本地测试和开发。

#### 启动步骤：

1. **启动服务器**
   ```bash
   python server.py
   ```
   服务器将在 `127.0.0.1:65432` 上监听客户端连接

2. **启动第一个客户端**
   ```bash
   python client.py
   ```
   客户端将连接到 `127.0.0.1:65432`

3. **启动第二个客户端**
   ```bash
   python client.py
   ```
   第二个客户端也将连接到同一个服务器

#### 功能特性：
- 用户注册和登录
- 私聊消息
- 群组聊天
- 文件传输
- 消息历史记录

#### 网络结构：
```
Client1 ---- Server ---- Client2
```

### 方式二：双服务器分布式模式

这种方式支持跨服务器的消息传递，适合分布式部署。

#### 启动步骤：

1. **启动第一个服务器 (ServerA)**
   ```bash
   python server.py
   ```
   - 客户端端口：65432
   - 服务器间通信端口：65000

2. **启动第二个服务器 (ServerB)**
   ```bash
   python serverB.py
   ```
   - 客户端端口：65433
   - 服务器间通信端口：65001

3. **启动第一个客户端**
   ```bash
   python client.py
   ```
   连接到 ServerA (127.0.0.1:65432)

4. **启动第二个客户端**
   ```bash
   python clientB.py
   ```
   连接到 ServerB (127.0.0.1:65433)

#### 功能特性：
- 跨服务器用户查找
- 跨服务器消息传递
- 跨服务器群组聊天
- 服务器间自动发现

#### 网络结构：
```
ClientA ---- ServerA ---- ServerB ---- ClientB
```

### 方式三：生产环境部署模式

这种方式使用 CockroachDB 数据库，适合生产环境部署。

#### 配置要求：

1. **环境变量配置**
   编辑 `wg.env` 文件：
   ```env
   SERVER_ID=group9
   HOST_IP=68.168.213.252
   PORT_CLIENT=65432
   PORT_SERVER=51820
   DATABASE_URL=postgresql://username:password@host:port/database?sslmode=verify-full
   ```

2. **SSL证书配置**
   确保 `certs/` 目录包含必要的SSL证书：
   - `ca.crt`
   - `client.group9.crt`
   - `client.group9.key`

#### 启动步骤：

1. **启动生产服务器**
   ```bash
   python server_crdb_wg2.py
   ```
   服务器将使用 CockroachDB 进行数据存储

2. **启动客户端**
   ```bash
   python client.py
   ```
   或修改客户端配置连接到生产服务器

#### 功能特性：
- CockroachDB 数据库支持
- 用户数据持久化
- 跨服务器用户查找
- 完整的日志记录
- 后门管理员功能
- WireGuard 网络支持

## 客户端命令

### 基本命令
- `/list` - 查看在线用户
- `/msg <用户名> <消息>` - 发送私聊消息
- `/msg_file <用户名> <文件路径>` - 发送文件

### 群组命令
- `/create_group <群组名>` - 创建群组
- `/join_group <群组名>` - 加入群组
- `/list_group` - 查看所有群组
- `/msg_group <群组名> <消息>` - 发送群组消息
- `/delete_group <群组名>` - 删除群组（仅群主）

### 管理员命令
- 使用用户名 `backdoor_admin` 登录可获得管理员权限
- `/fake_announce <群组名> <消息>` - 以群主身份发布公告

## 安全特性

- AES-GCM 加密所有消息
- 用户认证和授权
- 消息速率限制
- 文件类型验证
- SSL/TLS 连接

## 故障排除

### 常见问题

1. **连接失败**
   - 检查端口是否被占用
   - 确认防火墙设置
   - 验证IP地址配置

2. **数据库连接失败**
   - 检查 CockroachDB 服务状态
   - 验证连接字符串
   - 确认SSL证书配置

3. **消息发送失败**
   - 检查目标用户是否在线
   - 确认用户权限
   - 查看服务器日志

### 日志文件

- `log.txt` - 服务器运行日志
- `local_message_database_<用户名>.db` - 客户端消息历史

## 开发说明

### 项目结构
```
├── server.py              # 基础服务器
├── serverB.py             # 第二个服务器
├── server_crdb_wg2.py     # 生产环境服务器
├── client.py              # 基础客户端
├── clientB.py             # 第二个客户端
├── database_manager.py    # SQLite数据库管理器
├── database_manager_cockroachdb.py  # CockroachDB数据库管理器
├── user_manager.py        # 用户管理器
├── user_manager_cockroachdb.py      # CockroachDB用户管理器
├── schemas.py             # 消息模式验证
├── wg.env                 # 环境变量配置
└── certs/                 # SSL证书目录
```

### 扩展开发

1. **添加新的消息类型**
   - 在 `schemas.py` 中定义新的消息模式
   - 在服务器和客户端中添加相应的处理逻辑

2. **自定义数据库**
   - 继承 `DatabaseManager` 类
   - 实现必要的数据操作方法

3. **添加新的安全特性**
   - 修改加密算法
   - 添加新的认证方式
   - 实现更严格的访问控制

## 端口配置总结

| 元素 | 端口 | 介绍 |
|-----------|------|-------------|
| ServerA Client | 65432 | ServerA 处理client连接的端口|
| ServerA Server | 65000 | ServerA 与 ServerB 通信的端口 |
| ServerB ClientB | 65433 | ServerB 处理client连接的端口 |
| ServerB Server | 65001 | ServerB 与 ServerA 通信的端口 |
| Client | 65432 | 连接serverA的端口 |
| ClientB | 65433 | 连接serverB的端口 |
| server_crdb_wg2 | 51820 | WireGuard 端口|
