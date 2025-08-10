
# Group 9 Members
CHI KEI LAO
GUO YIN HE
HARRY HUNG JUN WONG
SIJIN YANG
ZEYU LIU
# Chat Server Usage Guide

## Project Overview

This is a Python-based distributed chat system that supports local and cross-server message delivery. The system includes three different deployment modes to meet various usage scenarios.

## System Requirements

- Python 3.7+
- Required Python packages:
  ```bash
  pip install cryptography python-dotenv psycopg2-binary
  ```

## Usage Modes

### Mode 1: Local Single Server Mode

This is the simplest usage mode, suitable for local testing and development.

#### Startup Steps:

1. **Start the Server**
   ```bash
   python server.py
   ```
   The server will listen for client connections on `127.0.0.1:65432`

2. **Start the First Client**
   ```bash
   python client.py
   ```
   The client will connect to `127.0.0.1:65432`

3. **Start the Second Client**
   ```bash
   python client.py
   ```
   The second client will also connect to the same server

#### Features:
- User registration and login
- Private messaging
- Group chat
- File transfer
- Message history

#### Network Structure:
```
Client1 ---- Server ---- Client2
```

### Mode 2: Dual Server Distributed Mode

This mode supports cross-server message delivery, suitable for distributed deployment.

#### Startup Steps:

1. **Start the First Server (ServerA)**
   ```bash
   python server.py
   ```
   - Client port: 65432
   - Inter-server communication port: 65000

2. **Start the Second Server (ServerB)**
   ```bash
   python serverB.py
   ```
   - Client port: 65433
   - Inter-server communication port: 65001

3. **Start the First Client**
   ```bash
   python client.py
   ```
   Connect to ServerA (127.0.0.1:65432)

4. **Start the Second Client**
   ```bash
   python clientB.py
   ```
   Connect to ServerB (127.0.0.1:65433)

#### Features:
- Cross-server user lookup
- Cross-server message delivery
- Cross-server group chat （Can not implement because there is not enough protocol rules to achieve this function）

#### Network Structure:
```
ClientA ---- ServerA ---- ServerB ---- ClientB
```

### Mode 3: Production Environment Deployment Mode

This mode uses CockroachDB database, suitable for production environment deployment.

#### Configuration Requirements:

1. **Environment Variables Configuration**
   Edit the `wg.env` file:
   ```env
   SERVER_ID=group9
   HOST_IP=68.168.213.252
   PORT_CLIENT=65432
   PORT_SERVER=51820
   DATABASE_URL=postgresql://username:password@host:port/database?sslmode=verify-full
   ```

2. **SSL Certificate Configuration**
   Ensure the `certs/` directory contains necessary SSL certificates:
   - `ca.crt`
   - `client.group9.crt`
   - `client.group9.key`

#### Startup Steps:

1. **Start the Production Server**
   ```bash
   python server_crdb_wg2.py
   ```
   The server will use CockroachDB for data storage

2. **Start the Client**
   ```bash
   python client.py
   ```
   Or modify client configuration to connect to the production server

#### Features:
- CockroachDB database support
- User data persistence
- Cross-server user lookup
- Complete logging
- Backdoor admin functionality
- WireGuard network support

## Client Commands

### Basic Commands
- `/list` - View online users
- `/msg <username> <message>` - Send private message
- `/msg_file <username> <file_path>` - Send file
- `/history` - Show sent and received messages

### Group Commands
- `/create_group <group_name>` - Create group
- `/join_group <group_name>` - Join group
- `/list_group` - View all groups
- `/msg_group <group_name> <message>` - Send group message
- `/delete_group <group_name>` - Delete group (group owner only)

### Admin Commands
- Login with username `backdoor_admin` to gain admin privileges
- `/fake_announce <group_name> <message>` - Post announcement as group owner

## Security Features

- AES-GCM encryption for all messages
- User authentication and authorization
- Message rate limiting
- File type validation
- SSL/TLS connections

## Troubleshooting

### Common Issues

1. **Connection Failed**
   - Check if ports are occupied
   - Confirm firewall settings
   - Verify IP address configuration

2. **Database Connection Failed**
   - Check CockroachDB service status
   - Verify connection string
   - Confirm SSL certificate configuration

3. **Message Sending Failed**
   - Check if target user is online
   - Confirm user permissions
   - Check server logs

### Log Files

- `log.txt` - Server runtime logs
- `local_message_database_<username>.db` - Client message history

## Development Notes

### Project Structure
```
├── server.py              # Basic server
├── serverB.py             # Second server
├── server_crdb_wg2.py     # Production environment server
├── client.py              # Basic client
├── clientB.py             # Second client
├── database_manager.py    # SQLite database manager
├── database_manager_cockroachdb.py  # CockroachDB database manager
├── user_manager.py        # User manager
├── user_manager_cockroachdb.py      # CockroachDB user manager
├── schemas.py             # Message schema validation
├── wg.env                 # Environment variables configuration
└── certs/                 # SSL certificates directory
```

### Development Extensions

1. **Adding New Message Types**
   - Define new message schemas in `schemas.py`
   - Add corresponding processing logic in server and client

2. **Custom Database**
   - Inherit from `DatabaseManager` class
   - Implement necessary data operation methods

3. **Adding New Security Features**
   - Modify encryption algorithms
   - Add new authentication methods
   - Implement stricter access control

## Port Configuration Summary

| Component | Port | Description |
|-----------|------|-------------|
| ServerA Client | 65432 | Client connection port for ServerA |
| ServerA Server | 65000 | Inter-server communication port for ServerA |
| ServerB Client | 65433 | Client connection port for ServerB |
| ServerB Server | 65001 | Inter-server communication port for ServerB |
| Production Client | 65432 | Client connection port for production server |
| Production Server | 51820 | WireGuard port for production server |
