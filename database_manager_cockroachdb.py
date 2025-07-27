import psycopg2
import os
from datetime import datetime
from typing import Optional, Dict, Any
import uuid

class DatabaseManagerCockroachDB:
    def __init__(self):
        """初始化CockroachDB数据库管理器"""
        # 使用testCockRoachDB_local.py中的连接字符串
        # local db: DATABASE_URL="postgresql://casey123:e3_zqOYLGKJAelKYksT-bA@smiley-mule-7838.jxf.gcp-asia-southeast1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"
        # remote db: CRDB_URL="postgresql://group9@68.168.213.252:26257/group9?sslmode=verify-full&sslrootcert=certs/ca.crt&sslcert=certs/client.group9.crt&sslkey=certs/client.group9.key"
        self.DATABASE_URL = "postgresql://casey123:e3_zqOYLGKJAelKYksT-bA@smiley-mule-7838.jxf.gcp-asia-southeast1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"
        self.init_database()
    
    def get_connection(self):
        """获取数据库连接"""
        return psycopg2.connect(self.DATABASE_URL)
    
    def init_database(self):
        """初始化数据库和表"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 创建server_info_table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS server_info_table (
                    server_id BIGINT PRIMARY KEY,
                    server_name CHAR(64),
                    server_pubip BYTEA,
                    server_port SMALLINT,
                    server_privip BYTEA,
                    server_pubkey BYTEA,
                    server_presharedkey BYTEA
                )
            """)
            
            # 创建user_info_table，使用BIGINT作为主键
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_info_table (
                    user_id BIGINT PRIMARY KEY,
                    username CHAR(64) UNIQUE NOT NULL,
                    display_name VARCHAR(256),
                    last_seen TIMESTAMP,
                    user_pubkey BYTEA,
                    invite_history TIMESTAMP[],
                    latest_ip BYTEA
                )
            """)
            
            conn.commit()
            print(f"[Database] CockroachDB database initialized")
    
    def get_next_user_id(self) -> int:
        """获取下一个可用的用户ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COALESCE(MAX(user_id), 0) + 1 FROM user_info_table")
            result = cursor.fetchone()
            return result[0] if result else 1
    
    def add_user(self, username: str, display_name: str = None, user_pubkey: bytes = None, latest_ip: bytes = None) -> int:
        """添加新用户，返回用户BIGINT ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            current_time = datetime.now()
            user_id = self.get_next_user_id()
            
            cursor.execute("""
                INSERT INTO user_info_table (user_id, username, display_name, last_seen, user_pubkey, latest_ip)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, username, display_name, current_time, user_pubkey, latest_ip))
            
            conn.commit()
            print(f"[Database] Added user {username} with ID {user_id}")
            return user_id
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """根据用户名获取用户信息"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, username, display_name, last_seen, user_pubkey, invite_history, latest_ip
                FROM user_info_table WHERE username = %s
            """, (username,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'user_id': row[0],
                    'username': row[1],
                    'display_name': row[2],
                    'last_seen': row[3],
                    'user_pubkey': row[4],
                    'invite_history': row[5],
                    'latest_ip': row[6]
                }
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """根据用户ID获取用户信息"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, username, display_name, last_seen, user_pubkey, invite_history, latest_ip
                FROM user_info_table WHERE user_id = %s
            """, (user_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'user_id': row[0],
                    'username': row[1],
                    'display_name': row[2],
                    'last_seen': row[3],
                    'user_pubkey': row[4],
                    'invite_history': row[5],
                    'latest_ip': row[6]
                }
            return None
    
    def update_user_last_seen(self, username: str):
        """更新用户最后上线时间"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            current_time = datetime.now()
            
            cursor.execute("""
                UPDATE user_info_table SET last_seen = %s WHERE username = %s
            """, (current_time, username))
            
            conn.commit()
            print(f"[Database] Updated last_seen for user {username}")
    
    def update_user_ip(self, username: str, latest_ip: bytes):
        """更新用户最新IP"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE user_info_table SET latest_ip = %s WHERE username = %s
            """, (latest_ip, username))
            
            conn.commit()
            print(f"[Database] Updated latest_ip for user {username}")
    
    def get_all_users(self) -> list:
        """获取所有用户信息"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, username, display_name, last_seen, user_pubkey, invite_history, latest_ip
                FROM user_info_table
            """)
            
            rows = cursor.fetchall()
            return [
                {
                    'user_id': row[0],
                    'username': row[1],
                    'display_name': row[2],
                    'last_seen': row[3],
                    'user_pubkey': row[4],
                    'invite_history': row[5],
                    'latest_ip': row[6]
                }
                for row in rows
            ]
    
    def add_server_info(self, server_id: int, server_name: str, server_pubip: bytes = None, 
                       server_port: int = None, server_privip: bytes = None, 
                       server_pubkey: bytes = None, server_presharedkey: bytes = None):
        """添加服务器信息"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO server_info_table 
                (server_id, server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (server_id) DO UPDATE SET
                server_name = EXCLUDED.server_name,
                server_pubip = EXCLUDED.server_pubip,
                server_port = EXCLUDED.server_port,
                server_privip = EXCLUDED.server_privip,
                server_pubkey = EXCLUDED.server_pubkey,
                server_presharedkey = EXCLUDED.server_presharedkey
            """, (server_id, server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey))
            
            conn.commit()
            print(f"[Database] Added/Updated server info for {server_name}")
    
    def get_server_info(self, server_id: int) -> Optional[Dict[str, Any]]:
        """获取服务器信息"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT server_id, server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey
                FROM server_info_table WHERE server_id = %s
            """, (server_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'server_id': row[0],
                    'server_name': row[1],
                    'server_pubip': row[2],
                    'server_port': row[3],
                    'server_privip': row[4],
                    'server_pubkey': row[5],
                    'server_presharedkey': row[6]
                }
            return None
    
    def add_invite_history(self, username: str, invite_time: datetime = None):
        """添加邀请历史"""
        if invite_time is None:
            invite_time = datetime.now()
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE user_info_table 
                SET invite_history = array_append(invite_history, %s)
                WHERE username = %s
            """, (invite_time, username))
            
            conn.commit()
            print(f"[Database] Added invite history for user {username}")
    
    def test_connection(self):
        """测试数据库连接"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT now()")
                result = cursor.fetchone()
                print(f"[Database] Connection test successful: {result[0]}")
                return True
        except Exception as e:
            print(f"[Database] Connection test failed: {e}")
            return False 

# # 测试连接
if __name__ == "__main__":
    db_manager = DatabaseManagerCockroachDB()
    db_manager.test_connection()