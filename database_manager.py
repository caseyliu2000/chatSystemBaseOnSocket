import sqlite3
import os
from datetime import datetime
from typing import Optional, Dict, Any

class DatabaseManager:
    def __init__(self, db_path: str = "chat_system.db"):
        """初始化数据库管理器"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """初始化数据库和表"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 创建server_info_table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS server_info_table (
                    server_id INTEGER PRIMARY KEY,
                    server_name TEXT,
                    server_pubip BLOB,
                    server_port INTEGER,
                    server_privip BLOB,
                    server_pubkey BLOB,
                    server_presharedkey BLOB
                )
            """)
            
            # 创建user_info_table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_info_table (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    display_name TEXT,
                    last_seen TIMESTAMP,
                    user_pubkey BLOB,
                    invite_history TEXT,
                    latest_ip BLOB
                )
            """)
            
            conn.commit()
            print(f"[Database] Database initialized at {self.db_path}")
    
    def add_user(self, username: str, display_name: str = None, user_pubkey: bytes = None, latest_ip: bytes = None) -> int:
        """添加新用户，返回用户ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            current_time = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT INTO user_info_table (username, display_name, last_seen, user_pubkey, latest_ip)
                VALUES (?, ?, ?, ?, ?)
            """, (username, display_name, current_time, user_pubkey, latest_ip))
            
            user_id = cursor.lastrowid
            conn.commit()
            print(f"[Database] Added user {username} with ID {user_id}")
            return user_id
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """根据用户名获取用户信息"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, username, display_name, last_seen, user_pubkey, invite_history, latest_ip
                FROM user_info_table WHERE username = ?
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
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, username, display_name, last_seen, user_pubkey, invite_history, latest_ip
                FROM user_info_table WHERE user_id = ?
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
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            current_time = datetime.now().isoformat()
            
            cursor.execute("""
                UPDATE user_info_table SET last_seen = ? WHERE username = ?
            """, (current_time, username))
            
            conn.commit()
            print(f"[Database] Updated last_seen for user {username}")
    
    def update_user_ip(self, username: str, latest_ip: bytes):
        """更新用户最新IP"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE user_info_table SET latest_ip = ? WHERE username = ?
            """, (latest_ip, username))
            
            conn.commit()
            print(f"[Database] Updated latest_ip for user {username}")
    
    def get_all_users(self) -> list:
        """获取所有用户信息"""
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO server_info_table 
                (server_id, server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (server_id, server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey))
            
            conn.commit()
            print(f"[Database] Added/Updated server info for {server_name}")
    
    def get_server_info(self, server_id: int) -> Optional[Dict[str, Any]]:
        """获取服务器信息"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT server_id, server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey
                FROM server_info_table WHERE server_id = ?
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