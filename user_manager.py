'''
Group 9
CHI KEI LAO
GUO YIN HE
HARRY HUNG JUN WONG
SIJIN YANG
ZEYU LIU
'''
import socket
import struct
from datetime import datetime
from typing import Optional, Dict, Any
from database_manager import DatabaseManager
import uuid

class UserManager:
    def __init__(self, db_manager: DatabaseManager):
        """初始化用户管理器"""
        self.db_manager = db_manager
        self.pending_lookups = {}  # {request_id: {"from_server": str, "target_user_id": str, "timestamp": str}}
    
    def register_user(self, username: str, client_ip: str, conn: socket.socket) -> int:
        """注册新用户"""
        try:
            # 将IP地址转换为bytes格式
            ip_bytes = socket.inet_aton(client_ip)
            
            # 检查用户是否已存在
            existing_user = self.db_manager.get_user_by_username(username)
            if existing_user:
                # 更新现有用户信息
                self.db_manager.update_user_last_seen(username)
                self.db_manager.update_user_ip(username, ip_bytes)
                return existing_user['user_id']
            else:
                # 创建新用户
                user_id = self.db_manager.add_user(
                    username=username,
                    display_name=username,
                    latest_ip=ip_bytes
                )
                return user_id
        except Exception as e:
            print(f"[UserManager] Error registering user {username}: {e}")
            return None
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """获取用户信息"""
        return self.db_manager.get_user_by_username(username)
    
    def get_user_info_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """根据用户ID获取用户信息"""
        return self.db_manager.get_user_by_id(user_id)
    
    def update_user_status(self, username: str):
        """更新用户状态（最后上线时间）"""
        self.db_manager.update_user_last_seen(username)
    
    def is_user_online(self, username: str, local_clients: dict) -> bool:
        """检查用户是否在线"""
        return username in local_clients
    
    def create_user_lookup_request(self, target_user_id: str, from_server: str) -> Dict[str, Any]:
        """创建用户查找请求"""
        request_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        request = {
            "type": "user_lookup_request",
            "request_id": request_id,
            "from_server": from_server,
            "target_user_id": target_user_id,
            "timestamp": timestamp
        }
        
        # 保存待处理的请求
        self.pending_lookups[request_id] = {
            "from_server": from_server,
            "target_user_id": target_user_id,
            "timestamp": timestamp
        }
        
        return request
    
    def create_user_lookup_response(self, request_id: str, user_id: str, online: bool, response_server: str) -> Dict[str, Any]:
        """创建用户查找响应"""
        timestamp = datetime.now().isoformat()
        
        response = {
            "type": "user_lookup_response",
            "request_id": request_id,
            "user_id": user_id,
            "online": online,
            "response_server": response_server,
            "timestamp": timestamp
        }
        
        return response
    
    def handle_user_lookup_request(self, request: Dict[str, Any], local_clients: dict, server_id: str) -> Optional[Dict[str, Any]]:
        """处理用户查找请求"""
        target_user_id = request.get("target_user_id")
        request_id = request.get("request_id")
        from_server = request.get("from_server")
        
        if not all([target_user_id, request_id, from_server]):
            print(f"[UserManager] Invalid user_lookup_request: {request}")
            return None
        
        # 检查用户是否在本地
        online = self.is_user_online(target_user_id, local_clients)
        
        # 创建响应
        response = self.create_user_lookup_response(
            request_id=request_id,
            user_id=target_user_id,
            online=online,
            response_server=server_id
        )
        
        print(f"[UserManager] Responding to user_lookup_request for {target_user_id}: online={online}")
        return response
    
    def handle_user_lookup_response(self, response: Dict[str, Any], external_clients: dict, peer_server_info: dict):
        """处理用户查找响应"""
        request_id = response.get("request_id")
        user_id = response.get("user_id")
        online = response.get("online")
        response_server = response.get("response_server")
        
        if not all([request_id, user_id, response_server]):
            print(f"[UserManager] Invalid user_lookup_response: {response}")
            return
        
        # 检查是否是我们要找的请求
        if request_id in self.pending_lookups:
            pending_request = self.pending_lookups[request_id]
            
            if online:
                # 用户在线，添加到external_clients
                external_clients[user_id] = {
                    "server_ip": peer_server_info.get("server_ip"),
                    "server_port": peer_server_info.get("server_port")
                }
                print(f"[UserManager] User {user_id} found online at {response_server}")
            else:
                print(f"[UserManager] User {user_id} is not online at {response_server}")
            
            # 清理已处理的请求
            del self.pending_lookups[request_id]
        else:
            print(f"[UserManager] Received response for unknown request_id: {request_id}")
    
    def cleanup_pending_lookups(self, timeout_seconds: int = 30):
        """清理超时的待处理请求"""
        current_time = datetime.now()
        expired_requests = []
        
        for request_id, request_data in self.pending_lookups.items():
            request_time = datetime.fromisoformat(request_data["timestamp"])
            if (current_time - request_time).total_seconds() > timeout_seconds:
                expired_requests.append(request_id)
        
        for request_id in expired_requests:
            del self.pending_lookups[request_id]
            print(f"[UserManager] Cleaned up expired request: {request_id}")
    
    def get_all_local_users(self) -> list:
        """获取所有本地用户信息"""
        return self.db_manager.get_all_users() 