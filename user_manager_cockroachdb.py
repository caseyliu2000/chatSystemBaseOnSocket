import socket
import struct
from datetime import datetime
from typing import Optional, Dict, Any
from database_manager_cockroachdb import DatabaseManagerCockroachDB
import uuid

class UserManager:
    def __init__(self, db_manager: DatabaseManagerCockroachDB):
        """初始化用户管理器"""
        self.db_manager = db_manager
        self.pending_lookups = {}  # {request_id: {"from_server": str, "target_user_id": int, "timestamp": str}}
    
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
    
    def create_user_lookup_request(self, target_username: str, from_server: str) -> Optional[Dict[str, Any]]:
        """创建用户查找请求，使用从数据库查询到的user_id作为request_id"""
        try:
            # 通过username查询数据库获取user_id
            user_info = self.db_manager.get_user_by_username(target_username)
            if not user_info:
                print(f"[UserManager] User {target_username} not found in database")
                return None
            
            target_user_id = user_info['user_id']
            timestamp = datetime.now().isoformat()
            
            request = {
                "type": "user_lookup_request",
                "request_id": target_user_id,  # 使用user_id作为request_id
                "from_server": from_server,
                "target_user_id": target_user_id,
                "timestamp": timestamp
            }
            
            # 保存待处理的请求
            self.pending_lookups[target_user_id] = {
                "from_server": from_server,
                "target_user_id": target_user_id,
                "timestamp": timestamp
            }
            
            print(f"[UserManager] Created user_lookup_request for {target_username} with user_id {target_user_id}")
            return request
        except Exception as e:
            print(f"[UserManager] Error creating user_lookup_request for {target_username}: {e}")
            return None
    
    def create_user_lookup_response(self, request_id: int, user_id: int, online: bool, response_server: str, server_ip: str = None, server_port: int = None) -> Dict[str, Any]:
        """创建用户查找响应"""
        timestamp = datetime.now().isoformat()
        
        response = {
            "type": "user_lookup_response",
            "request_id": request_id,
            "user_id": user_id,
            "online": online,
            "response_server": response_server,
            "server_ip": server_ip,
            "server_port": server_port,
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
        
        # 通过user_id查询用户信息
        user_info = self.db_manager.get_user_by_id(target_user_id)
        if not user_info:
            print(f"[UserManager] User with ID {target_user_id} not found in database")
            return None
        
        username = user_info['username']
        
        # 检查用户是否在本地在线
        online = self.is_user_online(username, local_clients)
        
        # 创建响应
        response = self.create_user_lookup_response(
            request_id=request_id,
            user_id=target_user_id,
            online=online,
            response_server=server_id
        )
        
        print(f"[UserManager] Responding to user_lookup_request for {username} (ID: {target_user_id}): online={online}")
        return response
    
    def handle_user_lookup_response(self, response: Dict[str, Any], external_clients: dict, peer_server_info: dict):
        """处理用户查找响应"""
        request_id = response.get("request_id")
        user_id = response.get("user_id")
        online = response.get("online")
        response_server = response.get("response_server")
        server_ip = response.get("server_ip")
        server_port = response.get("server_port")
        
        if not all([request_id, user_id, response_server]):
            print(f"[UserManager] Invalid user_lookup_response: {response}")
            return
        
        # 检查是否是我们要找的请求
        if request_id in self.pending_lookups:
            pending_request = self.pending_lookups[request_id]
            
            if online:
                # 通过user_id获取username
                user_info = self.db_manager.get_user_by_id(user_id)
                if user_info:
                    username = user_info['username']
                    # 用户在线，添加到external_clients
                    # 优先使用响应消息中的服务器信息，如果没有则使用peer_server_info
                    target_server_ip = server_ip or peer_server_info.get("server_ip")
                    target_server_port = server_port or peer_server_info.get("server_port")
                    
                    if target_server_ip and target_server_port:
                        external_clients[username] = {
                            "server_ip": target_server_ip,
                            "server_port": target_server_port
                        }
                        print(f"[UserManager] User {username} (ID: {user_id}) found online at {response_server} ({target_server_ip}:{target_server_port})")
                    else:
                        print(f"[UserManager] Missing server information for user {username}")
                else:
                    print(f"[UserManager] User with ID {user_id} not found in database")
            else:
                print(f"[UserManager] User with ID {user_id} is not online at {response_server}")
            
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