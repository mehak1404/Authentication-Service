import json
import os
from datetime import datetime
from typing import Optional, Dict, List

class FileStorage:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.ensure_file_exists()
    
    def ensure_file_exists(self):
        if not os.path.exists(self.file_path):
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            self.save_data([])
    
    def load_data(self) -> List[Dict]:
        try:
            with open(self.file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            return []
    
    def save_data(self, data: List[Dict]):
        with open(self.file_path, 'w') as file:
            json.dump(data, file, indent=2, default=str)

class UserStorage(FileStorage):
    def __init__(self):
        super().__init__('storage/users.json')
    
    def create_user(self, email: str, password: str) -> Dict:
        users = self.load_data()
        user_id = len(users) + 1
        user = {
            'id': user_id,
            'email': email,
            'password': password,
            'created_at': datetime.utcnow().isoformat()
        }
        users.append(user)
        self.save_data(users)
        return user
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        users = self.load_data()
        for user in users:
            if user['email'] == email:
                return user
        return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        users = self.load_data()
        for user in users:
            if user['id'] == user_id:
                return user
        return None

class TokenStorage(FileStorage):
    def __init__(self):
        super().__init__('storage/blacklisted_tokens.json')
    
    def blacklist_token(self, token: str):
        tokens = self.load_data()
        token_data = {
            'token': token,
            'blacklisted_at': datetime.utcnow().isoformat()
        }
        tokens.append(token_data)
        self.save_data(tokens)
    
    def is_blacklisted(self, token: str) -> bool:
        tokens = self.load_data()
        return any(t['token'] == token for t in tokens)