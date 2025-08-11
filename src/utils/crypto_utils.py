#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 加密工具模块

提供对称加密/解密、非对称加密/解密、哈希计算、密码生成、数字签名、密钥管理和编码转换等功能。

作者: TRAES团队
版本: 1.0.0
创建时间: 2024-01-01
"""

import os
import base64
import hashlib
import hmac
import secrets
import string
from typing import Optional, Union, Tuple, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 配置日志
import logging
logger = logging.getLogger(__name__)

class CryptoUtils:
    """
    加密工具类
    
    提供各种加密、解密、哈希和编码功能
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """
        生成Fernet密钥
        
        Returns:
            bytes: Fernet密钥
        """
        return Fernet.generate_key()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        从密码派生密钥
        
        Args:
            password (str): 密码
            salt (bytes): 盐值，如果为None则自动生成
            
        Returns:
            tuple: (密钥, 盐值)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_data(data: Union[str, bytes], key: bytes) -> Optional[bytes]:
        """
        使用Fernet加密数据
        
        Args:
            data (str|bytes): 要加密的数据
            key (bytes): 加密密钥
            
        Returns:
            bytes: 加密后的数据，失败返回None
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            f = Fernet(key)
            return f.encrypt(data)
        except Exception as e:
            logger.error(f"数据加密失败: {e}")
            return None
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> Optional[bytes]:
        """
        使用Fernet解密数据
        
        Args:
            encrypted_data (bytes): 加密的数据
            key (bytes): 解密密钥
            
        Returns:
            bytes: 解密后的数据，失败返回None
        """
        try:
            f = Fernet(key)
            return f.decrypt(encrypted_data)
        except Exception as e:
            logger.error(f"数据解密失败: {e}")
            return None
    
    @staticmethod
    def encrypt_file(file_path: str, key: bytes, output_path: str = None) -> bool:
        """
        加密文件
        
        Args:
            file_path (str): 源文件路径
            key (bytes): 加密密钥
            output_path (str): 输出文件路径，如果为None则覆盖原文件
            
        Returns:
            bool: 是否成功
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = CryptoUtils.encrypt_data(data, key)
            if encrypted_data is None:
                return False
            
            if output_path is None:
                output_path = file_path
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            return True
        except Exception as e:
            logger.error(f"文件加密失败: {e}")
            return False
    
    @staticmethod
    def decrypt_file(file_path: str, key: bytes, output_path: str = None) -> bool:
        """
        解密文件
        
        Args:
            file_path (str): 加密文件路径
            key (bytes): 解密密钥
            output_path (str): 输出文件路径，如果为None则覆盖原文件
            
        Returns:
            bool: 是否成功
        """
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = CryptoUtils.decrypt_data(encrypted_data, key)
            if decrypted_data is None:
                return False
            
            if output_path is None:
                output_path = file_path
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            return True
        except Exception as e:
            logger.error(f"文件解密失败: {e}")
            return False
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        生成RSA密钥对
        
        Args:
            key_size (int): 密钥长度
            
        Returns:
            tuple: (私钥PEM, 公钥PEM)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def rsa_encrypt(data: Union[str, bytes], public_key_pem: bytes) -> Optional[bytes]:
        """
        RSA公钥加密
        
        Args:
            data (str|bytes): 要加密的数据
            public_key_pem (bytes): 公钥PEM格式
            
        Returns:
            bytes: 加密后的数据，失败返回None
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            encrypted = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted
        except Exception as e:
            logger.error(f"RSA加密失败: {e}")
            return None
    
    @staticmethod
    def rsa_decrypt(encrypted_data: bytes, private_key_pem: bytes) -> Optional[bytes]:
        """
        RSA私钥解密
        
        Args:
            encrypted_data (bytes): 加密的数据
            private_key_pem (bytes): 私钥PEM格式
            
        Returns:
            bytes: 解密后的数据，失败返回None
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted
        except Exception as e:
            logger.error(f"RSA解密失败: {e}")
            return None
    
    @staticmethod
    def calculate_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
        """
        计算数据哈希值
        
        Args:
            data (str|bytes): 要计算哈希的数据
            algorithm (str): 哈希算法 (md5, sha1, sha256, sha512)
            
        Returns:
            str: 十六进制哈希值
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(data)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"哈希计算失败: {e}")
            return ''
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        计算文件哈希值
        
        Args:
            file_path (str): 文件路径
            algorithm (str): 哈希算法
            
        Returns:
            str: 十六进制哈希值
        """
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"文件哈希计算失败: {e}")
            return ''
    
    @staticmethod
    def calculate_hmac(data: Union[str, bytes], key: Union[str, bytes], algorithm: str = 'sha256') -> str:
        """
        计算HMAC
        
        Args:
            data (str|bytes): 数据
            key (str|bytes): 密钥
            algorithm (str): 哈希算法
            
        Returns:
            str: 十六进制HMAC值
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            if isinstance(key, str):
                key = key.encode('utf-8')
            
            return hmac.new(key, data, getattr(hashlib, algorithm)).hexdigest()
        except Exception as e:
            logger.error(f"HMAC计算失败: {e}")
            return ''
    
    @staticmethod
    def generate_password(length: int = 12, use_symbols: bool = True) -> str:
        """
        生成随机密码
        
        Args:
            length (int): 密码长度
            use_symbols (bool): 是否包含特殊字符
            
        Returns:
            str: 随机密码
        """
        characters = string.ascii_letters + string.digits
        if use_symbols:
            characters += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        return ''.join(secrets.choice(characters) for _ in range(length))
    
    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """
        生成随机盐值
        
        Args:
            length (int): 盐值长度
            
        Returns:
            bytes: 随机盐值
        """
        return os.urandom(length)
    
    @staticmethod
    def base64_encode(data: Union[str, bytes]) -> str:
        """
        Base64编码
        
        Args:
            data (str|bytes): 要编码的数据
            
        Returns:
            str: Base64编码后的字符串
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return base64.b64encode(data).decode('utf-8')
        except Exception as e:
            logger.error(f"Base64编码失败: {e}")
            return ''
    
    @staticmethod
    def base64_decode(encoded_data: str) -> Optional[bytes]:
        """
        Base64解码
        
        Args:
            encoded_data (str): Base64编码的字符串
            
        Returns:
            bytes: 解码后的数据，失败返回None
        """
        try:
            return base64.b64decode(encoded_data)
        except Exception as e:
            logger.error(f"Base64解码失败: {e}")
            return None
    
    @staticmethod
    def url_safe_base64_encode(data: Union[str, bytes]) -> str:
        """
        URL安全的Base64编码
        
        Args:
            data (str|bytes): 要编码的数据
            
        Returns:
            str: URL安全的Base64编码字符串
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return base64.urlsafe_b64encode(data).decode('utf-8')
        except Exception as e:
            logger.error(f"URL安全Base64编码失败: {e}")
            return ''
    
    @staticmethod
    def url_safe_base64_decode(encoded_data: str) -> Optional[bytes]:
        """
        URL安全的Base64解码
        
        Args:
            encoded_data (str): URL安全的Base64编码字符串
            
        Returns:
            bytes: 解码后的数据，失败返回None
        """
        try:
            return base64.urlsafe_b64decode(encoded_data)
        except Exception as e:
            logger.error(f"URL安全Base64解码失败: {e}")
            return None
    
    @staticmethod
    def hex_encode(data: Union[str, bytes]) -> str:
        """
        十六进制编码
        
        Args:
            data (str|bytes): 要编码的数据
            
        Returns:
            str: 十六进制编码字符串
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return data.hex()
        except Exception as e:
            logger.error(f"十六进制编码失败: {e}")
            return ''
    
    @staticmethod
    def hex_decode(hex_data: str) -> Optional[bytes]:
        """
        十六进制解码
        
        Args:
            hex_data (str): 十六进制编码字符串
            
        Returns:
            bytes: 解码后的数据，失败返回None
        """
        try:
            return bytes.fromhex(hex_data)
        except Exception as e:
            logger.error(f"十六进制解码失败: {e}")
            return None
    
    @staticmethod
    def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        安全比较两个值（防止时序攻击）
        
        Args:
            a (str|bytes): 第一个值
            b (str|bytes): 第二个值
            
        Returns:
            bool: 是否相等
        """
        try:
            if isinstance(a, str):
                a = a.encode('utf-8')
            if isinstance(b, str):
                b = b.encode('utf-8')
            
            return hmac.compare_digest(a, b)
        except Exception as e:
            logger.error(f"安全比较失败: {e}")
            return False
    
    @staticmethod
    def generate_uuid() -> str:
        """
        生成UUID
        
        Returns:
            str: UUID字符串
        """
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """
        生成安全令牌
        
        Args:
            length (int): 令牌长度
            
        Returns:
            str: 十六进制令牌字符串
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def verify_password_strength(password: str) -> Dict[str, Any]:
        """
        验证密码强度
        
        Args:
            password (str): 密码
            
        Returns:
            dict: 密码强度信息
        """
        result = {
            'length': len(password),
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_symbols': any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password),
            'score': 0,
            'strength': 'Very Weak'
        }
        
        # 计算强度分数
        if result['length'] >= 8:
            result['score'] += 1
        if result['length'] >= 12:
            result['score'] += 1
        if result['has_lowercase']:
            result['score'] += 1
        if result['has_uppercase']:
            result['score'] += 1
        if result['has_digits']:
            result['score'] += 1
        if result['has_symbols']:
            result['score'] += 1
        
        # 确定强度等级
        if result['score'] >= 6:
            result['strength'] = 'Very Strong'
        elif result['score'] >= 5:
            result['strength'] = 'Strong'
        elif result['score'] >= 4:
            result['strength'] = 'Medium'
        elif result['score'] >= 2:
            result['strength'] = 'Weak'
        
        return result

# 便捷函数
def quick_encrypt(data: str, password: str) -> Optional[str]:
    """
    快速加密字符串
    
    Args:
        data (str): 要加密的数据
        password (str): 密码
        
    Returns:
        str: Base64编码的加密数据，失败返回None
    """
    try:
        key, salt = CryptoUtils.derive_key_from_password(password)
        encrypted_data = CryptoUtils.encrypt_data(data, key)
        if encrypted_data:
            # 将盐值和加密数据组合
            combined = salt + encrypted_data
            return CryptoUtils.base64_encode(combined)
        return None
    except Exception as e:
        logger.error(f"快速加密失败: {e}")
        return None

def quick_decrypt(encrypted_data: str, password: str) -> Optional[str]:
    """
    快速解密字符串
    
    Args:
        encrypted_data (str): Base64编码的加密数据
        password (str): 密码
        
    Returns:
        str: 解密后的数据，失败返回None
    """
    try:
        combined = CryptoUtils.base64_decode(encrypted_data)
        if combined and len(combined) > 16:
            salt = combined[:16]
            encrypted = combined[16:]
            
            key, _ = CryptoUtils.derive_key_from_password(password, salt)
            decrypted_data = CryptoUtils.decrypt_data(encrypted, key)
            if decrypted_data:
                return decrypted_data.decode('utf-8')
        return None
    except Exception as e:
        logger.error(f"快速解密失败: {e}")
        return None

def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """
    哈希密码
    
    Args:
        password (str): 密码
        salt (bytes): 盐值
        
    Returns:
        tuple: (哈希值, 盐值的十六进制)
    """
    if salt is None:
        salt = CryptoUtils.generate_salt()
    
    # 使用PBKDF2进行密码哈希
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    
    return CryptoUtils.hex_encode(key), CryptoUtils.hex_encode(salt)

def verify_password(password: str, hashed_password: str, salt_hex: str) -> bool:
    """
    验证密码
    
    Args:
        password (str): 密码
        hashed_password (str): 哈希值
        salt_hex (str): 盐值的十六进制
        
    Returns:
        bool: 密码是否正确
    """
    try:
        salt = CryptoUtils.hex_decode(salt_hex)
        if salt is None:
            return False
        
        computed_hash, _ = hash_password(password, salt)
        return CryptoUtils.secure_compare(computed_hash, hashed_password)
    except Exception as e:
        logger.error(f"验证密码失败: {e}")
        return False