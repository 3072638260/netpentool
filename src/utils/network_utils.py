#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 网络工具模块

提供网络相关的实用工具函数，包括：
- IP地址操作
- 网络接口管理
- 网络连接检测
- MAC地址操作
- 网络配置获取
- 代理设置

作者: Security Researcher
版本: 1.0.0
"""

import sys
import socket
import struct
import random
import ipaddress
import subprocess
from typing import List, Optional, Dict, Any, Tuple

try:
    import requests
    import psutil
    import netifaces
    from loguru import logger
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install requests psutil netifaces loguru")
    sys.exit(1)

class NetworkUtils:
    """
    网络工具类
    
    提供各种网络相关的实用功能。
    """
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        检查IP地址是否有效
        
        Args:
            ip (str): IP地址字符串
            
        Returns:
            bool: 有效返回True
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_network(network: str) -> bool:
        """
        检查网络地址是否有效
        
        Args:
            network (str): 网络地址字符串 (如 192.168.1.0/24)
            
        Returns:
            bool: 有效返回True
        """
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        检查IP地址是否为私有地址
        
        Args:
            ip (str): IP地址字符串
            
        Returns:
            bool: 私有地址返回True
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def get_network_interfaces() -> Dict[str, Dict[str, Any]]:
        """
        获取网络接口信息
        
        Returns:
            dict: 网络接口信息字典
        """
        interfaces = {}
        
        try:
            for interface in netifaces.interfaces():
                interface_info = {
                    'name': interface,
                    'addresses': {},
                    'status': 'unknown'
                }
                
                # 获取地址信息
                addrs = netifaces.ifaddresses(interface)
                
                # IPv4地址
                if netifaces.AF_INET in addrs:
                    ipv4_info = addrs[netifaces.AF_INET][0]
                    interface_info['addresses']['ipv4'] = {
                        'addr': ipv4_info.get('addr'),
                        'netmask': ipv4_info.get('netmask'),
                        'broadcast': ipv4_info.get('broadcast')
                    }
                
                # IPv6地址
                if netifaces.AF_INET6 in addrs:
                    ipv6_info = addrs[netifaces.AF_INET6][0]
                    interface_info['addresses']['ipv6'] = {
                        'addr': ipv6_info.get('addr'),
                        'netmask': ipv6_info.get('netmask')
                    }
                
                # MAC地址
                if netifaces.AF_LINK in addrs:
                    mac_info = addrs[netifaces.AF_LINK][0]
                    interface_info['addresses']['mac'] = mac_info.get('addr')
                
                # 获取接口状态
                try:
                    stats = psutil.net_if_stats()[interface]
                    interface_info['status'] = 'up' if stats.isup else 'down'
                    interface_info['speed'] = stats.speed
                    interface_info['mtu'] = stats.mtu
                except KeyError:
                    pass
                
                interfaces[interface] = interface_info
                
        except Exception as e:
            logger.error(f"获取网络接口信息失败: {e}")
        
        return interfaces
    
    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """
        获取默认网关地址
        
        Returns:
            str: 默认网关IP地址
        """
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default')
            
            if default_gateway and netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][0]
                
        except Exception as e:
            logger.error(f"获取默认网关失败: {e}")
        
        return None
    
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """
        获取本机IP地址
        
        Returns:
            str: 本机IP地址
        """
        try:
            # 连接到外部地址获取本机IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            try:
                # 备用方法：获取主机名对应的IP
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except Exception as e:
                logger.error(f"获取本机IP失败: {e}")
                return None
    
    @staticmethod
    def get_public_ip() -> Optional[str]:
        """
        获取公网IP地址
        
        Returns:
            str: 公网IP地址
        """
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ipecho.net/plain',
            'https://myexternalip.com/raw'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if NetworkUtils.is_valid_ip(ip):
                        return ip
            except Exception:
                continue
        
        logger.error("获取公网IP失败")
        return None
    
    @staticmethod
    def generate_random_mac() -> str:
        """
        生成随机MAC地址
        
        Returns:
            str: 随机MAC地址
        """
        # 生成随机MAC地址，第一个字节设置为偶数（单播地址）
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        
        return ':'.join(map(lambda x: "%02x" % x, mac))
    
    @staticmethod
    def mac_to_bytes(mac: str) -> bytes:
        """
        将MAC地址字符串转换为字节
        
        Args:
            mac (str): MAC地址字符串
            
        Returns:
            bytes: MAC地址字节
        """
        try:
            return bytes.fromhex(mac.replace(':', '').replace('-', ''))
        except ValueError as e:
            logger.error(f"MAC地址格式错误: {e}")
            return b'\x00\x00\x00\x00\x00\x00'
    
    @staticmethod
    def bytes_to_mac(mac_bytes: bytes) -> str:
        """
        将字节转换为MAC地址字符串
        
        Args:
            mac_bytes (bytes): MAC地址字节
            
        Returns:
            str: MAC地址字符串
        """
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        """
        将IP地址转换为整数
        
        Args:
            ip (str): IP地址字符串
            
        Returns:
            int: IP地址整数值
        """
        try:
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        except socket.error as e:
            logger.error(f"IP地址转换失败: {e}")
            return 0
    
    @staticmethod
    def int_to_ip(ip_int: int) -> str:
        """
        将整数转换为IP地址
        
        Args:
            ip_int (int): IP地址整数值
            
        Returns:
            str: IP地址字符串
        """
        try:
            return socket.inet_ntoa(struct.pack("!I", ip_int))
        except struct.error as e:
            logger.error(f"整数转换IP失败: {e}")
            return "0.0.0.0"
    
    @staticmethod
    def get_network_range(network: str) -> List[str]:
        """
        获取网络范围内的所有IP地址
        
        Args:
            network (str): 网络地址 (如 192.168.1.0/24)
            
        Returns:
            list: IP地址列表
        """
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            return [str(ip) for ip in network_obj.hosts()]
        except ValueError as e:
            logger.error(f"网络范围解析失败: {e}")
            return []
    
    @staticmethod
    def parse_ip_range(ip_range: str) -> List[str]:
        """
        解析IP范围
        
        Args:
            ip_range (str): IP范围 (支持多种格式)
                          - 单个IP: 192.168.1.1
                          - CIDR: 192.168.1.0/24
                          - 范围: 192.168.1.1-192.168.1.100
                          - 列表: 192.168.1.1,192.168.1.2,192.168.1.3
            
        Returns:
            list: IP地址列表
        """
        ips = []
        
        try:
            # 处理逗号分隔的多个目标
            if ',' in ip_range:
                for target in ip_range.split(','):
                    ips.extend(NetworkUtils.parse_ip_range(target.strip()))
                return ips
            
            # 处理CIDR格式
            if '/' in ip_range:
                return NetworkUtils.get_network_range(ip_range)
            
            # 处理范围格式
            if '-' in ip_range:
                start_ip, end_ip = ip_range.split('-', 1)
                start_ip = start_ip.strip()
                end_ip = end_ip.strip()
                
                start_int = NetworkUtils.ip_to_int(start_ip)
                end_int = NetworkUtils.ip_to_int(end_ip)
                
                if start_int <= end_int:
                    for ip_int in range(start_int, end_int + 1):
                        ips.append(NetworkUtils.int_to_ip(ip_int))
                
                return ips
            
            # 单个IP地址
            if NetworkUtils.is_valid_ip(ip_range):
                return [ip_range]
            
        except Exception as e:
            logger.error(f"IP范围解析失败: {e}")
        
        return []
    
    @staticmethod
    def check_port_open(host: str, port: int, timeout: int = 3) -> bool:
        """
        检查端口是否开放
        
        Args:
            host (str): 主机地址
            port (int): 端口号
            timeout (int): 超时时间
            
        Returns:
            bool: 端口开放返回True
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    @staticmethod
    def get_hostname(ip: str) -> Optional[str]:
        """
        根据IP地址获取主机名
        
        Args:
            ip (str): IP地址
            
        Returns:
            str: 主机名
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None
    
    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """
        解析主机名获取IP地址
        
        Args:
            hostname (str): 主机名
            
        Returns:
            str: IP地址
        """
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None
    
    @staticmethod
    def get_network_stats() -> Dict[str, Any]:
        """
        获取网络统计信息
        
        Returns:
            dict: 网络统计信息
        """
        try:
            stats = psutil.net_io_counters()
            return {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout
            }
        except Exception as e:
            logger.error(f"获取网络统计信息失败: {e}")
            return {}
    
    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        """
        获取网络连接信息
        
        Returns:
            list: 网络连接列表
        """
        connections = []
        
        try:
            for conn in psutil.net_connections():
                connection_info = {
                    'fd': conn.fd,
                    'family': conn.family.name if conn.family else 'unknown',
                    'type': conn.type.name if conn.type else 'unknown',
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                connections.append(connection_info)
                
        except Exception as e:
            logger.error(f"获取网络连接信息失败: {e}")
        
        return connections
    
    @staticmethod
    def set_proxy(proxy_url: str) -> Dict[str, str]:
        """
        设置代理配置
        
        Args:
            proxy_url (str): 代理URL (如 http://127.0.0.1:8080)
            
        Returns:
            dict: 代理配置字典
        """
        if proxy_url:
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        return {}
    
    @staticmethod
    def test_connectivity(host: str = "8.8.8.8", port: int = 53, timeout: int = 5) -> bool:
        """
        测试网络连通性
        
        Args:
            host (str): 测试主机
            port (int): 测试端口
            timeout (int): 超时时间
            
        Returns:
            bool: 连通返回True
        """
        return NetworkUtils.check_port_open(host, port, timeout)
    
    @staticmethod
    def get_arp_table() -> List[Dict[str, str]]:
        """
        获取ARP表信息
        
        Returns:
            list: ARP表条目列表
        """
        arp_table = []
        
        try:
            if sys.platform.startswith('win'):
                # Windows系统
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'dynamic' in line.lower() or 'static' in line.lower():
                            parts = line.split()
                            if len(parts) >= 3:
                                arp_table.append({
                                    'ip': parts[0],
                                    'mac': parts[1],
                                    'type': parts[2] if len(parts) > 2 else 'unknown'
                                })
            else:
                # Linux/Unix系统
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '(' in line and ')' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                ip = parts[1].strip('()')
                                mac = parts[3]
                                arp_table.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'type': 'dynamic'
                                })
                                
        except Exception as e:
            logger.error(f"获取ARP表失败: {e}")
        
        return arp_table

# 便捷函数
def get_local_network() -> Optional[str]:
    """
    获取本地网络地址
    
    Returns:
        str: 本地网络地址 (CIDR格式)
    """
    try:
        local_ip = NetworkUtils.get_local_ip()
        if local_ip:
            # 假设是/24网络
            ip_parts = local_ip.split('.')
            network = f"{".join(ip_parts[:3])}.0/24"
            return network
    except Exception as e:
        logger.error(f"获取本地网络失败: {e}")
    
    return None

def is_internal_ip(ip: str) -> bool:
    """
    检查是否为内网IP
    
    Args:
        ip (str): IP地址
        
    Returns:
        bool: 内网IP返回True
    """
    return NetworkUtils.is_private_ip(ip)

def format_mac_address(mac: str, separator: str = ':') -> str:
    """
    格式化MAC地址
    
    Args:
        mac (str): MAC地址
        separator (str): 分隔符
        
    Returns:
        str: 格式化后的MAC地址
    """
    # 移除所有分隔符
    clean_mac = mac.replace(':', '').replace('-', '').replace('.', '')
    
    # 重新格式化
    if len(clean_mac) == 12:
        return separator.join([clean_mac[i:i+2] for i in range(0, 12, 2)])
    
    return mac