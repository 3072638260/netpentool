#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 系统工具模块

提供系统操作相关的实用工具函数，包括：
- 进程管理
- 系统信息获取
- 权限检查
- 服务管理
- 环境变量操作
- 系统监控
- 平台兼容性

作者: Security Researcher
版本: 1.0.0
"""

import os
import sys
import platform
import subprocess
import time
import signal
from typing import List, Dict, Optional, Any, Union
from pathlib import Path

try:
    import psutil
    from loguru import logger
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install psutil loguru")
    sys.exit(1)

class SystemUtils:
    """
    系统工具类
    
    提供各种系统操作功能。
    """
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """
        获取系统信息
        
        Returns:
            dict: 系统信息字典
        """
        try:
            info = {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': platform.node(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'python_implementation': platform.python_implementation(),
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'disk_usage': {},
                'network_interfaces': [],
                'boot_time': psutil.boot_time()
            }
            
            # 获取磁盘使用情况
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['disk_usage'][partition.device] = {
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': (usage.used / usage.total) * 100
                    }
                except PermissionError:
                    continue
            
            # 获取网络接口
            for interface, addresses in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                for addr in addresses:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                info['network_interfaces'].append(interface_info)
            
            return info
        except Exception as e:
            logger.error(f"获取系统信息失败: {e}")
            return {}
    
    @staticmethod
    def get_cpu_usage(interval: float = 1.0) -> float:
        """
        获取CPU使用率
        
        Args:
            interval (float): 采样间隔
            
        Returns:
            float: CPU使用率百分比
        """
        try:
            return psutil.cpu_percent(interval=interval)
        except Exception as e:
            logger.error(f"获取CPU使用率失败: {e}")
            return 0.0
    
    @staticmethod
    def get_memory_usage() -> Dict[str, Any]:
        """
        获取内存使用情况
        
        Returns:
            dict: 内存使用信息
        """
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                'virtual': {
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'free': memory.free,
                    'percent': memory.percent
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                }
            }
        except Exception as e:
            logger.error(f"获取内存使用情况失败: {e}")
            return {}
    
    @staticmethod
    def get_disk_usage(path: str = '/') -> Dict[str, Any]:
        """
        获取磁盘使用情况
        
        Args:
            path (str): 磁盘路径
            
        Returns:
            dict: 磁盘使用信息
        """
        try:
            usage = psutil.disk_usage(path)
            return {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': (usage.used / usage.total) * 100
            }
        except Exception as e:
            logger.error(f"获取磁盘使用情况失败 {path}: {e}")
            return {}
    
    @staticmethod
    def get_network_stats() -> Dict[str, Any]:
        """
        获取网络统计信息
        
        Returns:
            dict: 网络统计信息
        """
        try:
            stats = psutil.net_io_counters()
            connections = psutil.net_connections()
            
            return {
                'io_counters': {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                },
                'connections_count': len(connections),
                'connections': [{
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                } for conn in connections[:50]]  # 限制连接数量
            }
        except Exception as e:
            logger.error(f"获取网络统计信息失败: {e}")
            return {}
    
    @staticmethod
    def get_process_list() -> List[Dict[str, Any]]:
        """
        获取进程列表
        
        Returns:
            list: 进程信息列表
        """
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return processes
        except Exception as e:
            logger.error(f"获取进程列表失败: {e}")
            return []
    
    @staticmethod
    def find_process_by_name(name: str) -> List[Dict[str, Any]]:
        """
        根据名称查找进程
        
        Args:
            name (str): 进程名称
            
        Returns:
            list: 匹配的进程列表
        """
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    if name.lower() in proc.info['name'].lower():
                        processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return processes
        except Exception as e:
            logger.error(f"查找进程失败 {name}: {e}")
            return []
    
    @staticmethod
    def find_process_by_port(port: int) -> List[Dict[str, Any]]:
        """
        根据端口查找进程
        
        Args:
            port (int): 端口号
            
        Returns:
            list: 使用该端口的进程列表
        """
        try:
            processes = []
            for conn in psutil.net_connections():
                if conn.laddr and conn.laddr.port == port:
                    try:
                        proc = psutil.Process(conn.pid)
                        processes.append({
                            'pid': proc.pid,
                            'name': proc.name(),
                            'username': proc.username(),
                            'status': proc.status(),
                            'connection': {
                                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status
                            }
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            return processes
        except Exception as e:
            logger.error(f"根据端口查找进程失败 {port}: {e}")
            return []
    
    @staticmethod
    def kill_process(pid: int, force: bool = False) -> bool:
        """
        终止进程
        
        Args:
            pid (int): 进程ID
            force (bool): 是否强制终止
            
        Returns:
            bool: 终止成功返回True
        """
        try:
            proc = psutil.Process(pid)
            if force:
                proc.kill()
            else:
                proc.terminate()
            
            # 等待进程终止
            proc.wait(timeout=5)
            logger.info(f"进程 {pid} 已终止")
            return True
        except psutil.NoSuchProcess:
            logger.warning(f"进程 {pid} 不存在")
            return True
        except psutil.TimeoutExpired:
            logger.warning(f"进程 {pid} 终止超时")
            return False
        except Exception as e:
            logger.error(f"终止进程失败 {pid}: {e}")
            return False
    
    @staticmethod
    def kill_process_by_name(name: str, force: bool = False) -> int:
        """
        根据名称终止进程
        
        Args:
            name (str): 进程名称
            force (bool): 是否强制终止
            
        Returns:
            int: 终止的进程数量
        """
        try:
            killed_count = 0
            processes = SystemUtils.find_process_by_name(name)
            
            for proc_info in processes:
                if SystemUtils.kill_process(proc_info['pid'], force):
                    killed_count += 1
            
            logger.info(f"终止了 {killed_count} 个名为 '{name}' 的进程")
            return killed_count
        except Exception as e:
            logger.error(f"根据名称终止进程失败 {name}: {e}")
            return 0
    
    @staticmethod
    def run_command(command: Union[str, List[str]], shell: bool = True, 
                   timeout: int = 30, capture_output: bool = True) -> Dict[str, Any]:
        """
        执行系统命令
        
        Args:
            command (str|list): 要执行的命令
            shell (bool): 是否使用shell
            timeout (int): 超时时间（秒）
            capture_output (bool): 是否捕获输出
            
        Returns:
            dict: 执行结果
        """
        try:
            start_time = time.time()
            
            if capture_output:
                result = subprocess.run(
                    command,
                    shell=shell,
                    timeout=timeout,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                
                return {
                    'success': result.returncode == 0,
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'execution_time': time.time() - start_time
                }
            else:
                result = subprocess.run(
                    command,
                    shell=shell,
                    timeout=timeout
                )
                
                return {
                    'success': result.returncode == 0,
                    'returncode': result.returncode,
                    'stdout': '',
                    'stderr': '',
                    'execution_time': time.time() - start_time
                }
        except subprocess.TimeoutExpired:
            logger.error(f"命令执行超时: {command}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timeout',
                'execution_time': timeout
            }
        except Exception as e:
            logger.error(f"执行命令失败 {command}: {e}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'execution_time': time.time() - start_time
            }
    
    @staticmethod
    def is_admin() -> bool:
        """
        检查是否具有管理员权限
        
        Returns:
            bool: 是否为管理员
        """
        try:
            if platform.system() == 'Windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception as e:
            logger.error(f"检查管理员权限失败: {e}")
            return False
    
    @staticmethod
    def get_environment_variables() -> Dict[str, str]:
        """
        获取环境变量
        
        Returns:
            dict: 环境变量字典
        """
        return dict(os.environ)
    
    @staticmethod
    def set_environment_variable(name: str, value: str) -> bool:
        """
        设置环境变量
        
        Args:
            name (str): 变量名
            value (str): 变量值
            
        Returns:
            bool: 设置成功返回True
        """
        try:
            os.environ[name] = value
            return True
        except Exception as e:
            logger.error(f"设置环境变量失败 {name}: {e}")
            return False
    
    @staticmethod
    def get_current_user() -> str:
        """
        获取当前用户名
        
        Returns:
            str: 用户名
        """
        try:
            import getpass
            return getpass.getuser()
        except Exception as e:
            logger.error(f"获取当前用户失败: {e}")
            return ''
    
    @staticmethod
    def get_home_directory() -> str:
        """
        获取用户主目录
        
        Returns:
            str: 主目录路径
        """
        return str(Path.home())
    
    @staticmethod
    def get_temp_directory() -> str:
        """
        获取临时目录
        
        Returns:
            str: 临时目录路径
        """
        import tempfile
        return tempfile.gettempdir()
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
        """
        检查端口是否开放
        
        Args:
            host (str): 主机地址
            port (int): 端口号
            timeout (float): 超时时间
            
        Returns:
            bool: 端口是否开放
        """
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.error(f"检查端口失败 {host}:{port}: {e}")
            return False
    
    @staticmethod
    def get_open_ports(start_port: int = 1, end_port: int = 65535, 
                      host: str = 'localhost') -> List[int]:
        """
        获取开放的端口列表
        
        Args:
            start_port (int): 起始端口
            end_port (int): 结束端口
            host (str): 主机地址
            
        Returns:
            list: 开放的端口列表
        """
        try:
            open_ports = []
            for port in range(start_port, min(end_port + 1, 65536)):
                if SystemUtils.is_port_open(host, port, timeout=0.1):
                    open_ports.append(port)
                    if len(open_ports) >= 100:  # 限制结果数量
                        break
            return open_ports
        except Exception as e:
            logger.error(f"获取开放端口失败: {e}")
            return []
    
    @staticmethod
    def monitor_system_resources(duration: int = 60, interval: int = 5) -> List[Dict[str, Any]]:
        """
        监控系统资源
        
        Args:
            duration (int): 监控时长（秒）
            interval (int): 采样间隔（秒）
            
        Returns:
            list: 监控数据列表
        """
        try:
            monitoring_data = []
            start_time = time.time()
            
            while time.time() - start_time < duration:
                timestamp = time.time()
                cpu_usage = SystemUtils.get_cpu_usage(interval=1)
                memory_usage = SystemUtils.get_memory_usage()
                
                monitoring_data.append({
                    'timestamp': timestamp,
                    'cpu_percent': cpu_usage,
                    'memory_percent': memory_usage['virtual']['percent'],
                    'memory_available': memory_usage['virtual']['available'],
                    'swap_percent': memory_usage['swap']['percent']
                })
                
                time.sleep(interval)
            
            return monitoring_data
        except Exception as e:
            logger.error(f"监控系统资源失败: {e}")
            return []
    
    @staticmethod
    def cleanup_temp_files(pattern: str = '*', max_age_hours: int = 24) -> int:
        """
        清理临时文件
        
        Args:
            pattern (str): 文件模式
            max_age_hours (int): 最大文件年龄（小时）
            
        Returns:
            int: 清理的文件数量
        """
        try:
            temp_dir = Path(SystemUtils.get_temp_directory())
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600
            cleaned_count = 0
            
            for file_path in temp_dir.glob(pattern):
                try:
                    if file_path.is_file():
                        file_age = current_time - file_path.stat().st_mtime
                        if file_age > max_age_seconds:
                            file_path.unlink()
                            cleaned_count += 1
                except Exception:
                    continue
            
            logger.info(f"清理了 {cleaned_count} 个临时文件")
            return cleaned_count
        except Exception as e:
            logger.error(f"清理临时文件失败: {e}")
            return 0

# 便捷函数
def get_platform_info() -> Dict[str, str]:
    """
    获取平台信息
    
    Returns:
        dict: 平台信息
    """
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version()
    }

def is_windows() -> bool:
    """
    检查是否为Windows系统
    
    Returns:
        bool: 是否为Windows
    """
    return platform.system().lower() == 'windows'

def is_linux() -> bool:
    """
    检查是否为Linux系统
    
    Returns:
        bool: 是否为Linux
    """
    return platform.system().lower() == 'linux'

def is_macos() -> bool:
    """
    检查是否为macOS系统
    
    Returns:
        bool: 是否为macOS
    """
    return platform.system().lower() == 'darwin'

def get_system_load() -> Dict[str, float]:
    """
    获取系统负载
    
    Returns:
        dict: 系统负载信息
    """
    try:
        cpu_percent = SystemUtils.get_cpu_usage()
        memory_info = SystemUtils.get_memory_usage()
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_info['virtual']['percent'],
            'swap_percent': memory_info['swap']['percent']
        }
    except Exception as e:
        logger.error(f"获取系统负载失败: {e}")
        return {'cpu_percent': 0.0, 'memory_percent': 0.0, 'swap_percent': 0.0}

def check_system_requirements() -> Dict[str, bool]:
    """
    检查系统要求
    
    Returns:
        dict: 系统要求检查结果
    """
    try:
        requirements = {
            'python_version_ok': sys.version_info >= (3, 7),
            'memory_sufficient': psutil.virtual_memory().total >= 1024 * 1024 * 1024,  # 1GB
            'disk_space_sufficient': psutil.disk_usage('/').free >= 100 * 1024 * 1024,  # 100MB
            'admin_privileges': SystemUtils.is_admin()
        }
        
        return requirements
    except Exception as e:
        logger.error(f"检查系统要求失败: {e}")
        return {
            'python_version_ok': False,
            'memory_sufficient': False,
            'disk_space_sufficient': False,
            'admin_privileges': False
        }