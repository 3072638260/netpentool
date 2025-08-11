#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 日志管理模块

提供统一的日志管理功能，包括：
- 多级别日志记录
- 文件和控制台输出
- 日志格式化
- 日志轮转
- 彩色输出
- 性能监控

作者: Security Researcher
版本: 1.0.0
"""

import sys
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from loguru import logger
    from colorama import Fore, Back, Style, init
    init(autoreset=True)  # 初始化colorama
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install loguru colorama")
    sys.exit(1)

class TraesLogger:
    """
    TRAES 日志管理器
    
    提供统一的日志管理功能。
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化日志管理器
        
        Args:
            config (dict): 日志配置字典
        """
        self.config = config or {}
        self.log_config = self.config.get('logging', {})
        
        # 日志配置
        self.log_level = self.log_config.get('level', 'INFO')
        self.log_file = self.log_config.get('file', 'logs/traes.log')
        self.max_file_size = self.log_config.get('max_file_size', '10 MB')
        self.backup_count = self.log_config.get('backup_count', 5)
        self.console_output = self.log_config.get('console_output', True)
        self.file_output = self.log_config.get('file_output', True)
        self.colored_output = self.log_config.get('colored_output', True)
        
        # 日志格式
        self.console_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
        
        self.file_format = (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
            "{level: <8} | "
            "{name}:{function}:{line} - "
            "{message}"
        )
        
        # 性能监控
        self.performance_logs = self.log_config.get('performance_logs', False)
        self.start_times = {}
        
        # 初始化日志器
        self._setup_logger()
    
    def _setup_logger(self):
        """
        设置日志器配置
        """
        # 移除默认处理器
        logger.remove()
        
        # 控制台输出
        if self.console_output:
            if self.colored_output:
                logger.add(
                    sys.stderr,
                    format=self.console_format,
                    level=self.log_level,
                    colorize=True
                )
            else:
                logger.add(
                    sys.stderr,
                    format=self.file_format,
                    level=self.log_level,
                    colorize=False
                )
        
        # 文件输出
        if self.file_output:
            # 确保日志目录存在
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            logger.add(
                self.log_file,
                format=self.file_format,
                level=self.log_level,
                rotation=self.max_file_size,
                retention=self.backup_count,
                compression="zip",
                encoding="utf-8"
            )
        
        # 添加自定义级别
        logger.level("SUCCESS", no=25, color="<green><bold>")
        logger.level("ATTACK", no=35, color="<red><bold>")
        logger.level("SCAN", no=15, color="<blue>")
        
        logger.info("日志系统初始化完成")
    
    def get_logger(self, name: str = "TRAES"):
        """
        获取日志器实例
        
        Args:
            name (str): 日志器名称
            
        Returns:
            logger: 日志器实例
        """
        return logger.bind(name=name)
    
    def log_attack(self, message: str, target: str = None, **kwargs):
        """
        记录攻击日志
        
        Args:
            message (str): 日志消息
            target (str): 攻击目标
            **kwargs: 额外参数
        """
        if target:
            message = f"[目标: {target}] {message}"
        
        logger.log("ATTACK", message, **kwargs)
    
    def log_scan(self, message: str, target: str = None, **kwargs):
        """
        记录扫描日志
        
        Args:
            message (str): 日志消息
            target (str): 扫描目标
            **kwargs: 额外参数
        """
        if target:
            message = f"[目标: {target}] {message}"
        
        logger.log("SCAN", message, **kwargs)
    
    def log_success(self, message: str, **kwargs):
        """
        记录成功日志
        
        Args:
            message (str): 日志消息
            **kwargs: 额外参数
        """
        logger.log("SUCCESS", message, **kwargs)
    
    def start_timer(self, operation: str):
        """
        开始计时
        
        Args:
            operation (str): 操作名称
        """
        if self.performance_logs:
            self.start_times[operation] = time.time()
            logger.debug(f"开始操作: {operation}")
    
    def end_timer(self, operation: str):
        """
        结束计时并记录
        
        Args:
            operation (str): 操作名称
        """
        if self.performance_logs and operation in self.start_times:
            elapsed = time.time() - self.start_times[operation]
            logger.info(f"操作 '{operation}' 完成，耗时: {elapsed:.2f}秒")
            del self.start_times[operation]
    
    def log_error_with_traceback(self, message: str, exception: Exception = None):
        """
        记录错误日志并包含堆栈跟踪
        
        Args:
            message (str): 错误消息
            exception (Exception): 异常对象
        """
        if exception:
            logger.exception(f"{message}: {str(exception)}")
        else:
            logger.error(message)
    
    def log_network_event(self, event_type: str, source: str, destination: str, 
                         protocol: str, details: str = None):
        """
        记录网络事件
        
        Args:
            event_type (str): 事件类型
            source (str): 源地址
            destination (str): 目标地址
            protocol (str): 协议
            details (str): 详细信息
        """
        message = f"[{event_type}] {source} -> {destination} ({protocol})"
        if details:
            message += f" | {details}"
        
        logger.info(message)
    
    def log_security_event(self, event_type: str, severity: str, description: str, 
                          source_ip: str = None, target_ip: str = None):
        """
        记录安全事件
        
        Args:
            event_type (str): 事件类型
            severity (str): 严重程度
            description (str): 事件描述
            source_ip (str): 源IP
            target_ip (str): 目标IP
        """
        message = f"[安全事件] {event_type} | 严重程度: {severity} | {description}"
        
        if source_ip:
            message += f" | 源IP: {source_ip}"
        if target_ip:
            message += f" | 目标IP: {target_ip}"
        
        if severity.upper() in ['HIGH', 'CRITICAL']:
            logger.error(message)
        elif severity.upper() == 'MEDIUM':
            logger.warning(message)
        else:
            logger.info(message)
    
    def create_session_log(self, session_id: str) -> str:
        """
        创建会话专用日志文件
        
        Args:
            session_id (str): 会话ID
            
        Returns:
            str: 日志文件路径
        """
        session_log_file = f"logs/session_{session_id}.log"
        
        # 确保目录存在
        Path(session_log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # 添加会话日志处理器
        logger.add(
            session_log_file,
            format=self.file_format,
            level="DEBUG",
            filter=lambda record: record["extra"].get("session_id") == session_id
        )
        
        logger.info(f"创建会话日志文件: {session_log_file}")
        return session_log_file
    
    def set_log_level(self, level: str):
        """
        动态设置日志级别
        
        Args:
            level (str): 日志级别
        """
        self.log_level = level.upper()
        logger.info(f"日志级别已设置为: {self.log_level}")
        
        # 重新配置日志器
        self._setup_logger()
    
    def get_log_stats(self) -> Dict[str, Any]:
        """
        获取日志统计信息
        
        Returns:
            dict: 日志统计信息
        """
        stats = {
            'log_level': self.log_level,
            'log_file': self.log_file,
            'console_output': self.console_output,
            'file_output': self.file_output,
            'colored_output': self.colored_output,
            'performance_logs': self.performance_logs,
            'active_timers': len(self.start_times)
        }
        
        # 获取日志文件大小
        if self.file_output and os.path.exists(self.log_file):
            stats['log_file_size'] = os.path.getsize(self.log_file)
        
        return stats

# 全局日志管理器实例
_global_logger = None

def setup_logger(config: Dict[str, Any] = None) -> TraesLogger:
    """
    设置全局日志管理器
    
    Args:
        config (dict): 日志配置
        
    Returns:
        TraesLogger: 日志管理器实例
    """
    global _global_logger
    _global_logger = TraesLogger(config)
    return _global_logger

def get_logger(name: str = "TRAES"):
    """
    获取全局日志器
    
    Args:
        name (str): 日志器名称
        
    Returns:
        logger: 日志器实例
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = TraesLogger()
    
    return _global_logger.get_logger(name)

# 便捷函数
def log_attack(message: str, target: str = None, **kwargs):
    """
    记录攻击日志的便捷函数
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = TraesLogger()
    
    _global_logger.log_attack(message, target, **kwargs)

def log_scan(message: str, target: str = None, **kwargs):
    """
    记录扫描日志的便捷函数
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = TraesLogger()
    
    _global_logger.log_scan(message, target, **kwargs)

def log_success(message: str, **kwargs):
    """
    记录成功日志的便捷函数
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = TraesLogger()
    
    _global_logger.log_success(message, **kwargs)

def start_timer(operation: str):
    """
    开始计时的便捷函数
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = TraesLogger()
    
    _global_logger.start_timer(operation)

def end_timer(operation: str):
    """
    结束计时的便捷函数
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = TraesLogger()
    
    _global_logger.end_timer(operation)

# 彩色输出辅助函数
def colored_text(text: str, color: str = 'white', style: str = None) -> str:
    """
    生成彩色文本
    
    Args:
        text (str): 文本内容
        color (str): 颜色名称
        style (str): 样式名称
        
    Returns:
        str: 彩色文本
    """
    color_map = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE,
        'magenta': Fore.MAGENTA,
        'cyan': Fore.CYAN,
        'white': Fore.WHITE,
        'black': Fore.BLACK
    }
    
    style_map = {
        'bright': Style.BRIGHT,
        'dim': Style.DIM,
        'normal': Style.NORMAL
    }
    
    result = ""
    
    if color in color_map:
        result += color_map[color]
    
    if style in style_map:
        result += style_map[style]
    
    result += text + Style.RESET_ALL
    
    return result

def print_banner(text: str, color: str = 'cyan', width: int = 60):
    """
    打印横幅文本
    
    Args:
        text (str): 横幅文本
        color (str): 颜色
        width (int): 宽度
    """
    border = '=' * width
    padding = (width - len(text) - 2) // 2
    
    print(colored_text(border, color))
    print(colored_text(f"{'=' * padding} {text} {'=' * padding}", color))
    print(colored_text(border, color))

def print_status(status: str, message: str, status_color: str = 'green'):
    """
    打印状态消息
    
    Args:
        status (str): 状态标识
        message (str): 消息内容
        status_color (str): 状态颜色
    """
    status_text = colored_text(f"[{status}]", status_color, 'bright')
    print(f"{status_text} {message}")

# 装饰器
def log_function_call(func):
    """
    记录函数调用的装饰器
    
    Args:
        func: 被装饰的函数
        
    Returns:
        function: 装饰后的函数
    """
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        logger.debug(f"调用函数: {func_name}")
        
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.debug(f"函数 {func_name} 执行完成，耗时: {elapsed:.3f}秒")
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"函数 {func_name} 执行失败，耗时: {elapsed:.3f}秒，错误: {e}")
            raise
    
    return wrapper

def log_performance(operation_name: str = None):
    """
    性能监控装饰器
    
    Args:
        operation_name (str): 操作名称
        
    Returns:
        function: 装饰器函数
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            name = operation_name or func.__name__
            start_timer(name)
            try:
                result = func(*args, **kwargs)
                end_timer(name)
                return result
            except Exception as e:
                end_timer(name)
                raise
        return wrapper
    return decorator