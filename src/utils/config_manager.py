#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 配置管理模块

提供配置文件的读取、写入、验证和管理功能，包括：
- JSON/YAML配置文件支持
- 配置验证
- 默认配置管理
- 配置热重载
- 环境变量支持
- 配置加密

作者: Security Researcher
版本: 1.0.0
"""

import os
import sys
import json
import copy
from pathlib import Path
from typing import Dict, Any, Optional, Union

try:
    import yaml
    from loguru import logger
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install pyyaml loguru")
    sys.exit(1)

class ConfigManager:
    """
    配置管理器
    
    提供统一的配置管理功能。
    """
    
    def __init__(self, config_file: str = None, auto_create: bool = True):
        """
        初始化配置管理器
        
        Args:
            config_file (str): 配置文件路径
            auto_create (bool): 是否自动创建配置文件
        """
        self.config_file = config_file or "config/config.json"
        self.auto_create = auto_create
        self.config_data = {}
        self.default_config = self._get_default_config()
        
        # 配置文件监控
        self._last_modified = None
        
        # 加载配置
        self.load_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        获取默认配置
        
        Returns:
            dict: 默认配置字典
        """
        return {
            "logging": {
                "level": "INFO",
                "file": "logs/traes.log",
                "max_file_size": "10 MB",
                "backup_count": 5,
                "console_output": True,
                "file_output": True,
                "colored_output": True,
                "performance_logs": False
            },
            "network": {
                "timeout": 5,
                "max_retries": 3,
                "user_agent": "TRAES/1.0",
                "proxy": {
                    "enabled": False,
                    "http": "",
                    "https": ""
                },
                "interface": "auto"
            },
            "attack": {
                "arp": {
                    "enabled": True,
                    "interval": 1,
                    "restore_on_exit": True,
                    "randomize_mac": False,
                    "max_targets": 100
                },
                "dhcp": {
                    "enabled": True,
                    "server_ip": "192.168.1.1",
                    "dns_servers": ["8.8.8.8", "8.8.4.4"],
                    "lease_time": 3600,
                    "max_clients": 50
                },
                "bruteforce": {
                    "enabled": True,
                    "max_threads": 10,
                    "delay": 0.1,
                    "max_attempts": 1000,
                    "timeout": 10
                }
            },
            "security": {
                "whitelist": {
                    "enabled": True,
                    "ips": [],
                    "networks": []
                },
                "rate_limiting": {
                    "enabled": True,
                    "max_requests_per_second": 10
                },
                "encryption": {
                    "enabled": False,
                    "algorithm": "AES-256",
                    "key_file": "config/encryption.key"
                }
            },
            "output": {
                "format": "json",
                "file": "output/results.json",
                "console": True,
                "save_screenshots": False,
                "save_packets": False
            },
            "performance": {
                "max_threads": 50,
                "memory_limit": "1GB",
                "cpu_limit": 80,
                "disk_space_limit": "5GB"
            },
            "dictionaries": {
                "usernames": "data/usernames.txt",
                "passwords": "data/passwords.txt",
                "subdomains": "data/subdomains.txt",
                "directories": "data/directories.txt"
            }
        }
    
    def load_config(self) -> bool:
        """
        加载配置文件
        
        Returns:
            bool: 加载成功返回True
        """
        try:
            config_path = Path(self.config_file)
            
            if not config_path.exists():
                if self.auto_create:
                    logger.info(f"配置文件不存在，创建默认配置: {self.config_file}")
                    self.save_config(self.default_config)
                    self.config_data = copy.deepcopy(self.default_config)
                    return True
                else:
                    logger.error(f"配置文件不存在: {self.config_file}")
                    return False
            
            # 检查文件修改时间
            current_modified = config_path.stat().st_mtime
            if self._last_modified and current_modified == self._last_modified:
                return True  # 文件未修改
            
            self._last_modified = current_modified
            
            # 根据文件扩展名选择解析器
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                with open(config_path, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f)
            else:
                with open(config_path, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
            
            if loaded_config:
                # 合并默认配置和加载的配置
                self.config_data = self._merge_configs(self.default_config, loaded_config)
                logger.info(f"配置文件加载成功: {self.config_file}")
                return True
            else:
                logger.error("配置文件为空")
                return False
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON配置文件格式错误: {e}")
            return False
        except yaml.YAMLError as e:
            logger.error(f"YAML配置文件格式错误: {e}")
            return False
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return False
    
    def save_config(self, config_data: Dict[str, Any] = None) -> bool:
        """
        保存配置文件
        
        Args:
            config_data (dict): 要保存的配置数据
            
        Returns:
            bool: 保存成功返回True
        """
        try:
            if config_data is None:
                config_data = self.config_data
            
            config_path = Path(self.config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 根据文件扩展名选择格式
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                with open(config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config_data, f, default_flow_style=False, 
                             allow_unicode=True, indent=2)
            else:
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            # 更新修改时间
            self._last_modified = config_path.stat().st_mtime
            
            logger.info(f"配置文件保存成功: {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            return False
    
    def _merge_configs(self, default: Dict[str, Any], loaded: Dict[str, Any]) -> Dict[str, Any]:
        """
        合并默认配置和加载的配置
        
        Args:
            default (dict): 默认配置
            loaded (dict): 加载的配置
            
        Returns:
            dict: 合并后的配置
        """
        result = copy.deepcopy(default)
        
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值
        
        Args:
            key (str): 配置键，支持点号分隔的嵌套键
            default: 默认值
            
        Returns:
            Any: 配置值
        """
        try:
            keys = key.split('.')
            value = self.config_data
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            # 检查环境变量覆盖
            env_key = f"TRAES_{key.upper().replace('.', '_')}"
            env_value = os.getenv(env_key)
            
            if env_value is not None:
                # 尝试转换环境变量值的类型
                if isinstance(value, bool):
                    return env_value.lower() in ['true', '1', 'yes', 'on']
                elif isinstance(value, int):
                    try:
                        return int(env_value)
                    except ValueError:
                        return value
                elif isinstance(value, float):
                    try:
                        return float(env_value)
                    except ValueError:
                        return value
                else:
                    return env_value
            
            return value
            
        except Exception as e:
            logger.error(f"获取配置值失败 {key}: {e}")
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """
        设置配置值
        
        Args:
            key (str): 配置键，支持点号分隔的嵌套键
            value: 配置值
            
        Returns:
            bool: 设置成功返回True
        """
        try:
            keys = key.split('.')
            config = self.config_data
            
            # 导航到目标位置
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # 设置值
            config[keys[-1]] = value
            
            logger.debug(f"配置值已设置: {key} = {value}")
            return True
            
        except Exception as e:
            logger.error(f"设置配置值失败 {key}: {e}")
            return False
    
    def validate_config(self) -> Dict[str, list]:
        """
        验证配置
        
        Returns:
            dict: 验证结果，包含错误和警告
        """
        errors = []
        warnings = []
        
        try:
            # 验证日志配置
            log_level = self.get('logging.level', 'INFO')
            if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                errors.append(f"无效的日志级别: {log_level}")
            
            # 验证网络配置
            timeout = self.get('network.timeout', 5)
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                errors.append(f"无效的网络超时时间: {timeout}")
            
            max_retries = self.get('network.max_retries', 3)
            if not isinstance(max_retries, int) or max_retries < 0:
                errors.append(f"无效的最大重试次数: {max_retries}")
            
            # 验证攻击配置
            max_threads = self.get('attack.bruteforce.max_threads', 10)
            if not isinstance(max_threads, int) or max_threads <= 0:
                errors.append(f"无效的最大线程数: {max_threads}")
            
            # 验证白名单配置
            whitelist_ips = self.get('security.whitelist.ips', [])
            if not isinstance(whitelist_ips, list):
                errors.append("白名单IP必须是列表格式")
            
            # 验证文件路径
            log_file = self.get('logging.file', '')
            if log_file:
                log_dir = Path(log_file).parent
                if not log_dir.exists():
                    try:
                        log_dir.mkdir(parents=True, exist_ok=True)
                    except Exception:
                        warnings.append(f"无法创建日志目录: {log_dir}")
            
            # 验证字典文件
            dict_files = {
                'usernames': self.get('dictionaries.usernames'),
                'passwords': self.get('dictionaries.passwords'),
                'subdomains': self.get('dictionaries.subdomains'),
                'directories': self.get('dictionaries.directories')
            }
            
            for dict_type, dict_file in dict_files.items():
                if dict_file and not Path(dict_file).exists():
                    warnings.append(f"{dict_type}字典文件不存在: {dict_file}")
            
        except Exception as e:
            errors.append(f"配置验证过程中出错: {e}")
        
        return {
            'errors': errors,
            'warnings': warnings
        }
    
    def reload_config(self) -> bool:
        """
        重新加载配置文件
        
        Returns:
            bool: 重新加载成功返回True
        """
        logger.info("重新加载配置文件")
        self._last_modified = None  # 强制重新加载
        return self.load_config()
    
    def reset_to_default(self) -> bool:
        """
        重置为默认配置
        
        Returns:
            bool: 重置成功返回True
        """
        logger.info("重置为默认配置")
        self.config_data = copy.deepcopy(self.default_config)
        return self.save_config()
    
    def export_config(self, export_file: str, format_type: str = 'json') -> bool:
        """
        导出配置到文件
        
        Args:
            export_file (str): 导出文件路径
            format_type (str): 导出格式 (json/yaml)
            
        Returns:
            bool: 导出成功返回True
        """
        try:
            export_path = Path(export_file)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format_type.lower() == 'yaml':
                with open(export_path, 'w', encoding='utf-8') as f:
                    yaml.dump(self.config_data, f, default_flow_style=False,
                             allow_unicode=True, indent=2)
            else:
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(self.config_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"配置已导出到: {export_file}")
            return True
            
        except Exception as e:
            logger.error(f"导出配置失败: {e}")
            return False
    
    def import_config(self, import_file: str) -> bool:
        """
        从文件导入配置
        
        Args:
            import_file (str): 导入文件路径
            
        Returns:
            bool: 导入成功返回True
        """
        try:
            import_path = Path(import_file)
            
            if not import_path.exists():
                logger.error(f"导入文件不存在: {import_file}")
                return False
            
            # 备份当前配置
            backup_config = copy.deepcopy(self.config_data)
            
            # 临时设置配置文件路径
            original_config_file = self.config_file
            self.config_file = str(import_path)
            
            # 加载新配置
            success = self.load_config()
            
            if success:
                # 恢复原配置文件路径并保存
                self.config_file = original_config_file
                self.save_config()
                logger.info(f"配置已从 {import_file} 导入")
            else:
                # 恢复备份配置
                self.config_data = backup_config
                self.config_file = original_config_file
                logger.error("导入配置失败，已恢复原配置")
            
            return success
            
        except Exception as e:
            logger.error(f"导入配置失败: {e}")
            return False
    
    def get_config_summary(self) -> Dict[str, Any]:
        """
        获取配置摘要信息
        
        Returns:
            dict: 配置摘要
        """
        summary = {
            'config_file': self.config_file,
            'last_modified': self._last_modified,
            'sections': list(self.config_data.keys()),
            'validation': self.validate_config()
        }
        
        # 统计配置项数量
        def count_items(data):
            count = 0
            for value in data.values():
                if isinstance(value, dict):
                    count += count_items(value)
                else:
                    count += 1
            return count
        
        summary['total_items'] = count_items(self.config_data)
        
        return summary
    
    def create_config_template(self, template_file: str) -> bool:
        """
        创建配置模板文件
        
        Args:
            template_file (str): 模板文件路径
            
        Returns:
            bool: 创建成功返回True
        """
        try:
            template_config = copy.deepcopy(self.default_config)
            
            # 添加注释说明
            template_config['_comments'] = {
                'logging': '日志配置',
                'network': '网络配置',
                'attack': '攻击模块配置',
                'security': '安全配置',
                'output': '输出配置',
                'performance': '性能配置',
                'dictionaries': '字典文件配置'
            }
            
            template_path = Path(template_file)
            template_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(template_path, 'w', encoding='utf-8') as f:
                json.dump(template_config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"配置模板已创建: {template_file}")
            return True
            
        except Exception as e:
            logger.error(f"创建配置模板失败: {e}")
            return False

# 全局配置管理器实例
_global_config_manager = None

def get_config_manager(config_file: str = None) -> ConfigManager:
    """
    获取全局配置管理器
    
    Args:
        config_file (str): 配置文件路径
        
    Returns:
        ConfigManager: 配置管理器实例
    """
    global _global_config_manager
    if _global_config_manager is None:
        _global_config_manager = ConfigManager(config_file)
    return _global_config_manager

def get_config(key: str, default: Any = None) -> Any:
    """
    获取配置值的便捷函数
    
    Args:
        key (str): 配置键
        default: 默认值
        
    Returns:
        Any: 配置值
    """
    return get_config_manager().get(key, default)

def set_config(key: str, value: Any) -> bool:
    """
    设置配置值的便捷函数
    
    Args:
        key (str): 配置键
        value: 配置值
        
    Returns:
        bool: 设置成功返回True
    """
    return get_config_manager().set(key, value)

def reload_config() -> bool:
    """
    重新加载配置的便捷函数
    
    Returns:
        bool: 重新加载成功返回True
    """
    return get_config_manager().reload_config()