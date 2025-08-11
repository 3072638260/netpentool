#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 文件工具模块

提供文件操作相关的实用工具函数，包括：
- 文件读写操作
- 目录管理
- 文件搜索
- 文件压缩
- 文件加密
- 临时文件管理
- 文件监控

作者: Security Researcher
版本: 1.0.0
"""

import os
import sys
import shutil
import tempfile
import hashlib
import zipfile
import tarfile
import json
import csv
from pathlib import Path
from typing import List, Optional, Dict, Any, Union, Generator
from datetime import datetime

try:
    from loguru import logger
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install loguru")
    sys.exit(1)

class FileUtils:
    """
    文件工具类
    
    提供各种文件操作的实用功能。
    """
    
    @staticmethod
    def ensure_directory(directory: Union[str, Path]) -> bool:
        """
        确保目录存在，如果不存在则创建
        
        Args:
            directory (str|Path): 目录路径
            
        Returns:
            bool: 创建成功返回True
        """
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"创建目录失败 {directory}: {e}")
            return False
    
    @staticmethod
    def read_file(file_path: Union[str, Path], encoding: str = 'utf-8') -> Optional[str]:
        """
        读取文件内容
        
        Args:
            file_path (str|Path): 文件路径
            encoding (str): 文件编码
            
        Returns:
            str: 文件内容，失败返回None
        """
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return None
    
    @staticmethod
    def write_file(file_path: Union[str, Path], content: str, 
                   encoding: str = 'utf-8', append: bool = False) -> bool:
        """
        写入文件内容
        
        Args:
            file_path (str|Path): 文件路径
            content (str): 文件内容
            encoding (str): 文件编码
            append (bool): 是否追加模式
            
        Returns:
            bool: 写入成功返回True
        """
        try:
            # 确保目录存在
            FileUtils.ensure_directory(Path(file_path).parent)
            
            mode = 'a' if append else 'w'
            with open(file_path, mode, encoding=encoding) as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")
            return False
    
    @staticmethod
    def read_lines(file_path: Union[str, Path], encoding: str = 'utf-8', 
                   strip_whitespace: bool = True) -> List[str]:
        """
        按行读取文件内容
        
        Args:
            file_path (str|Path): 文件路径
            encoding (str): 文件编码
            strip_whitespace (bool): 是否去除空白字符
            
        Returns:
            list: 文件行列表
        """
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                lines = f.readlines()
                if strip_whitespace:
                    lines = [line.strip() for line in lines if line.strip()]
                return lines
        except Exception as e:
            logger.error(f"按行读取文件失败 {file_path}: {e}")
            return []
    
    @staticmethod
    def write_lines(file_path: Union[str, Path], lines: List[str], 
                    encoding: str = 'utf-8', append: bool = False) -> bool:
        """
        按行写入文件内容
        
        Args:
            file_path (str|Path): 文件路径
            lines (list): 行列表
            encoding (str): 文件编码
            append (bool): 是否追加模式
            
        Returns:
            bool: 写入成功返回True
        """
        try:
            # 确保目录存在
            FileUtils.ensure_directory(Path(file_path).parent)
            
            mode = 'a' if append else 'w'
            with open(file_path, mode, encoding=encoding) as f:
                for line in lines:
                    f.write(line + '\n')
            return True
        except Exception as e:
            logger.error(f"按行写入文件失败 {file_path}: {e}")
            return False
    
    @staticmethod
    def read_json(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """
        读取JSON文件
        
        Args:
            file_path (str|Path): 文件路径
            
        Returns:
            dict: JSON数据，失败返回None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"读取JSON文件失败 {file_path}: {e}")
            return None
    
    @staticmethod
    def write_json(file_path: Union[str, Path], data: Dict[str, Any], 
                   indent: int = 2) -> bool:
        """
        写入JSON文件
        
        Args:
            file_path (str|Path): 文件路径
            data (dict): JSON数据
            indent (int): 缩进空格数
            
        Returns:
            bool: 写入成功返回True
        """
        try:
            # 确保目录存在
            FileUtils.ensure_directory(Path(file_path).parent)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"写入JSON文件失败 {file_path}: {e}")
            return False
    
    @staticmethod
    def read_csv(file_path: Union[str, Path], delimiter: str = ',') -> List[Dict[str, str]]:
        """
        读取CSV文件
        
        Args:
            file_path (str|Path): 文件路径
            delimiter (str): 分隔符
            
        Returns:
            list: CSV数据列表
        """
        try:
            data = []
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    data.append(row)
            return data
        except Exception as e:
            logger.error(f"读取CSV文件失败 {file_path}: {e}")
            return []
    
    @staticmethod
    def write_csv(file_path: Union[str, Path], data: List[Dict[str, str]], 
                  delimiter: str = ',') -> bool:
        """
        写入CSV文件
        
        Args:
            file_path (str|Path): 文件路径
            data (list): CSV数据列表
            delimiter (str): 分隔符
            
        Returns:
            bool: 写入成功返回True
        """
        try:
            if not data:
                return True
            
            # 确保目录存在
            FileUtils.ensure_directory(Path(file_path).parent)
            
            fieldnames = data[0].keys()
            with open(file_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delimiter)
                writer.writeheader()
                writer.writerows(data)
            return True
        except Exception as e:
            logger.error(f"写入CSV文件失败 {file_path}: {e}")
            return False
    
    @staticmethod
    def copy_file(src: Union[str, Path], dst: Union[str, Path]) -> bool:
        """
        复制文件
        
        Args:
            src (str|Path): 源文件路径
            dst (str|Path): 目标文件路径
            
        Returns:
            bool: 复制成功返回True
        """
        try:
            # 确保目标目录存在
            FileUtils.ensure_directory(Path(dst).parent)
            
            shutil.copy2(src, dst)
            return True
        except Exception as e:
            logger.error(f"复制文件失败 {src} -> {dst}: {e}")
            return False
    
    @staticmethod
    def move_file(src: Union[str, Path], dst: Union[str, Path]) -> bool:
        """
        移动文件
        
        Args:
            src (str|Path): 源文件路径
            dst (str|Path): 目标文件路径
            
        Returns:
            bool: 移动成功返回True
        """
        try:
            # 确保目标目录存在
            FileUtils.ensure_directory(Path(dst).parent)
            
            shutil.move(src, dst)
            return True
        except Exception as e:
            logger.error(f"移动文件失败 {src} -> {dst}: {e}")
            return False
    
    @staticmethod
    def delete_file(file_path: Union[str, Path]) -> bool:
        """
        删除文件
        
        Args:
            file_path (str|Path): 文件路径
            
        Returns:
            bool: 删除成功返回True
        """
        try:
            Path(file_path).unlink()
            return True
        except Exception as e:
            logger.error(f"删除文件失败 {file_path}: {e}")
            return False
    
    @staticmethod
    def delete_directory(directory: Union[str, Path], force: bool = False) -> bool:
        """
        删除目录
        
        Args:
            directory (str|Path): 目录路径
            force (bool): 是否强制删除非空目录
            
        Returns:
            bool: 删除成功返回True
        """
        try:
            dir_path = Path(directory)
            if force:
                shutil.rmtree(dir_path)
            else:
                dir_path.rmdir()  # 只删除空目录
            return True
        except Exception as e:
            logger.error(f"删除目录失败 {directory}: {e}")
            return False
    
    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """
        获取文件大小
        
        Args:
            file_path (str|Path): 文件路径
            
        Returns:
            int: 文件大小（字节），失败返回-1
        """
        try:
            return Path(file_path).stat().st_size
        except Exception as e:
            logger.error(f"获取文件大小失败 {file_path}: {e}")
            return -1
    
    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = 'md5') -> Optional[str]:
        """
        计算文件哈希值
        
        Args:
            file_path (str|Path): 文件路径
            algorithm (str): 哈希算法 (md5, sha1, sha256)
            
        Returns:
            str: 文件哈希值，失败返回None
        """
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"计算文件哈希失败 {file_path}: {e}")
            return None
    
    @staticmethod
    def find_files(directory: Union[str, Path], pattern: str = '*', 
                   recursive: bool = True) -> List[Path]:
        """
        查找文件
        
        Args:
            directory (str|Path): 搜索目录
            pattern (str): 文件模式
            recursive (bool): 是否递归搜索
            
        Returns:
            list: 匹配的文件路径列表
        """
        try:
            dir_path = Path(directory)
            if recursive:
                return list(dir_path.rglob(pattern))
            else:
                return list(dir_path.glob(pattern))
        except Exception as e:
            logger.error(f"查找文件失败 {directory}: {e}")
            return []
    
    @staticmethod
    def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        获取文件信息
        
        Args:
            file_path (str|Path): 文件路径
            
        Returns:
            dict: 文件信息字典
        """
        try:
            path = Path(file_path)
            stat = path.stat()
            
            return {
                'name': path.name,
                'path': str(path.absolute()),
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.fromtimestamp(stat.st_atime),
                'is_file': path.is_file(),
                'is_directory': path.is_dir(),
                'extension': path.suffix,
                'parent': str(path.parent)
            }
        except Exception as e:
            logger.error(f"获取文件信息失败 {file_path}: {e}")
            return {}
    
    @staticmethod
    def create_zip_archive(archive_path: Union[str, Path], 
                          files: List[Union[str, Path]]) -> bool:
        """
        创建ZIP压缩包
        
        Args:
            archive_path (str|Path): 压缩包路径
            files (list): 要压缩的文件列表
            
        Returns:
            bool: 创建成功返回True
        """
        try:
            # 确保目录存在
            FileUtils.ensure_directory(Path(archive_path).parent)
            
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in files:
                    path = Path(file_path)
                    if path.exists():
                        if path.is_file():
                            zipf.write(path, path.name)
                        elif path.is_dir():
                            for file in path.rglob('*'):
                                if file.is_file():
                                    zipf.write(file, file.relative_to(path.parent))
            return True
        except Exception as e:
            logger.error(f"创建ZIP压缩包失败 {archive_path}: {e}")
            return False
    
    @staticmethod
    def extract_zip_archive(archive_path: Union[str, Path], 
                           extract_to: Union[str, Path]) -> bool:
        """
        解压ZIP压缩包
        
        Args:
            archive_path (str|Path): 压缩包路径
            extract_to (str|Path): 解压目录
            
        Returns:
            bool: 解压成功返回True
        """
        try:
            # 确保目录存在
            FileUtils.ensure_directory(extract_to)
            
            with zipfile.ZipFile(archive_path, 'r') as zipf:
                zipf.extractall(extract_to)
            return True
        except Exception as e:
            logger.error(f"解压ZIP压缩包失败 {archive_path}: {e}")
            return False
    
    @staticmethod
    def create_temp_file(suffix: str = '', prefix: str = 'traes_', 
                        directory: str = None) -> str:
        """
        创建临时文件
        
        Args:
            suffix (str): 文件后缀
            prefix (str): 文件前缀
            directory (str): 临时目录
            
        Returns:
            str: 临时文件路径
        """
        try:
            fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=directory)
            os.close(fd)  # 关闭文件描述符
            return temp_path
        except Exception as e:
            logger.error(f"创建临时文件失败: {e}")
            return ''
    
    @staticmethod
    def create_temp_directory(suffix: str = '', prefix: str = 'traes_', 
                             directory: str = None) -> str:
        """
        创建临时目录
        
        Args:
            suffix (str): 目录后缀
            prefix (str): 目录前缀
            directory (str): 父目录
            
        Returns:
            str: 临时目录路径
        """
        try:
            return tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=directory)
        except Exception as e:
            logger.error(f"创建临时目录失败: {e}")
            return ''
    
    @staticmethod
    def clean_temp_files(pattern: str = 'traes_*') -> int:
        """
        清理临时文件
        
        Args:
            pattern (str): 文件模式
            
        Returns:
            int: 清理的文件数量
        """
        try:
            temp_dir = Path(tempfile.gettempdir())
            temp_files = list(temp_dir.glob(pattern))
            
            cleaned_count = 0
            for temp_file in temp_files:
                try:
                    if temp_file.is_file():
                        temp_file.unlink()
                        cleaned_count += 1
                    elif temp_file.is_dir():
                        shutil.rmtree(temp_file)
                        cleaned_count += 1
                except Exception:
                    continue
            
            logger.info(f"清理了 {cleaned_count} 个临时文件")
            return cleaned_count
        except Exception as e:
            logger.error(f"清理临时文件失败: {e}")
            return 0
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """
        格式化文件大小
        
        Args:
            size_bytes (int): 文件大小（字节）
            
        Returns:
            str: 格式化后的文件大小
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        size = float(size_bytes)
        
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        
        return f"{size:.1f} {size_names[i]}"
    
    @staticmethod
    def backup_file(file_path: Union[str, Path], backup_dir: str = None) -> Optional[str]:
        """
        备份文件
        
        Args:
            file_path (str|Path): 文件路径
            backup_dir (str): 备份目录
            
        Returns:
            str: 备份文件路径，失败返回None
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            if backup_dir is None:
                backup_dir = path.parent / 'backup'
            
            FileUtils.ensure_directory(backup_dir)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{path.stem}_{timestamp}{path.suffix}"
            backup_path = Path(backup_dir) / backup_name
            
            if FileUtils.copy_file(path, backup_path):
                logger.info(f"文件已备份: {backup_path}")
                return str(backup_path)
            
            return None
        except Exception as e:
            logger.error(f"备份文件失败 {file_path}: {e}")
            return None
    
    @staticmethod
    def rotate_log_files(log_file: Union[str, Path], max_files: int = 5) -> bool:
        """
        轮转日志文件
        
        Args:
            log_file (str|Path): 日志文件路径
            max_files (int): 最大保留文件数
            
        Returns:
            bool: 轮转成功返回True
        """
        try:
            path = Path(log_file)
            if not path.exists():
                return True
            
            # 删除最旧的文件
            oldest_file = path.with_suffix(f"{path.suffix}.{max_files}")
            if oldest_file.exists():
                oldest_file.unlink()
            
            # 轮转现有文件
            for i in range(max_files - 1, 0, -1):
                old_file = path.with_suffix(f"{path.suffix}.{i}")
                new_file = path.with_suffix(f"{path.suffix}.{i + 1}")
                if old_file.exists():
                    old_file.rename(new_file)
            
            # 轮转当前文件
            if path.exists():
                rotated_file = path.with_suffix(f"{path.suffix}.1")
                path.rename(rotated_file)
            
            return True
        except Exception as e:
            logger.error(f"轮转日志文件失败 {log_file}: {e}")
            return False

# 便捷函数
def read_wordlist(file_path: Union[str, Path]) -> List[str]:
    """
    读取字典文件
    
    Args:
        file_path (str|Path): 字典文件路径
        
    Returns:
        list: 字典内容列表
    """
    return FileUtils.read_lines(file_path, strip_whitespace=True)

def save_results(results: List[Dict[str, Any]], output_file: str, 
                format_type: str = 'json') -> bool:
    """
    保存结果到文件
    
    Args:
        results (list): 结果列表
        output_file (str): 输出文件路径
        format_type (str): 输出格式 (json/csv)
        
    Returns:
        bool: 保存成功返回True
    """
    try:
        if format_type.lower() == 'csv':
            return FileUtils.write_csv(output_file, results)
        else:
            return FileUtils.write_json(output_file, {'results': results})
    except Exception as e:
        logger.error(f"保存结果失败: {e}")
        return False

def load_config_file(config_file: str) -> Dict[str, Any]:
    """
    加载配置文件
    
    Args:
        config_file (str): 配置文件路径
        
    Returns:
        dict: 配置数据
    """
    config = FileUtils.read_json(config_file)
    return config if config else {}

def ensure_output_directory(output_file: str) -> bool:
    """
    确保输出目录存在
    
    Args:
        output_file (str): 输出文件路径
        
    Returns:
        bool: 创建成功返回True
    """
    return FileUtils.ensure_directory(Path(output_file).parent)