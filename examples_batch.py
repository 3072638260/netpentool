#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 批量攻击使用示例
演示如何使用批量攻击功能从ip.txt文件攻击多个目标

作者: Security Researcher
版本: 1.0.0
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def print_banner():
    """
    打印示例程序横幅
    """
    print("\n" + "="*60)
    print("    TRAES 批量攻击功能使用示例")
    print("    Batch Attack Examples")
    print("="*60)

def check_requirements():
    """
    检查运行环境和必要文件
    
    Returns:
        bool: 环境检查是否通过
    """
    print("\n[1] 检查运行环境...")
    
    # 检查Python版本
    if sys.version_info < (3, 7):
        print("❌ Python版本过低，需要Python 3.7+")
        return False
    print("✅ Python版本检查通过")
    
    # 检查必要文件
    required_files = [
        'main.py',
        'batch_attack.py',
        'ip.txt',
        'src/core/arp.py',
        'config/config.json'
    ]
    
    for file_path in required_files:
        if not os.path.exists(file_path):
            print(f"❌ 缺少必要文件: {file_path}")
            return False
    print("✅ 必要文件检查通过")
    
    return True

def show_ip_file_content():
    """
    显示ip.txt文件内容
    """
    print("\n[2] 当前ip.txt文件内容:")
    try:
        with open('ip.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    print(f"    {i}. {line}")
                elif line.startswith('#'):
                    print(f"    {i}. {line} (注释)")
    except FileNotFoundError:
        print("❌ ip.txt文件不存在")
        return False
    except Exception as e:
        print(f"❌ 读取ip.txt文件出错: {e}")
        return False
    
    return True

def create_sample_ip_file():
    """
    创建示例ip.txt文件
    """
    print("\n[3] 创建示例ip.txt文件...")
    
    sample_ips = [
        "# TRAES 批量攻击目标IP列表",
        "# 请根据实际测试环境修改以下IP地址",
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "# 192.168.1.103  # 这是被注释的IP",
        "192.168.1.104"
    ]
    
    try:
        with open('ip.txt', 'w', encoding='utf-8') as f:
            for ip in sample_ips:
                f.write(ip + '\n')
        print("✅ 示例ip.txt文件创建成功")
        return True
    except Exception as e:
        print(f"❌ 创建示例文件失败: {e}")
        return False

def show_usage_examples():
    """
    显示使用示例
    """
    print("\n[4] 批量攻击使用示例:")
    
    examples = [
        {
            "title": "方法1: 使用main.py的batch模式",
            "command": "python main.py --mode batch --gateway 192.168.1.1",
            "description": "自动使用ip.txt文件进行批量攻击"
        },
        {
            "title": "方法2: 使用专用批量攻击脚本（推荐）",
            "command": "python batch_attack.py --gateway 192.168.1.1",
            "description": "使用专门的批量攻击脚本，功能更完整"
        },
        {
            "title": "方法3: 指定自定义目标文件",
            "command": "python batch_attack.py --gateway 192.168.1.1 --target-file custom_ips.txt",
            "description": "使用自定义的目标IP文件"
        },
        {
            "title": "方法4: 详细输出模式",
            "command": "python batch_attack.py --gateway 192.168.1.1 --verbose",
            "description": "启用详细日志输出，便于调试"
        },
        {
            "title": "方法5: 指定网络接口",
            "command": "python batch_attack.py --gateway 192.168.1.1 --interface eth0",
            "description": "指定特定的网络接口进行攻击"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n  {i}. {example['title']}")
        print(f"     命令: {example['command']}")
        print(f"     说明: {example['description']}")

def show_advanced_options():
    """
    显示高级选项
    """
    print("\n[5] 高级选项说明:")
    
    options = [
        {
            "option": "--spoof-mac",
            "description": "指定伪造的MAC地址",
            "example": "--spoof-mac 00:11:22:33:44:55"
        },
        {
            "option": "--interval",
            "description": "设置ARP包发送间隔（秒）",
            "example": "--interval 0.5"
        },
        {
            "option": "--threads",
            "description": "设置并发线程数",
            "example": "--threads 10"
        },
        {
            "option": "--log-file",
            "description": "指定日志文件路径",
            "example": "--log-file logs/batch_attack.log"
        }
    ]
    
    for option in options:
        print(f"\n  {option['option']}")
        print(f"    说明: {option['description']}")
        print(f"    示例: {option['example']}")

def show_safety_warnings():
    """
    显示安全警告
    """
    print("\n[6] ⚠️  安全警告和注意事项:")
    
    warnings = [
        "本工具仅用于授权的安全测试环境",
        "使用前请确保已获得网络管理员的明确授权",
        "请在隔离的测试环境中使用，避免影响生产网络",
        "攻击过程中可能会中断目标设备的网络连接",
        "使用Ctrl+C可以随时停止攻击",
        "建议先在虚拟环境中测试功能",
        "请遵守当地法律法规，禁止用于非法用途"
    ]
    
    for i, warning in enumerate(warnings, 1):
        print(f"  {i}. {warning}")

def interactive_demo():
    """
    交互式演示
    """
    print("\n[7] 交互式演示:")
    
    while True:
        print("\n请选择要演示的功能:")
        print("  1. 查看帮助信息")
        print("  2. 验证目标文件")
        print("  3. 模拟批量攻击（仅显示命令，不实际执行）")
        print("  4. 退出演示")
        
        try:
            choice = input("\n请输入选项 (1-4): ").strip()
            
            if choice == '1':
                print("\n执行: python batch_attack.py --help")
                try:
                    result = subprocess.run([sys.executable, 'batch_attack.py', '--help'], 
                                          capture_output=True, text=True, timeout=10)
                    print(result.stdout)
                except Exception as e:
                    print(f"执行失败: {e}")
                    
            elif choice == '2':
                print("\n验证ip.txt文件...")
                if show_ip_file_content():
                    print("✅ 目标文件验证通过")
                else:
                    print("❌ 目标文件验证失败")
                    
            elif choice == '3':
                gateway = input("请输入网关IP地址 (例: 192.168.1.1): ").strip()
                if gateway:
                    command = f"python batch_attack.py --gateway {gateway}"
                    print(f"\n模拟执行命令: {command}")
                    print("注意: 这只是演示，没有实际执行攻击")
                    print("实际使用时请确保在授权的测试环境中运行")
                else:
                    print("❌ 请输入有效的网关IP地址")
                    
            elif choice == '4':
                print("\n退出演示")
                break
                
            else:
                print("❌ 无效选项，请输入1-4")
                
        except KeyboardInterrupt:
            print("\n\n用户中断演示")
            break
        except Exception as e:
            print(f"\n❌ 演示过程中出错: {e}")

def main():
    """
    主函数
    """
    print_banner()
    
    # 检查运行环境
    if not check_requirements():
        print("\n❌ 环境检查失败，请检查安装和文件完整性")
        return
    
    # 显示ip.txt内容，如果不存在则创建示例文件
    if not show_ip_file_content():
        create_sample_ip_file()
        show_ip_file_content()
    
    # 显示使用示例
    show_usage_examples()
    
    # 显示高级选项
    show_advanced_options()
    
    # 显示安全警告
    show_safety_warnings()
    
    # 交互式演示
    try:
        interactive_demo()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    
    print("\n" + "="*60)
    print("感谢使用TRAES批量攻击功能演示！")
    print("请在授权的测试环境中安全使用本工具。")
    print("="*60)

if __name__ == '__main__':
    main()