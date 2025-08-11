# TRAES - 网络渗透测试工具集

## 项目简介
TRAES (Tactical Reconnaissance and Attack Exploitation Suite) 是一个专业的网络渗透测试工具集，专注于网络层攻击和安全评估。

## 核心功能

### 🎯 网络层攻击
- **ARP欺骗攻击**：支持单目标和多目标ARP欺骗
- **DHCP攻击**：DHCP饥饿攻击和恶意DHCP服务器
- **网络嗅探**：数据包捕获和分析

### 🔐 认证测试
- **密码爆破**：支持多种协议的暴力破解
- **字典攻击**：内置常用密码字典
- **哈希破解**：支持多种哈希算法

### 🛡️ 安全控制
- **白名单机制**：保护关键设备免受攻击
- **攻击限制**：可配置的攻击强度和频率
- **日志记录**：详细的操作日志和审计跟踪

## 项目结构
```
traes/
├── src/
│   ├── core/
│   │   ├── arp.py          # ARP攻击模块
│   │   ├── dhcp.py         # DHCP攻击模块
│   │   └── bruteforce.py   # 暴力破解模块
│   ├── utils/
│   │   ├── network.py      # 网络工具函数
│   │   ├── logger.py       # 日志管理
│   │   └── config.py       # 配置管理
│   └── __init__.py
├── config/
│   └── config.json         # 主配置文件
├── logs/                   # 日志目录
├── data/                   # 数据文件目录
├── requirements.txt        # 依赖包列表
└── main.py                # 主程序入口
```

## 环境要求
- Python 3.7+
- Windows/Linux/macOS
- 管理员权限（用于网络操作）

## 快速开始

### 安装依赖
```bash
pip install -r requirements.txt
```

### 基本使用
```bash
# ARP欺骗攻击
python main.py --mode arp --target 192.168.1.100 --gateway 192.168.1.1

# DHCP饥饿攻击
python main.py --mode dhcp --interface eth0

# 密码爆破
python main.py --mode bruteforce --target 192.168.1.100 --service ssh
```

## 配置说明

主配置文件位于 `config/config.json`，包含以下主要配置项：

- `logging`: 日志配置
- `network`: 网络接口配置
- `attack`: 攻击参数配置
- `security`: 安全控制配置

## 法律声明

⚠️ **重要提醒**：
- 本工具仅用于授权的网络安全测试和教育目的
- 使用者必须确保在合法授权的环境中使用
- 禁止用于任何非法活动或未授权的网络攻击
- 使用者需承担使用本工具的所有法律责任

## 贡献指南

欢迎提交Issue和Pull Request来改进项目。

## 许可证

MIT License - 详见 LICENSE 文件