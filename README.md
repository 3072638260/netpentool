# TRAES - 网络渗透测试工具集

## 项目简介

TRAES (Threat Reconnaissance and Attack Emulation System) 是一款基于 Python 开发的综合性网络渗透测试工具集，旨在帮助安全研究人员、渗透测试工程师和系统管理员进行网络安全评估、漏洞发现和攻击模拟。本工具集集成了多种攻击模块和实用工具，覆盖了从信息收集、漏洞扫描到攻击利用的多个阶段。

## 主要功能模块

### 1. ARP 攻击模块 (`src/core/arp.py`)
- **ARP 欺骗**：支持单目标、多目标和双向 ARP 欺骗，用于中间人攻击。
- **ARP 缓存投毒**：向目标发送伪造的 ARP 响应，修改其 ARP 缓存。
- **MAC 地址随机化**：在攻击过程中随机化攻击者的 MAC 地址，增加溯源难度。
- **ARP 表恢复**：在攻击结束后恢复受害者的 ARP 表，清理攻击痕迹。
- **白名单保护**：防止对特定 IP/MAC 地址进行攻击。

### 2. DHCP 攻击模块 (`src/core/dhcp.py`)
- **DHCP 饥饿攻击**：耗尽 DHCP 服务器的 IP 地址池，阻止新设备获取 IP。
- **DHCP 欺骗攻击**：模拟恶意 DHCP 服务器，向受害者分配虚假 IP 地址、网关和 DNS 服务器。
- **DHCP 发现扫描**：发现网络中的 DHCP 服务器。
- **DHCP 选项注入**：在 DHCP 响应中注入恶意选项，如强制使用恶意 DNS 服务器。

### 3. 密码爆破模块 (`src/core/bruteforce.py`)
- **多协议支持**：支持 SSH、FTP、Telnet、HTTP (基础认证/表单)、RDP、SMB、MySQL 等多种常见协议的密码爆破。
- **字典攻击**：通过加载预设的用户名和密码字典进行尝试。
- **多线程/协程**：提高爆破效率。
- **自定义字典**：支持用户自定义字典文件。
- **白名单/黑名单**：排除特定目标或凭证。

### 4. 网络扫描模块 (`src/core/scanner.py`)
- **端口扫描**：支持 TCP SYN、TCP Connect、UDP 扫描等多种模式。
- **服务识别**：识别开放端口上运行的服务及其版本。
- **操作系统指纹识别**：通过分析网络响应推断目标操作系统类型。
- **网络发现**：发现局域网内的存活主机。
- **子域名扫描**：通过多种方式（如字典、证书透明度）发现目标子域名。

### 5. 实用工具模块 (`src/utils/`)
- **网络工具 (`network_utils.py`)**：IP 地址操作、网络接口管理、MAC 地址操作、代理设置等。
- **日志管理 (`logger.py`)**：多级别日志记录、文件/控制台输出、日志轮转、彩色输出。
- **配置管理 (`config_manager.py`)**：JSON/YAML 配置文件读写、验证、热重载、加密。
- **文件工具 (`file_utils.py`)**：文件读写、目录管理、文件搜索、加密、哈希计算。
- **加密工具 (`crypto_utils.py`)**：对称/非对称加密、哈希、密码生成、数字签名。
- **系统工具 (`system_utils.py`)**：系统信息获取、进程管理、命令执行、权限检查。

## 安装与使用

### 环境要求
- Python 3.x
- 推荐在 Linux 或 macOS 环境下运行，部分功能在 Windows 上可能受限（如原始套接字操作）。

### 依赖安装
```bash
pip install -r requirements.txt
```

### 运行示例

#### 1. ARP 欺骗示例
```bash
python main.py arp --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0
```

#### 2. SSH 密码爆破示例
```bash
python main.py bruteforce ssh --host 192.168.1.50 --port 22 --users data/usernames.txt --passwords data/passwords.txt --threads 10
```

#### 3. 端口扫描示例
```bash
python main.py scanner port --target 192.168.1.0/24 --ports 22,80,443 --scan-type syn
```

## 项目结构

```
TRAES/
├── config/                 # 配置文件目录
│   └── config.json         # 主配置文件
├── data/                   # 数据文件目录（字典、payload等）
│   ├── passwords.txt       # 常用密码字典
│   └── usernames.txt      # 常用用户名字典
├── logs/                   # 日志文件目录
├── src/                    # 源代码目录
│   ├── __init__.py         # 项目初始化文件
│   ├── core/               # 核心攻击模块
│   │   ├── __init__.py
│   │   ├── arp.py          # ARP 攻击模块
│   │   ├── dhcp.py         # DHCP 攻击模块
│   │   ├── bruteforce.py   # 密码爆破模块
│   │   └── scanner.py      # 网络扫描模块
│   └── utils/              # 实用工具模块
│       ├── __init__.py
│       ├── network_utils.py    # 网络工具
│       ├── logger.py           # 日志管理
│       ├── config_manager.py   # 配置管理
│       ├── file_utils.py       # 文件工具
│       ├── crypto_utils.py     # 加密工具
│       └── system_utils.py     # 系统工具
├── main.py                 # 项目主入口文件
├── requirements.txt        # Python 依赖库列表
└── README.md               # 项目说明文档
```

## 贡献与支持

欢迎对本项目进行贡献，包括但不限于提交 Bug、提出新功能建议或提交 Pull Request。如果您在使用过程中遇到任何问题，请通过 Issue 提交。

## 许可证

本项目采用 MIT 许可证。详情请参阅 `LICENSE` 文件（如果存在）。

## 免责声明

本工具仅用于网络安全学习、研究和授权的渗透测试活动。严禁将本工具用于任何非法目的。使用者应对其行为负全部责任。作者不对任何滥用行为负责。