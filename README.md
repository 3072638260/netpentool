# TRAES 网络渗透测试工具集

一个专业的网络渗透测试工具集，提供ARP攻击、网络扫描、DHCP攻击等功能。

## 🚀 主要功能

### 核心攻击模块
- **ARP欺骗攻击**: 支持单目标和批量攻击，具备智能MAC地址获取功能
- **DHCP攻击**: DHCP饥饿攻击和欺骗攻击
- **网络扫描**: 端口扫描、服务识别、存活主机发现

### 增强特性
- **智能MAC地址获取**: 多层次获取策略，成功率高达88.2%
- **批量攻击模式**: 支持从文件批量导入目标进行攻击
- **跨平台支持**: 兼容Windows、Linux、macOS
- **详细日志记录**: 支持多级别日志输出和文件保存
- **白名单保护**: 防止误攻击关键设备

## 📦 安装

### 自动安装（推荐）
```bash
python install.py
```

### 手动安装
```bash
# 克隆仓库
git clone https://github.com/3072638260/netpentool.git
cd netpentool

# 安装依赖
pip install -r requirements.txt
```

## 🎯 基本使用

### ARP攻击
```bash
# 单目标攻击
python main.py arp --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0

# 批量攻击
python main.py arp --batch ip.txt --gateway 192.168.1.1 --interface eth0

# 详细模式
python main.py arp --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0 --verbose
```

### 批量攻击模式
```bash
# 使用专用批量攻击脚本
python batch_attack.py --gateway 192.168.1.1 --interface eth0 --verbose

# 指定目标文件
python batch_attack.py --file targets.txt --gateway 192.168.1.1 --interface eth0
```

### MAC地址获取测试
```bash
# 测试单个IP
python test_mac_detection.py --target 192.168.1.1 --interface eth0

# 批量测试
python test_mac_detection.py --batch ip.txt --interface eth0

# 详细日志模式
python test_mac_detection.py --target 192.168.1.1 --interface eth0 --verbose
```

### MAC地址获取功能改进

本项目针对MAC地址获取难题进行了重大改进：

#### 🔧 问题解决
- **原问题**: MAC地址获取失败率高，导致ARP攻击无法执行
- **解决方案**: 实现多层次MAC地址获取策略

#### ✨ 改进特性
- **多重获取策略**: 本地ARP表查询 → Ping预热 → 增强ARP请求 → 二次ARP表检查
- **跨平台支持**: 兼容Windows、Linux、macOS的ARP表查询
- **性能优化**: 智能缓存和超时控制
- **智能重试**: 多次尝试机制，提高成功率
- **详细日志**: 完整的获取过程记录和错误诊断

#### 📊 测试结果
- **单个IP测试**: 成功获取网关MAC地址，耗时0.05秒
- **批量测试**: 17个目标中15个成功，成功率88.2%
- **平均耗时**: 每个目标3.66秒

详细改进报告请参考: [MAC_DETECTION_IMPROVEMENTS.md](MAC_DETECTION_IMPROVEMENTS.md)

### 网络扫描
```bash
# 端口扫描
python main.py scan --target 192.168.1.100 --ports 1-1000

# 存活主机发现
python main.py scan --network 192.168.1.0/24 --ping-sweep
```

### DHCP攻击
```bash
# DHCP饥饿攻击
python main.py dhcp --interface eth0 --attack-type starvation

# DHCP欺骗攻击
python main.py dhcp --interface eth0 --attack-type spoofing --fake-server 192.168.1.200
```

## 📁 项目结构

```
netpentool/
├── README.md                          # 项目说明文档
├── requirements.txt                    # Python依赖包
├── install.py                         # 自动安装脚本
├── main.py                            # 主程序入口
├── batch_attack.py                    # 批量攻击专用脚本
├── test_mac_detection.py              # MAC地址获取测试工具
├── examples.py                        # 使用示例
├── examples_batch.py                  # 批量攻击示例
├── ip.txt                             # 目标IP列表文件
├── MAC_DETECTION_IMPROVEMENTS.md      # MAC地址获取改进报告
├── config/
│   └── config.json                    # 配置文件
├── src/
│   ├── core/
│   │   ├── arp.py                     # ARP攻击模块（增强MAC地址获取）
│   │   ├── dhcp.py                    # DHCP攻击模块
│   │   └── scanner.py                 # 网络扫描模块
│   └── utils/
│       ├── logger.py                  # 日志工具
│       ├── network_utils.py           # 网络工具
│       ├── config_manager.py          # 配置管理
│       ├── file_utils.py              # 文件工具
│       ├── crypto_utils.py            # 加密工具
│       └── system_utils.py            # 系统工具
└── logs/                              # 日志文件目录
```

## ⚙️ 配置

### 配置文件 (config/config.json)
```json
{
    "default_interface": "eth0",
    "default_timeout": 30,
    "max_threads": 50,
    "log_level": "INFO",
    "whitelist": [
        "192.168.1.1",
        "192.168.1.254"
    ]
}
```

### 环境变量
```bash
export TRAES_INTERFACE=eth0
export TRAES_LOG_LEVEL=DEBUG
```

## 🔧 高级功能

### 批量攻击模式

本工具支持强大的批量攻击功能，具备以下特性：

#### 📋 目标管理
- **文件导入**: 支持从文本文件批量导入目标IP
- **格式灵活**: 支持IP地址、IP段、CIDR格式
- **自动验证**: 自动验证IP格式和可达性

#### 🎯 攻击策略
- **并发控制**: 可配置并发攻击数量，避免网络拥塞
- **白名单保护**: 自动跳过白名单中的关键设备
- **智能重试**: 失败目标自动重试机制

#### 🔍 增强MAC地址获取
批量攻击模式集成了增强的MAC地址获取功能：
- **多层次获取策略**: 本地ARP表查询、Ping预热、增强ARP请求
- **跨平台兼容**: 支持Windows、Linux、macOS
- **智能缓存**: 避免重复查询，提高效率

#### 📊 实时监控
- **进度显示**: 实时显示攻击进度和成功率
- **详细日志**: 记录每个目标的攻击结果
- **统计报告**: 生成攻击统计和成功率报告

### 白名单配置
```json
{
    "whitelist": [
        "192.168.1.1",      // 网关
        "192.168.1.254",    // 备用网关
        "192.168.1.10"      // DNS服务器
    ]
}
```

### 日志配置
```json
{
    "logging": {
        "level": "INFO",
        "file": "logs/traes.log",
        "max_size": "10MB",
        "backup_count": 5
    }
}
```

## 🛡️ 安全注意事项

⚠️ **重要提醒**: 本工具仅用于授权的渗透测试和安全研究

### 使用前必读
1. **获得授权**: 确保已获得目标网络所有者的明确书面授权
2. **合法使用**: 遵守当地法律法规，不得用于非法活动
3. **测试环境**: 建议在隔离的测试环境中使用
4. **备份数据**: 攻击前备份重要数据和配置

### 最佳实践
- 使用白名单保护关键设备
- 设置合理的攻击间隔，避免网络拥塞
- 及时停止攻击并恢复网络状态
- 详细记录测试过程和结果

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目！

### 开发指南
1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🔗 相关链接

- [项目主页](https://github.com/3072638260/netpentool)
- [问题反馈](https://github.com/3072638260/netpentool/issues)
- [更新日志](CHANGELOG.md)

## 📞 联系方式

- 作者: Sukalis
- 邮箱: 3072638260@qq.com
- GitHub: [@3072638260](https://github.com/3072638260)

---

**免责声明**: 本工具仅供教育和授权测试使用。使用者需对其行为负责，开发者不承担任何法律责任。