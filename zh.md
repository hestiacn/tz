# PHP 服务器探针系统

[![Gurubase](https://hestiamb.org/tbzh.webp)](https://codeberg.org/hestiacn/tz/raw/commit/b593404acfb7b58de3c9b492a03983190daa42a2/cn.webp)

- 服务器系统说明：本站演示使用的是[hestiacp](https://hestiacp.com)服务器开源管理面板。
- 专业的服务器状态监控与分析工具，为系统管理员和开发者提供可视化web在线浏览！
- 为了更完整的体验！此文件需要root权限！如果您的网站目录不支持则无法显示部分功能！但整体不影响浏览体验！
- 能直观显示CPU、内存、硬盘使用情况，网络流量等关键指标，就像给您的服务器装上"健康监测仪"。

## 功能特性

### 🚀 核心监控

- 实时 CPU 使用率与核心温度
- 内存使用率与交换空间分析
- 磁盘 I/O 与存储空间可视化
- 网络流量实时监控（支持多网卡）

### 🔒 安全增强

- CSRF 双重防护机制
- 请求频率限制（1次/秒）
- 安全HTTP头部配置
- 扩展风险等级评估系统

### 📊 深度分析

- PHP 扩展依赖关系图谱
- 数据库安装检测（MySQL/PostgreSQL/Redis等）
- 动态系统负载趋势图(20s)

### 🌐 PHP版本支持

- 默认7.0-8.4均可运行！
- 推荐8.0-8.4最佳体验！

### ip位置

仅显示大概位置！不收集任何IP信息，使用的是 https://myip.ipip.net 提取的相关信息！

## 快速部署

- 你可以使用以下命令将它下载到服务器的`/var/www/html`文件目录,完成后您直接访问服务器`IP/随机字符.php`即可访问该文件！

```bash
curl -fsSL https://codeberg.org/hestiacn/tz/raw/branch/main/tz.sh | bash
```

- 您也可以在此将`cn.php`文件下载到你的服务器
