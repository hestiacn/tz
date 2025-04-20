# PHP Server Probe System

## [中文说明](./zh.md)

[![Gurubase](https://hestiamb.org/tben.webp)](https://codeberg.org/hestiacn/tz/raw/commit/b593404acfb7b58de3c9b492a03983190daa42a2/en.webp)

- Server System Description: This site demonstrates the use of [hestiacp](https://hestiacp.com)Server open source management panel.
- A professional server status monitoring and analysis tool, providing system administrators and developers with visual web-based browsing!
- For a more complete experience! This file requires root permissions! If your website directory does not support it, some functions may not be displayed! However, it does not affect the overall browsing experience!
- It can intuitively display key metrics such as CPU, memory, disk usage, and network traffic, just like installing a "health monitor" for your server.

## Features

### 🚀 Core Monitoring

- Real-time CPU usage and core temperature
- Memory usage and swap space analysis
- Disk I/O and storage space visualization
- Real-time network traffic monitoring (supports multiple network cards)

### 🔒 Security Enhancement

- Dual protection mechanism against CSRF
- Request frequency limitation (1 time/second)
- Secure HTTP header configuration
- Extended risk assessment system

### 📊 In-depth Analysis

- PHP extension dependency relationship mapping
- Database installation detection (MySQL/PostgreSQL/Redis, etc.)
- Dynamic system load trend chart (20s)

### 🌐 PHP Version Support

- Default runs on 7.0-8.4!
- Best experience recommended on 8.0-8.4!

### IP Location

Only approximate location is displayed! No IP information is collected, using information extracted from https://ipapi.co !

## Quick Deployment

- You can use the following command to download it to the server's `/var/www/html` directory. After completion, you can directly access the server `IP/random characters.php` to access the file!

```bash
curl -fsSL https://codeberg.org/hestiacn/tz/raw/branch/main/th.sh   | bash
```

- You can also download the `en.php` file to your server here
