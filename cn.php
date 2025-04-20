<?php
/**
 * PHP 8.4 + HTML5 + Bootstrap 5.3.3 探针系统
 * 版本: 2.2 (PHP 8.4)
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
ini_set("display_errors", "0");
ini_set("error_reporting", E_ALL);
ob_start();

// 安全设置
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Content-Type: text/html; charset=UTF-8");
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Expires: ' . gmdate('D, d M Y H:i:s', time()-3600) . ' GMT');
header("Permissions-Policy: geolocation=(), camera=(), microphone=()");

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 新增监控接口响应（保持与现有代码兼容）
if (isset($_GET['monitor'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-cache');
    
    try {
        // 频率限制（1秒1次）
        if (isset($_SESSION['last_monitor']) && (time() - $_SESSION['last_monitor'] < 1))
        $_SESSION['last_monitor'] = time();

        // 获取当前流量数据
        $current_traffic = get_network_traffic();
        $current_time = microtime(true);
        
        // 初始化会话数据
        if (!isset($_SESSION['network_traffic'])) {
            $_SESSION['network_traffic'] = $current_traffic;
            $_SESSION['last_traffic_time'] = $current_time;
        }

        $time_diff = $current_time - $_SESSION['last_traffic_time'];

        $traffic_data = [];
        foreach ($current_traffic as $interface => $data) {
            $prev_data = $_SESSION['network_traffic'][$interface] ?? ['receive' => 0, 'transmit' => 0];
            
            // 计算速率（字节/秒）
            $receive_rate = $time_diff > 0 ? 
                ($data['receive'] - $prev_data['receive']) / $time_diff : 0;
            $transmit_rate = $time_diff > 0 ? 
                ($data['transmit'] - $prev_data['transmit']) / $time_diff : 0;
            
            $traffic_data[$interface] = [
                'receive_rate' => $receive_rate,
                'transmit_rate' => $transmit_rate
            ];
        }

        // 更新会话数据
        $_SESSION['network_traffic'] = $current_traffic;
        $_SESSION['last_traffic_time'] = $current_time;

        // 获取监控数据
        $data = [
            'cpu' => get_cpu_usage() ?: ['usage' => 0, 'cores' => 0],
            'memory' => array_merge(['percent' => 0, 'used' => 0, 'total' => 0], get_memory_info() ?: []),
            'disk' => array_merge(['percent' => 0, 'used' => 0, 'total' => 0], (array)current(get_disk_usage())),
            'network' => $traffic_data
        ];

        // 格式化响应
        $response = [
            'cpu' => [
                'usage' => round(($data['cpu']['usage'] ?? 0), 1),
                'cores' => $data['cpu']['cores'] ?? 0
            ],
            'memory' => [
                'percent' => round(($data['memory']['percent'] ?? 0), 1),
                'used' => $data['memory']['used'] ?? 0
            ],
            'disk' => [
                'percent' => round(($data['disk']['percent'] ?? 0), 1)
            ],
            'network' => $data['network']
        ];

        die(json_encode($response));
    } catch (Exception $e) {
        http_response_code(500);
        die(json_encode(['error' => '服务器内部错误']));
    }
}

// phpInfo
if (isset($_GET['action']) && $_GET['action'] === 'phpInfo') {
    phpinfo();
    exit;
}

// 日志检测函数
function detect_log_files() {
    $isRoot = function_exists('posix_getuid') && (posix_getuid() === 0);
    
    $logDirs = [
        '/var/log',
        '/var/log/nginx',
        '/var/log/apache2',
        '/var/log/httpd',
        '/var/log/mysql',
        '/var/log/postgresql',
        '/var/log/php',
        '/var/log/syslog',
        '/var/log/auth.log',
        '/var/log/kern.log',
        '/var/log/dmesg',
        '/var/log/audit',
        '/var/log/ufw',
        '/var/log/journal',
        '/opt/lampp/logs',
        '/usr/local/nginx/logs',
        '/var/www/logs',
        '/usr/local/logs',
        '/home/*/logs',
    ];

    $detectedLogs = [];
    $errors = [];

    foreach ($logDirs as $dir) {
        try {
            // 处理通配符路径
            if (strpos($dir, '*') !== false) {
                $expandedDirs = glob($dir, GLOB_ONLYDIR);
                if (empty($expandedDirs)) continue;
                foreach ($expandedDirs as $expandedDir) {
                    process_directory($expandedDir, $detectedLogs, $errors, $isRoot);
                }
            } else {
                process_directory($dir, $detectedLogs, $errors, $isRoot);
            }
        } catch (Exception $e) {
            $errors[] = "目录处理异常: $dir (" . $e->getMessage() . ")";
        }
    }

    return [
        'logs' => $detectedLogs,
        'errors' => $errors,
        'timestamp' => date('Y-m-d H:i:s')
    ];
}

function process_directory($dir, &$detectedLogs, &$errors, $isRoot) {
    static $processedDirs = [];
    
    if (isset($processedDirs[$dir])) return;
    $processedDirs[$dir] = true;

    try {
        if (!@is_readable($dir)) {
            $errors[] = "目录不可读: $dir";
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        $iterator->setMaxDepth(2);

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;

            // 日志文件匹配逻辑
            $filename = $file->getFilename();
            $isLogFile = preg_match('/(?:^|\b)(\.log$|\.log\.\d+$|_log$|(?:error|access|fatal|debug|auth|syslog|mail|kern|secure))/ix', $filename);
            
            if (!$isLogFile && in_array($filename, ['messages', 'syslog', 'auth.log', 'daemon.log', 'kern.log', 'mail.log', 'user.log', 'cron.log'])) {
                $isLogFile = true;
            }

            if ($isLogFile) {
                $path = $file->getPathname();
                $size = $file->getSize();
                
                // 跳过空文件
                if ($size <= 0) continue;

                // 权限检查
                $isReadable = $isRoot ? true : $file->isReadable();
                
                // 获取详细信息
                clearstatcache(true, $path);
                $perms = $file->getPerms() & 0777;
			 $owner = '未知';
				if (function_exists('posix_getpwuid')) {
				   $userInfo = @posix_getpwuid($file->getOwner());
				   $owner = $userInfo['name'] ?? '未知';
				} else {
				   $owner = $file->getOwner();
				}
				
			 $group = '未知';
				if (function_exists('posix_getgrgid')) {
				   $groupInfo = @posix_getgrgid($file->getGroup());
				   $group = $groupInfo['name'] ?? '未知';
				} else {
				   $group = $file->getGroup();
				}
                $mtime = $file->getMTime() ? date('Y-m-d H:i:s', $file->getMTime()) : '未知时间';

                $detectedLogs[] = [
                    'path' => $path,
                    'size' => $size,
                    'modified' => $mtime,
                    'readable' => $isReadable,
                    'perms' => sprintf('%03o', $perms),
                    'owner' => $owner,
                    'group' => $group,
                    'status' => $isReadable ? '可读' : '权限不足',
                    'inode' => $file->getInode()
                ];
            }
        }
    } catch (Exception $e) {
        $errors[] = "目录访问失败: $dir (" . $e->getMessage() . ")";
    }
}

// 安全日志查看功能
if (isset($_GET['action']) && $_GET['action'] === 'view_log' && isset($_GET['path'])) {
    $logPath = urldecode($_GET['path']);
    $logFile = realpath($logPath);
    
    // 安全验证
    $allowedBases = [
        '/var/log',
        '/usr/local/logs',
        '/var/www/logs',
        '/opt/lampp/logs',
        '/usr/local/nginx/logs',
        '/var/log/nginx',
        '/var/log/apache2',
        '/var/log/httpd',
        '/var/log/mysql',
        '/var/log/postgresql'
    ];
    
    $isAllowed = false;
    foreach ($allowedBases as $base) {
        $basePath = realpath($base);
        if ($basePath && strpos($logFile, $basePath) === 0) {
            $isAllowed = true;
            break;
        }
    }
    
    if ($isAllowed && is_readable($logFile)) {
        header('Content-Type: text/plain');
        header('X-Content-Type-Options: nosniff');
        
        // 高效读取最后1000行
        $lines = [];
        $fp = fopen($logFile, 'r');
        if ($fp) {
            fseek($fp, -10240, SEEK_END); // 从文件末尾回退10KB开始读取
            while (!feof($fp) && count($lines) < 1000) {
                $lines[] = fgets($fp);
            }
            fclose($fp);
            
            // 显示最新内容在前
            echo implode('', array_reverse($lines));
        }
        exit;
    }
    
    header('HTTP/1.1 403 Forbidden');
    exit('<div class="alert alert-danger">无权访问该日志文件</div>');
}

// 公网IP获取
function get_enhanced_public_ip() {
    $public_ip = '未知';
    
    if (!empty($_SERVER['SERVER_ADDR']) && 
        filter_var($_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return $_SERVER['SERVER_ADDR'];
    }

    if (!empty($_SERVER['SERVER_NAME'])) {
        $dns_ip = @gethostbyname($_SERVER['SERVER_NAME']);
        if ($dns_ip && $dns_ip != $_SERVER['SERVER_NAME'] && 
            filter_var($dns_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $dns_ip;
        }
    }

    $hostname = php_uname('n');
    if ($hostname) {
        $system_ip = @gethostbyname($hostname);
        if ($system_ip && $system_ip != $hostname && 
            filter_var($system_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $system_ip;
        }
    }

    if (strpos(PHP_OS, 'Linux') !== false && function_exists('shell_exec')) {
        $commands = [
            'ip' => '/sbin/ip -o -4 addr show 2>/dev/null',
            'ifconfig' => '/sbin/ifconfig -a 2>/dev/null'
        ];

        $output = '';
        foreach ($commands as $cmd) {
            $output = @shell_exec($cmd);
            if ($output) break;
        }

        if ($output) {
            $lines = preg_split('/\r?\n/', trim($output));
            foreach ($lines as $line) {
                if (preg_match('/^(docker|lo|veth|br-|tunl)/', $line)) continue;

                if (preg_match('/inet\s+(\d+\.\d+\.\d+\.\d+)(\/|\s+)/', $line, $matches)) {
                    $candidate = $matches[1];
                    if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $candidate;
                    }
                }
            }
        }
    }

    $external_services = [
        'https://api.ipify.org',
        'https://checkip.amazonaws.com'
    ];
    
    foreach ($external_services as $url) {
        try {
            $ip = trim(@file_get_contents($url));
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        } catch (Exception $e) {
            continue;
        }
    }

    return $public_ip;
}

// 新增获取CPU型号的函数
function get_cpu_model() {
    $model = '未知';
    $cores = [];
    $details = [];
    $physicalCores = 0;
    $logicalCores = 0;
    $avgSpeed = '未知';

    if (is_readable('/proc/cpuinfo')) {
        $info = @file_get_contents('/proc/cpuinfo');
        if ($info !== false) {
            // 提取CPU型号
            preg_match_all('/^(model name|Hardware)\s+:\s+(.+)$/mi', $info, $matches);
            if (!empty($matches[2])) {
                foreach ($matches[2] as $m) {
                    $clean_model = trim(str_replace(['(R)', '(TM)', 'CPU', '@'], '', $m));
                    if (!in_array($clean_model, $cores)) {
                        $cores[] = $clean_model;
                    }
                }
            }

            // 提取物理核心数
            preg_match_all('/^cpu cores\s+:\s+(\d+)$/mi', $info, $coreMatches);
            $physicalCores = array_sum($coreMatches[1]) ?: '未知';

            // 提取逻辑核心数（线程数）
            preg_match_all('/^processor\s+:\s+\d+$/mi', $info, $procMatches);
            $logicalCores = count($procMatches[0]) ?: '未知';

            // 提取主频
            preg_match_all('/^cpu MHz\s+:\s+([\d.]+)$/mi', $info, $speedMatches);
            $avgSpeed = $speedMatches[1] ? round(array_sum($speedMatches[1]) / count($speedMatches[1])) : '未知';
        }
    }

    // 策略2: 通过 lscpu 命令检测
    if (empty($cores) && function_exists('shell_exec')) {
        $lscpu = @shell_exec(escapeshellcmd('lscpu 2>/dev/null'));
        if ($lscpu) {
            // 提取型号
            if (preg_match('/Model name:\s+(.+)/i', $lscpu, $match)) {
                $cores[] = trim(str_replace(['(R)', '(TM)'], '', $match[1]));
            }

            // 提取核心信息
            preg_match('/Socket$s$:\s+(\d+).*?Core$s$ per socket:\s+(\d+).*?Thread$s$ per core:\s+(\d+)/s', $lscpu, $coreData);
            if ($coreData) {
                $physicalCores = $coreData[1] * $coreData[2];
                $logicalCores = $physicalCores * $coreData[3];
            }

            // 提取缓存
            if (preg_match('/L3 cache:\s+([\d.]+ [KMG]?B)/i', $lscpu, $cacheMatch)) {
                $details[] = $cacheMatch[1] . '缓存';
            }

            // 提取主频
            if (preg_match('/CPU MHz:\s+([\d.]+)/i', $lscpu, $speedMatch)) {
                $avgSpeed = round($speedMatch[1] / 1000, 1) . 'GHz';
            }
        }
    }

    // 策略3: 通过 dmidecode 检测 
    if (empty($cores) && function_exists('shell_exec')) {
        $dmi = @shell_exec('dmidecode processor 2>/dev/null');
        if ($dmi && preg_match('/Version:\s+(.+)/i', $dmi, $match)) {
            $cores[] = trim($match[1]);
        }
    }

    // 策略4: 通过 Windows WMI
    if (empty($cores) && PHP_OS_FAMILY === 'Windows') {
        $output = @shell_exec('wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed /value');
        if (preg_match('/Name=(.+)\s+NumberOfCores=(\d+)\s+NumberOfLogicalProcessors=(\d+)\s+MaxClockSpeed=(\d+)/i', $output, $winMatches)) {
            $cores[] = trim($winMatches[1]);
            $physicalCores = $winMatches[2];
            $logicalCores = $winMatches[3];
            $avgSpeed = ($winMatches[4] ? round($winMatches[4]/1000,1) : '未知') . 'GHz';
        }
    }

    // 合并型号信息
    if (!empty($cores)) {
        $unique_models = array_unique($cores);
        $model = count($unique_models) > 1 ? 
            implode(' + ', $unique_models) : 
            preg_replace('/\s@\s.+$/', '', $unique_models[0]);
    }

    // 添加技术参数
    $specs = [];
    if ($physicalCores && $logicalCores) {
        $specs[] = "{$physicalCores}核/{$logicalCores}线程";
    }
    if (!empty($avgSpeed) && $avgSpeed !== '未知') {
        $specs[] = $avgSpeed;
    }
	if (!empty($details)) {
	    $specs = array_merge($specs, $details);
	}

    // 补充架构信息
    $arch = php_uname('m');
    $archText = '';
    if (strpos($arch, 'aarch64') !== false) {
        $archText = ' (ARM64)';
    } elseif (preg_match('/x86_64|amd64/i', $arch)) {
        $archText = ' (x86-64)';
    }

    // 最终组合
    $specs = [];
    if ($physicalCores && $logicalCores) {
        $specs[] = "{$physicalCores}核/{$logicalCores}线程";
    }
    if ($avgSpeed !== '未知') {
        $specs[] = $avgSpeed;
    }

    if (!empty($specs)) {
        $model .= sprintf(' [%s%s]', implode(', ', $specs), $archText);
    } else {
        $model .= $archText;
    }

    if (strpos($model, '未知') !== false) {
        return '当前网站目录权限不足 - 无法读取硬件信息';
    }
    
    return $model;
}

// 新增 format_uptime() 函数
function format_uptime($seconds) {
    if ($seconds === false) {
        return '当前网站目录权限不足 - 无法读取硬件信息';
    }
    
    $seconds = (int)$seconds;
    $days = floor($seconds / 86400);
    $remaining_after_days = $seconds % 86400;
    $hours = floor($remaining_after_days / 3600);
    $remaining_after_hours = $remaining_after_days % 3600;
    $minutes = floor($remaining_after_hours / 60);
    
    $result = '';
    if ($days > 0) $result .= $days . '天';
    if ($hours > 0) $result .= $hours . '小时';
    $result .= $minutes . '分钟';
    
    return $result ?: '刚刚启动';
}

function get_server_uptime() {
    // 通用尝试：/proc/uptime（适用于Linux和兼容系统）
    if (@is_readable('/proc/uptime')) {
        $contents = @file_get_contents('/proc/uptime');
        if ($contents !== false) {
            return floatval(explode(' ', $contents)[0]);
        }
    }

    // 根据操作系统类型处理
    $osFamily = strtolower(PHP_OS_FAMILY);
    switch ($osFamily) {
        case 'linux':
            return get_linux_uptime() ?: false;
        
        case 'darwin':
        case 'bsd':
            return get_bsd_uptime() ?: false;
        
        case 'windows':
            return get_windows_uptime() ?: false;
        
        default:
            return get_generic_uptime() ?: false;
    }
}

function get_linux_uptime() {
    // 尝试 uptime -s 格式
    if (function_exists('shell_exec')) {
        $uptimeStr = trim(@shell_exec('uptime -s 2>/dev/null'));
        if ($uptimeStr) {
            $bootTime = strtotime($uptimeStr);
            return $bootTime !== false ? time() - $bootTime : false;
        }
    }
    
    // 尝试直接计算启动时间
    if (function_exists('sys_getloadavg')) {
        $uptime = @sys_getloadavg()[2];
        return $uptime ? $uptime : false;
    }
    return false;
}

function get_bsd_uptime() {
    if (function_exists('shell_exec')) {
        // 获取内核启动时间（FreeBSD/macOS）
        $output = @shell_exec('sysctl -n kern.boottime 2>/dev/null');
        if ($output) {
            // 格式处理：{ sec = 1620000000, usec = 0 } 或 1620000000
            if (preg_match('/sec\s*=\s*(\d+)/', $output, $m)) {
                return time() - intval($m[1]);
            } elseif (is_numeric(trim($output))) {
                return time() - intval(trim($output));
            }
        }
        
        // 尝试通过启动日志获取（macOS备用方案）
        $output = @shell_exec('last reboot | head -1 | awk \'{print $5 " " $6}\'');
        if ($output && preg_match('/\w{3} \d{2}/', $output)) {
            $bootTime = strtotime(trim($output));
            return $bootTime ? time() - $bootTime : false;
        }
    }
    return false;
}

function get_windows_uptime() {
    // 方法1：通过WMI获取
    if (extension_loaded('com_dotnet')) {
        try {
            $wmi = new COM('WinMgmts:{impersonationLevel=impersonate}!\\\\.\\root\\CIMV2');
            $items = $wmi->ExecQuery('SELECT LastBootUpTime FROM Win32_OperatingSystem');
            foreach ($items as $os) {
                $bootTime = parse_wmi_time($os->LastBootUpTime);
                return $bootTime ? time() - $bootTime : false;
            }
        } catch (Exception $e) {}
    }

    // 方法2：通过WMIC命令获取
    if (function_exists('shell_exec')) {
        $output = @shell_exec('wmic os get lastbootuptime /format:value 2>&1');
        if ($output && preg_match('/LastBootUpTime=(\d{14})/', $output, $m)) {
            $bootTime = parse_wmi_time($m[1]);
            return $bootTime ? time() - $bootTime : false;
        }
    }

    // 方法3：通过系统启动记录估算
    if (function_exists('shell_exec')) {
        $output = @shell_exec('net statistics workstation 2>&1');
        if ($output && preg_match('/since (.*?)\r?\n/', $output, $m)) {
            $bootTime = strtotime($m[1]);
            return $bootTime ? time() - $bootTime : false;
        }
    }
    return false;
}

function get_generic_uptime() {
    // 通用方法：解析uptime命令输出
    if (function_exists('shell_exec')) {
        $output = @shell_exec('uptime 2>/dev/null');
        if ($output) {
            // 匹配格式：up 5 days, 3:14 或 up 1 week, 2 days, 3:14
            if (preg_match('/up\s+((\d+\s+weeks?,\s+)?(\d+\s+days?,\s+)?(\d+:\d+)/', $output, $m)) {
                $parts = explode(':', $m[4]);
                return ((int)$parts[0] * 3600) + ((int)$parts[1] * 60);
            }
        }
    }
    return false;
}

function parse_wmi_time($wmiTime) {
    // 解析WMI时间格式：YYYYMMDDHHMMSS.xxxxxx±UUU
    if (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', $wmiTime, $m)) {
        return mktime($m[4], $m[5], $m[6], $m[2], $m[3], $m[1]);
    }
    return false;
}

// 时区
date_default_timezone_set('Asia/Shanghai');

// 修改后的服务器信息获取函数
function get_server_info() {
    $timezone_mapping = [
        'Asia/Shanghai'   => '上海',
        'Asia/Chongqing'  => '重庆',
        'Asia/Urumqi'     => '乌鲁木齐',
        'Asia/Tokyo'      => '东京',
        'America/New_York'=> '纽约',
        'Europe/London'   => '伦敦',
    ];

    $timezone_identifier = date_default_timezone_get();
	$kernel_version = '未知';
	if (!is_readable('/proc/version')) {
		$kernel_version = '当前网站目录权限不足 - 无法读取硬件信息';
	} else {
		$kernel = file_get_contents('/proc/version');
		if (preg_match('/Linux version (\S+)/', $kernel, $matches)) {
			$kernel_version = $matches[1];
		}
	}
	return [
	    '主机名称' => @php_uname('n') ?: '未知',
	    '操作系统' => PHP_OS,
	    '内核版本' => $kernel_version,
	    '系统发行版名称' => get_distro_name(),
	    '硬件架构' => @php_uname('m') ?: '未知',
	    '虚拟化类型' => get_virtualization_type(),
	
	    'CPU型号' => get_cpu_model(),
	    '服务器已运行时间' => format_uptime(get_server_uptime()),
	
	    'Web服务器' => $_SERVER['SERVER_SOFTWARE'] ?? '未知',
	    '服务器端口' => $_SERVER['SERVER_PORT'] ?? '未知',
	
	    'PHP版本' => PHP_VERSION,
	    'PHP信息' => '<span class="developer-prompt me-2">如果你是开发者请查看:</span>' .
	        '<a href="?action=phpInfo" target="_blank" class="btn btn-sm btn-outline-primary">phpinfo</a>',
	    'Zend引擎版本' => zend_version(),
	    'PHP安装路径' => PHP_BINARY,
	    'PHP配置文件' => php_ini_loaded_file() ?: '无',
	
	    'PHP内存限制' => ini_get('memory_limit'),
	    'PHP最大执行时间' => ini_get('max_execution_time') . ' 秒',
	    '最大上传文件大小' => ini_get('upload_max_filesize'),
	    'OpenSSL支持' => extension_loaded('openssl') ? '已启用' : '未启用',
	    'CGI模式' => (php_sapi_name() === 'cgi') ? '是' : '否',
	
	    '服务器公网IP' => get_enhanced_public_ip(),
	    '服务器内网IP' => $_SERVER['SERVER_ADDR'] ?? '未知',
	    '访客IP' => '<span id="visitorIp" class="visitor-info">获取中...</span>',
	    
	    '当前用户' => get_current_user(),
	    '当前探针时区' => $timezone_mapping[$timezone_identifier] ?? $timezone_identifier,
	    '当前目录' => $_SERVER['DOCUMENT_ROOT'] ?? '未知',
	    '当前探针路径' => str_replace('\\', '/', __FILE__),
	    '系统负载' => @sys_getloadavg()[0] ?? '未知',
	    'OPcache状态' => function_exists('opcache_get_status') ? '启用 (' . opcache_get_status()['opcache_enabled'] . ')' : '未启用',
	    '峰值内存' => function_exists('memory_get_peak_usage') ? round(memory_get_peak_usage(true)/(1024*1024), 2) . ' MB' : '未知'
	];
}

// 新增辅助函数
function get_kernel_version() {
    if (is_readable('/proc/version')) {
        $kernel = file_get_contents('/proc/version');
        if (preg_match('/Linux version (\S+)/', $kernel, $matches)) {
            return $matches[1];
        }
    }
    return '未知';
}

function get_distro_name() {
    $files = [
        '/etc/os-release' => function($c) {
            preg_match('/PRETTY_NAME="(.+?)"/', $c, $m);
            return isset($m[1]) ? $m[1] : '未知';
        },
        '/etc/redhat-release' => function($c) {
            return trim(str_replace(' release ', ' ', $c));
        },
        '/etc/centos-release' => function($c) {
            return trim(str_replace(' release ', ' ', $c));
        },
        '/etc/lsb-release' => function($c) {
            preg_match('/DISTRIB_DESCRIPTION=(.+)/', $c, $m);
            return trim($m[1], '"\'') ?? '未知';
        },
        '/etc/debian_version' => function($c) {
            return "Debian ".trim($c);
        },
        '/etc/alpine-release' => function($c) {
            return "Alpine Linux ".trim($c);
        }
    ];

    foreach ($files as $file => $parser) {
        if (@is_readable($file)) {
            $content = @file_get_contents($file);
            if ($content && ($name = $parser($content))) {
                return $name;
            }
        }
    }

    // 所有尝试失败时返回权限提示
    return '当前网站目录权限不足 - 无法读取硬件信息';
}

function get_virtualization_type() {
    try {
        if (is_readable('/proc/1/cgroup')) {
            $cgroup = @file_get_contents('/proc/1/cgroup');
            if ($cgroup !== false && preg_match('/docker|kubepods/', $cgroup)) {
                return '容器 (Docker/Kubernetes)';
            }
        }

        if (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo !== false && preg_match('/hypervisor vendor\s+:\s+(\w+)/i', $cpuinfo, $m)) {
                return $m[1];
            }
        }

        $dmi_file = '/sys/devices/virtual/dmi/id/product_name';
        if (is_readable($dmi_file)) {
            $dmi = @file_get_contents($dmi_file);
            if ($dmi !== false) {
                $vm_signatures = [
                    'KVM' => 'KVM', 
                    'VMware' => 'VMware', 
                    'VirtualBox' => 'VirtualBox',
                    'Xen' => 'Xen',
                    'Bochs' => 'Bochs',
                    'Amazon EC2' => 'AWS EC2',
                    'Microsoft Hv' => 'Hyper-V'
                ];
                foreach ($vm_signatures as $sig => $name) {
                    if (stripos($dmi, $sig) !== false) return $name;
                }
            }
        }
    } catch (Exception $e) {
        // 忽略权限错误
    }
    return '物理机';
}

// ================== 新增安全检测函数 ================== //
function get_extension_risk_level($ext) {
    $high_risk = [
        'exec', 'system', 'passthru', 'eval', 'shell_exec',
        'phpinfo', 'assert', 'dl', 'open_basedir'
    ];
    
    $medium_risk = [
        'curl', 'wget', 'socket', 'ldap', 'proc_open',
        'sqlite', 'oci8', 'ssh2', 'imap', 'mb_send_mail'
    ];

    $ext_lower = strtolower($ext);
    foreach ($high_risk as $keyword) {
        if (strpos($ext_lower, $keyword) !== false) return '高危';
    }
    
    foreach ($medium_risk as $keyword) {
        if (strpos($ext_lower, $keyword) !== false) return '中危';
    }
    
    return '低危';
}
// 基础辅助函数
function detect_extension_path(ReflectionExtension $reflection): string {
    if (method_exists($reflection, 'getFileName')) {
        $path = $reflection->getFileName();
        if ($path && file_exists($path)) {
            return $path;
        }
    }

    ob_start();
    $reflection->info();
    $info = ob_get_clean();
    if (preg_match('/Compiled => (.+\.so)/', $info, $matches)) {
        return $matches[1];
    }

    $extensionDir = ini_get('extension_dir');
    $apiVersion = '';
    
    if (defined('PHP_ZTS') && PHP_ZTS) {
        $apiVersion .= 'zts_';
    }
    
    if (defined('PHP_DEBUG') && PHP_DEBUG) {
        $apiVersion .= 'debug_';
    }
    
    if (defined('PHP_API_VERSION')) {
        $apiVersion .= PHP_API_VERSION;
    } else {
        preg_match('/\d+/', phpversion('zend'), $match);
        $apiVersion .= $match[0] ?? '20210902';
    }

    $guessedPaths = [
        "/usr/lib/php/{$apiVersion}/",
        "/usr/lib/php/modules/",
        'C:\\php\\ext\\',
        '/usr/local/lib/php/pecl/',
        '/usr/lib/php5/',
    ];

    foreach ($guessedPaths as $basePath) {
        $fullPath = $basePath . $reflection->getName() . '.' . PHP_SHLIB_SUFFIX;
        if (file_exists($fullPath)) {
            return $fullPath;
        }
    }

    return "{$extensionDir}/{$reflection->getName()}.so";
}
// 扩展检测相关函数
function find_available_extensions(): array {
    $found = [];
    
    $extension_dir = ini_get('extension_dir');
    if (is_dir($extension_dir)) {
        $files = scandir($extension_dir);
        foreach ($files as $file) {
            if (preg_match('/^(php_)?([\w]+)\.(so|dll)$/i', $file, $matches)) {
                $found[] = strtolower($matches[2]);
            }
        }
    }
    // 通过pecl获取已安装扩展（需要pecl命令）
    if (function_exists('shell_exec') && `which pecl`) {
        $pecl_list = shell_exec('pecl list');
        preg_match_all('/^([a-z]+)\s+/mi', $pecl_list, $matches);
        $found = array_merge($found, $matches[1]);
    }

    return array_unique($found);
}

function get_extension_warning($ext) {
    $risk = get_extension_risk_level($ext);
    switch ($risk) {
        case '高危':
            return "此扩展包含高风险功能，启用需严格评估必要性！";
        case '中危':
            return "此扩展可能存在安全风险，建议按需启用并做好安全配置";
        default:
            return "常规扩展，按需启用即可";
    }
}
// 扩展启用检测
function get_extension_config_tip($ext) {
    $sapi = php_sapi_name();
    $phpVersion = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    
    $configPaths = [
        'cli' => "/etc/php/{$phpVersion}/cli/php.ini",
        'fpm' => "/etc/php/{$phpVersion}/fpm/php.ini",
        'apache2' => "/etc/php/{$phpVersion}/apache2/php.ini",
        'cgi' => "/etc/php/{$phpVersion}/cgi/php.ini"
    ];

    $currentEnv = array_key_exists($sapi, $configPaths) ? $sapi : 'cli';
    $configFile = $configPaths[$currentEnv];

    $directiveType = 'extension';
    $baseConfig = "{$directiveType}={$ext}.so";

    $tips = [
        '高危' => [
            '建议' => "🚨 强烈建议在 php.ini 中禁用该扩展",
            '例外情况' => "如需启用必须添加安全限制：\n" .
                "1. 禁用危险函数：\n" .
                "   disable_functions = exec,passthru,shell_exec\n" .
                "2. 限制文件系统访问：\n" .
                "   open_basedir = /var/www/:/tmp/\n" .
                "3. 日志记录所有操作：\n" .
                "   {$ext}.log_operations = On",
            '配置路径' => $configFile
        ],
        '中危' => [
            '建议' => "⚠️ 启用时需配置安全参数：",
            '安全配置' => [
                "1. 限制网络访问：\n" .
                "   {$ext}.allowed_hosts = 127.0.0.1",
                "2. 启用沙盒模式：\n" .
                "   {$ext}.safe_mode = On",
                "3. 设置内存限制：\n" .
                "   {$ext}.memory_limit = 128M"
            ],
            '配置方法' => "在 {$configFile} 中添加：\n{$baseConfig}"
        ],
        '低危' => [
            '建议' => "✅ 安全扩展可按需启用：",
            '配置方法' => "根据不同运行环境选择配置：\n" .
                implode("\n", array_map(
                    function($env) use ($configPaths) {  // 修复此处语法
                        return "• {$env}环境: {$configPaths[$env]}";
                    },
                    array_keys($configPaths)
                )) . 
                "\n\n添加配置指令：\n{$baseConfig}",
            '验证命令' => "php -i | grep {$ext} && systemctl restart php{$phpVersion}-{$currentEnv}"
        ]
    ];

    $risk = get_extension_risk_level($ext);
    $tip = $tips[$risk] ?? ['建议' => '请参考官方文档进行配置'];

    return implode("\n\n", array_map(
        function($k, $v) {
            return "【{$k}】\n" . (is_array($v) ? implode("\n", $v) : $v);
        },
        array_keys($tip),
        array_values($tip)
    ));
}
// 扩展元数据相关函数
function get_extension_metadata($ext) {
    $metadata = [
        'redis' => [
            'functions' => ['Redis::connect', 'Redis::get', 'Redis::set', 'Redis::hGetAll'],
            'dependencies' => ['libredis' => '>=3.0'],
            'doc_url' => 'https://pecl.php.net/package/redis'
        ],
        'mongodb' => [
            'functions' => ['MongoDB\Driver\Manager', 'MongoDB\BSON\fromPHP'],
            'dependencies' => ['libmongoc' => '>=1.17.0'],
            'doc_url' => 'https://pecl.php.net/package/mongodb'
        ],
        'xdebug' => [
            'functions' => ['xdebug_break', 'xdebug_call_class'],
            'dependencies' => [],
            'doc_url' => 'https://xdebug.org/docs/'
        ]
    ];
    
    return $metadata[strtolower($ext)] ?? [
        'functions' => [],
        'dependencies' => [],
        'doc_url' => 'https://pecl.php.net/package-search.php?pkg_name=' . $ext
    ];
}
// 在 get_php_extensions() 函数之前添加以下元数据函数
function get_function_metadata($functionName) {
    // 内置的已知函数元数据
	$metadata = [
        'json_encode' => [
            'description' => '将PHP值转换为JSON字符串',
            'parameters' => ['mixed $value', 'int $flags = 0', 'int $depth = 512'],
            'return' => 'string|false'
        ],
        'mysqli_connect' => [
            'description' => '打开到MySQL服务器的新连接',
            'parameters' => ['string $host', 'string $username', 'string $password', 'string $database', 'int $port = 3306'],
            'return' => 'mysqli|false'
        ],
        'PDO::__construct' => [
            'description' => '创建数据库连接实例',
            'parameters' => ['string $dsn', 'string $username', 'string $password', 'array $options = []'],
            'return' => 'PDO'
        ],
        'openssl_encrypt' => [
            'description' => '使用指定方法和密钥加密数据',
            'parameters' => ['string $data', 'string $method', 'string $key', 'int $options = 0', 'string $iv = ""'],
            'return' => 'string|false'
        ]
    ];

    $lowerName = strtolower($functionName);
    if (isset($metadata[$lowerName])) {
        return $metadata[$lowerName];
    }

    // 动态反射获取未知函数信息
    try {
        $refFunc = new ReflectionFunction($lowerName);
        
        // 重构参数类型处理
        $params = [];
        foreach ($refFunc->getParameters() as $param) {
            $paramStr = '';
            
            // 增强类型处理 (修复点)
            if ($param->hasType()) {
                $type = $param->getType();
                
                if ($type instanceof ReflectionUnionType) {
                    $types = [];
                    foreach ($type->getTypes() as $t) {
                        $types[] = $t->getName();
                    }
                    $paramStr .= implode('|', $types).' ';
                } elseif ($type instanceof ReflectionNamedType) {
                    $paramStr .= $type->getName().' ';
                }
            }

            $paramStr .= '$'.$param->getName();
            
            // 默认值处理保持不变
            if ($param->isOptional() && $param->isDefaultValueAvailable()) {
                $default = str_replace(PHP_EOL, '', var_export($param->getDefaultValue(), true));
                $paramStr .= ' = '.$default;
            }
            
            $params[] = $paramStr;
        }

        // 返回值类型
        $returnType = $refFunc->getReturnType();
        if ($returnType) {
            if ($returnType instanceof ReflectionUnionType) {
                $types = [];
                foreach ($returnType->getTypes() as $t) {
                    $types[] = $t->getName();
                }
                $returnStr = implode('|', $types);
            } elseif ($returnType instanceof ReflectionNamedType) {
                $returnStr = $returnType->getName();
                if ($returnType->allowsNull() && $returnStr !== 'mixed') {
                    $returnStr .= '|null';
                }
            } else {
                $returnStr = 'mixed';
            }
        } else {
            $returnStr = 'mixed';
        }

        return [
            'description' => '（通过反射获取）该函数暂无详细文档',
            'parameters' => $params ?: [],
            'return' => $returnStr
        ];
    } catch (ReflectionException $e) {
        return [
            'description' => '函数不存在或无法反射',
            'parameters' => [],
            'return' => 'mixed'
        ];
    }
}

function get_constant_metadata($constantName) {
    $metadata = [
        'JSON_PRETTY_PRINT' => [
            'description' => '格式化JSON输出，使用空格和缩进',
            'since' => '5.4.0'
        ],
        'E_STRICT' => [
            'description' => '严格错误报告级别 (已废弃)',
            'since' => '5.0.0',
            'deprecated' => true,
            'deprecated_since' => '8.0.0',
            'alternative' => 'E_ALL'
        ],
        'PHP_VERSION' => [
            'description' => '当前PHP版本号字符串',
            'since' => '4.0'
        ],
        'PDO::ATTR_ERRMODE' => [
            'description' => '设置错误处理模式',
            'values' => ['PDO::ERRMODE_SILENT', 'PDO::ERRMODE_WARNING', 'PDO::ERRMODE_EXCEPTION']
        ],
        'OPENSSL_RAW_DATA' => [
            'description' => '指定加密/解密使用原始输出格式',
            'since' => '5.4.0'
        ]
    ];

    if (isset($metadata[$constantName])) {
        return $metadata[$constantName];
    }

    $result = [
        'description' => '',
        'value' => 'undefined',
        'since' => '未知',
        'deprecated' => false
    ];

    // 错误处理器捕获废弃警告
    set_error_handler(function($severity, $message) use (&$result) {
        if (strpos($message, 'is deprecated') !== false) {
            $result['deprecated'] = true;
            $result['description'] = '（已废弃）';
        }
    }, E_DEPRECATED);
    
    // 处理类常量 (如 PDO::ATTR_ERRMODE)
    if (strpos($constantName, '::') !== false) {
        list($class, $const) = explode('::', $constantName, 2);
        try {
            $refClass = new ReflectionClass($class);
            if ($refClass->hasConstant($const)) {
                return [
                    'description' => '（类常量）动态获取的常量',
                    'value' => $refClass->getConstant($const),
                    'since' => '未知版本'
                ];
            }
        } catch (ReflectionException $e) {
            // 类不存在则跳过
        }
    } 
    // 处理全局常量
    elseif (defined($constantName)) {
        $result['value'] = constant($constantName); // 自动触发错误处理器
        $result['description'] = '（全局常量）动态获取的常量';
    }

    restore_error_handler();

    // 补充默认描述
    if ($result['description'] === '') {
        $result['description'] = $result['deprecated'] 
            ? '（已废弃的常量）' 
            : '（未分类常量）';
    }

    return $result;
}

// 核心函数
function get_php_extensions() {
    $extensions = [];
    $all_ini = ini_get_all();
    // 处理已加载的扩展
    foreach (get_loaded_extensions() as $ext) {
        $reflection = new ReflectionExtension($ext);
        $version = phpversion($ext) ?: '未知';
        $constants = get_defined_constants(true)[$ext] ?? [];
        // 文件路径兼容处理
        $file_path = detect_extension_path($reflection);

        $extensions[$ext] = [
            '基本信息' => [
                '版本' => $version,
                '状态' => '已启用',
                '编译类型' => $reflection->isPersistent() ? '动态' : '静态',
                '依赖扩展' => implode(', ', $reflection->getDependencies()['required'] ?? []),
                '文件路径' => $file_path
            ],
            '配置参数' => array_filter($all_ini, function($key) use ($ext) {
                return strpos($key, $ext . '.') === 0;
            }, ARRAY_FILTER_USE_KEY),
			'函数列表' => (function() use ($ext) {
			    $funcs = get_extension_funcs($ext);
			    if ($funcs === false) {
			        return [];
			    }
			    return array_map(function($func) {
			        try {
			            $reflection = new ReflectionFunction($func);
			            $meta = get_function_metadata($func);
			            $returnType = '';
			            
			            // 版本兼容：处理联合类型（PHP >=8.0）
			            $returnTypeReflection = $reflection->getReturnType();
			            if ($returnTypeReflection) {
			                if ($returnTypeReflection instanceof ReflectionNamedType) {
			                    $returnType = $returnTypeReflection->getName();
			                } elseif ($returnTypeReflection instanceof ReflectionUnionType) {
			                    $types = [];
			                    foreach ($returnTypeReflection->getTypes() as $type) {
			                        $types[] = $type->getName();
			                    }
			                    $returnType = implode('|', $types);
			                }
			            }
			
			            return [
			                'name' => $func,
			                'parameters' => array_map(function($param) {
					                    return [
					                        'name' => $param->getName(),
					                        'type' => $param->getType(),
					                        'optional' => $param->isOptional()
					                    ];
			                }, $reflection->getParameters()),
			                'returnType' => $returnType ?: 'void',
			                'description' => $meta['description'] ?? '无描述',
			                'meta' => $meta
			            ];
			        } catch (ReflectionException $e) {
			            return [
			                'name' => $func,
			                'error' => $e->getMessage()
			            ];
			        }
			    }, array_slice($funcs, 0, 20));
			})(),
		    
		    '常量列表' => array_map(function($const, $value) {
		        return [
		            'name' => $const,
		            'value' => $value,
		            'meta' => get_constant_metadata($const)
		        ];
		    }, array_keys(array_slice($constants, 0, 15)), 
		        array_values(array_slice($constants, 0, 15)))
		];
    }
    // 获取所有可用扩展（包括已加载和未加载）
    $available_extensions = [];
    // 1. 扫描扩展目录    
    $extension_dir = ini_get('extension_dir');
    if (is_dir($extension_dir)) {
        $files = scandir($extension_dir);
        foreach ($files as $file) {
            if (preg_match('/^(php_)?([\w]+)\.(so|dll)$/i', $file, $matches)) {
                $available_extensions[] = strtolower($matches[2]);
            }
        }
    }
    // 2. 通过pecl获取（需要pecl命令）
    if (function_exists('shell_exec') && `which pecl`) {
        $pecl_list = shell_exec('pecl list');
        preg_match_all('/^([a-z]+)\s+/mi', $pecl_list, $matches);
        $available_extensions = array_merge($available_extensions, $matches[1]);
    }
    // 去重并转换为小写
    $available_extensions = array_unique(array_map('strtolower', $available_extensions));
    // 计算未启用的扩展
    $disabled_extensions = array_diff(
        $available_extensions, 
        array_map('strtolower', array_keys($extensions))
    );
    // 添加未启用的扩展信息
    $extensions['未启用扩展'] = [];
    foreach ($disabled_extensions as $ext) {
        $extensions['未启用扩展'][$ext] = [
            '风险等级' => get_extension_risk_level($ext),
            '启用建议' => get_extension_warning($ext),
            '配置建议' => get_extension_config_tip($ext),
            '文件路径' => $extension_dir ? $extension_dir . "/$ext.so" : '未知'
        ];
    }

    ksort($extensions);
    return $extensions;
}
// 获取磁盘使用情况（支持多分区）
function get_disk_usage() {
    if (get_current_user() !== 'root') {
        return [];
    }
    $disks = [];
    $os = strtolower(php_uname('s'));
    
    // 增强的排除策略
    $exclude_mounts = [
        '/proc', '/sys', '/dev', '/run', '/snap', '/tmp',
        '/var/lib/docker', '/var/snap', '/sys/fs/cgroup',
        '/dev/shm', '/run/lock', '/run/user', '/sys/fs/pstore',
        '/boot/efi', '/var/lib/lxd', '/var/lib/containers',
        '/var/lib/kubelet', '/var/lib/rancher'
    ];

    $exclude_types = [
        'proc', 'sysfs', 'tmpfs', 'devtmpfs', 'overlay', 'devpts',
        'securityfs', 'cgroup', 'pstore', 'autofs', 'hugetlbfs',
        'mqueue', 'debugfs', 'tracefs', 'configfs', 'ramfs', 'fusectl',
        'binfmt_misc', 'fuse', 'fuse.sshfs', 'rpc_pipefs', 'nfsd',
        'squashfs', 'iso9660', 'udf', 'nfs', 'cifs', 'smb3', 'ceph'
    ];

    if (strpos($os, 'linux') === 0) {
        $mounts = @file('/proc/mounts');
        if ($mounts) {
            foreach ($mounts as $mount) {
                $parts = preg_split('/\s+/', trim($mount), 5);
                if (count($parts) < 4) continue;

                list($device, $mount_point, $fs_type) = $parts;
                
                // 排除逻辑增强
                if (in_array($fs_type, $exclude_types)) continue;
                if (strpos($device, '/dev/loop') === 0) continue;
                
                // 检查挂载点前缀排除
                $excluded = false;
                foreach ($exclude_mounts as $exclude) {
                    if (strpos($mount_point, $exclude) === 0) {
                        $excluded = true;
                        break;
                    }
                }
                if ($excluded) continue;
                if (!is_dir($mount_point)) continue;

                try {
                    $total = (int)@disk_total_space($mount_point);
                    if ($total > 0) {
                        $free = (int)@disk_free_space($mount_point);
                        $used = $total - $free;
                        $percent = round(($used / $total) * 100, 1);

                        // 合并重复挂载点（取最大值）
                        $exists = false;
                        foreach ($disks as &$existing) {
                            if ($existing['mount'] === $mount_point) {
                                if ($total > $existing['total']) {
                                    $existing = [
                                        'mount'   => $mount_point,
                                        'device'  => basename($device),
                                        'type'    => strtoupper($fs_type),
                                        'total'   => $total,
                                        'used'    => $used,
                                        'free'    => $free,
                                        'percent' => $percent
                                    ];
                                }
                                $exists = true;
                                break;
                            }
                        }
                        if (!$exists) {
                            $disks[] = [
                                'mount'   => $mount_point,
                                'device'  => basename($device),
                                'type'    => strtoupper($fs_type),
                                'total'   => $total,
                                'used'    => $used,
                                'free'    => $free,
                                'percent' => $percent
                            ];
                        }
                    }
                } catch (Exception $e) {
                    continue;
                }
            }
        }
    }

    // 按使用率降序排序，使用率相同时按挂载点排序
    usort($disks, function($a, $b) {
        if ($b['percent'] !== $a['percent']) {
            return $b['percent'] <=> $a['percent'];
        }
        return $a['mount'] <=> $b['mount'];
    });

    return $disks;
}

// 新增网络流量监控函数
function get_network_traffic() {
    $traffic = [];
    if (is_readable('/proc/net/dev')) {
        $content = @file_get_contents('/proc/net/dev');
        if ($content !== false) {
            preg_match_all(
                '/(\S+):\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/m',
                $content,
                $matches
            );
            
            $interfaces = $matches[1] ?? [];
            $receive = $matches[2] ?? [];
            $transmit = $matches[3] ?? [];

            for ($i = 0; $i < count($interfaces); $i++) {
                $traffic[trim($interfaces[$i])] = [
                    'receive' => (int)$receive[$i],
                    'transmit' => (int)$transmit[$i]
                ];
            }
        }
    }
    return $traffic;
}
// 初始化网络流量跟踪
if (!isset($_SESSION['network_traffic'])) {
    $_SESSION['network_traffic'] = [];
    $_SESSION['last_traffic_time'] = microtime(true);
}
// 获取当前流量数据
$current_traffic = get_network_traffic();
$current_time = microtime(true);
$time_diff = $current_time - ($_SESSION['last_traffic_time'] ?? $current_time);

$traffic_data = [];
foreach ($current_traffic as $interface => $data) {
    $prev_data = $_SESSION['network_traffic'][$interface] ?? ['receive' => 0, 'transmit' => 0];
        // 计算速率（防止除零错误）
    $receive_rate = $time_diff > 0 ? 
        ($data['receive'] - $prev_data['receive']) / $time_diff : 0;
    $transmit_rate = $time_diff > 0 ? 
        ($data['transmit'] - $prev_data['transmit']) / $time_diff : 0;
    
    $traffic_data[$interface] = [
        'receive' => $data['receive'],
        'transmit' => $data['transmit'],
        'receive_rate' => $receive_rate,
        'transmit_rate' => $transmit_rate
    ];
    
    $_SESSION['network_traffic'][$interface] = $data;
}
$_SESSION['last_traffic_time'] = $current_time;
// 获取详细内存信息
function get_memory_info() {
    $mem = ['percent' => 0, 'used' => 0, 'total' => 0];
    try {
        if (is_readable('/proc/meminfo')) {
            $info = @file_get_contents('/proc/meminfo');
            if ($info !== false) {
                preg_match_all('/(\w+):\s+([\d.]+)\s*kB/', $info, $matches);
                if (!empty($matches[1])) {
                    $data = array_combine($matches[1], $matches[2]);
                    
                    $mem['total'] = (int)($data['MemTotal'] * 1024);
                    $mem['free'] = (int)($data['MemFree'] * 1024);
                    $mem['available'] = (int)($data['MemAvailable'] * 1024);
                    
                    $mem['used'] = $mem['total'] - $mem['available'];
                    if ($mem['total'] > 0) {
                        $mem['percent'] = round(($mem['used'] / $mem['total']) * 100, 2);
                    }
                }
            }
        }
    } catch (Exception $e) {
        // Ignore permission errors
    }
    return $mem;
}
// 获取网络接口信息（跨平台）
function get_network_info() {
    $result = [];
    
    if (!function_exists('net_get_interfaces')) {
        return ['错误' => '需要PHP 7.3+版本支持'];
    }

    $interfaces = @net_get_interfaces();
    if ($interfaces === false) {
        return ['错误' => '无法获取网络接口信息'];
    }

    foreach ($interfaces as $name => $info) {
        if (!isset($info['unicast'])) continue;

        $ipv4 = [];
        $ipv6 = [];
        
	foreach ($info['unicast'] as $addr) {
	    if ($addr['family'] === 2) {
	        $ipv4[] = $addr['address'];
	    } elseif ($addr['family'] === 10) {
	        $ipv6[] = $addr['address'];
	    }
	}
	
        if (!empty($ipv4)) {
            $result[$name]['ipv4'] = implode(', ', $ipv4);
        }
        if (!empty($ipv6)) {
            $result[$name]['ipv6'] = implode(', ', $ipv6);
        }
    }
    
    return $result;
}
// 获取CPU使用率和详细信息
function get_cpu_usage() {
    $cpu = ['usage' => 0, 'cores' => 0];
    try {
        if (is_readable('/proc/stat')) {
            $stat = @file_get_contents('/proc/stat');
            if ($stat !== false) {
                preg_match('/^cpu\s+(.*)$/m', $stat, $matches);
                if (isset($matches[1])) {
                    $times = array_map('intval', explode(' ', $matches[1]));
                    $cpu['usage'] = 100 - ($times[3] / array_sum($times) * 100);
                }
            }
        }

        if (is_readable('/proc/cpuinfo')) {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo !== false) {
                preg_match_all('/^processor\s+:\s+\d+$/m', $cpuinfo, $matches);
                $cpu['cores'] = count($matches[0]);
            }
        }
    } catch (Exception $e) {
        // Ignore permission errors
    }
    return $cpu;
}

// 数据库测试函数
function test_database_connections() {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['db_test'])) {
        // 清理所有输出缓冲区
        while (ob_get_level()) ob_end_clean();
        header('Content-Type: application/json');
        header('Cache-Control: no-cache');
        http_response_code(200);

        $response = ['status' => 'error', 'message' => '未知错误'];
        
        try {
            // 验证CSRF令牌
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                throw new Exception("安全验证失败，请刷新页面后重试", 403);
            }

            // 获取配置参数
            $config = $_POST['db_config'] ?? [];
            $required = ['type', 'host', 'port', 'user'];
            foreach ($required as $field) {
                if (empty($config[$field])) {
                    throw new Exception("缺少必要参数: $field", 400);
                }
            }

            $type = $config['type'];
            $response = ['status' => 'error', 'message' => '不支持的数据库类型'];

            switch ($type) {
			case 'MySQL':
			    if (empty($config['driver'])) {
			        throw new Exception("请选择数据库驱动类型 (PDO 或 mysqli)", 400);
			    }
			
			    $requiredKeys = ['host', 'port', 'user', 'name'];
			    foreach ($requiredKeys as $key) {
			        if (empty($config[$key])) {
			            throw new Exception("缺少必要参数: $key", 400);
			        }
			    }
			
			    $host = $config['host'];
			    $port = (int)$config['port'] ?: 3306;
			    $user = $config['user'];
			    $pass = $config['pass'] ?? '';
			    $name = $config['name'];
			
			    try {
			        if ($config['driver'] === 'pdo') {
			            if (!extension_loaded('pdo_mysql')) {
			                throw new Exception("需要启用 pdo_mysql 扩展", 501);
			            }
			
			            $dsn = "mysql:host=$host;port=$port;dbname=$name;charset=utf8mb4";
			            $options = [
			                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
			                PDO::ATTR_EMULATE_PREPARES => false,
			                PDO::ATTR_TIMEOUT => 5
			            ];
			            
			            $pdo = new PDO($dsn, $user, $pass, $options);
			            $version = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);
			        } else {
			            if (!extension_loaded('mysqli')) {
			                throw new Exception("需要启用 mysqli 扩展", 501);
			            }
			
			            $conn = new mysqli($host, $user, $pass, $name, $port);
			            if ($conn->connect_error) {
			                throw new Exception(
			                    "连接失败: (" . $conn->connect_errno . ") " . $conn->connect_error, 
			                    $conn->connect_errno
			                );
			            }
			            $version = $conn->server_version;
			            $conn->close();
			        }
			
			        $response = [
			            'status' => 'success',
			            'message' => 'MySQL连接成功',
			            'details' => [
			                'version' => $version,
			                'protocol' => ($config['driver'] === 'pdo') ? 'PDO' : 'MySQLi',
			                'host' => substr($host, 0, 3).'***',
			                'user' => substr($user, 0, 2).'***'
			            ]
			        ];
			    } catch (Exception $e) {
			        throw new Exception("MySQL连接错误: " . $e->getMessage(), $e->getCode());
			    }
			    break;

                case 'PostgreSQL':
                    if (!extension_loaded('pgsql') && !extension_loaded('pdo_pgsql')) {
                        throw new Exception("需要安装pgsql或pdo_pgsql扩展");
                    }
                    
                    $dsn = "host={$config['host']} port={$config['port']} dbname={$config['name']} user={$config['user']} password={$config['pass']}";
                    if ($config['driver'] === 'pdo') {
                        $pdo = new PDO("pgsql:$dsn");
                        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    } else {
                        $conn = pg_connect($dsn);
                        if (!$conn) {
                            throw new Exception(pg_last_error());
                        }
                    }
                    $response = ['status' => 'success', 'message' => '连接成功'];
                    break;

                case 'SQLite':
                    $path = $config['path'] ?? ':memory:';
                    if ($config['driver'] === 'pdo') {
                        $pdo = new PDO("sqlite:$path");
                        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    } else {
                        $db = new SQLite3($path);
                        if (!$db) {
                            throw new Exception("无法打开SQLite数据库");
                        }
                    }
                    $response = ['status' => 'success', 'message' => '连接成功'];
                    break;

                case 'MongoDB':
                    if (!extension_loaded('mongodb')) {
                        throw new Exception("需要安装mongodb扩展");
                    }
                    
                    $uri = "mongodb://{$config['user']}:{$config['pass']}@{$config['host']}:{$config['port']}";
                    $client = new MongoDB\Client($uri);
                    $dbs = $client->listDatabases();
                    $response = ['status' => 'success', 'message' => '连接成功'];
                    break;

                case 'Redis':
                    if (!extension_loaded('redis')) {
                        throw new Exception("需要安装redis扩展");
                    }
                    
                    $redis = new Redis();
                    $redis->connect($config['host'], $config['port']);
                    if (!empty($config['pass'])) {
                        $redis->auth($config['pass']);
                    }
                    $response = [
                        'status' => 'success', 
                        'message' => '连接成功',
                        'details' => $redis->info()
                    ];
                    break;
                default:
                    throw new Exception("不支持的数据库类型: $type", 400);
            }

        } catch (PDOException $e) {
            $response = ['status' => 'error', 'message' => '数据库连接错误: ' . $e->getMessage()];
        } catch (mysqli_sql_exception $e) {
            $response = ['status' => 'error', 'message' => 'MySQL错误: ' . $e->getMessage()];
        } catch (Exception $e) {
            $code = $e->getCode() ?: 500;
            http_response_code($code);
            $response = [
                'status' => 'error',
                'message' => $e->getMessage(),
                'code' => $code
            ];
        }

        // 确保仅输出JSON
        die(json_encode($response));
        exit; 
    }

    // 返回扩展状态
    $results = [];
    $extensions = [
        'MySQL' => ['mysqli', 'pdo_mysql'],
        'PostgreSQL' => ['pgsql', 'pdo_pgsql'],
        'SQLite' => ['sqlite3', 'pdo_sqlite'],
        'MongoDB' => ['mongodb'],
        'Redis' => ['redis']
    ];
    
    foreach ($extensions as $db => $exts) {
        $installed = array_filter($exts, function($ext) {
            return extension_loaded($ext);
        });
        
        $results[$db] = [
            'installed' => !empty($installed),
            'extensions' => $exts,
            'status' => '未测试'
        ];
    }
    
    return $results;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    $database_tests = test_database_connections();
} else {
    $database_tests = []; 
}

function test_mail() {
    $result = [
        'status' => '失败',
        'message' => '邮件发送失败'
    ];

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $result['message'] = '安全验证失败';
        return $result;
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    if (!$email) {
        $result['message'] = '无效的邮件地址格式';
        return $result;
    }

    if (isset($_SESSION['last_mail_time']) && (time() - $_SESSION['last_mail_time'] < 60)) {
        $result['message'] = '发送频率过高，请稍后再试';
        return $result;
    }

    try {
        $to = $email;
        $subject = '服务器探针测试邮件 - ' . date('Y-m-d H:i:s');
        $message = "这是一封来自服务器探针系统的测试邮件。\n\n";
        $message .= "发送时间: " . date('Y-m-d H:i:s') . "\n";
        $message .= "服务器IP: " . ($_SERVER['SERVER_ADDR'] ?? '未知') . "\n";
        $message .= "客户端IP: " . ($_SERVER['REMOTE_ADDR'] ?? '未知') . "\n";

        $headers = [
            'From' => 'noreply@' . ($_SERVER['SERVER_NAME'] ?? 'localhost'),
            'Reply-To' => 'noreply@' . ($_SERVER['SERVER_NAME'] ?? 'localhost'),
            'X-Mailer' => 'PHP/' . phpversion(),
            'Content-Type' => 'text/plain; charset=UTF-8'
        ];

        $headerString = '';
        foreach ($headers as $name => $value) {
            $headerString .= "$name: $value\r\n";
        }

        if (mail($to, $subject, $message, $headerString)) {
            $_SESSION['last_mail_time'] = time();
            $result = [
                'status' => '成功',
                'message' => '测试邮件已发送至 ' . htmlspecialchars($email)
            ];
        } else {
            $result['message'] = '邮件服务器返回错误';
        }
    } catch (Exception $e) {
        $result['message'] = '发送失败: ' . $e->getMessage();
    }

    return $result;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['action']) && $_POST['action'] === 'send_mail') {
    header('Content-Type: application/json');
    echo json_encode(test_mail());
    exit;
}

function safe_output($data) {
    $data = $data ?? '';
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

function format_bytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}

function get_execution_time() {
    return number_format((microtime(true) - $_SERVER['REQUEST_TIME_FLOAT']) * 1000, 2) . ' ms';
}

function get_traffic_stats() {
    $size = ob_get_length(); 
    return format_bytes($size);
}

// 主程序
$php_extensions = get_php_extensions();
$server_info = get_server_info();
$disk_usage = get_disk_usage();
$network_traffic = get_network_traffic();
$memory_info = get_memory_info();
$network_info = get_network_info();
$cpu_usage = get_cpu_usage();
$database_tests = test_database_connections();
$mail_test = test_mail();
$detectedLogs = detect_log_files();
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
<title>服务器探针系统 v2.2</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>👁️</text></svg>">
<link href="https://unpkg.com/bootstrap@5.3.5/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://unpkg.com/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<link href="https://unpkg.com/animate.css@4.1.1/animate.min.css" rel="stylesheet">
<link href="https://cdn.datatables.net/2.2.2/css/dataTables.bootstrap5.css" rel="stylesheet">
<style>
:root {
    --bs-primary: #4a90e2;
    --bs-success: #50c878;
    --bs-warning: #ffc107;
    --bs-danger: #dc3545;
}

body { 
    background: #f8f9fa;
    font-family: 'Noto Sans SC', system-ui, -apple-system, sans-serif;
}

.dataTables_wrapper .dataTables_filter input {
    border: 1px solid #dee2e6;
    border-radius: 0.375rem;
    padding: 0.375rem 0.75rem;
}

.progress {
    height: 1.5rem;
}

@media (max-width: 768px) {
    html {
        text-size-adjust: 100%;
    }
}

.network-graph {
    height: 200px;
    margin: 10px 0;
    display: grid;
    grid-template-columns: 1fr;
}

.traffic-badge {
    cursor: pointer;
    transition: transform 0.2s ease;
    
    &:hover {
        transform: scale(1.05);
    }
}
@media (max-width: 768px) {
    /* 基础布局调整 */
    .container {
        padding-left: 8px;
        padding-right: 8px;
    }
    
    /* 卡片标题缩小 */
    .card-header h2 {
        font-size: 1.1rem;
    }

    /* 表格响应式处理 */
    .table-responsive {
        border: none;
        -webkit-overflow-scrolling: touch;
    }

    /* 系统信息表格调整为块状布局 */
    .table.table-sm.table-striped {
        display: block;
    }
    .table.table-sm.table-striped tr {
        display: flex;
        flex-wrap: wrap;
        border-bottom: 1px solid #dee2e6;
    }
    .table.table-sm.table-striped th,
    .table.table-sm.table-striped td {
        flex: 1 1 100%;
        max-width: 100%;
        white-space: normal;
    }

    /* 图表容器高度调整 */
    .network-graph {
        height: 180px;
    }

    /* 扩展信息手风琴优化 */
    .accordion-button {
        padding: 0.75rem;
        font-size: 0.9rem;
    }
    .accordion-body .row {
        flex-direction: column;
    }

    /* 数据库测试表单调整为垂直布局 */
    #dbTestForm .col-md-3,
    #dbTestForm .col-md-2 {
        flex: 1 1 100%;
        margin-bottom: 8px;
    }

    /* 网络流量表格字体调整 */
    .network-rate {
        font-size: 0.8rem;
    }

    /* 磁盘使用进度条优化 */
    .progress {
        height: 18px;
    }
    .progress-bar {
        font-size: 0.7rem;
    }

    /* 移动端隐藏部分表格列 */
    .disk-table th-child(3),
    .disk-table td:nth-child(3),
    .network-table th:nth-child(2),
    .network-table td:nth-child(2) {
        display: none;
    }
}
/*文本加粗*/
.fw-light,
.fw-light *:not(strong) {
  font-weight: inherit !important;
}

/* 通用触控优化 */
.btn, .form-control, .accordion-button {
    touch-action: manipulation;
}

/* 防止长按出现复制菜单 */
.card, table, .btn {
    -webkit-touch-callout: none;
}
.back-to-top {
    position: fixed;
    bottom: 70px;
    right: 40px;
    width: 50px;
    height: 50px;
    border-radius: 50%;
    background: rgba(74, 144, 226, 0.9);
    color: white;
    border: none;
    cursor: pointer;
    opacity: 0;
    transition: all 0.3s ease;
    box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    transform: translateY(20px);
    visibility: hidden;
}
.back-to-top:hover {
    background: #4a90e2;
    transform: scale(1.1);
}

.back-to-top:hover::after {
    content: "返回顶部";
    position: absolute;
    bottom: -30px;
    left: 50%;
    transform: translateX(-50%);
    white-space: nowrap;
    background: rgba(0,0,0,0.7);
    color: white;
    padding: 5px 10px;
    border-radius: 4px;
    font-size: 12px;
    opacity: 1;
}

.back-to-top.show {
    opacity: 1;
    visibility: visible;
    transform: translateY(0);
}

@media (max-width: 768px) {
    .back-to-top {
        bottom: 20px;
        right: 20px;
        width: 40px;
        height: 40px;
    }
}
</style>
</head>
<body>
	<div class="container py-4">
		<header class="text-center mb-5">
		    <h1 class="display-4 mb-3"><span class="eye-icon" aria-label="眼睛图标">👁️</span> PHP服务器探针系统</h1>
		    <div class="alert alert-info d-flex flex-wrap flex-md-nowrap justify-content-center justify-content-md-center align-items-center gap-2">
		        实时状态更新：<span id="currentDateTime"></span>
		        <span class="badge bg-primary">PHP <?= safe_output(PHP_VERSION) ?></span>
		        <div class="d-flex flex-md-row gap-2">
				<a href="https://hestiamb.org/tz.php" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary me-3">下载探针文件</a>
				<a href="/" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary">返回主页</a>
		        </div>
		    </div>
		</header>
		<div class="card border-danger mt-4 shadow-sm">
		    <div class="card-header bg-danger text-white d-flex justify-content-between align-items-center">
		        <h3 class="h5 mb-0"><i class="bi bi-info-circle-fill me-2"></i>系统权限要求</h3>
		        <div class="d-flex gap-2">
		            <button class="btn btn-sm btn-light" type="button" data-bs-toggle="collapse" data-bs-target="#importantNotice" aria-expanded="false">
		                <i class="bi bi-chevron-double-down"></i>
		            </button>
		        </div>
		    </div>
		    <div class="collapse show" id="importantNotice">
		        <div class="card-body p-3 p-md-4">
		            <!-- 权限警告卡片 -->
		            <div class="alert alert-warning border-danger rounded-3 mb-4">
		                <div class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-3">
		                    <div class="alert-icon text-center mb-3 mb-md-0">
		                        <i class="bi bi-shield-check text-success fs-5"></i>
		                    </div>
		                    <div class="flex-grow-1 w-100 text-center text-md-start">
		                        <h4 class="text-danger mb-3">系统权限要求</h4>
		                        <p class="mb-3">
		                            为了全面精准地获取服务器运行参数并确保监测数据的完整性，本诊断工具需要具备对网站根目录的访问权限。如果当前目录权限不足，请将工具移至具备适当权限的目录中运行。
		                        </p>
		                        <div class="ms-0 ms-md-4">
		                            <div class="d-flex align-items-center gap-2 mb-2 justify-content-center justify-content-md-start">
		                                <i class="bi bi-arrow-right-short text-primary"></i>
		                                <span>本工具仅建议在必要监测场景下临时启用。</span>
		                            </div>
		                            <div class="d-flex align-items-center gap-2 mb-2 justify-content-center justify-content-md-start">
		                                <i class="bi bi-arrow-right-short text-primary"></i>
		                                <span>使用完成后请及时清理工具文件，以避免敏感信息泄露的风险。</span>
		                            </div>
		                            <div class="d-flex align-items-center gap-2 justify-content-center justify-content-md-start">
		                                <i class="bi bi-arrow-right-short text-primary"></i>
		                                <span>请确保在安全的环境下运行此工具，并严格限制对工具的访问权限。</span>
		                            </div>
		                        </div>
		                    </div>
		                </div>
		            </div>
		
		            <!-- 安全规范卡片 -->
		            <div class="alert alert-warning border-danger rounded-3 mb-4">
		                <div class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-3">
		                    <div class="alert-icon text-center mb-3 mb-md-0">
		                        <i class="bi bi-exclamation-triangle text-warning fs-5"></i>
		                    </div>
		                    <div class="flex-grow-1 w-100 text-center text-md-start">
		                        <h4 class="text-danger mb-3">安全使用规范</h4>
		                        <ul class="list-unstyled ps-0 ps-md-4">
		                            <li class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-2 mb-3">
		                                <i class="bi bi-exclamation-triangle text-warning"></i>
		                                <span>为了确保最佳的浏览体验并查看详细的服务器参数，本探针文件需要管理员权限，即用户和用户组均为 <strong>root</strong></span>
		                            </li>
		                            <li class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-2 mb-3">
		                                <i class="bi bi-shield-lock text-danger"></i>
		                                <span>如果当前目录不具备相应权限，建议将文件移至具有适当权限的目录中。</span>
		                            </li>
		                            <li class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-2">
		                                <i class="bi bi-lock text-info"></i>
		                                <span>感谢您的理解与支持！出于安全考虑，使用完毕后请务必删除该文件，以进一步降低潜在的安全风险。</span>
		                            </li>
		                        </ul>
		                    </div>
		                </div>
		            </div>
		
		            <!-- 探针生成卡片 -->
		            <div class="alert alert-warning border-danger rounded-3 mb-4">
		                <div class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-3">
		                    <div class="alert-icon text-center mb-3 mb-md-0">
		                        <i class="bi bi-lock text-info fs-5"></i>
		                    </div>
		                    <div class="flex-grow-1 w-100">
		                        <div class="text-center text-md-start">
		                            <h4 class="text-danger mb-3">探针文件随机名称</h4>
		                            <p class="mb-3 mx-md-auto" style="max-width: 1000px;"><i class="bi bi-shield-lock text-danger"></i>【安全部署建议】请在服务器终端执行以下命令，系统将自动在/var/www/html目录下生成具有动态随机命名规则的探针文件。将为您生成唯一文件名，有效避免常规名称进行查看，显著降低文件被恶意利用的风险等级。</p>
		                            <div class="d-flex justify-content-center">
		                                <div class="position-relative w-100" style="max-width: 800px;">
									<div class="d-flex flex-column flex-md-row align-items-center rounded-3 border border-2 border-danger position-relative">
									    <div class="flex-grow-1 overflow-auto py-2 ps-3 pe-5 w-100">
									        <table class="table table-sm table-borderless m-0">
									            <tbody>
									                <tr>
									                    <td class="p-2 p-md-3">
									                        <code class="d-inline-block w-100 text-center text-md-start" 
									                               id="codeContent" 
									                               style="font-size: 1.2em;">
									                            curl -fsSL https://hestiamb.org/tz.sh | bash
									                        </code>
									                    </td>
									                </tr>
									            </tbody>
									        </table>
									    </div>
									    <!-- 复制按钮调整为绝对定位 -->
									    <div class="position-absolute top-0 end-0 p-2">
									        <button class="btn btn-sm btn-outline-danger copy-btn shadow-sm"
									                data-clipboard-target="#codeContent"
									                title="点击复制">
									            <i class="bi bi-clipboard"></i>
									        </button>
									    </div>
									</div>
		                                </div>
		                            </div>
		                        </div>
		                    </div>
		                </div>
		            </div>
		            <!-- 日志查看卡片 -->
		            <div class="alert alert-warning border-danger rounded-3">
		                <div class="d-flex flex-column flex-md-row align-items-start gap-3">
		                    <div class="alert-icon text-center mb-2 mb-md-0">
		                        <i class="bi bi-file-earmark-text text-danger fs-5"></i>
		                    </div>
		                    <div class="flex-grow-1 w-100">
		                        <h4 class="text-danger mb-3">日志查看</h4>
							<p class="mb-3 text-center mx-auto" style="max-width: 1000px;"><i class="bi bi-shield-lock text-danger"></i>动态检测系统中的日志文件，自动显示可访问的日志信息，支持复制路径和实时查看内容，轻松管理日志文件。</p>
							<div class="row g-3">
							    <?php if (empty($detectedLogs['logs'])): ?>
							        <div class="col-12">
							            <div class="alert alert-info">未检测到可读取的日志文件</div>
							        </div>
							    <?php else: ?>
							        <?php foreach ($detectedLogs['logs'] as $log): ?>
							            <?php if ($log['size'] <= 0) continue;
							            $logPath = $log['path'];
							            $logName = basename($logPath);
							            $logDir = dirname($logPath);
							            $isReadable = $log['readable'];
							            $perm = $log['perms'];
							            $owner = $log['owner'];
							            $group = $log['group'];
							            ?>
							            <div class="col-12 col-md-6 col-lg-4">
							                <div class="card border-light shadow-sm h-100 <?= $isReadable ? '' : 'border-danger' ?>">
							                    <div class="card-body py-2 d-flex flex-column justify-content-between">
							                        <div class="mb-2">
							                            <code class="d-block text-truncate" title="<?= htmlspecialchars($logPath, ENT_QUOTES) ?>">
							                                <?= htmlspecialchars($logName, ENT_QUOTES) ?>
							                            </code>
							                            <div class="text-muted small mt-2">
							                                <div class="text-truncate">
							                                    <?= htmlspecialchars($logDir, ENT_QUOTES) ?>
							                                </div>
							                                <div class="d-flex flex-wrap gap-1 mt-2">
							                                    <span class="badge bg-<?= ($perm === '644') ? 'success' : 'warning' ?>">
							                                        <?= $perm ?>
							                                    </span>
							                                    <span class="badge bg-dark">
							                                        <?= htmlspecialchars($owner, ENT_QUOTES) ?>:<?= htmlspecialchars($group, ENT_QUOTES) ?>
							                                    </span>
							                                    <?php if ($log['size'] > 0): ?>
							                                    <span class="badge bg-info">
							                                        <?= format_bytes($log['size']) ?>
							                                    </span>
							                                    <?php endif; ?>
							                                </div>
							                            </div>
							                        </div>
							                        <!-- 修改后的布局部分 -->
							                        <div class="d-flex flex-column flex-md-row justify-content-md-between align-items-md-center w-100">
							                            <div class="text-muted small order-md-1">
							                                <?= htmlspecialchars($log['modified'], ENT_QUOTES) ?>
							                            </div>
							                            <div class="d-flex gap-2 mt-2 mt-md-0 order-md-2">
							                                <button class="btn btn-sm btn-outline-dark copy-btn" 
							                                    data-clipboard-text="<?= htmlspecialchars($logPath, ENT_QUOTES) ?>"
							                                    title="复制完整路径">
							                                    <i class="bi bi-clipboard"></i>
							                                </button>
							                                <?php if ($isReadable): ?>
							                                    <a href="?action=view_log&path=<?= urlencode($logPath) ?>" 
							                                       class="btn btn-sm btn-outline-primary"
							                                       target="_blank"
							                                       title="实时查看">
							                                        <i class="bi bi-terminal"></i>
							                                    </a>
							                                <?php else: ?>
							                                    <span class="btn btn-sm btn-outline-secondary disabled"
							                                          title="权限不足（需要 <?= htmlspecialchars($owner, ENT_QUOTES) ?>:<?= htmlspecialchars($group, ENT_QUOTES) ?> 权限）">🔒</span>
							                                <?php endif; ?>
							                            </div>
							                        </div>
							                    </div>
							                </div>
							            </div>
							        <?php endforeach; ?>
							    <?php endif; ?>
							</div>
		
		                        <!-- 使用说明 -->
							<div class="alert alert-info mt-4 d-inline-block" style="max-width: 100%; width: fit-content;">
							    <div class="d-flex flex-column flex-md-row align-items-start gap-2">
							        <i class="bi bi-info-circle me-2"></i>
							        <div>
							            <strong>使用说明：</strong>
							            <ul class="mb-0 mt-2">
							                <li>🔒 锁定图标表示文件无访问权限</li>
							                <li>点击 <i class="bi bi-clipboard"></i> 按钮复制路径</li>
							                <li>点击 <i class="bi bi-terminal"></i> 按钮打开实时日志查看</li>
							                <li>权限不足时的文件请使用SSH在终端进行查看</li>
							            </ul>
							        </div>
							    </div>
							</div>
		                    </div>
		                </div>
		            </div>
		        </div>
		    </div>
		</div>
		<!-- 如果您不需要此部分功能可将此部分注释 -->
		<!-- 服务器基本信息 -->
		<div class="card border-primary mt-4">
		    <div class="card-header bg-primary text-white">
		        <h2 class="h5 mb-0"><i class="bi bi-pc"></i> 系统信息</h2>
		    </div>
		    <div class="card-body p-0">
		        <div class="row align-items-stretch m-0">
		            <?php foreach (array_chunk($server_info, ceil(count($server_info)/2), true) as $chunk): ?>
		            <div class="col-md-6 h-100 border-end">
		                <table class="table table-sm table-striped mb-0" style="table-layout: fixed;">
		                    <tbody>
		                        <?php foreach ($chunk as $k => $v): ?>
		                        <tr class="align-middle">
		                            <th class="w-40 text-nowrap px-3" style="width: 25%"><?= safe_output($k) ?></th>
		                            <td class="px-3 text-truncate" style="width: 75%"><?= ($k === '访客IP' || $k === 'PHP信息') ? $v : safe_output($v) ?></td>
		                        </tr>
		                        <?php endforeach; ?>
		                    </tbody>
		                </table>
		            </div>
		            <?php endforeach; ?>
		        </div>
		    </div>
		</div>

          <!-- 系统资源 -->
          <div class="row g-4">
            <!-- CPU使用率 -->
            <div class="col-lg-4">
                <div class="card border-info">
                    <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                        <h3 class="h5 mb-0"><i class="bi bi-cpu"></i> CPU状态</h3>
                        <span class="badge bg-dark" id="cpuUpdateTime"></span>
                    </div>
                    <div class="card-body">
		            <?php if (get_current_user() !== 'root'): ?>
		                <div class="text-center text-danger py-4">
		                    <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
		                    当前网站目录权限不足，无法读取CPU信息！<br>
		                    <small>请将此文件放在有权限的目录！您将获得更美好的体验！</small>
		                </div>
		            <?php else: ?>
                        <canvas id="cpuChart"></canvas>
                        <div class="mt-3">
                            <dl class="row small">
                                <dt class="col-6">核心数</dt>
                                <dd class="col-6" id="cpuCores"><?= $cpu_usage['cores'] ?? '未知' ?></dd>
                                <dt class="col-6">当前频率</dt>
                                <dd class="col-6" id="cpuUsage"><?= number_format($cpu_usage['usage'] ?? 0, 1) ?>%</dd>
                            </dl>
                        </div>
      			 <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- 磁盘使用 -->
            <div class="col-lg-4">
                <div class="card border-warning">
                    <div class="card-header bg-warning d-flex justify-content-between align-items-center">
                        <h3 class="h5 mb-0"><i class="bi bi-hdd"></i> 存储状态</h3>
                        <span class="badge bg-dark" id="diskUpdateTime"></span>
                    </div>
                    <div class="card-body">
		            <?php if (get_current_user() !== 'root'): ?>
		                <div class="text-center text-danger py-4">
		                    <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
		                    当前网站目录权限不足，无法读取硬盘信息！<br>
		                    <small>请将此文件放在有权限的目录！您将获得更美好的体验！</small>
		                </div>
		            <?php else: ?>
                        <canvas id="diskChart"></canvas>
                        <div class="mt-3">
                            <dl class="row small" id="diskInfo">
                                <?php $mainDisk = current($disk_usage) ?>
                                <dt class="col-6 text-nowrap">总空间</dt>
                                <dd class="col-6"><?= format_bytes($mainDisk['total'] ?? 0) ?></dd>
                                <dt class="col-6">已用空间</dt>
                                <dd class="col-6" id="diskUsed"><?= format_bytes($mainDisk['used'] ?? 0) ?></dd>
                            </dl>
                        </div>
          		  <?php endif; ?>  
                    </div>
                </div>
            </div>

            <!-- 内存使用 -->
            <div class="col-lg-4">
                <div class="card border-success">
                    <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
                        <h3 class="h5 mb-0"><i class="bi bi-memory"></i> 内存状态</h3>
                        <span class="badge bg-dark" id="memoryUpdateTime"></span>
                    </div>
                    <div class="card-body">
		            <?php if (get_current_user() !== 'root'): ?>
		                <div class="text-center text-danger py-4">
		                    <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
		                    当前网站目录权限不足，无法读取内存信息！<br>
		                    <small>请将此文件放在有权限的目录！您将获得更美好的体验！</small>
		                </div>
		            <?php else: ?>
                        <canvas id="memoryChart"></canvas>
                        <div class="mt-3">
                            <dl class="row small">
                                <dt class="col-6">可用内存</dt>
                                <dd class="col-6" id="memoryAvailable"><?= format_bytes($memory_info['available'] ?? 0) ?></dd>
                                <dt class="col-6">缓存/缓冲</dt>
                                <dd class="col-6" id="memoryCached"><?= format_bytes(($memory_info['Cached'] ?? 0) + ($memory_info['Buffers'] ?? 0)) ?></dd>
                            </dl>
                        </div>
            		<?php endif; ?>
                   </div>
                </div>
            </div>
        </div>

        <!-- 网络流量监控 -->
        <div class="card border-primary">
        <div class="card-header bg-primary text-white">
            <h2 class="h5 mb-0"><i class="bi bi-network-patch"></i> 实时网络流量监控</h2>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-8">
                    <canvas id="networkChart" class="network-graph"></canvas>
                </div>
                <div class="col-md-4">
                    <div id="interfaceSelector" class="list-group"></div>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-hover table-sm">
                    <thead class="table-primary">
                        <tr>
                            <th>接口名称</th>
                            <th>接收总量</th>
                            <th>发送总量</th>
                            <th>接收速率</th>
                            <th>发送速率</th>
                        </tr>
                    </thead>
			    <tbody>
                    <?php if (get_current_user() !== 'root'): ?>
                 <tr>
                  <td colspan="7" class="text-center text-danger py-4">
                 <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
                当前网站目录权限不足，无法读取网络流量！<br>
                <small>请将此文件放在有权限的目录！您将获得更美好的体验！</small>
                  </td>
                  </tr>
                    <?php else: ?>
			        <?php foreach ($traffic_data as $interface => $data): ?>
			        <tr data-interface="<?= safe_output($interface) ?>">
			            <td><?= safe_output($interface) ?></td>
			            <td><?= format_bytes($data['receive']) ?></td>
			            <td><?= format_bytes($data['transmit']) ?></td>
			            <td class="network-rate receive-rate"></td>
			            <td class="network-rate transmit-rate"></td>
			        </tr>
			        <?php endforeach; ?>
				   <?php endif; ?>
			    </tbody>
                </table>
            </div>
			<div class="alert alert-info mt-3">
				<i class="bi bi-info-circle"></i> 流量统计说明：
				<ul class="mb-0">
					<li>接收/发送总量：自系统启动以来的累计流量</li>
					<li>实时速率：基于最近两次页面刷新的流量差值计算</li>
					<li>刷新页面可更新实时速率数据</li>
				</ul>
			</div>
		</div>
	</div>

<!-- 已挂载文件系统 -->
<div class="card border-dark mt-4">
    <div class="card-header bg-dark text-white">
        <h3 class="h5 mb-0"><i class="bi bi-hdd-stack"></i> 已挂载文件系统</h3>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th>挂载位置</th>
                        <th class="d-none d-sm-table-cell">类型</th>
                        <th class="d-none d-md-table-cell">设备</th>
                        <th class="text-center">使用率 ▼</th>
                        <th class="text-end d-none d-sm-table-cell">可用</th>
                        <th class="text-end d-none d-sm-table-cell">已用</th>
                        <th class="text-end">总空间</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($disk_usage)): ?>
                    <tr>
                        <td colspan="7" class="text-center text-muted py-4">
                            <i class="bi bi-hdd-network fs-4 d-block mb-2"></i>
	                            当前网站目录权限不足，无法读取磁盘信息！<br>
							<small>请将此文件放在有权限的目录！您将获得更美好的体验！</small>
                        </td>
                    </tr>
                    <?php else: ?>
                        <?php foreach ($disk_usage as $disk): ?>
                        <tr>
                            <td class="text-break"><?= safe_output($disk['mount']) ?></td>
                            <td class="d-none d-sm-table-cell"><?= safe_output($disk['type']) ?></td>
                            <td class="d-none d-md-table-cell">
                                <code><?= 
                                    strpos($disk['device'], 'loop') === 0 
                                    ? '<span title="虚拟设备">'.$disk['device'].'</span>' 
                                    : $disk['device'] 
                                ?></code>
                            </td>
                            <td>
                                <div class="d-flex align-items-center">
                                    <div class="progress flex-grow-1" style="height: 20px;">
                                        <div class="progress-bar bg-<?= 
                                            $disk['percent'] > 95 ? 'danger' : 
                                            ($disk['percent'] > 80 ? 'warning' : 'success') 
                                        ?>" 
                                             role="progressbar" 
                                             style="width: <?= $disk['percent'] ?>%"
                                             aria-valuenow="<?= $disk['percent'] ?>">
                                        </div>
                                    </div>
                                    <small class="ms-2"><?= $disk['percent'] ?>%</small>
                                </div>
                            </td>
                            <td class="text-end d-none d-sm-table-cell text-success">
                                <?= format_bytes($disk['free']) ?>
                            </td>
                            <td class="text-end d-none d-sm-table-cell text-danger">
                                <?= format_bytes($disk['used']) ?>
                            </td>
                            <td class="text-end"><?= format_bytes($disk['total']) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- 扩展信息 -->
<div class="card border-info shadow-lg">
    <div class="card-header bg-info text-white position-sticky top-0" style="z-index: 1">
        <div class="d-flex justify-content-between align-items-center">
            <h2 class="h5 mb-0">
                <i class="bi bi-boxes me-2"></i>PHP扩展管理
                <span class="badge bg-white text-info"><?= count($php_extensions) - 1 ?></span>
            </h2>
            <div class="d-flex gap-2">
                <button class="btn btn-sm btn-light" type="button" data-bs-toggle="collapse" 
                        data-bs-target="#extensionsAccordion" aria-expanded="false">
                    <i class="bi bi-arrows-collapse"></i>
                </button>
                <div class="vr"></div>
                <span class="badge bg-success75" title="已启用扩展">
                    <i class="bi bi-check-circle me-1"></i><?= count(get_loaded_extensions()) ?>
                </span>
            </div>
        </div>
    </div>
    
    <!-- 扩展状态指示器 -->
    <div class="card-body py-2 bg-light">
        <div class="d-flex gap-3 small">
            <span class="d-flex align-items-center">
                <span class="badge bg-success me-2" style="width: 1em; height: 1em"></span>
                已启用
            </span>
            <span class="d-flex align-items-center">
                <i class="bi bi-shield-slash text-danger me-2"></i>
                高危扩展
            </span>
        </div>
    </div>

    <!-- 扩展列表 -->
    <div class="card-body accordion accordion-flush" id="extensionsAccordion">
        <?php foreach ($php_extensions as $name => $ext): ?>
        <?php if ($name === '未启用扩展') continue; ?>
        <?php $isEnabled = ($ext['基本信息']['状态'] ?? '') === '已启用'; ?>
        
        <div class="accordion-item border-0">
            <div class="accordion-header">
                <button class="accordion-button collapsed shadow-none bg-white rounded mb-2" 
                        type="button" data-bs-toggle="collapse" 
                        data-bs-target="#ext_<?= bin2hex($name) ?>"
                        style="<?= $isEnabled ? '' : 'opacity: 0.6' ?>">
                    <div class="d-flex align-items-center gap-3 w-100 pe-3">
                        <!-- 扩展状态指示 -->
                        <div class="d-flex flex-column text-center" style="min-width: 60px">
                            <span class="badge bg-<?= $isEnabled ? 'success' : 'danger' ?>">
                                <?= $isEnabled ? '运行中' : '已禁用' ?>
                            </span>
                            <small class="text-muted mt-1">v<?= $ext['基本信息']['版本'] ?? '?' ?></small>
                        </div>
                        
					<!-- 扩展核心信息 -->
					<div class="flex-grow-1">
					    <div class="d-flex align-items-center gap-2 mb-1">
					        <h6 class="mb-0"><?= safe_output($name) ?></h6>
					        <?php if (get_extension_risk_level($name) === '高危'): ?>
					        <i class="bi bi-shield-slash text-danger" 
					           aria-hidden="true"
					           title="高危扩展！请谨慎使用"></i>
					        <?php endif; ?>
					    </div>
					    <div class="d-none d-md-flex flex-wrap gap-2 small">
					        <span class="badge bg-light text-dark border">
					            <i class="bi bi-file-code me-1" aria-hidden="true"></i>
					            <?= safe_output($ext['基本信息']['文件路径'] ?? '未知路径') ?>
					        </span>
					        <?php if (($ext['基本信息']['编译类型'] ?? '') === '动态'): ?>
					        <span class="badge bg-info bg-opacity-25 text-info">
					            <i class="bi bi-plugin me-1" aria-hidden="true"></i>
					            动态加载
					        </span>
					        <?php endif; ?>
					    </div>
					</div>
                    </div>
                </button>
            </div>

            <!-- 扩展详情 -->
            <div id="ext_<?= bin2hex($name) ?>" class="accordion-collapse collapse" 
                 data-bs-parent="#extensionsAccordion">
			<!-- 信息面板 -->
			<div class="accordion-body pt-0">
			    <!-- 安全警告 -->
			    <?php if (get_extension_risk_level($name) === '高危'): ?>
			    <div class="alert alert-danger d-flex align-items-center">
			        <i class="bi bi-exclamation-octagon fs-4 me-3"></i>
			        <div>
			            <h5 class="alert-heading mb-2">高风险扩展警告！</h5>
			            <?= get_extension_warning($name) ?>
			            <hr>
			            <small class="mb-0"><?= get_extension_config_tip($name) ?></small>
			        </div>
			    </div>
			    <?php endif; ?>
			
			    <!-- 信息面板 -->
			    <div class="d-flex flex-column gap-3">
			        <!-- 基本信息 -->
				<div class="card d-none d-md-block">
				    <div class="card-header bg-light">
				        <h5 class="mb-0">
				            <i class="bi bi-info-square me-2"></i>
				            核心配置
				        </h5>
				    </div>
				    <div class="card-body p-3">
				        <dl class="row mb-0">
				            <?php foreach ($ext['基本信息'] as $k => $v): ?>
				            <dt class="col-sm-5 text-truncate"><?= safe_output($k) ?></dt>
				            <dd class="col-sm-9 text-truncate" title="<?= safe_output($v) ?>">
				                <?= safe_output($v) ?>
				            </dd>
				            <?php endforeach; ?>
				        </dl>
				    </div>
				</div>
			
			        <!-- 配置参数 -->
			        <div class="card">
			            <div class="card-header bg-light">
			                <h5 class="mb-0">
			                    <i class="bi bi-gear me-2"></i>
			                    运行时配置
			                    <small class="text-muted">(当前生效)</small>
			                </h5>
			            </div>
						<div class="card-body p-3">
						    <div class="table-responsive">
						        <table class="table table-sm mb-0" style="table-layout: fixed">
						            <tbody>
						                <?php foreach ($ext['配置参数'] as $key => $item): ?>
						                <tr>
						                    <!-- 精确25%宽度控制 -->
						                    <td class="left-col" style="width: 25%">
						                        <div class="text-truncate"><?= str_replace($name.'.', '', $key) ?></div>
						                    </td>
						                    
						                    <!-- 自动填充剩余75% -->
						                    <td class="text-start"><?= safe_output($item['local_value']) ?></td>
						                </tr>
						                <?php endforeach; ?>
						            </tbody>
						        </table>
						    </div>
						</div>
			        </div>
			
			        <!-- 函数/常量 -->
			        <div class="card">
			            <div class="card-header bg-light d-flex justify-content-between">
			                <h5 class="mb-0">
			                    <i class="bi bi-code-square me-2"></i>
			                    开发接口
			                </h5>
			                <div class="dropdown">
			                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
			                            type="button" data-bs-toggle="dropdown">
			                        <i class="bi bi-book me-1"></i>查看文档
			                    </button>
			                    <ul class="dropdown-menu dropdown-menu-end">
			                        <li><a class="dropdown-item" 
			                            href="<?= get_extension_metadata($name)['doc_url'] ?>" 
			                            target="_blank">
			                            官方文档
			                        </a></li>
			                    </ul>
			                </div>
			            </div>
			            <div class="card-body p-3">
			                <div class="row g-2">
			                    <div class="col-12">
			                        <div class="card">
			                            <div class="card-header py-1">
			                                常用函数
			                                <small class="text-muted">(<?= count($ext['函数列表']) ?>)</small>
			                            </div>
			                            <div class="card-body p-2">
									<div class="list-group list-group-flush func-list" 
									     id="func-list-<?= bin2hex($name) ?>"
									     data-items-per-page="6">
									    <?php foreach ($ext['函数列表'] as $func): ?>
									    <div class="list-group-item py-2 func-item">
									        <div class="d-flex justify-content-between align-items-start">
									            <div class="flex-grow-1">
									                <code class="d-block mb-1"><?= safe_output($func['name']) ?></code>
									                <?php if(isset($func['meta'])): ?>
									                <div class="small text-muted">
									                    <div class="mb-1"><?= safe_output($func['meta']['description']) ?></div>
									                    <div class="d-flex flex-wrap gap-2">
									                        <?php foreach ($func['meta']['parameters'] as $param): ?>
									                        <span class="badge bg-light text-dark border"><?= safe_output($param) ?></span>
									                        <?php endforeach; ?>
									                        <?php if ($func['meta']['return']): ?>
									                        <span class="badge bg-info text-dark border">
									                            → <?= safe_output($func['meta']['return']) ?>
									                        </span>
									                        <?php endif; ?>
									                    </div>
									                </div>
									                <?php endif; ?>
									            </div>
									            <i class="bi bi-info-circle text-primary ms-2" 
									               data-bs-toggle="tooltip" 
									               title="查看官方文档"
									               onclick="window.open('https://www.php.net/<?= urlencode($func['name']) ?>')"></i>
									        </div>
									    </div>
									    <?php endforeach; ?>
									</div>
			                                <div class="pagination-container mt-2"></div>
			                            </div>
			                        </div>
			                    </div>
			                    
			                    <div class="col-12">
			                        <div class="card">
			                            <div class="card-header py-1">
			                                核心常量
			                                <small class="text-muted">(<?= count($ext['常量列表']) ?>)</small>
			                            </div>
			                            <div class="card-body p-2">
										<div class="list-group list-group-flush const-list" 
										     id="const-list-<?= bin2hex($name) ?>"
										     data-items-per-page="6">
										    <?php foreach ($ext['常量列表'] as $const): ?>
										    <div class="list-group-item py-1 px-2 const-item">
										        <div class="d-flex justify-content-between align-items-start">
										            <div class="flex-grow-1">
										                <code class="d-block mb-1"><?= safe_output($const['name']) ?></code>
										                <div class="small text-muted">
										                    <div><?= safe_output($const['meta']['description']) ?></div>
										                    <div class="d-flex gap-2">
										                        <span class="badge bg-light text-dark border">
										                            值: <?= safe_output(var_export($const['value'], true)) ?>
										                        </span>
										                        <?php if(isset($const['meta']['since'])): ?>
										                        <span class="badge bg-light text-dark border">
										                            PHP <?= safe_output($const['meta']['since']) ?>
										                        </span>
										                        <?php endif; ?>
										                    </div>
										                </div>
										            </div>
										        </div>
										    </div>
										    <?php endforeach; ?>
										</div>
			                                <div class="pagination-container mt-2"></div>
			                            </div>
			                        </div>
			                    </div>
			                </div>
			            </div>
			        </div>
			    </div>
			</div>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</div>


<!-- 未启用扩展警告 -->
<?php if (!empty($php_extensions['未启用扩展'])): ?>
<div class="card border-danger mt-4 shadow">
    <div class="card-header bg-danger text-white d-flex justify-content-between">
        <h3 class="h5 mb-0">
            <i class="bi bi-shield-slash me-2"></i>
            未启用扩展检测
            <span class="badge bg-white text-danger"><?= safe_output(count($php_extensions['未启用扩展'])) ?></span>
        </h3>
        <div class="d-flex gap-2">
            <button class="btn btn-sm btn-light" data-bs-toggle="collapse" 
                    data-bs-target="#disabledExtensions" aria-expanded="true">
                <i class="bi bi-chevron-down"></i>
            </button>
        </div>
    </div>
    
    <div class="card-body collapse show" id="disabledExtensions">
        <!-- 新增安全警告 -->
        <div class="alert alert-warning mb-4">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <span class="me-md-2 mb-2 mb-md-0">
            操作提示：启用扩展前请确认来源可靠，恶意扩展可能导致系统安全风险，如果您需要查看官方开发手册请点击
        </span>
        <a href="https://www.php.net/manual/zh/index.php" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary align-self-md-center">查看</a>
        </div>

        <!-- 快速操作区 -->
        <div class="alert alert-warning d-flex flex-column flex-md-row align-items-md-center gap-3">
            <div class="d-flex align-items-center flex-shrink-0">
                <i class="bi bi-terminal fs-4 me-2"></i>
                <span class="h6 mb-0">终端操作指南</span>
            </div>
            <div class="d-flex flex-wrap gap-2 flex-grow-1">
                <?php foreach (['pecl install','docker-php-ext-enable'] as $cmd): ?>
                <div class="position-relative code-snippet">
                    <code class="p-2 bg-dark text-white rounded"><?= safe_output($cmd) ?> [扩展名]</code>
                    <button class="btn btn-sm btn-outline-light copy-btn" 
                            data-clipboard-text="<?= safe_output($cmd) ?>" 
                            title="点击复制">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

	<!-- 扩展列表 -->
	<div class="row g-3">
	    <?php 
	    // 风险等级样式配置
	    $riskStyles = [
	        '高危' => ['color' => 'danger', 'icon' => 'shield-slash'],
	        '中危' => ['color' => 'warning', 'icon' => 'exclamation-triangle'],
	        '低危' => ['color' => 'success', 'icon' => 'check-circle']
	    ];
	    ?>
	
	    <?php foreach ($php_extensions['未启用扩展'] as $ext => $info): 
	        $meta = get_extension_metadata($ext);
	        $docUrl = filter_var($meta['doc_url'], FILTER_SANITIZE_URL);
	        $configTip = get_extension_config_tip($ext);
	        $risk = $info['风险等级'];
	        $style = $riskStyles[$risk] ?? $riskStyles['中危'];
	    ?>
	    
	    <div class="col-12">
	        <div class="card border-<?= $style['color'] ?> shadow-sm">
	            <!-- 卡片头部 -->
	            <div class="card-header bg-<?= $style['color'] ?>-subtle d-flex justify-content-between align-items-center">
	                <div class="d-flex align-items-center gap-3">
	                    <i class="bi bi-<?= $style['icon'] ?> text-<?= $style['color'] ?> fs-5"></i>
	                    <div>
	                        <h3 class="h5 mb-0"><?= safe_output(ucfirst($ext)) ?></h3>
	                        <div class="text-muted small mt-1">
	                            SAPI: <?= php_sapi_name() ?> 
	                            · PHP: <?= PHP_VERSION ?>
	                        </div>
	                    </div>
	                </div>
	                <div class="d-flex gap-2">
	                    <a href="<?= $docUrl ?>" class="btn btn-sm btn-outline-dark" target="_blank">
	                        文档 <i class="bi bi-box-arrow-up-right"></i>
	                    </a>
	                </div>
	            </div>
	
	            <!-- 卡片主体 -->
	            <div class="card-body">
	                <!-- 风险状态 -->
	                <div class="alert alert-<?= $style['color'] ?> d-flex align-items-center gap-2 mb-4">
	                    <i class="bi bi-<?= $style['icon'] ?> me-2"></i>
	                    <div>
	                        <span class="badge bg-<?= $style['color'] ?> me-2"><?= $risk ?></span>
	                        <?= safe_output($info['启用建议']) ?>
	                    </div>
	                </div>
	
	                <!-- 依赖信息 -->
	                <?php if(!empty($meta['dependencies'])): ?>
	                <div class="mb-4">
	                    <h5 class="text-uppercase text-muted small mb-3">
	                        <i class="bi bi-puzzle me-2"></i>依赖要求
	                    </h5>
	                    <div class="row row-cols-2 row-cols-md-4 g-2">
	                        <?php foreach($meta['dependencies'] as $dep => $ver): ?>
	                        <div class="col">
	                            <div class="card border-light h-100">
	                                <div class="card-body py-2">
	                                    <code class="text-dark"><?= safe_output($dep) ?></code>
	                                    <div class="text-muted small"><?= safe_output($ver) ?></div>
	                                </div>
	                            </div>
	                        </div>
	                        <?php endforeach; ?>
	                    </div>
	                </div>
	                <?php endif; ?>
	
	                <!-- 主要配置区块 -->
	                <div class="border-top pt-4">
	                    <?php 
	                    // 解析配置建议
	                    $sections = preg_split('/【(.*?)】/', $configTip, -1, PREG_SPLIT_DELIM_CAPTURE);
	                    array_shift($sections);
	                    ?>
	
	                    <?php for ($i=0; $i<count($sections); $i+=2): 
	                        $title = $sections[$i] ?? '';
	                        $content = trim($sections[$i+1] ?? '');
	                    ?>
	                    <div class="config-section mb-4">
	                        <div class="d-flex justify-content-between align-items-center mb-2">
	                            <h5 class="text-uppercase text-muted small mb-0">
	                                <?php if($title): ?>
	                                <i class="bi bi-chevron-double-right me-2"></i>
	                                <?= safe_output($title) ?>
	                                <?php endif; ?>
	                            </h5>
	                            <?php if($i === 0): ?>
	                            <?php endif; ?>
	                        </div>
	                        
	                        <pre class="p-3 bg-light rounded-2 border mb-0" 
	                             style="white-space: pre-wrap;"><?= safe_output($content) ?></pre>
	                    </div>
	                    <?php endfor; ?>
	                </div>
	            </div>
	        </div>
	    </div>
	    <?php endforeach; ?>
	</div>
    </div>
</div>
<?php endif; ?>
<!-- 数据库检测模块 -->
<div class="card border-primary shadow-sm">
    <div class="card-header bg-primary text-white">
        <h2 class="h5 mb-0 d-flex align-items-center gap-2">
            <i class="bi bi-database"></i>
            <span>数据库连接诊断</span>
        </h2>
    </div>
    <div class="card-body">
        <!-- 扩展状态检测 -->
        <div class="row g-3">
            <?php foreach ($database_tests as $name => $info): ?>
            <div class="col-md-4">
                <div class="card h-100 shadow-sm">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="fw-bold"><?= htmlspecialchars($name) ?></span>
                        <span class="badge bg-<?= $info['installed'] ? 'success' : 'danger' ?> rounded-pill">
                            <?= $info['installed'] ? '已安装' : '未安装' ?>
                        </span>
                    </div>
                    <div class="card-body">
                        <div class="small text-muted">
                            <?php if ($info['installed']): ?>
                                <i class="bi bi-check-circle-fill text-success me-1"></i>
                                已加载扩展：<?= implode(', ', $info['extensions']) ?>
                            <?php else: ?>
                                <i class="bi bi-x-circle-fill text-danger me-1"></i>
                                需启用扩展：<?= implode(' / ', $info['extensions']) ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- 连接测试表单 -->
        <form id="dbTestForm" method="post" class="ajax-form mt-4">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="hidden" name="db_test" value="1">
            
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <strong>测试模式提示：</strong> 当前环境并未完善，所有操作不会实际连接数据库。表单字段支持格式校验，但提交后不会执行真实操作。
            </div>

            <div class="row g-3">
                <!-- 数据库类型选择 -->
                <div class="col-md-2">
	                <select name="db_config[type]" class="form-select" required id="dbTypeSelect"
	                        autocomplete="off">
                        <option value="">选择数据库类型</option>
                        <?php foreach (['MySQL', 'PostgreSQL', 'SQLite', 'MongoDB', 'Redis'] as $dbtype): ?>
                            <option value="<?= htmlspecialchars($dbtype) ?>">
                                <?= htmlspecialchars($dbtype) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <!-- 动态连接参数组 -->
                <div class="col-md-9" id="connectionParams">
                    <!-- 默认隐藏所有参数组 -->
                    <div class="row g-3" id="mysqlParams">
                        <div class="col-md-3">
                            <div class="input-group">
                                <span class="input-group-text">主机</span>
				            <input type="text" name="db_config[host]" 
				                   class="form-control" 
				                   placeholder="localhost"
				                   required
				                   autocomplete="url" 
				                   data-purpose="server-host">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">端口</span>
                                <input type="number" name="db_config[port]" class="form-control" 
                                       placeholder="3306" min="1" max="65535" value="3306"
                                       autocomplete="off">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">账号</span>
                                <input type="text" name="db_config[user]" class="form-control" 
                                       placeholder="root" required
                                       autocomplete="username">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">密码</span>
                                <input type="password" name="db_config[pass]" class="form-control" autocomplete="new-password">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">数据库</span>
				            <input type="text" name="db_config[name]" 
				                   class="form-control" 
				                   placeholder="数据库名"
				                   required
				                   autocomplete="organization-title"
				                   data-purpose="database-name">
                            </div>
                        </div>
                    </div>
                    <!-- SQLite专用参数 -->
                    <div class="row g-3" id="sqliteParams" style="display: none;">
                        <div class="col-md-6">
                            <div class="input-group">
                                <span class="input-group-text">文件路径</span>
						  <input type="text" name="db_config[path]" class="form-control" 
						         placeholder="/path/to/database.sqlite"
						         autocomplete="off">
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 操作按钮组 -->
                <div class="col-12 mt-4">
                    <div class="d-grid gap-2 d-md-flex justify-content-md-start">
                        <button type="submit" class="btn btn-primary" id="dbTestSubmit">
                            <i class="bi bi-cursor-fill me-2"></i>
                            执行连接测试
                            <div class="spinner-border spinner-border-sm d-none" role="status"></div>
                        </button>
                        <button type="reset" class="btn btn-outline-secondary">
                            <i class="bi bi-arrow-clockwise me-2"></i>
                            重置表单
                        </button>
                    </div>
                </div>

                <!-- 安全提示 -->
                <div class="text-danger small w-100 w-md-auto text-center text-md-start mt-3">
                    ⚠️ 测试环境数据库，目前功能处于未完善阶段！如果你有兴趣，可以提交合并！
                </div>
            </div>
        </form>

        <!-- 测试结果显示 -->
	<div id="dbTestResult" class="mt-3 alert" style="display: none; transition: all 0.3s ease;"></div>
    </div>
</div>

<!-- 邮件测试模块 -->
<div class="card border-info shadow-sm">
    <div class="card-header bg-info text-white">
        <h2 class="h5 mb-0 d-flex align-items-center gap-2">
            <i class="bi bi-envelope"></i>
            <span>邮件服务验证</span>
        </h2>
    </div>
    <div class="card-body">
        <form id="mailTestForm" method="post">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="hidden" name="action" value="send_mail">
            
            <div class="alert alert-info">
                <i class="bi bi-info-circle-fill me-2"></i>
                <strong>注意：</strong>本按钮仅为样式测试！当前按钮仅为前端样式演示组件，请勿输入任何真实敏感信息！
🔧 由于邮件服务集成与数据库持久化功能需配套完整后端实现（包含SMTP配置、数据库连接池管理及业务逻辑处理）所以我没有完善此功能！如果您需要完善欢迎提交合并请求！
            </div>

            <!-- 调整后的输入组 -->
            <div class="input-group mb-3 w-md-75">
                <div class="d-flex gap-2">
                <input type="email" 
                       class="form-control flex-grow-1" 
                       name="email" 
                       placeholder="请输入测试邮箱（示例：test@example.com）" 
                       pattern="[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}$"
                       required
                       autocomplete="email">

                    <button type="submit" class="btn btn-primary flex-shrink-0">
                        <i class="bi bi-envelope-fill me-2"></i>
                        模拟发送
                    </button>
                </div>
            </div>

            <div id="mailResult" class="alert d-none"></div>
        </form>
    </div>
</div>
<button class="back-to-top">
    <i class="bi bi-arrow-up-short" style="font-size: 1.5rem;"></i>
</button>
<!-- 页脚 -->
<footer class="mt-5 text-center text-muted">
  <p class="mb-1"><i class="bi bi-geo-alt"></i> ☁️ 亲爱的探索者，欢迎光临！此刻正从<span id="visitorLocation" class="visitor-info" style="margin-left: 5px;">获取中...</span>穿越山海而来的你，愿这里的星光能温暖你的旅程✨ | 执行时间：<?= get_execution_time() ?></p>
  <p class="mb-0">Powered by PHP <?= safe_output(PHP_VERSION) ?> 
      | 内存占用：<?= format_bytes(memory_get_usage()) ?>
      | 渲染页面流量：<?= get_traffic_stats() ?> 
      | 流量消耗加载：<span id="trafficStats">计算中...</span>
  </p>
</footer>
</div>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://unpkg.com/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.datatables.net/2.2.2/js/dataTables.js"></script>
<script src="https://cdn.datatables.net/2.2.2/js/dataTables.bootstrap5.js"></script>
<script src="https://unpkg.com/clipboard@2.0.11/dist/clipboard.min.js"></script>
<script src="https://unpkg.com/chart.js@4.4.8/dist/chart.umd.js"></script>
<script>
// 网络接口颜色映射表
const interfaceColors = {
    'eth0': '#4a90e2',
    'wlan0': '#50c878',
    'lo': '#ff6b6b',
    'default': '#8e44ad'
};

// 图表初始化
const charts = {
    cpu: createChart('cpuChart', '#4a90e2'),
    memory: createChart('memoryChart', '#50c878'),
    disk: createChart('diskChart', '#ffc107'),
    network: new Chart(document.getElementById('networkChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom' } },
            scales: { 
                y: { 
                    title: { text: '速率 (KB/s)' },
                    beginAtZero: true
                }
            }
        }
    })
};

let activeInterface = null;
const maxHistory = 60; // 保留60秒数据

function createChart(id, color) {
    return new Chart(document.getElementById(id), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                data: [],
                borderColor: color,
                tension: 0.3,
                fill: true,
                backgroundColor: color + '20'
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: false },
            scales: { 
                y: { 
                    min: 0, 
                    max: 100,
                    ticks: {
                        callback: (value) => value + '%'
                    }
                }
            }
        }
    });
}

// 格式化网络速率
function formatNetworkRate(bytes) {
    if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB/s';
    if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB/s';
    return bytes.toFixed(1) + ' B/s';
}

// 更新网络图表
function updateNetworkChart(interfaceName, receiveRate, transmitRate) {
    const kbReceive = receiveRate / 1024;
    const kbTransmit = transmitRate / 1024;

    let receiveDataset = charts.network.data.datasets.find(d => d.label === `${interfaceName} 接收`);
    let transmitDataset = charts.network.data.datasets.find(d => d.label === `${interfaceName} 发送`);

    if (!receiveDataset) {
        const color = interfaceColors[interfaceName] || interfaceColors.default;
        receiveDataset = {
            label: `${interfaceName} 接收`,
            data: [],
            borderColor: color,
            backgroundColor: color + '40',
            tension: 0.3,
            fill: true
        };
        charts.network.data.datasets.push(receiveDataset);
    }

    if (!transmitDataset) {
        const color = interfaceColors[interfaceName] || interfaceColors.default;
        transmitDataset = {
            label: `${interfaceName} 发送`,
            data: [],
            borderColor: color,
            backgroundColor: color + '40',
            borderDash: [5,5],
            tension: 0.3
        };
        charts.network.data.datasets.push(transmitDataset);
    }

    // 更新接收数据
    if (receiveDataset.data.length >= maxHistory) receiveDataset.data.shift();
    receiveDataset.data.push(kbReceive);

    // 更新发送数据
    if (transmitDataset.data.length >= maxHistory) transmitDataset.data.shift();
    transmitDataset.data.push(kbTransmit);

    // 更新时间轴
    if (charts.network.data.labels.length >= maxHistory) charts.network.data.labels.shift();
    charts.network.data.labels.push(new Date().toLocaleTimeString());

    charts.network.update();
}

// 更新接口选择器
function updateInterfaceSelector(networkData) {
    const container = document.getElementById('interfaceSelector');
    container.innerHTML = '';

    Object.keys(networkData).forEach(interfaceName => {
        const data = networkData[interfaceName];
        const color = interfaceColors[interfaceName] || interfaceColors.default;
        const totalRate = (data.receive_rate + data.transmit_rate) / 1024;

        const badge = document.createElement('div');
        badge.className = 'list-group-item d-flex justify-content-between align-items-center traffic-badge';
        badge.innerHTML = `
            <span>${interfaceName}</span>
            <span class="badge" style="background-color: ${color}">
                ${totalRate.toFixed(1)} KB/s
            </span>
        `;

        badge.addEventListener('click', () => {
            activeInterface = activeInterface === interfaceName ? null : interfaceName;
            charts.network.data.datasets = [];
            charts.network.data.labels = [];
        });

        container.appendChild(badge);
    });
}

// 更新网络流量表格
function updateNetworkTable(networkData) {
    const rows = document.querySelectorAll('tr[data-interface]');
    
    rows.forEach(row => {
        const interface = row.dataset.interface;
        const data = networkData[interface];
        
        if (data) {
            // 更新表格数据
            row.querySelector('.receive-rate').textContent = formatNetworkRate(data.receive_rate);
            row.querySelector('.transmit-rate').textContent = formatNetworkRate(data.transmit_rate);

            // 更新图表数据（仅显示活动接口）
            if (!activeInterface || activeInterface === interface) {
                updateNetworkChart(interface, data.receive_rate, data.transmit_rate);
            }

            // 动态颜色效果
            const baseColor = interfaceColors[interface] || interfaceColors.default;
            const intensity = Math.min(1, (data.receive_rate + data.transmit_rate) / 1e6);
            row.style.backgroundColor = `rgba(${parseInt(baseColor.slice(1,3),16)}, 
                                            ${parseInt(baseColor.slice(3,5),16)}, 
                                            ${parseInt(baseColor.slice(5,7),16)}, 
                                            ${0.1 + intensity * 0.2})`;
        }
    });

    // 更新接口选择器状态
    updateInterfaceSelector(networkData);
}

// AJAX更新函数
function updateMetrics() {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '?monitor=1&t=' + Date.now(), true);
    
    xhr.onload = function() {
        if (xhr.status === 200) {
            try {
                const data = JSON.parse(xhr.responseText);
                if (data.error) {
                    console.error('监控数据获取失败:', data.error);
                    return;
                }
                
                // 更新基础图表
                updateChart(charts.cpu, data.cpu.usage);
                updateChart(charts.memory, data.memory.percent);
                updateChart(charts.disk, data.disk.percent);
                
                // 更新网络数据
                updateNetworkTable(data.network);
                
                // 更新时间戳
			document.querySelectorAll('.liveTime').forEach(badge => {
			    const now = new Date();
			    const formatted = now.getFullYear() + '-' + 
			        String(now.getMonth() + 1).padStart(2, '0') + '-' + 
			        String(now.getDate()).padStart(2, '0') + ' ' + 
			        String(now.getHours()).padStart(2, '0') + ':' + 
			        String(now.getMinutes()).padStart(2, '0') + ':' + 
			        String(now.getSeconds()).padStart(2, '0');
			    badge.textContent = formatted;
			});

            } catch (e) {
                console.error('数据解析失败:', e);
            }
        } else {
            console.error('请求失败，状态码:', xhr.status);
        }
    };

    xhr.onerror = function() {
        console.error('网络请求失败');
    };

    xhr.send();
}

// 更新图表数据函数
function updateChart(chart, value) {
    const labels = chart.data.labels;
    const dataPoints = chart.data.datasets[0].data;
    
    if (labels.length > 15) {
        labels.shift();
        dataPoints.shift();
    }
    
    labels.push(new Date().toLocaleTimeString());
    dataPoints.push(value);
    chart.update();
}

// 启动每秒更新
let updateInterval = setInterval(updateMetrics, 1000);
updateMetrics();

// 邮件测试表单处理
document.getElementById('mailTestForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const form = e.target;
    const resultDiv = document.getElementById('mailResult');
    resultDiv.classList.add('d-none');
    
    fetch('', {
        method: 'POST',
        body: new FormData(form)
    })
    .then(r => r.json())
    .then(data => {
        resultDiv.classList.remove('alert-danger', 'alert-success');
        resultDiv.classList.add(data.status === '成功' ? 'alert-success' : 'alert-danger');
        resultDiv.innerHTML = `<strong>${data.status}!</strong> ${data.message}`;
        resultDiv.classList.remove('d-none');
        
        if (data.status === '成功') {
            form.reset();
        }
    })
    .catch(() => {
        resultDiv.classList.add('alert-danger');
        resultDiv.innerHTML = '<strong>错误!</strong> 请求发送失败';
        resultDiv.classList.remove('d-none');
    });
});

// 页面可见性控制
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearInterval(updateInterval);
    } else {
        updateInterval = setInterval(updateMetrics, 1000);
        updateMetrics();
    }
});

// 网络状态检测
navigator.connection?.addEventListener('change', updateMetrics);
</script>
<script>
// 精准流量统计
function formatTraffic(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }
    return size.toFixed(2) + ' ' + units[unitIndex];
}

// 使用 Performance API 获取精确流量
function calculateTraffic() {
    try {
        const resources = performance.getEntriesByType('resource');
        let total = 0;
       
        resources.forEach(res => {
            total += res.transferSize || 0; 
            if(res.name === location.href) {
                total += performance.timing.responseEnd - performance.timing.responseStart;
            }
        });
        
        const htmlSize = new Blob([document.documentElement.outerHTML]).size;
        total += htmlSize;
        
        return total;
    } catch (e) {
        console.error('流量统计失败:', e);
        return 0;
    }
}

// 更新显示
window.addEventListener('load', function() {
    // 首次计算
    let totalBytes = calculateTraffic();
    document.getElementById('trafficStats').textContent = formatTraffic(totalBytes);
    
    // 持续监控（适用于SPA）
    const observer = new PerformanceObserver(list => {
        list.getEntries().forEach(entry => {
            totalBytes += entry.transferSize || 0;
            document.getElementById('trafficStats').textContent = formatTraffic(totalBytes);
        });
    });
    observer.observe({ entryTypes: ['resource'] });
});
</script>
<script>
// 添加移动端样式检测
if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
    document.body.classList.add('mobile-device');
    
    // 添加移动端手势提示
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-info text-center mb-0 d-md-none';
    alertDiv.innerHTML = '<i class="bi bi-phone"></i> 横屏可获得更好体验';
    document.body.insertBefore(alertDiv, document.body.firstChild);
}
</script>
<script>
// 新增分页功能
function initPagination() {
    document.querySelectorAll('.func-list, .const-list').forEach(list => {
        const container = list.closest('.card-body');
        const paginationContainer = container.querySelector('.pagination-container');
        const itemsPerPage = parseInt(list.dataset.itemsPerPage) || 6;
        const items = list.querySelectorAll('.func-item, .const-item');
        const totalItems = items.length;
        const totalPages = Math.ceil(totalItems / itemsPerPage);

        if (totalPages <= 1) return;

        // 创建分页元素
        const pagination = document.createElement('div');
        pagination.className = 'd-flex justify-content-center align-items-center gap-2';

        // 上一页按钮
        const prevBtn = document.createElement('button');
        prevBtn.className = 'btn btn-sm btn-outline-primary';
        prevBtn.innerHTML = '<i class="bi bi-chevron-left"></i>';
        prevBtn.disabled = true;

        // 页码显示
        const pageInfo = document.createElement('span');
        pageInfo.className = 'page-info text-muted small';
        pageInfo.textContent = `1/${totalPages}`;

        // 下一页按钮
        const nextBtn = document.createElement('button');
        nextBtn.className = 'btn btn-sm btn-outline-primary';
        nextBtn.innerHTML = '<i class="bi bi-chevron-right"></i>';
        if (totalPages === 1) nextBtn.disabled = true;

        // 组装分页
        pagination.append(prevBtn, pageInfo, nextBtn);
        paginationContainer.appendChild(pagination);

        let currentPage = 1;

        function updateItems() {
            const start = (currentPage - 1) * itemsPerPage;
            const end = start + itemsPerPage;

            items.forEach((item, index) => {
                item.style.display = (index >= start && index < end) ? 'block' : 'none';
            });

            prevBtn.disabled = currentPage === 1;
            nextBtn.disabled = currentPage === totalPages;
            pageInfo.textContent = `${currentPage}/${totalPages}`;
        }

        prevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                updateItems();
            }
        });

        nextBtn.addEventListener('click', () => {
            if (currentPage < totalPages) {
                currentPage++;
                updateItems();
            }
        });

        // 初始状态
        updateItems();
    });
}

// 初始化分页
document.addEventListener('DOMContentLoaded', initPagination);
</script>
<script>
// 数据库测试表单处理
document.getElementById('dbTestForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const form = e.target;
    const resultDiv = document.getElementById('dbTestResult');
    const submitBtn = document.getElementById('dbTestSubmit');
    const spinner = submitBtn.querySelector('.spinner-border');

    // 重置状态
    resultDiv.style.display = 'none';
    submitBtn.disabled = true;
    spinner.classList.remove('d-none');

    try {
        const formData = new FormData(form);
        const response = await fetch('', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        
        // 构造结果显示
        resultDiv.className = `alert alert-${data.status === 'success' ? 'success' : 'danger'}`;
        resultDiv.innerHTML = `
            <h5 class="alert-heading">
                ${data.status === 'success' ? '✅ 连接成功' : '❌ 连接失败'}
            </h5>
            <div class="mb-2">${data.message}</div>
            ${data.details ? `<pre class="bg-dark text-white p-3 rounded">${JSON.stringify(data.details, null, 2)}</pre>` : ''}
            ${data.code ? `<div class="text-muted small mt-2">错误代码: ${data.code}</div>` : ''}
        `;
        
        // 特殊处理MySQL连接信息
        if (data.status === 'success' && data.details?.protocol) {
            resultDiv.innerHTML += `
                <div class="mt-2">
                    <span class="badge bg-info">协议</span> ${data.details.protocol}
                    ${data.details.version ? `<span class="badge bg-info ms-2">版本</span> ${data.details.version}` : ''}
                </div>
            `;
        }

    } catch (error) {
        resultDiv.className = 'alert alert-danger';
        resultDiv.innerHTML = `
            <h5 class="alert-heading">🚨 网络请求失败</h5>
            <div>${error.message}</div>
        `;
    } finally {
        resultDiv.style.display = 'block';
        submitBtn.disabled = false;
        spinner.classList.add('d-none');
        
        // 滚动到结果区域
        resultDiv.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
});
</script>
<script>
// 初始化工具提示
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltipTriggerList.map(t => new bootstrap.Tooltip(t, {
        trigger: 'hover'
    }));
});
</script>
<script>
// DataTables 初始化
document.addEventListener('DOMContentLoaded', function () {
    $('.network-table, .disk-table').DataTable({
        ordering: true,
        searching: true,
        language: {
            url: 'https://cdn.datatables.net/plug-ins/2.2.2/i18n/zh.json'
        },
        dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>rt<"row"<"col-sm-12 col-md-6"i><"col-sm-12 col-md-6"p>>',
        responsive: true
    });
});

// Clipboard.js 初始化
new ClipboardJS('.copy-btn').on('success', function(e) {
    const originalHTML = e.trigger.innerHTML;
    e.trigger.innerHTML = '<i class="bi bi-check2"></i> 已复制';
    setTimeout(() => {
        e.trigger.innerHTML = originalHTML;
    }, 2000);
});

// 添加动态动画
document.querySelectorAll('.traffic-badge').forEach(badge => {
    badge.classList.add('animate__animated', 'animate__fadeInRight');
});
</script>
<script>
// IP地理位置查询
function updateIpInfo() {
    fetch('https://myip.ipip.net/json')
        .then(response => response.json())
        .then(data => {
            if (data.ret === 'ok') {
                const locParts = data.data.location
                    .slice(0, 4)
                    .filter(part => part && part !== 'XX');
                const processedLoc = locParts.map((part, index) => {
                    if (index === 1) {
                        if (locParts[2] === part) {
                            return part.endsWith('市') ? part : part + '市';
                        }
                        return part.endsWith('省') ? part : part + '省';
                    }
                    if (index === 2) { 
                        return (locParts[1] !== part) ? 
                            (part.endsWith('市') ? part : part + '市') : null;
                    }
                    return part;
                }).filter(Boolean);
                
                document.getElementById('visitorIp').innerHTML = `
                    ${data.data.ip}
                `;
                document.getElementById('visitorLocation').innerHTML = `
                    ${processedLoc.join(' - ')}
                `;
            }
        })
        .catch(() => {
            document.getElementById('visitorIp').textContent = '<?= $_SERVER["REMOTE_ADDR"] ?? "未知" ?>';
        });
}

// 时间更新函数
function updateDateTime() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hour = String(now.getHours()).padStart(2, '0');
    const minute = String(now.getMinutes()).padStart(2, '0');
    const second = String(now.getSeconds()).padStart(2, '0');
    const formattedDateTime = `${year}年${month}月${day}日 ${hour}:${minute}:${second}`;
    document.getElementById('currentDateTime').textContent = formattedDateTime;
}

// 初始化函数
function initPage() {
    // 初始化IP信息
    updateIpInfo();
    
    // 初始化时间并设置定时器
    updateDateTime();
    setInterval(updateDateTime, 1000);
}

// 页面加载完成后执行初始化
document.addEventListener('DOMContentLoaded', initPage);
</script>
<script>
const backToTopButton = document.querySelector('.back-to-top');
window.addEventListener('scroll', () => {
    if (window.scrollY > 200) {
        backToTopButton.classList.add('show');
    } else {
        backToTopButton.classList.remove('show');
    }
});

backToTopButton.addEventListener('click', () => {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

backToTopButton.addEventListener('touchstart', () => {
    backToTopButton.style.transform = 'scale(0.95)';
});

backToTopButton.addEventListener('touchend', () => {
    backToTopButton.style.transform = 'scale(1)';
});
</script>
</body>
</html>