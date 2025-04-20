<?php
/**
 * PHP 8.0-8.4 + HTML5 + Bootstrap 5.3.5 Server Probe System
 * Version: 2.2 (PHP 8.0-8.4)
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
ini_set("display_errors", "0");
ini_set("error_reporting", E_ALL);
ob_start();

// Security Settings
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

// Add monitoring interface response (compatible with existing code)
if (isset($_GET['monitor'])) {
    header('Content-Type: application/json');
    header('Cache-Control: no-cache');
    
    try {
        // Rate limiting (1 request per second)
        if (isset($_SESSION['last_monitor']) && (time() - $_SESSION['last_monitor'] < 1))
        $_SESSION['last_monitor'] = time();

        // Get current traffic data
        $current_traffic = get_network_traffic();
        $current_time = microtime(true);
        
        // Initialize session data
        if (!isset($_SESSION['network_traffic'])) {
            $_SESSION['network_traffic'] = $current_traffic;
            $_SESSION['last_traffic_time'] = $current_time;
        }

        $time_diff = $current_time - $_SESSION['last_traffic_time'];

        $traffic_data = [];
        foreach ($current_traffic as $interface => $data) {
            $prev_data = $_SESSION['network_traffic'][$interface] ?? ['receive' => 0, 'transmit' => 0];
            
            // Calculate rate (bytes/second)
            $receive_rate = $time_diff > 0 ? 
                ($data['receive'] - $prev_data['receive']) / $time_diff : 0;
            $transmit_rate = $time_diff > 0 ? 
                ($data['transmit'] - $prev_data['transmit']) / $time_diff : 0;
            
            $traffic_data[$interface] = [
                'receive_rate' => $receive_rate,
                'transmit_rate' => $transmit_rate
            ];
        }

        // Update session data
        $_SESSION['network_traffic'] = $current_traffic;
        $_SESSION['last_traffic_time'] = $current_time;

        // Get monitoring data
        $data = [
            'cpu' => get_cpu_usage() ?: ['usage' => 0, 'cores' => 0],
            'memory' => array_merge(['percent' => 0, 'used' => 0, 'total' => 0], get_memory_info() ?: []),
            'disk' => array_merge(['percent' => 0, 'used' => 0, 'total' => 0], (array)current(get_disk_usage())),
            'network' => $traffic_data
        ];

        // Format response
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
        die(json_encode(['error' => 'Internal Server Error']));
    }
}

// phpInfo
if (isset($_GET['action']) && $_GET['action'] === 'phpInfo') {
    phpinfo();
    exit;
}

// Log Detection Function
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
            // Handle wildcard paths
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
            $errors[] = "Directory processing error: $dir (" . $e->getMessage() . ")";
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
            $errors[] = "Directory not readable: $dir";
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        $iterator->setMaxDepth(2);

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;

            // Log file matching logic
            $filename = $file->getFilename();
            $isLogFile = preg_match('/(?:^|\b)(\.log$|\.log\.\d+$|_log$|(?:error|access|fatal|debug|auth|syslog|mail|kern|secure))/ix', $filename);
            
            if (!$isLogFile && in_array($filename, ['messages', 'syslog', 'auth.log', 'daemon.log', 'kern.log', 'mail.log', 'user.log', 'cron.log'])) {
                $isLogFile = true;
            }

            if ($isLogFile) {
                $path = $file->getPathname();
                $size = $file->getSize();
                
                // Skip empty files
                if ($size <= 0) continue;

                // Permission check
                $isReadable = $isRoot ? true : $file->isReadable();
                
                // Get detailed information
                clearstatcache(true, $path);
                $perms = $file->getPerms() & 0777;
                $owner = 'Unknown';
                if (function_exists('posix_getpwuid')) {
                    $userInfo = @posix_getpwuid($file->getOwner());
                    $owner = $userInfo['name'] ?? 'Unknown';
                } else {
                    $owner = $file->getOwner();
                }
                
                $group = 'Unknown';
                if (function_exists('posix_getgrgid')) {
                    $groupInfo = @posix_getgrgid($file->getGroup());
                    $group = $groupInfo['name'] ?? 'Unknown';
                } else {
                    $group = $file->getGroup();
                }
                $mtime = $file->getMTime() ? date('Y-m-d H:i:s', $file->getMTime()) : 'Unknown time';

                $detectedLogs[] = [
                    'path' => $path,
                    'size' => $size,
                    'modified' => $mtime,
                    'readable' => $isReadable,
                    'perms' => sprintf('%03o', $perms),
                    'owner' => $owner,
                    'group' => $group,
                    'status' => $isReadable ? 'Readable' : 'Permission denied',
                    'inode' => $file->getInode()
                ];
            }
        }
    } catch (Exception $e) {
        $errors[] = "Directory access failed: $dir (" . $e->getMessage() . ")";
    }
}

// Secure Log Viewing Feature
if (isset($_GET['action']) && $_GET['action'] === 'view_log' && isset($_GET['path'])) {
    $logPath = urldecode($_GET['path']);
    $logFile = realpath($logPath);
    
    // Security validation
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
        
        // Efficiently read last 1000 lines
        $lines = [];
        $fp = fopen($logFile, 'r');
        if ($fp) {
            fseek($fp, -10240, SEEK_END); // Start reading from 10KB before the end of the file
            while (!feof($fp) && count($lines) < 1000) {
                $lines[] = fgets($fp);
            }
            fclose($fp);
            
            // Display newest content first
            echo implode('', array_reverse($lines));
        }
        exit;
    }
    
    header('HTTP/1.1 403 Forbidden');
    exit('<div class="alert alert-danger">Access to this log file is forbidden</div>');
}

// Enhanced Public IP Retrieval
function get_enhanced_public_ip() {
    $public_ip = 'unknown';
    
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

// New function to get CPU model
function get_cpu_model() {
    $model = 'Unknown';
    $cores = [];
    $details = [];
    $physicalCores = 0;
    $logicalCores = 0;
    $avgSpeed = 'Unknown';

    if (is_readable('/proc/cpuinfo')) {
        $info = @file_get_contents('/proc/cpuinfo');
        if ($info !== false) {
            // Extract CPU model
            preg_match_all('/^(model name|Hardware)\s+:\s+(.+)$/mi', $info, $matches);
            if (!empty($matches[2])) {
                foreach ($matches[2] as $m) {
                    $clean_model = trim(str_replace(['(R)', '(TM)', 'CPU', '@'], '', $m));
                    if (!in_array($clean_model, $cores)) {
                        $cores[] = $clean_model;
                    }
                }
            }

            // Extract number of physical cores
            preg_match_all('/^cpu cores\s+:\s+(\d+)$/mi', $info, $coreMatches);
            $physicalCores = array_sum($coreMatches[1]) ?: 'Unknown';

            // Extract number of logical cores (threads)
            preg_match_all('/^processor\s+:\s+\d+$/mi', $info, $procMatches);
            $logicalCores = count($procMatches[0]) ?: 'Unknown';

            // Extract clock speed
            preg_match_all('/^cpu MHz\s+:\s+([\d.]+)$/mi', $info, $speedMatches);
            $avgSpeed = $speedMatches[1] ? round(array_sum($speedMatches[1]) / count($speedMatches[1])) : 'Unknown';
        }
    }

    // Strategy 2: Using the lscpu command
    if (empty($cores) && function_exists('shell_exec')) {
        $lscpu = @shell_exec(escapeshellcmd('lscpu 2>/dev/null'));
        if ($lscpu) {
            // Extract model
            if (preg_match('/Model name:\s+(.+)/i', $lscpu, $match)) {
                $cores[] = trim(str_replace(['(R)', '(TM)'], '', $match[1]));
            }

            // Extract core information
            preg_match('/Socket$s$:\s+(\d+).*?Core$s$ per socket:\s+(\d+).*?Thread$s$ per core:\s+(\d+)/s', $lscpu, $coreData);
            if ($coreData) {
                $physicalCores = $coreData[1] * $coreData[2];
                $logicalCores = $physicalCores * $coreData[3];
            }

            // Extract cache information
            if (preg_match('/L3 cache:\s+([\d.]+ [KMG]?B)/i', $lscpu, $cacheMatch)) {
                $details[] = $cacheMatch[1] . ' cache';
            }

            // Extract clock speed
            if (preg_match('/CPU MHz:\s+([\d.]+)/i', $lscpu, $speedMatch)) {
                $avgSpeed = round($speedMatch[1] / 1000, 1) . 'GHz';
            }
        }
    }

    // Strategy 3: Using dmidecode
    if (empty($cores) && function_exists('shell_exec')) {
        $dmi = @shell_exec('dmidecode processor 2>/dev/null');
        if ($dmi && preg_match('/Version:\s+(.+)/i', $dmi, $match)) {
            $cores[] = trim($match[1]);
        }
    }

    // Strategy 4: Using Windows WMI
    if (empty($cores) && PHP_OS_FAMILY === 'Windows') {
        $output = @shell_exec('wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed /value');
        if (preg_match('/Name=(.+)\s+NumberOfCores=(\d+)\s+NumberOfLogicalProcessors=(\d+)\s+MaxClockSpeed=(\d+)/i', $output, $winMatches)) {
            $cores[] = trim($winMatches[1]);
            $physicalCores = $winMatches[2];
            $logicalCores = $winMatches[3];
            $avgSpeed = ($winMatches[4] ? round($winMatches[4]/1000,1) : 'Unknown') . 'GHz';
        }
    }

    // Combine model information
    if (!empty($cores)) {
        $unique_models = array_unique($cores);
        $model = count($unique_models) > 1 ? 
            implode(' + ', $unique_models) : 
            preg_replace('/\s@\s.+$/', '', $unique_models[0]);
    }

    // Add technical specifications
    $specs = [];
    if ($physicalCores && $logicalCores) {
        $specs[] = "{$physicalCores} cores / {$logicalCores} threads";
    }
    if (!empty($avgSpeed) && $avgSpeed !== 'Unknown') {
        $specs[] = $avgSpeed;
    }
    if (!empty($details)) {
        $specs = array_merge($specs, $details);
    }

    // Add architecture information
    $arch = php_uname('m');
    $archText = '';
    if (strpos($arch, 'aarch64') !== false) {
        $archText = ' (ARM64)';
    } elseif (preg_match('/x86_64|amd64/i', $arch)) {
        $archText = ' (x86-64)';
    }

    // Final combination
    $specs = [];
    if ($physicalCores && $logicalCores) {
        $specs[] = "{$physicalCores} cores / {$logicalCores} threads";
    }
    if ($avgSpeed !== 'Unknown') {
        $specs[] = $avgSpeed;
    }

    if (!empty($specs)) {
        $model .= sprintf(' [%s%s]', implode(', ', $specs), $archText);
    } else {
        $model .= $archText;
    }

    if (strpos($model, 'Unknown') !== false) {
        return 'Insufficient directory permissions to read hardware information';
    }
    
    return $model;
}

// Added format_uptime() function
function format_uptime($seconds) {
    if ($seconds === false) {
        return 'Insufficient directory permissions to read hardware information';
    }
    
    $seconds = (int)$seconds;
    $days = floor($seconds / 86400);
    $remaining_after_days = $seconds % 86400;
    $hours = floor($remaining_after_days / 3600);
    $remaining_after_hours = $remaining_after_days % 3600;
    $minutes = floor($remaining_after_hours / 60);
    
    $result = '';
    if ($days > 0) $result .= $days . ' days ';
    if ($hours > 0) $result .= $hours . ' hours ';
    $result .= $minutes . ' minutes';
    
    return $result ?: 'Just started';
}

function get_server_uptime() {
    // General attempt: /proc/uptime (for Linux and compatible systems)
    if (@is_readable('/proc/uptime')) {
        $contents = @file_get_contents('/proc/uptime');
        if ($contents !== false) {
            return floatval(explode(' ', $contents)[0]);
        }
    }

    // Handle based on operating system
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
    // Try uptime -s format
    if (function_exists('shell_exec')) {
        $uptimeStr = trim(@shell_exec('uptime -s 2>/dev/null'));
        if ($uptimeStr) {
            $bootTime = strtotime($uptimeStr);
            return $bootTime !== false ? time() - $bootTime : false;
        }
    }
    
    // Try direct boot time calculation
    if (function_exists('sys_getloadavg')) {
        $uptime = @sys_getloadavg()[2];
        return $uptime ? $uptime : false;
    }
    return false;
}

function get_bsd_uptime() {
    if (function_exists('shell_exec')) {
        // Get kernel boot time (for FreeBSD/macOS)
        $output = @shell_exec('sysctl -n kern.boottime 2>/dev/null');
        if ($output) {
            // Format handling: { sec = 1620000000, usec = 0 } or 1620000000
            if (preg_match('/sec\s*=\s*(\d+)/', $output, $m)) {
                return time() - intval($m[1]);
            } elseif (is_numeric(trim($output))) {
                return time() - intval(trim($output));
            }
        }
        
        // Try to get from boot log (macOS fallback)
        $output = @shell_exec('last reboot | head -1 | awk \'{print $5 " " $6}\'');
        if ($output && preg_match('/\w{3} \d{2}/', $output)) {
            $bootTime = strtotime(trim($output));
            return $bootTime ? time() - $bootTime : false;
        }
    }
    return false;
}

function get_windows_uptime() {
    // Method 1: Using WMI
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

    // Method 2: Using WMIC command
    if (function_exists('shell_exec')) {
        $output = @shell_exec('wmic os get lastbootuptime /format:value 2>&1');
        if ($output && preg_match('/LastBootUpTime=(\d{14})/', $output, $m)) {
            $bootTime = parse_wmi_time($m[1]);
            return $bootTime ? time() - $bootTime : false;
        }
    }

    // Method 3: Estimate from system start record
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
    // General method: Parse uptime command output
    if (function_exists('shell_exec')) {
        $output = @shell_exec('uptime 2>/dev/null');
        if ($output) {
            // Match format: up 5 days, 3:14 or up 1 week, 2 days, 3:14
            if (preg_match('/up\s+((\d+\s+weeks?,\s+)?(\d+\s+days?,\s+)?(\d+:\d+)/', $output, $m)) {
                $parts = explode(':', $m[4]);
                return ((int)$parts[0] * 3600) + ((int)$parts[1] * 60);
            }
        }
    }
    return false;
}

function parse_wmi_time($wmiTime) {
    // Parse WMI time format: YYYYMMDDHHMMSS.xxxxxx±UUU
    if (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', $wmiTime, $m)) {
        return mktime($m[4], $m[5], $m[6], $m[2], $m[3], $m[1]);
    }
    return false;
}

// Timezone
date_default_timezone_set('America/Los_Angeles');

// Modified server information function
function get_server_info() {
    $timezone_mapping = [
        'Asia/Shanghai'   => 'Shanghai',
        'Asia/Chongqing'  => 'Chongqing',
        'Asia/Urumqi'     => 'Urumqi',
        'Asia/Tokyo'      => 'Tokyo',
        'America/Los_Angeles' => 'Los Angeles',
        'America/New_York'=> 'New York',
        'Europe/London'   => 'London',
    ];

    $timezone_identifier = date_default_timezone_get();
	$kernel_version = 'Unknown';
	if (!is_readable('/proc/version')) {
		$kernel_version = 'Current directory permissions insufficient - Hardware information cannot be read';
	} else {
		$kernel = file_get_contents('/proc/version');
		if (preg_match('/Linux version (\S+)/', $kernel, $matches)) {
			$kernel_version = $matches[1];
		}
	}
	return [
	    'Host Name' => @php_uname('n') ?: 'Unknown',
	    'Operating System' => PHP_OS,
	    'Kernel Version' => $kernel_version,
	    'System Distribution Name' => get_distro_name(),
	    'Hardware Architecture' => @php_uname('m') ?: 'Unknown',
	    'Virtualization Type' => get_virtualization_type(),
	
	    'CPU Model' => get_cpu_model(),
	    'Server Uptime' => format_uptime(get_server_uptime()),
	
	    'Web Server' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
	    'Server Port' => $_SERVER['SERVER_PORT'] ?? 'Unknown',
	
	    'PHP Version' => PHP_VERSION,
	    'PHP Information' => '<span class="developer-prompt me-2">If you are a developer, please view:</span>' .
	        '<a href="?action=phpInfo" target="_blank" class="btn btn-sm btn-outline-primary">phpinfo</a>',
	    'Zend Engine Version' => zend_version(),
	    'PHP Installation Path' => PHP_BINARY,
	    'PHP Configuration File' => php_ini_loaded_file() ?: 'None',
	
	    'PHP Memory Limit' => ini_get('memory_limit'),
	    'PHP Maximum Execution Time' => ini_get('max_execution_time') . ' seconds',
	    'Maximum Upload File Size' => ini_get('upload_max_filesize'),
	    'OpenSSL Support' => extension_loaded('openssl') ? 'Enabled' : 'Disabled',
	    'CGI Mode' => (php_sapi_name() === 'cgi') ? 'Yes' : 'No',
	
	    'Server Public IP' => get_enhanced_public_ip(),
	    'Server Internal IP' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
	    'Visitor IP' => '<span id="visitorIp" class="visitor-info">LOADING...</span>',
	
	    'Current User' => get_current_user(),
	    'Current Probe Timezone' => $timezone_mapping[$timezone_identifier] ?? $timezone_identifier,
	    'Current Directory' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
	    'Current Probe Path' => str_replace('\\', '/', __FILE__),
	    'System Load' => @sys_getloadavg()[0] ?? 'Unknown',
	    'OPcache Status' => function_exists('opcache_get_status') ? 'Enabled (' . opcache_get_status()['opcache_enabled'] . ')' : 'Disabled',
	    'Peak Memory' => function_exists('memory_get_peak_usage') ? round(memory_get_peak_usage(true)/(1024*1024), 2) . ' MB' : 'Unknown'
	];
}

// New helper function
function get_kernel_version() {
    if (is_readable('/proc/version')) {
        $kernel = file_get_contents('/proc/version');
        if (preg_match('/Linux version (\S+)/', $kernel, $matches)) {
            return $matches[1];
        }
    }
    return 'Unknown';
}

function get_distro_name() {
    $files = [
        '/etc/os-release' => function($c) {
            preg_match('/PRETTY_NAME="(.+?)"/', $c, $m);
            return isset($m[1]) ? $m[1] : 'Unknown';
        },
        '/etc/redhat-release' => function($c) {
            return trim(str_replace(' release ', ' ', $c));
        },
        '/etc/centos-release' => function($c) {
            return trim(str_replace(' release ', ' ', $c));
        },
        '/etc/lsb-release' => function($c) {
            preg_match('/DISTRIB_DESCRIPTION=(.+)/', $c, $m);
            return trim($m[1], '"\'') ?? 'Unknown';
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

    // Return permission message if all attempts fail
    return 'Current directory permissions insufficient - Hardware information cannot be read';
}

function get_virtualization_type() {
    try {
        if (is_readable('/proc/1/cgroup')) {
            $cgroup = @file_get_contents('/proc/1/cgroup');
            if ($cgroup !== false && preg_match('/docker|kubepods/', $cgroup)) {
                return 'Container (Docker/Kubernetes)';
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
        // Ignore permission errors
    }
    return 'Physical Machine';
}

// ================== New Security Detection Functions ================== //
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
        if (strpos($ext_lower, $keyword) !== false) return 'High Risk';
    }
    
    foreach ($medium_risk as $keyword) {
        if (strpos($ext_lower, $keyword) !== false) return 'Medium Risk';
    }
    
    return 'Low Risk';
}
// Basic Helper Function
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
// Extension Detection Related Functions
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
    // Get installed extensions via pecl (requires pecl command)
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
        case 'High Risk':
            return "This extension contains high-risk functions, enabling it requires strict evaluation of necessity!";
        case 'Medium Risk':
            return "This extension may pose security risks, it is recommended to enable it as needed and configure security settings";
        default:
            return "Regular extension, enable as needed";
    }
}
// Extension Enablement Detection
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
        'High Risk' => [
            'Suggestion' => "🚨 Strongly recommended to disable this extension in php.ini",
            'Exception Cases' => "If enabling is necessary, add security restrictions:\n" .
                "1. Disable dangerous functions:\n" .
                "   disable_functions = exec,passthru,shell_exec\n" .
                "2. Restrict file system access:\n" .
                "   open_basedir = /var/www/:/tmp/\n" .
                "3. Log all operations:\n" .
                "   {$ext}.log_operations = On",
            'Configuration Path' => $configFile
        ],
        'Medium Risk' => [
            'Suggestion' => "⚠️ Enable with security configurations:",
            'Security Configurations' => [
                "1. Restrict network access:\n" .
                "   {$ext}.allowed_hosts = 127.0.0.1",
                "2. Enable sandbox mode:\n" .
                "   {$ext}.safe_mode = On",
                "3. Set memory limit:\n" .
                "   {$ext}.memory_limit = 128M"
            ],
            'Configuration Method' => "Add to {$configFile}:\n{$baseConfig}"
        ],
        'Low Risk' => [
            'Suggestion' => "✅ Safe extension can be enabled as needed:",
            'Configuration Method' => "Configure according to different runtime environments:\n" .
                implode("\n", array_map(
                    function($env) use ($configPaths) {
                        return "• {$env}environment: {$configPaths[$env]}";
                    },
                    array_keys($configPaths)
                )) . 
                "\n\nAdd configuration directive:\n{$baseConfig}",
            'Verification Command' => "php -i | grep {$ext} && systemctl restart php{$phpVersion}-{$currentEnv}"
        ]
    ];

    $risk = get_extension_risk_level($ext);
    $tip = $tips[$risk] ?? ['Suggestion' => 'Please refer to the official documentation for configuration'];

    return implode("\n\n", array_map(
        function($k, $v) {
            return "【{$k}】\n" . (is_array($v) ? implode("\n", $v) : $v);
        },
        array_keys($tip),
        array_values($tip)
    ));
}
// Extension Metadata Related Functions
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

// Add the following metadata function before get_php_extensions()
function get_function_metadata($functionName) {
    // Built-in known function metadata
    $metadata = [
        'json_encode' => [
            'description' => 'Converts PHP values to JSON strings',
            'parameters' => ['mixed $value', 'int $flags = 0', 'int $depth = 512'],
            'return' => 'string|false'
        ],
        'mysqli_connect' => [
            'description' => 'Opens a new connection to a MySQL server',
            'parameters' => ['string $host', 'string $username', 'string $password', 'string $database', 'int $port = 3306'],
            'return' => 'mysqli|false'
        ],
        'PDO::__construct' => [
            'description' => 'Creates a database connection instance',
            'parameters' => ['string $dsn', 'string $username', 'string $password', 'array $options = []'],
            'return' => 'PDO'
        ],
        'openssl_encrypt' => [
            'description' => 'Encrypts data using the specified method and key',
            'parameters' => ['string $data', 'string $method', 'string $key', 'int $options = 0', 'string $iv = ""'],
            'return' => 'string|false'
        ]
    ];

    $lowerName = strtolower($functionName);
    if (isset($metadata[$lowerName])) {
        return $metadata[$lowerName];
    }

    // Dynamically retrieve information about unknown functions using reflection
    try {
        $refFunc = new ReflectionFunction($lowerName);
        
        // Reconstruct parameter type handling
        $params = [];
        foreach ($refFunc->getParameters() as $param) {
            $paramStr = '';
            
            // Enhanced type handling (fix point)
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
            
            // Default value handling remains unchanged
            if ($param->isOptional() && $param->isDefaultValueAvailable()) {
                $default = str_replace(PHP_EOL, '', var_export($param->getDefaultValue(), true));
                $paramStr .= ' = '.$default;
            }
            
            $params[] = $paramStr;
        }

        // Return type
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
            'description' => '(Retrieved via reflection) No detailed documentation available for this function',
            'parameters' => $params ?: [],
            'return' => $returnStr
        ];
    } catch (ReflectionException $e) {
        return [
            'description' => 'Function does not exist or cannot be reflected',
            'parameters' => [],
            'return' => 'mixed'
        ];
    }
}

function get_constant_metadata($constantName) {
    $metadata = [
        'JSON_PRETTY_PRINT' => [
            'description' => 'Formats JSON output with spaces and indentation',
            'since' => '5.4.0'
        ],
        'E_STRICT' => [
            'description' => 'Strict error reporting level (deprecated)',
            'since' => '5.0.0',
            'deprecated' => true,
            'deprecated_since' => '8.0.0',
            'alternative' => 'E_ALL'
        ],
        'PHP_VERSION' => [
            'description' => 'Current PHP version string',
            'since' => '4.0'
        ],
        'PDO::ATTR_ERRMODE' => [
            'description' => 'Sets the error handling mode',
            'values' => ['PDO::ERRMODE_SILENT', 'PDO::ERRMODE_WARNING', 'PDO::ERRMODE_EXCEPTION']
        ],
        'OPENSSL_RAW_DATA' => [
            'description' => 'Specifies using raw output format for encryption/decryption',
            'since' => '5.4.0'
        ]
    ];

    if (isset($metadata[$constantName])) {
        return $metadata[$constantName];
    }

    $result = [
        'description' => '',
        'value' => 'undefined',
        'since' => 'Unknown',
        'deprecated' => false
    ];

    // Error handler to capture deprecation warnings
    set_error_handler(function($severity, $message) use (&$result) {
        if (strpos($message, 'is deprecated') !== false) {
            $result['deprecated'] = true;
            $result['description'] = '(Deprecated)';
        }
    }, E_DEPRECATED);
    
    // Handle class constants (e.g., PDO::ATTR_ERRMODE)
    if (strpos($constantName, '::') !== false) {
        list($class, $const) = explode('::', $constantName, 2);
        try {
            $refClass = new ReflectionClass($class);
            if ($refClass->hasConstant($const)) {
                return [
                    'description' => '(Class constant) Dynamically retrieved constant',
                    'value' => $refClass->getConstant($const),
                    'since' => 'Unknown version'
                ];
            }
        } catch (ReflectionException $e) {
            // Skip if class does not exist
        }
    } 
    // Handle global constants
    elseif (defined($constantName)) {
        $result['value'] = constant($constantName); // Automatically triggers error handler
        $result['description'] = '(Global constant) Dynamically retrieved constant';
    }

    restore_error_handler();

    // Supplement default description
    if ($result['description'] === '') {
        $result['description'] = $result['deprecated'] 
            ? '(Deprecated constant)' 
            : '(Uncategorized constant)';
    }

    return $result;
}
// Core Function
function get_php_extensions() {
    $extensions = [];
    $all_ini = ini_get_all();
    // Process loaded extensions
    foreach (get_loaded_extensions() as $ext) {
        $reflection = new ReflectionExtension($ext);
        $version = phpversion($ext) ?: 'Unknown';
        $constants = get_defined_constants(true)[$ext] ?? [];
        // File path compatibility handling
        $file_path = detect_extension_path($reflection);

        $extensions[$ext] = [
            'Basic Information' => [
                'Version' => $version,
                'Status' => 'Enabled',
                'Compilation Type' => $reflection->isPersistent() ? 'Dynamic' : 'Static',
                'Dependent Extensions' => implode(', ', $reflection->getDependencies()['required'] ?? []),
                'File Path' => $file_path
            ],
            'Configuration Parameters' => array_filter($all_ini, function($key) use ($ext) {
                return strpos($key, $ext . '.') === 0;
            }, ARRAY_FILTER_USE_KEY),
            'Function List' => (function() use ($ext) {
                $funcs = get_extension_funcs($ext);
                if ($funcs === false) {
                    return [];
                }
                return array_map(function($func) {
                    try {
                        $reflection = new ReflectionFunction($func);
                        $meta = get_function_metadata($func);
                        $returnType = '';
                        
                        // Version compatibility: Handle union types (PHP >=8.0)
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
                            'description' => $meta['description'] ?? 'No description',
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
            
            'Constant List' => array_map(function($const, $value) {
                return [
                    'name' => $const,
                    'value' => $value,
                    'meta' => get_constant_metadata($const)
                ];
            }, array_keys(array_slice($constants, 0, 15)), 
                array_values(array_slice($constants, 0, 15)))
        ];
    }
    // Get all available extensions (including loaded and unloaded)
    $available_extensions = [];
    // 1. Scan extension directory    
    $extension_dir = ini_get('extension_dir');
    if (is_dir($extension_dir)) {
        $files = scandir($extension_dir);
        foreach ($files as $file) {
            if (preg_match('/^(php_)?([\w]+)\.(so|dll)$/i', $file, $matches)) {
                $available_extensions[] = strtolower($matches[2]);
            }
        }
    }
    // 2. Get via pecl (requires pecl command)
    if (function_exists('shell_exec') && `which pecl`) {
        $pecl_list = shell_exec('pecl list');
        preg_match_all('/^([a-z]+)\s+/mi', $pecl_list, $matches);
        $available_extensions = array_merge($available_extensions, $matches[1]);
    }
    // Remove duplicates and convert to lowercase
    $available_extensions = array_unique(array_map('strtolower', $available_extensions));
    // Calculate disabled extensions
    $disabled_extensions = array_diff(
        $available_extensions, 
        array_map('strtolower', array_keys($extensions))
    );
    // Add information for disabled extensions
    $extensions['Disabled Extensions'] = [];
    foreach ($disabled_extensions as $ext) {
        $extensions['Disabled Extensions'][$ext] = [
            'Risk Level' => get_extension_risk_level($ext),
            'Enable Recommendation' => get_extension_warning($ext),
            'Configuration Recommendation' => get_extension_config_tip($ext),
            'File Path' => $extension_dir ? $extension_dir . "/$ext.so" : 'Unknown'
        ];
    }

    ksort($extensions);
    return $extensions;
}
// Get disk usage (supports multiple partitions)
function get_disk_usage() {
    if (get_current_user() !== 'root') {
        return [];
    }
    $disks = [];
    $os = strtolower(php_uname('s'));
    
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
                
                if (in_array($fs_type, $exclude_types)) continue;
                if (strpos($device, '/dev/loop') === 0) continue;
                
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

    usort($disks, function($a, $b) {
        if ($b['percent'] !== $a['percent']) {
            return $b['percent'] <=> $a['percent'];
        }
        return $a['mount'] <=> $b['mount'];
    });

    return $disks;
}

// New network traffic monitoring function
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
// Initialize network traffic tracking
if (!isset($_SESSION['network_traffic'])) {
    $_SESSION['network_traffic'] = [];
    $_SESSION['last_traffic_time'] = microtime(true);
}
// Get current traffic data
$current_traffic = get_network_traffic();
$current_time = microtime(true);
$time_diff = $current_time - ($_SESSION['last_traffic_time'] ?? $current_time);

$traffic_data = [];
foreach ($current_traffic as $interface => $data) {
    $prev_data = $_SESSION['network_traffic'][$interface] ?? ['receive' => 0, 'transmit' => 0];
        // Calculate rate (prevent division by zero)
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
// Get detailed memory information
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
// Get network interface information (cross-platform)
function get_network_info() {
    $result = [];
    
    if (!function_exists('net_get_interfaces')) {
        return ['Error' => 'PHP 7.3+ version support required'];
    }

    $interfaces = @net_get_interfaces();
    if ($interfaces === false) {
        return ['Error' => 'Unable to retrieve network interface information'];
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
// Get CPU usage and detailed information
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

// Database Test Functions
function test_database_connections() {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['db_test'])) {
        // Clean all output buffers
        while (ob_get_level()) ob_end_clean();
        header('Content-Type: application/json');
        header('Cache-Control: no-cache');
        http_response_code(200);

        $response = ['status' => 'error', 'message' => 'Unknown error'];
        
        try {
            // Validate CSRF token
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                throw new Exception("Security verification failed, please refresh the page and try again", 403);
            }

            // Get configuration parameters
            $config = $_POST['db_config'] ?? [];
            $required = ['type', 'host', 'port', 'user'];
            foreach ($required as $field) {
                if (empty($config[$field])) {
                    throw new Exception("Missing required parameter: $field", 400);
                }
            }

            $type = $config['type'];
            $response = ['status' => 'error', 'message' => 'Unsupported database type'];

            switch ($type) {
			case 'MySQL':
			    if (empty($config['driver'])) {
			        throw new Exception("Please select a database driver type (PDO or mysqli)", 400);
			    }
			
			    $requiredKeys = ['host', 'port', 'user', 'name'];
			    foreach ($requiredKeys as $key) {
			        if (empty($config[$key])) {
			            throw new Exception("Missing required parameter: $key", 400);
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
			                throw new Exception("pdo_mysql extension needs to be enabled", 501);
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
			                throw new Exception("mysqli extension needs to be enabled", 501);
			            }
			
			            $conn = new mysqli($host, $user, $pass, $name, $port);
			            if ($conn->connect_error) {
			                throw new Exception(
			                    "Connection failed: (" . $conn->connect_errno . ") " . $conn->connect_error, 
			                    $conn->connect_errno
			                );
			            }
			            $version = $conn->server_version;
			            $conn->close();
			        }
			
			        $response = [
			            'status' => 'success',
			            'message' => 'MySQL connection successful',
			            'details' => [
			                'version' => $version,
			                'protocol' => ($config['driver'] === 'pdo') ? 'PDO' : 'MySQLi',
			                'host' => substr($host, 0, 3).'***',
			                'user' => substr($user, 0, 2).'***'
			            ]
			        ];
			    } catch (Exception $e) {
			        throw new Exception("MySQL connection error: " . $e->getMessage(), $e->getCode());
			    }
			    break;

                case 'PostgreSQL':
                    if (!extension_loaded('pgsql') && !extension_loaded('pdo_pgsql')) {
                        throw new Exception("pgsql or pdo_pgsql extension needs to be installed");
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
                    $response = ['status' => 'success', 'message' => 'Connection successful'];
                    break;

                case 'SQLite':
                    $path = $config['path'] ?? ':memory:';
                    if ($config['driver'] === 'pdo') {
                        $pdo = new PDO("sqlite:$path");
                        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    } else {
                        $db = new SQLite3($path);
                        if (!$db) {
                            throw new Exception("Unable to open SQLite database");
                        }
                    }
                    $response = ['status' => 'success', 'message' => 'Connection successful'];
                    break;

                case 'MongoDB':
                    if (!extension_loaded('mongodb')) {
                        throw new Exception("mongodb extension needs to be installed");
                    }
                    
                    $uri = "mongodb://{$config['user']}:{$config['pass']}@{$config['host']}:{$config['port']}";
                    $client = new MongoDB\Client($uri);
                    $dbs = $client->listDatabases();
                    $response = ['status' => 'success', 'message' => 'Connection successful'];
                    break;

                case 'Redis':
                    if (!extension_loaded('redis')) {
                        throw new Exception("redis extension needs to be installed");
                    }
                    
                    $redis = new Redis();
                    $redis->connect($config['host'], $config['port']);
                    if (!empty($config['pass'])) {
                        $redis->auth($config['pass']);
                    }
                    $response = [
                        'status' => 'success', 
                        'message' => 'Connection successful',
                        'details' => $redis->info()
                    ];
                    break;
                default:
                    throw new Exception("Unsupported database type: $type", 400);
            }

        } catch (PDOException $e) {
            $response = ['status' => 'error', 'message' => 'Database connection error: ' . $e->getMessage()];
        } catch (mysqli_sql_exception $e) {
            $response = ['status' => 'error', 'message' => 'MySQL error: ' . $e->getMessage()];
        } catch (Exception $e) {
            $code = $e->getCode() ?: 500;
            http_response_code($code);
            $response = [
                'status' => 'error',
                'message' => $e->getMessage(),
                'code' => $code
            ];
        }

        // Ensure only JSON is output
        die(json_encode($response));
        exit; 
    }

    // Return extension status
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
            'status' => 'Not Tested'
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
        'status' => 'Failed',
        'message' => 'Mail sending failed'
    ];

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $result['message'] = 'Security verification failed';
        return $result;
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    if (!$email) {
        $result['message'] = 'Invalid email address format';
        return $result;
    }

    if (isset($_SESSION['last_mail_time']) && (time() - $_SESSION['last_mail_time'] < 60)) {
        $result['message'] = 'Too frequent sending, please try again later';
        return $result;
    }

    try {
        $to = $email;
        $subject = 'Server Probe Test Mail - ' . date('Y-m-d H:i:s');
        $message = "This is a test email from the server probe system.\n\n";
        $message .= "Sending time: " . date('Y-m-d H:i:s') . "\n";
        $message .= "Server IP: " . ($_SERVER['SERVER_ADDR'] ?? 'Unknown') . "\n";
        $message .= "Client IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown') . "\n";

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
                'status' => 'Success',
                'message' => 'Test email sent to ' . htmlspecialchars($email)
            ];
        } else {
            $result['message'] = 'Mail server returned error';
        }
    } catch (Exception $e) {
        $result['message'] = 'Sending failed: ' . $e->getMessage();
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

// Main Program
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
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
<title>Server Probe System v2.2</title>
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
    /* Basic layout adjustment */
    .container {
        padding-left: 8px;
        padding-right: 8px;
    }
    
    /* Card title reduction */
    .card-header h2 {
        font-size: 1.1rem;
    }

    /* Table responsive handling */
    .table-responsive {
        border: none;
        -webkit-overflow-scrolling: touch;
    }

    /* System information table adjusted to block layout */
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

    /* Chart container height adjustment */
    .network-graph {
        height: 180px;
    }

    /* Accordion optimization */
    .accordion-button {
        padding: 0.75rem;
        font-size: 0.9rem;
    }
    .accordion-body .row {
        flex-direction: column;
    }

    /* Database test form adjusted to vertical layout */
    #dbTestForm .col-md-3,
    #dbTestForm .col-md-2 {
        flex: 1 1 100%;
        margin-bottom: 8px;
    }

    /* Network traffic table font adjustment */
    .network-rate {
        font-size: 0.8rem;
    }

    /* Disk usage progress bar optimization */
    .progress {
        height: 18px;
    }
    .progress-bar {
        font-size: 0.7rem;
    }

    /* Hide some table columns on mobile */
    .disk-table th:nth-child(3),
    .disk-table td:nth-child(3),
    .network-table th:nth-child(2),
    .network-table td:nth-child(2) {
        display: none;
    }
}
.fw-light,
.fw-light *:not(strong) {
  font-weight: inherit !important;
}
/* General touch optimization */
.btn, .form-control, .accordion-button {
    touch-action: manipulation;
}

/* Prevent long press from showing copy menu */
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
    content: "TOP";
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
        bottom: 50px;
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
	    <h1 class="display-4 mb-3"><span class="eye-icon" aria-label="Eye Icon">👁️</span> PHP Server Probe System</h1>
	    <div class="alert alert-info d-flex flex-wrap flex-md-nowrap justify-content-center justify-content-md-center align-items-center gap-2">
		     Real-time status update: <span id="currentDateTime"></span>
	        <span class="badge bg-primary ms-2 me-3">PHP <?= safe_output(PHP_VERSION) ?></span>
	        <a href="https://codeberg.org/hestiacn/tz/raw/branch/main/en.php" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary me-3">Download file</a>
		   <a href="/" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary">go home</a>
		</div>
	</header>
	<div class="card border-danger mt-4 shadow-sm">
	    <div class="card-header bg-danger text-white d-flex justify-content-between align-items-center">
	        <h3 class="h5 mb-0"><i class="bi bi-info-circle-fill me-2"></i> System Permission Requirements</h3>
	        <div class="d-flex gap-2">
	            <button class="btn btn-sm btn-light" type="button" data-bs-toggle="collapse" data-bs-target="#importantNotice" aria-expanded="false">
	                <i class="bi bi-chevron-double-down"></i>
	            </button>
	        </div>
	    </div>
	    <div class="collapse show" id="importantNotice">
	        <div class="card-body p-3 p-md-4">
	            <!-- Permission Warning Card -->
	            <div class="alert alert-warning border-danger rounded-3 mb-4">
	                <div class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-3">
	                    <div class="alert-icon text-center mb-3 mb-md-0">
	                        <i class="bi bi-shield-check text-success fs-5"></i>
	                    </div>
	                    <div class="flex-grow-1 w-100 text-center text-md-start">
	                        <h4 class="text-danger mb-3">System Permission Requirements</h4>
	                        <p class="mb-3">
	                            To comprehensively and accurately obtain server runtime parameters and ensure the integrity of monitoring data, this diagnostic tool requires access to the website root directory. If the current directory permissions are insufficient, please move the tool to a directory with appropriate permissions before running it.
	                        </p>
	                        <div class="ms-0 ms-md-4">
	                            <div class="d-flex align-items-center gap-2 mb-2 justify-content-center justify-content-md-start">
	                                <i class="bi bi-arrow-right-short text-primary"></i>
	                                <span>This tool is only recommended for temporary use in necessary monitoring scenarios.</span>
	                            </div>
	                            <div class="d-flex align-items-center gap-2 mb-2 justify-content-center justify-content-md-start">
	                                <i class="bi bi-arrow-right-short text-primary"></i>
	                                <span>Please promptly remove the tool files after use to avoid the risk of sensitive information leakage.</span>
	                            </div>
	                            <div class="d-flex align-items-center gap-2 justify-content-center justify-content-md-start">
	                                <i class="bi bi-arrow-right-short text-primary"></i>
	                                <span>Please ensure to run this tool in a secure environment and strictly limit access to it.</span>
	                            </div>
	                        </div>
	                    </div>
	                </div>
	            </div>
	
	            <!-- Security Guidelines Card -->
	            <div class="alert alert-warning border-danger rounded-3 mb-4">
	                <div class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-3">
	                    <div class="alert-icon text-center mb-3 mb-md-0">
	                        <i class="bi bi-exclamation-triangle text-warning fs-5"></i>
	                    </div>
	                    <div class="flex-grow-1 w-100 text-center text-md-start">
	                        <h4 class="text-danger mb-3">Security Usage Guidelines</h4>
	                        <ul class="list-unstyled ps-0 ps-md-4">
	                            <li class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-2 mb-3">
	                                <i class="bi bi-exclamation-triangle text-warning"></i>
	                                <span>To ensure the best browsing experience and view detailed server parameters, this probe file requires administrator privileges, i.e., the user and user group should both be <strong>root</strong></span>
	                            </li>
	                            <li class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-2 mb-3">
	                                <i class="bi bi-shield-lock text-danger"></i>
	                                <span>If the current directory does not have the appropriate permissions, it is recommended to move the file to a directory with the necessary permissions.</span>
	                            </li>
	                            <li class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-2">
	                                <i class="bi bi-lock text-info"></i>
	                                <span>Thank you for your understanding and support! Out of security considerations, please be sure to delete this file after use to further reduce potential security risks.</span>
	                            </li>
	                        </ul>
	                    </div>
	                </div>
	            </div>
	
	            <!-- Probe Generation Card -->
	            <div class="alert alert-warning border-danger rounded-3 mb-4">
	                <div class="d-flex flex-column flex-md-row align-items-center align-items-md-start gap-3">
	                    <div class="alert-icon text-center mb-3 mb-md-0">
	                        <i class="bi bi-lock text-info fs-5"></i>
	                    </div>
	                    <div class="flex-grow-1 w-100">
	                        <div class="text-center text-md-start">
	                            <h4 class="text-danger mb-3">Probe File Random Name</h4>
	                            <p class="mb-3 mx-md-auto" style="max-width: 1000px;"><i class="bi bi-shield-lock text-danger"></i>【Security Deployment Recommendation】Please execute the following command in your server terminal. The system will automatically generate a probe file with a dynamic random naming rule in the /var/www/html directory. A unique file name will be generated for you, effectively avoiding the use of conventional names for viewing and significantly reducing the risk level of the file being maliciously exploited.</p>
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
	                                                                   style="font-size: 1em;">
	                                                                   curl -fsSL https://codeberg.org/hestiacp/tz/raw/branch/main/th.sh | bash
	                                                                   </code>
	                                                        </td>
	                                                    </tr>
	                                                </tbody>
	                                            </table>
	                                        </div>
	                                        <!-- Copy button adjusted to absolute positioning -->
	                                        <div class="position-absolute top-0 end-0 p-2">
	                                            <button class="btn btn-sm btn-outline-danger copy-btn shadow-sm"
	                                                    data-clipboard-target="#codeContent"
	                                                    title="Click to copy">
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
	            <!-- Log Viewing Card -->
	            <div class="alert alert-warning border-danger rounded-3">
	                <div class="d-flex flex-column flex-md-row align-items-start gap-3">
	                    <div class="alert-icon text-center mb-2 mb-md-0">
	                        <i class="bi bi-file-earmark-text text-danger fs-5"></i>
	                    </div>
	                    <div class="flex-grow-1 w-100">
	                        <h4 class="text-danger mb-3">Log Viewing</h4>
	                        <p class="mb-3 text-center mx-auto" style="max-width: 1000px;"><i class="bi bi-shield-lock text-danger"></i> Dynamically detect log files in the system, automatically display accessible log information, support copying paths and real-time viewing of content, and easily manage log files.</p>
	                        <div class="row g-3">
	                            <?php if (empty($detectedLogs['logs'])): ?>
	                                <div class="col-12">
	                                    <div class="alert alert-info">No readable log files detected</div>
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
	                                                <!-- Modified layout section -->
	                                                <div class="d-flex flex-column flex-md-row justify-content-md-between align-items-md-center w-100">
	                                                    <div class="text-muted small order-md-1">
	                                                        <?= htmlspecialchars($log['modified'], ENT_QUOTES) ?>
	                                                    </div>
	                                                    <div class="d-flex gap-2 mt-2 mt-md-0 order-md-2">
	                                                        <button class="btn btn-sm btn-outline-dark copy-btn" 
	                                                                data-clipboard-text="<?= htmlspecialchars($logPath, ENT_QUOTES) ?>"
	                                                                title="Copy full path">
	                                                            <i class="bi bi-clipboard"></i>
	                                                        </button>
	                                                        <?php if ($isReadable): ?>
	                                                            <a href="?action=view_log&path=<?= urlencode($logPath) ?>" 
	                                                               class="btn btn-sm btn-outline-primary"
	                                                               target="_blank"
	                                                               title="Real-time viewing">
	                                                                <i class="bi bi-terminal"></i>
	                                                            </a>
	                                                        <?php else: ?>
	                                                            <span class="btn btn-sm btn-outline-secondary disabled"
	                                                                  title="Insufficient permissions (<?= htmlspecialchars($owner, ENT_QUOTES) ?>:<?= htmlspecialchars($group, ENT_QUOTES) ?> permissions required)">🔒</span>
	                                                        <?php endif; ?>
	                                                    </div>
	                                                </div>
	                                            </div>
	                                        </div>
	                                    </div>
	                                <?php endforeach; ?>
	                            <?php endif; ?>
	                        </div>
	
	                        <!-- Usage Instructions -->
	                        <div class="alert alert-info mt-4 d-inline-block" style="max-width: 100%; width: fit-content;">
	                            <div class="d-flex flex-column flex-md-row align-items-start gap-2">
	                                <i class="bi bi-info-circle me-2"></i>
	                                <div>
	                                    <strong>Usage Instructions:</strong>
	                                    <ul class="mb-0 mt-2">
	                                        <li>🔒 A locked icon indicates that the file is not accessible</li>
	                                        <li>Click the <i class="bi bi-clipboard"></i> button to copy the path</li>
	                                        <li>Click the <i class="bi bi-terminal"></i> button to open real-time log viewing</li>
	                                        <li>For files with insufficient permissions, please view them in the terminal via SSH</li>
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

	<!-- Server Basic Information -->
	<div class="card border-primary">
	    <div class="card-header bg-primary text-white">
	        <h2 class="h5 mb-0"><i class="bi bi-pc"></i> System Information</h2>
	    </div>
	    <div class="card-body p-0">
	        <div class="row align-items-stretch m-0">
	            <?php foreach (array_chunk($server_info, ceil(count($server_info)/2), true) as $chunk): ?>
	            <div class="col-md-6 h-100 border-end">
	                <table class="table table-sm table-striped mb-0" style="table-layout: fixed;">
	                    <tbody>
	                        <?php foreach ($chunk as $k => $v): ?>
	                        <tr class="align-middle">
	                            <th class="w-40 text-nowrap px-3" style="width: 40%"><?= safe_output($k) ?></th>
	                            <td class="px-3 text-truncate" style="width: 60%"><?= ($k === 'Visitor IP' || $k === 'PHP Information') ? $v : safe_output($v) ?></td>
	                        </tr>
	                        <?php endforeach; ?>
	                    </tbody>
	                </table>
	            </div>
	            <?php endforeach; ?>
	        </div>
	    </div>
	</div>

        <!-- System Resources -->
        <div class="row g-4">
            <!-- CPU Usage -->
            <div class="col-lg-4">
                <div class="card border-info">
                    <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                        <h3 class="h5 mb-0"><i class="bi bi-cpu"></i> CPU Status</h3>
                        <span class="badge bg-dark" id="cpuUpdateTime"></span>
                    </div>
                    <div class="card-body">
		            <?php if (get_current_user() !== 'root'): ?>
		                <div class="text-center text-danger py-4">
		                    <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
		                    Current directory permissions are insufficient to read CPU information!<br>
		                    <small>Please place this file in a directory with appropriate permissions! You will have a better experience!</small>
		                </div>
		            <?php else: ?>
                        <canvas id="cpuChart"></canvas>
                        <div class="mt-3">
                            <dl class="row small">
                                <dt class="col-6">Cores</dt>
                                <dd class="col-6" id="cpuCores"><?= $cpu_usage['cores'] ?? 'Unknown' ?></dd>
                                <dt class="col-6">Current Frequency</dt>
                                <dd class="col-6" id="cpuUsage"><?= number_format($cpu_usage['usage'] ?? 0, 1) ?>%</dd>
                            </dl>
                        </div>
      			 <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Disk Usage -->
            <div class="col-lg-4">
                <div class="card border-warning">
                    <div class="card-header bg-warning d-flex justify-content-between align-items-center">
                        <h3 class="h5 mb-0"><i class="bi bi-hdd"></i> Storage Status</h3>
                        <span class="badge bg-dark" id="diskUpdateTime"></span>
                    </div>
                    <div class="card-body">
		            <?php if (get_current_user() !== 'root'): ?>
		                <div class="text-center text-danger py-4">
		                    <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
		                    Current directory permissions are insufficient to read disk information!<br>
		                    <small>Please place this file in a directory with appropriate permissions! You will have a better experience!</small>
		                </div>
		            <?php else: ?>
                        <canvas id="diskChart"></canvas>
                        <div class="mt-3">
                            <dl class="row small" id="diskInfo">
                                <?php $mainDisk = current($disk_usage) ?>
                                <dt class="col-6 text-nowrap">Total Space</dt>
                                <dd class="col-6"><?= format_bytes($mainDisk['total'] ?? 0) ?></dd>
                                <dt class="col-6">Used Space</dt>
                                <dd class="col-6" id="diskUsed"><?= format_bytes($mainDisk['used'] ?? 0) ?></dd>
                            </dl>
                        </div>
          		  <?php endif; ?>  
                    </div>
                </div>
            </div>

            <!-- Memory Usage -->
            <div class="col-lg-4">
                <div class="card border-success">
                    <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
                        <h3 class="h5 mb-0"><i class="bi bi-memory"></i> Memory Status</h3>
                        <span class="badge bg-dark" id="memoryUpdateTime"></span>
                    </div>
                    <div class="card-body">
		            <?php if (get_current_user() !== 'root'): ?>
		                <div class="text-center text-danger py-4">
		                    <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
		                    Current directory permissions are insufficient to read memory information!<br>
		                    <small>Please place this file in a directory with appropriate permissions! You will have a better experience!</small>
		                </div>
		            <?php else: ?>
                        <canvas id="memoryChart"></canvas>
                        <div class="mt-3">
                            <dl class="row small">
                                <dt class="col-6">Available Memory</dt>
                                <dd class="col-6" id="memoryAvailable"><?= format_bytes($memory_info['available'] ?? 0) ?></dd>
                                <dt class="col-6">Cached/Buffered</dt>
                                <dd class="col-6" id="memoryCached"><?= format_bytes(($memory_info['Cached'] ?? 0) + ($memory_info['Buffers'] ?? 0)) ?></dd>
                            </dl>
                        </div>
            		<?php endif; ?>
                   </div>
                </div>
            </div>
        </div>

        <!-- Network Traffic Monitoring -->
    <div class="card border-primary">
        <div class="card-header bg-primary text-white">
            <h2 class="h5 mb-0"><i class="bi bi-network-patch"></i> Real-time Network Traffic Monitoring</h2>
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
                            <th>Interface Name</th>
                            <th>Received Total</th>
                            <th>Transmitted Total</th>
                            <th>Receive Rate</th>
                            <th>Transmit Rate</th>
                        </tr>
                    </thead>
			    <tbody>
                    <?php if (get_current_user() !== 'root'): ?>
                 <tr>
                  <td colspan="7" class="text-center text-danger py-4">
                 <i class="bi bi-shield-lock fs-4 d-block mb-2"></i>
                Current directory permissions are insufficient to read network traffic!<br>
                <small>Please place this file in a directory with appropriate permissions! You will have a better experience!</small>
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
				<i class="bi bi-info-circle"></i> Traffic Statistics Explanation:
				<ul class="mb-0">
					<li>Received/Transmitted Total: Cumulative traffic since system startup</li>
					<li>Real-time Rate: Calculated based on the traffic difference from the last two page refreshes</li>
					<li>Refresh the page to update real-time rate data</li>
				</ul>
			</div>
		</div>
	</div>

<!-- Mounted File Systems -->
<div class="card border-dark mt-4">
    <div class="card-header bg-dark text-white">
        <h3 class="h5 mb-0"><i class="bi bi-hdd-stack"></i> Mounted File Systems</h3>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th>Mount location</th>
                        <th class="d-none d-sm-table-cell">Type</th>
                        <th class="d-none d-md-table-cell">Device</th>
                        <th class="text-center">Usage ▼</th>
                        <th class="text-end d-none d-sm-table-cell">Available</th>
                        <th class="text-end d-none d-sm-table-cell">Used</th>
                        <th class="text-end">Total space</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($disk_usage)): ?>
                    <tr>
                        <td colspan="7" class="text-center text-muted py-4">
                            <i class="bi bi-hdd-network fs-4 d-block mb-2"></i>
                      Current directory permissions are insufficient to read disk information!<br>
                      <small>Please place this file in a directory with appropriate permissions! You will have a better experience!</small>
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

<!-- Extension Information -->
<div class="card border-info shadow-lg">
    <div class="card-header bg-info text-white position-sticky top-0" style="z-index: 1">
        <div class="d-flex justify-content-between align-items-center">
            <h2 class="h5 mb-0">
                <i class="bi bi-boxes me-2"></i>PHP Extension Management
                <span class="badge bg-white text-info"><?= count($php_extensions) - 1 ?></span>
            </h2>
            <div class="d-flex gap-2">
                <button class="btn btn-sm btn-light" type="button" data-bs-toggle="collapse" 
                        data-bs-target="#extensionsAccordion" aria-expanded="false">
                    <i class="bi bi-arrows-collapse"></i>
                </button>
                <div class="vr"></div>
                <span class="badge bg-success75" title="Enabled Extensions">
                    <i class="bi bi-check-circle me-1"></i><?= count(get_loaded_extensions()) ?>
                </span>
            </div>
        </div>
    </div>
    
    <!-- Extension Status Indicator -->
    <div class="card-body py-2 bg-light">
        <div class="d-flex gap-3 small">
            <span class="d-flex align-items-center">
                <span class="badge bg-success me-2" style="width: 1em; height: 1em"></span>
                Enabled
            </span>
            <span class="d-flex align-items-center">
                <i class="bi bi-shield-slash text-danger me-2"></i>
                High-Risk Extension
            </span>
        </div>
    </div>

    <!-- Extension List -->
    <div class="card-body accordion accordion-flush" id="extensionsAccordion">
        <?php foreach ($php_extensions as $name => $ext): ?>
        <?php if ($name === 'Disabled Extensions') continue; ?>
        <?php $isEnabled = ($ext['Basic Information']['Status'] ?? '') === 'Enabled'; ?>
        
        <div class="accordion-item border-0">
            <div class="accordion-header">
                <button class="accordion-button collapsed shadow-none bg-white rounded mb-2" 
                        type="button" data-bs-toggle="collapse" 
                        data-bs-target="#ext_<?= bin2hex($name) ?>"
                        style="<?= $isEnabled ? '' : 'opacity: 0.6' ?>">
                    <div class="d-flex align-items-center gap-3 w-100 pe-3">
                        <!-- Extension Status Indicator -->
                        <div class="d-flex flex-column text-center" style="min-width: 60px">
                            <span class="badge bg-<?= $isEnabled ? 'success' : 'danger' ?>">
                                <?= $isEnabled ? 'Running' : 'Disabled' ?>
                            </span>
                            <small class="text-muted mt-1">v<?= $ext['Basic Information']['Version'] ?? '?' ?></small>
                        </div>
                        
                        <!-- Extension Core Information -->
                        <div class="flex-grow-1">
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <h6 class="mb-0"><?= safe_output($name) ?></h6>
                                <?php if (get_extension_risk_level($name) === 'High-Risk'): ?>
                                <i class="bi bi-shield-slash text-danger" 
					           aria-hidden="true"
					           title="High risk expansion! Please use with caution"></i>
                                <?php endif; ?>
                            </div>
                            <div class="d-flex flex-wrap gap-2 small">
                                <span class="badge bg-light text-dark border">
                                    <i class="bi bi-file-code me-1" aria-hidden="true"></i>
                                    <?= safe_output($ext['Basic Information']['File Path'] ?? 'Unknown Path') ?>
                                </span>
                                <?php if (($ext['Basic Information']['Compile Type'] ?? '') === 'Dynamic'): ?>
                                <span class="badge bg-info bg-opacity-25 text-info">
                                    <i class="bi bi-plugin me-1" aria-hidden="true"></i>
                                    Dynamically Loaded
                                </span>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </button>
            </div>

            <!-- Extension Details -->
            <div id="ext_<?= bin2hex($name) ?>" class="accordion-collapse collapse" 
                 data-bs-parent="#extensionsAccordion">
			<!-- Information Panel -->
			<div class="accordion-body pt-0">
			    <!-- Security Warning -->
			    <?php if (get_extension_risk_level($name) === 'High-Risk'): ?>
			    <div class="alert alert-danger d-flex align-items-center">
			        <i class="bi bi-exclamation-octagon fs-4 me-3"></i>
			        <div>
			            <h5 class="alert-heading mb-2">High-Risk Extension Warning!</h5>
			            <?= get_extension_warning($name) ?>
			            <hr>
			            <small class="mb-0"><?= get_extension_config_tip($name) ?></small>
			        </div>
			    </div>
			    <?php endif; ?>
			
			    <!-- Information Panel -->
			    <div class="d-flex flex-column gap-3">
			        <!-- Basic Information -->
			        <div class="card">
			            <div class="card-header bg-light">
			                <h5 class="mb-0">
			                    <i class="bi bi-info-square me-2"></i>
			                    Core Configuration
			                </h5>
			            </div>
			            <div class="card-body p-3">
			                <dl class="row mb-0">
			                    <?php foreach ($ext['Basic Information'] as $k => $v): ?>
			                    <dt class="col-sm-5 text-truncate"><?= safe_output($k) ?></dt>
			                    <dd class="col-sm-9 text-truncate" title="<?= safe_output($v) ?>">
			                        <?= safe_output($v) ?>
			                    </dd>
			                    <?php endforeach; ?>
			                </dl>
			            </div>
			        </div>
			
			        <!-- Configuration Parameters -->
			        <div class="card">
			            <div class="card-header bg-light">
			                <h5 class="mb-0">
			                    <i class="bi bi-gear me-2"></i>
			                    Runtime Configuration
			                    <small class="text-muted">(Currently Active)</small>
			                </h5>
			            </div>
						<div class="card-body p-3">
						    <div class="table-responsive">
						        <table class="table table-sm mb-0" style="table-layout: fixed">
						            <tbody>
						                <?php foreach ($ext['Configuration Parameters'] as $key => $item): ?>
						                <tr>
						                    <!-- Precise 25% Width Control -->
						                    <td class="left-col" style="width: 25%">
						                        <div class="text-truncate"><?= str_replace($name.'.', '', $key) ?></div>
						                    </td>
						                    
						                    <!-- Auto-fill the remaining 75% -->
						                    <td class="text-start"><?= safe_output($item['local_value']) ?></td>
						                </tr>
						                <?php endforeach; ?>
						            </tbody>
						        </table>
						    </div>
						</div>
			        </div>
			
			        <!-- Functions/Constants -->
			        <div class="card">
			            <div class="card-header bg-light d-flex justify-content-between">
			                <h5 class="mb-0">
			                    <i class="bi bi-code-square me-2"></i>
			                    Development Interface
			                </h5>
			                <div class="dropdown">
			                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" 
			                            type="button" data-bs-toggle="dropdown">
			                        <i class="bi bi-book me-1"></i>View Documentation
			                    </button>
			                    <ul class="dropdown-menu dropdown-menu-end">
			                        <li><a class="dropdown-item" 
			                            href="<?= get_extension_metadata($name)['doc_url'] ?>" 
			                            target="_blank">
			                            Official Documentation
			                        </a></li>
			                    </ul>
			                </div>
			            </div>
			            <div class="card-body p-3">
			                <div class="row g-2">
			                    <div class="col-12">
			                        <div class="card">
			                            <div class="card-header py-1">
			                                Common Functions
			                                <small class="text-muted">(<?= count($ext['Function List']) ?>)</small>
			                            </div>
			                            <div class="card-body p-2">
									<div class="list-group list-group-flush func-list" 
									     id="func-list-<?= bin2hex($name) ?>"
									     data-items-per-page="6">
									    <?php foreach ($ext['Function List'] as $func): ?>
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
									               title="View Official Documentation"
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
			                                Core Constants
			                                <small class="text-muted">(<?= count($ext['Constant List']) ?>)</small>
			                            </div>
			                            <div class="card-body p-2">
										<div class="list-group list-group-flush const-list" 
										     id="const-list-<?= bin2hex($name) ?>"
										     data-items-per-page="6">
										    <?php foreach ($ext['Constant List'] as $const): ?>
										    <div class="list-group-item py-1 px-2 const-item">
										        <div class="d-flex justify-content-between align-items-start">
										            <div class="flex-grow-1">
										                <code class="d-block mb-1"><?= safe_output($const['name']) ?></code>
										                <div class="small text-muted">
										                    <div><?= safe_output($const['meta']['description']) ?></div>
										                    <div class="d-flex gap-2">
										                        <span class="badge bg-light text-dark border">
										                            Value: <?= safe_output(var_export($const['value'], true)) ?>
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


<!-- Disabled Extensions Warning -->
<?php if (!empty($php_extensions['Disabled Extensions'])): ?>
<div class="card border-danger mt-4 shadow">
    <div class="card-header bg-danger text-white d-flex justify-content-between">
        <h3 class="h5 mb-0">
            <i class="bi bi-shield-slash me-2"></i>
            Disabled Extensions Detection
            <span class="badge bg-white text-danger"><?= safe_output(count($php_extensions['Disabled Extensions'])) ?></span>
        </h3>
        <div class="d-flex gap-2">
            <button class="btn btn-sm btn-light" data-bs-toggle="collapse" 
                    data-bs-target="#disabledExtensions" aria-expanded="true">
                <i class="bi bi-chevron-down"></i>
            </button>
        </div>
    </div>
    
    <div class="card-body collapse show" id="disabledExtensions">
        <!-- New Security Warning -->
        <div class="alert alert-warning mb-4">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <span class="me-md-2 mb-2 mb-md-0">
            Operation Tip: Before enabling extensions, please confirm they are reliable. Malicious extensions may pose security risks to your system. If you need to view the official development manual, click
        </span>
        <a href="https://www.php.net/manual/zh/index.php" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary align-self-md-center">View</a>
        </div>

        <!-- Quick Operation Area -->
        <div class="alert alert-warning d-flex flex-column flex-md-row align-items-md-center gap-3">
            <div class="d-flex align-items-center flex-shrink-0">
                <i class="bi bi-terminal fs-4 me-2"></i>
                <span class="h6 mb-0">Terminal Operation Guide</span>
            </div>
            <div class="d-flex flex-wrap gap-2 flex-grow-1">
                <?php foreach (['pecl install','docker-php-ext-enable'] as $cmd): ?>
                <div class="position-relative code-snippet">
                    <code class="p-2 bg-dark text-white rounded"><?= safe_output($cmd) ?> [extension name]</code>
                    <button class="btn btn-sm btn-outline-light copy-btn" 
                            data-clipboard-text="<?= safe_output($cmd) ?>" 
                            title="Click to copy">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

	<!-- Extension List -->
	<div class="row g-3">
	    <?php 
	    // Risk level style configuration
	    $riskStyles = [
	        'High-Risk' => ['color' => 'danger', 'icon' => 'shield-slash'],
	        'Medium-Risk' => ['color' => 'warning', 'icon' => 'exclamation-triangle'],
	        'Low-Risk' => ['color' => 'success', 'icon' => 'check-circle']
	    ];
	    ?>
	
	    <?php foreach ($php_extensions['Disabled Extensions'] as $ext => $info): 
	        $meta = get_extension_metadata($ext);
	        $docUrl = filter_var($meta['doc_url'], FILTER_SANITIZE_URL);
	        $configTip = get_extension_config_tip($ext);
	        $risk = $info['Risk Level'];
	        $style = $riskStyles[$risk] ?? $riskStyles['Medium-Risk'];
	    ?>
	    
	    <div class="col-12">
	        <div class="card border-<?= $style['color'] ?> shadow-sm">
	            <!-- Card header -->
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
	                        Documentation <i class="bi bi-box-arrow-up-right"></i>
	                    </a>
	                </div>
	            </div>
	
	            <!-- Card body -->
	            <div class="card-body">
	                <!-- Risk status -->
	                <div class="alert alert-<?= $style['color'] ?> d-flex align-items-center gap-2 mb-4">
	                    <i class="bi bi-<?= $style['icon'] ?> me-2"></i>
	                    <div>
	                        <span class="badge bg-<?= $style['color'] ?> me-2"><?= $risk ?></span>
	                        <?= safe_output($info['Enable Recommendation']) ?>
	                    </div>
	                </div>
	
	                <!-- Dependency information -->
	                <?php if(!empty($meta['dependencies'])): ?>
	                <div class="mb-4">
	                    <h5 class="text-uppercase text-muted small mb-3">
	                        <i class="bi bi-puzzle me-2"></i>Dependency Requirements
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
	
	                <!-- Main configuration section -->
	                <div class="border-top pt-4">
	                    <?php 
	                    // Parse configuration suggestions
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
<!-- Database Testing Module -->
<div class="card border-primary shadow-sm">
    <div class="card-header bg-primary text-white">
        <h2 class="h5 mb-0 d-flex align-items-center gap-2">
            <i class="bi bi-database"></i>
            <span>Database Connection Diagnosis</span>
        </h2>
    </div>
    <div class="card-body">
        <!-- Extension Status Detection -->
        <div class="row g-3">
            <?php foreach ($database_tests as $name => $info): ?>
            <div class="col-md-4">
                <div class="card h-100 shadow-sm">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span class="fw-bold"><?= htmlspecialchars($name) ?></span>
                        <span class="badge bg-<?= $info['installed'] ? 'success' : 'danger' ?> rounded-pill">
                            <?= $info['installed'] ? 'Installed' : 'Not Installed' ?>
                        </span>
                    </div>
                    <div class="card-body">
                        <div class="small text-muted">
                            <?php if ($info['installed']): ?>
                                <i class="bi bi-check-circle-fill text-success me-1"></i>
                                Loaded extensions: <?= implode(', ', $info['extensions']) ?>
                            <?php else: ?>
                                <i class="bi bi-x-circle-fill text-danger me-1"></i>
                                Required extensions: <?= implode(' / ', $info['extensions']) ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- Connection Test Form -->
        <form id="dbTestForm" method="post" class="ajax-form mt-4">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="hidden" name="db_test" value="1">
            
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <strong>Test Mode Hint:</strong> The current environment is not fully implemented. All operations will not actually connect to the database. The form fields support format validation, but after submission, no real operations will be performed.
            </div>

            <div class="row g-3">
                <!-- Database Type Selection -->
                <div class="col-md-2">
	                <select name="db_config[type]" class="form-select" required id="dbTypeSelect"
	                        autocomplete="off">
                        <option value="">Select Database Type</option>
                        <?php foreach (['MySQL', 'PostgreSQL', 'SQLite', 'MongoDB', 'Redis'] as $dbtype): ?>
                            <option value="<?= htmlspecialchars($dbtype) ?>">
                                <?= htmlspecialchars($dbtype) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <!-- Dynamic Connection Parameters Group -->
                <div class="col-md-9" id="connectionParams">
                    <!-- Default hide all parameter groups -->
                    <div class="row g-3" id="mysqlParams">
                        <div class="col-md-3">
                            <div class="input-group">
                                <span class="input-group-text">Host</span>
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
                                <span class="input-group-text">Port</span>
                                <input type="number" name="db_config[port]" class="form-control" 
                                       placeholder="3306" min="1" max="65535" value="3306"
                                       autocomplete="off">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">Account</span>
                                <input type="text" name="db_config[user]" class="form-control" 
                                       placeholder="root" required
                                       autocomplete="username">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">Password</span>
                                <input type="password" name="db_config[pass]" class="form-control" autocomplete="new-password">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="input-group">
                                <span class="input-group-text">Database</span>
				            <input type="text" name="db_config[name]" 
				                   class="form-control" 
				                   placeholder="Database Name"
				                   required
				                   autocomplete="organization-title"
				                   data-purpose="database-name">
                            </div>
                        </div>
                    </div>
                    <!-- SQLite-specific parameters -->
                    <div class="row g-3" id="sqliteParams" style="display: none;">
                        <div class="col-md-6">
                            <div class="input-group">
                                <span class="input-group-text">File Path</span>
						  <input type="text" name="db_config[path]" class="form-control" 
						         placeholder="/path/to/database.sqlite"
						         autocomplete="off">
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Operation Button Group -->
                <div class="col-12 mt-4">
                    <div class="d-grid gap-2 d-md-flex justify-content-md-start">
                        <button type="submit" class="btn btn-primary" id="dbTestSubmit">
                            <i class="bi bi-cursor-fill me-2"></i>
                            Execute Connection Test
                            <div class="spinner-border spinner-border-sm d-none" role="status"></div>
                        </button>
                        <button type="reset" class="btn btn-outline-secondary">
                            <i class="bi bi-arrow-clockwise me-2"></i>
                            Reset Form
                        </button>
                    </div>
                </div>

                <!-- Security Hint -->
                <div class="text-danger small w-100 w-md-auto text-center text-md-start mt-3">
                    ⚠️ Test environment database, currently in an unimplemented stage! If you are interested, you can submit a merge request!
                </div>
            </div>
        </form>

        <!-- Test Result Display -->
	<div id="dbTestResult" class="mt-3 alert" style="display: none; transition: all 0.3s ease;"></div>
    </div>
</div>

<!-- Email Testing Module -->
<div class="card border-info shadow-sm">
    <div class="card-header bg-info text-white">
        <h2 class="h5 mb-0 d-flex align-items-center gap-2">
            <i class="bi bi-envelope"></i>
            <span>Email Service Verification</span>
        </h2>
    </div>
    <div class="card-body">
        <form id="mailTestForm" method="post">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <input type="hidden" name="action" value="send_mail">
            
            <div class="alert alert-info">
                <i class="bi bi-info-circle-fill me-2"></i>
                <strong>Note:</strong> This button is only for style testing! This button is currently only a front-end style demonstration component. Please do not enter any real sensitive information!
🔧 Since email service integration and database persistence features require a complete backend implementation (including SMTP configuration, database connection pool management, and business logic processing), I have not completed this functionality! If you need to complete it, feel free to submit a merge request!
            </div>

            <!-- Adjusted Input Group -->
            <div class="input-group mb-3 w-md-75">
                <div class="d-flex gap-2">
                <input type="email" 
                       class="form-control flex-grow-1" 
                       name="email" 
                       placeholder="Please enter a test email (example: test@example.com)" 
                       pattern="[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}$"
                       required
                       autocomplete="email">

                    <button type="submit" class="btn btn-primary flex-shrink-0">
                        <i class="bi bi-envelope-fill me-2"></i>
                        Simulate Send
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
<!-- Footer -->
<footer class="mt-5 text-center text-muted"> 
  <p class="mb-1"><i class="bi bi-geo-alt"></i>Welcome to this page from<span id="ip-info" style="margin-left: 5px;">Retrieving...</span> May the starlight here warm your journey! | Execution Time: <?= get_execution_time() ?></p>
  <p class="mb-0">Powered by PHP <?= safe_output(PHP_VERSION) ?> 
      | Memory Usage: <?= format_bytes(memory_get_usage()) ?>
      | Page Rendering Traffic: <?= get_traffic_stats() ?> 
      | Traffic Consumption Loading: <span id="trafficStats">Calculating...</span>
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
// Network Interface Color Mapping
const interfaceColors = {
    'eth0': '#4a90e2',
    'wlan0': '#50c878',
    'lo': '#ff6b6b',
    'default': '#8e44ad'
};

// Chart Initialization
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
                    title: { text: 'Rate (KB/s)' },
                    beginAtZero: true
                }
            }
        }
    })
};

let activeInterface = null;
const maxHistory = 60; // Keep 60 seconds of data

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

// Format Network Rate
function formatNetworkRate(bytes) {
    if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB/s';
    if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB/s';
    return bytes.toFixed(1) + ' B/s';
}

// Update Network Chart
function updateNetworkChart(interfaceName, receiveRate, transmitRate) {
    const kbReceive = receiveRate / 1024;
    const kbTransmit = transmitRate / 1024;

    let receiveDataset = charts.network.data.datasets.find(d => d.label === `${interfaceName} Receive`);
    let transmitDataset = charts.network.data.datasets.find(d => d.label === `${interfaceName} Transmit`);

    if (!receiveDataset) {
        const color = interfaceColors[interfaceName] || interfaceColors.default;
        receiveDataset = {
            label: `${interfaceName} Receive`,
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
            label: `${interfaceName} Transmit`,
            data: [],
            borderColor: color,
            backgroundColor: color + '40',
            borderDash: [5,5],
            tension: 0.3
        };
        charts.network.data.datasets.push(transmitDataset);
    }

    // Update receive data
    if (receiveDataset.data.length >= maxHistory) receiveDataset.data.shift();
    receiveDataset.data.push(kbReceive);

    // Update transmit data
    if (transmitDataset.data.length >= maxHistory) transmitDataset.data.shift();
    transmitDataset.data.push(kbTransmit);

    // Update time axis
    if (charts.network.data.labels.length >= maxHistory) charts.network.data.labels.shift();
    charts.network.data.labels.push(new Date().toLocaleTimeString());

    charts.network.update();
}

// Update Interface Selector
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

// Update Network Traffic Table
function updateNetworkTable(networkData) {
    const rows = document.querySelectorAll('tr[data-interface]');
    
    rows.forEach(row => {
        const interface = row.dataset.interface;
        const data = networkData[interface];
        
        if (data) {
            // Update table data
            row.querySelector('.receive-rate').textContent = formatNetworkRate(data.receive_rate);
            row.querySelector('.transmit-rate').textContent = formatNetworkRate(data.transmit_rate);

            // Update chart data (only show active interface)
            if (!activeInterface || activeInterface === interface) {
                updateNetworkChart(interface, data.receive_rate, data.transmit_rate);
            }

            // Dynamic color effect
            const baseColor = interfaceColors[interface] || interfaceColors.default;
            const intensity = Math.min(1, (data.receive_rate + data.transmit_rate) / 1e6);
            row.style.backgroundColor = `rgba(${parseInt(baseColor.slice(1,3),16)}, 
                                            ${parseInt(baseColor.slice(3,5),16)}, 
                                            ${parseInt(baseColor.slice(5,7),16)}, 
                                            ${0.1 + intensity * 0.2})`;
        }
    });

    // Update interface selector status
    updateInterfaceSelector(networkData);
}

// AJAX Update Function
function updateMetrics() {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '?monitor=1&t=' + Date.now(), true);
    
    xhr.onload = function() {
        if (xhr.status === 200) {
            try {
                const data = JSON.parse(xhr.responseText);
                if (data.error) {
                    console.error('Monitoring data acquisition failed:', data.error);
                    return;
                }
                
                // Update base charts
                updateChart(charts.cpu, data.cpu.usage);
                updateChart(charts.memory, data.memory.percent);
                updateChart(charts.disk, data.disk.percent);
                
                // Update network data
                updateNetworkTable(data.network);
                
                // Update timestamp
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
                console.error('Data parsing failed:', e);
            }
        } else {
            console.error('Request failed, status code:', xhr.status);
        }
    };

    xhr.onerror = function() {
        console.error('Network request failed');
    };

    xhr.send();
}

// Update Chart Data Function
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

// Start updating every second
let updateInterval = setInterval(updateMetrics, 1000);
updateMetrics();

// Email Test Form Handling
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
        resultDiv.classList.add(data.status === 'Success' ? 'alert-success' : 'alert-danger');
        resultDiv.innerHTML = `<strong>${data.status}!</strong> ${data.message}`;
        resultDiv.classList.remove('d-none');
        
        if (data.status === 'Success') {
            form.reset();
        }
    })
    .catch(() => {
        resultDiv.classList.add('alert-danger');
        resultDiv.innerHTML = '<strong>Error!</strong> Request failed';
        resultDiv.classList.remove('d-none');
    });
});

// Page Visibility Control
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearInterval(updateInterval);
    } else {
        updateInterval = setInterval(updateMetrics, 1000);
        updateMetrics();
    }
});

// Network Status Detection
navigator.connection?.addEventListener('change', updateMetrics);
</script>
<script>
// Precise traffic statistics
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

// Use Performance API to get precise traffic
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
        console.error('Traffic statistics failed:', e);
        return 0;
    }
}

// Update display
window.addEventListener('load', function() {
    // First calculation
    let totalBytes = calculateTraffic();
    document.getElementById('trafficStats').textContent = formatTraffic(totalBytes);
    
    // Continuous monitoring (for SPA)
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
// Add mobile style detection
if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
    document.body.classList.add('mobile-device');
    
    // Add mobile gesture hint
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-info text-center mb-0 d-md-none';
    alertDiv.innerHTML = '<i class="bi bi-phone"></i> Landscape mode provides a better experience';
    document.body.insertBefore(alertDiv, document.body.firstChild);
}
</script>
<script>
// New pagination feature
function initPagination() {
    document.querySelectorAll('.func-list, .const-list').forEach(list => {
        const container = list.closest('.card-body');
        const paginationContainer = container.querySelector('.pagination-container');
        const itemsPerPage = parseInt(list.dataset.itemsPerPage) || 6;
        const items = list.querySelectorAll('.func-item, .const-item');
        const totalItems = items.length;
        const totalPages = Math.ceil(totalItems / itemsPerPage);

        if (totalPages <= 1) return;

        // Create pagination element
        const pagination = document.createElement('div');
        pagination.className = 'd-flex justify-content-center align-items-center gap-2';

        // Previous page button
        const prevBtn = document.createElement('button');
        prevBtn.className = 'btn btn-sm btn-outline-primary';
        prevBtn.innerHTML = '<i class="bi bi-chevron-left"></i>';
        prevBtn.disabled = true;

        // Page number display
        const pageInfo = document.createElement('span');
        pageInfo.className = 'page-info text-muted small';
        pageInfo.textContent = `1/${totalPages}`;

        // Next page button
        const nextBtn = document.createElement('button');
        nextBtn.className = 'btn btn-sm btn-outline-primary';
        nextBtn.innerHTML = '<i class="bi bi-chevron-right"></i>';
        if (totalPages === 1) nextBtn.disabled = true;

        // Assemble pagination
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

        // Initial state
        updateItems();
    });
}

// Initialize pagination
document.addEventListener('DOMContentLoaded', initPagination);
</script>
<script>
// Database testing form processing
document.getElementById('dbTestForm').addEventListener('submit', function(e) {
    e.preventDefault();
    handleDatabaseTest(e);
});

async function handleDatabaseTest(e) {
    const form = e.target;
    const resultDiv = document.getElementById('dbTestResult');
    const submitBtn = document.querySelector('#dbTestSubmit');
    const spinner = submitBtn.querySelector('.spinner-border');

    resultDiv.style.display = 'none';
    submitBtn.disabled = true;
    spinner.classList.remove('d-none');

    try {
        const response = await fetch('', {
            method: 'POST',
            body: new FormData(form)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        
        resultDiv.className = `alert alert-${data.status === 'success' ? 'success' : 'danger'}`;
        resultDiv.innerHTML = `
            <h5>${data.status === 'success' ? '✅ 连接成功' : '❌ 连接失败'}</h5>
            <div>${data.message}</div>
            ${data.details ? `<pre>${JSON.stringify(data.details, null, 2)}</pre>` : ''}
        `;

    } catch (error) {
        console.error('request failure:', error);
        resultDiv.className = 'alert alert-danger';
        resultDiv.innerHTML = `
            <h5>🚨 Request Error</h5>
            <div>${error.message}</div>
        `;
    } finally {
        resultDiv.style.display = 'block';
        submitBtn.disabled = false;
        spinner.classList.add('d-none');
        resultDiv.scrollIntoView({ behavior: 'smooth' });
    }
}
</script>
<script>
// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltipTriggerList.map(t => new bootstrap.Tooltip(t, {
        trigger: 'hover'
    }));
});
</script>
<script>
// DataTables initialization
document.addEventListener('DOMContentLoaded', function () {
    $('.network-table, .disk-table').DataTable({
        ordering: true,
        searching: true,
        language: {
            url: 'https://cdn.datatables.net/plug-ins/2.2.2/i18n/en-GB.json'
        },
        dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>rt<"row"<"col-sm-12 col-md-6"i><"col-sm-12 col-md-6"p>>',
        responsive: true
    });
});

// Clipboard.js initialization
new ClipboardJS('.copy-btn').on('success', function(e) {
    const originalHTML = e.trigger.innerHTML;
    e.trigger.innerHTML = '<i class="bi bi-check2"></i> Copied!';
    setTimeout(() => {
        e.trigger.innerHTML = originalHTML;
    }, 2000);
});

// Add dynamic animations
document.querySelectorAll('.traffic-badge').forEach(badge => {
    badge.classList.add('animate__animated', 'animate__fadeInRight');
});
</script>
<script>
// IP Information Query (IPv4 enforced)
async function initIPLocation() {
    try {
        // Step 1: Get pure IPv4 address
        const ipResponse = await fetch('https://ipapi.co/ip/?version=4');
        if (!ipResponse.ok) throw new Error('Failed to get IPv4 address');
        const ipv4Address = await ipResponse.text();

        // Step 2: Get details with IPv4 address
        const detailResponse = await fetch(`https://ipapi.co/${ipv4Address}/json/`);
        if (!detailResponse.ok) throw new Error('Failed to get IP details');
        const data = await detailResponse.json();

        // Update IP display
        document.getElementById('visitorIp').textContent = data.ip || 'Unknown IP';

        // Build location information
        const locationParts = [];
        if (data.country_name) locationParts.push(data.country_name);
        if (data.region) locationParts.push(data.region);
        if (data.city) locationParts.push(data.city);

        document.getElementById('ip-info').textContent = 
            locationParts.length > 0 ? locationParts.join(' · ') : 'Unknown Location';

    } catch (error) {
        console.error('IP Query Error:', error);
        document.getElementById('visitorIp').textContent = 'Fetch Failed';
        document.getElementById('ip-info').textContent = 'Location Unavailable';
    }
}

// Date time update function (US format)
function updateDateTime() {
    const now = new Date();
    const options = { 
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
        timeZone: 'America/New_York'
    };
    document.getElementById('currentDateTime').textContent = 
        new Intl.DateTimeFormat('en-US', options).format(now)
        .replace(/(\d+)\/(\d+)\/(\d+), (\d+:\d+:\d+)/, '$1/$2/$3 $4');
}

// Initialization
window.onload = function() {
    initIPLocation();
    updateDateTime();
    setInterval(updateDateTime, 1000); // Update every second
};
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