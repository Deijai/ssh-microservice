/**
 * 🖥️ Server Status Model
 * Defines the structure for server status and monitoring data
 */

/**
 * Complete server status information
 */
export interface ServerStatus {
    /** Unique identifier for the server */
    readonly serverId: string;

    /** Whether the server is reachable via SSH */
    readonly isOnline: boolean;

    /** Connection status details */
    readonly connection: ConnectionStatus;

    /** System resource usage */
    readonly resources: SystemResources;

    /** Running services information */
    readonly services: readonly ServiceInfo[];

    /** Network information */
    readonly network: NetworkStatus;

    /** Security information */
    readonly security: SecurityStatus;

    /** Performance metrics */
    readonly performance: PerformanceMetrics;

    /** System information */
    readonly system: SystemInfo;

    /** Timestamp of last status check */
    readonly lastCheck: Date;

    /** How long the status check took */
    readonly checkDuration: number;

    /** Any errors encountered during status check */
    readonly errors?: readonly string[];

    /** Additional metadata */
    readonly metadata?: Record<string, unknown>;
}

/**
 * SSH Connection status details
 */
export interface ConnectionStatus {
    /** Whether SSH connection is available */
    readonly connected: boolean;

    /** Connection response time in milliseconds */
    readonly responseTime: number;

    /** SSH protocol version */
    readonly protocolVersion?: string;

    /** Encryption algorithm in use */
    readonly encryption?: string;

    /** Authentication method used */
    readonly authMethod?: 'password' | 'publickey' | 'keyboard-interactive';

    /** Number of active SSH sessions */
    readonly activeSessions: number;

    /** Connection quality score (0-100) */
    readonly quality: number;

    /** Last successful connection time */
    readonly lastConnected?: Date;

    /** Connection error if any */
    readonly error?: string;
}

/**
 * System resource usage information
 */
export interface SystemResources {
    /** CPU usage information */
    readonly cpu: CPUUsage;

    /** Memory usage information */
    readonly memory: MemoryUsage;

    /** Disk usage information */
    readonly disk: DiskUsage;

    /** Swap usage information */
    readonly swap: SwapUsage;

    /** I/O statistics */
    readonly io: IOStats;
}

/**
 * CPU usage details
 */
export interface CPUUsage {
    /** Overall CPU usage percentage (0-100) */
    readonly overall: number;

    /** Per-core usage percentages */
    readonly cores: readonly number[];

    /** Load averages (1, 5, 15 minutes) */
    readonly loadAverage: readonly [number, number, number];

    /** CPU frequency in MHz */
    readonly frequency?: number;

    /** CPU temperature in Celsius (if available) */
    readonly temperature?: number;

    /** Time spent in different states */
    readonly times: {
        readonly user: number;
        readonly nice: number;
        readonly system: number;
        readonly idle: number;
        readonly iowait: number;
        readonly irq: number;
        readonly softirq: number;
    };
}

/**
 * Memory usage details
 */
export interface MemoryUsage {
    /** Total memory in bytes */
    readonly total: number;

    /** Used memory in bytes */
    readonly used: number;

    /** Free memory in bytes */
    readonly free: number;

    /** Available memory in bytes */
    readonly available: number;

    /** Memory usage percentage (0-100) */
    readonly usage: number;

    /** Buffer memory in bytes */
    readonly buffers: number;

    /** Cached memory in bytes */
    readonly cached: number;

    /** Shared memory in bytes */
    readonly shared: number;
}

/**
 * Disk usage details
 */
export interface DiskUsage {
    /** Overall disk usage percentage (0-100) */
    readonly overall: number;

    /** Individual filesystem usage */
    readonly filesystems: readonly FilesystemUsage[];

    /** Total disk space across all filesystems */
    readonly totalSpace: number;

    /** Total used space across all filesystems */
    readonly totalUsed: number;

    /** Total free space across all filesystems */
    readonly totalFree: number;

    /** Disk I/O statistics */
    readonly io: {
        readonly readBytes: number;
        readonly writeBytes: number;
        readonly readOps: number;
        readonly writeOps: number;
    };
}

/**
 * Individual filesystem usage
 */
export interface FilesystemUsage {
    readonly device: string;
    readonly mountpoint: string;
    readonly type: string;
    readonly size: number;
    readonly used: number;
    readonly free: number;
    readonly usage: number;
    readonly inodes: {
        readonly total: number;
        readonly used: number;
        readonly free: number;
        readonly usage: number;
    };
}

/**
 * Swap usage details
 */
export interface SwapUsage {
    readonly total: number;
    readonly used: number;
    readonly free: number;
    readonly usage: number;
}

/**
 * I/O statistics
 */
export interface IOStats {
    readonly read: {
        readonly bytes: number;
        readonly operations: number;
        readonly time: number;
    };
    readonly write: {
        readonly bytes: number;
        readonly operations: number;
        readonly time: number;
    };
}

/**
 * Service information
 */
export interface ServiceInfo {
    readonly name: string;
    readonly status: 'running' | 'stopped' | 'failed' | 'unknown';
    readonly pid?: number;
    readonly uptime?: number;
    readonly cpuUsage?: number;
    readonly memoryUsage?: number;
    readonly description?: string;
    readonly autoStart: boolean;
    readonly restartCount?: number;
    readonly lastRestart?: Date;
}

/**
 * Network status information
 */
export interface NetworkStatus {
    /** Network interfaces */
    readonly interfaces: readonly NetworkInterfaceStatus[];

    /** Active network connections */
    readonly connections: {
        readonly total: number;
        readonly established: number;
        readonly listening: number;
        readonly timeWait: number;
    };

    /** Network traffic statistics */
    readonly traffic: {
        readonly bytesReceived: number;
        readonly bytesSent: number;
        readonly packetsReceived: number;
        readonly packetsSent: number;
        readonly errorsReceived: number;
        readonly errorsSent: number;
    };

    /** DNS configuration */
    readonly dns: {
        readonly servers: readonly string[];
        readonly domain?: string;
        readonly search?: readonly string[];
    };
}

/**
 * Network interface status
 */
export interface NetworkInterfaceStatus {
    readonly name: string;
    readonly type: 'ethernet' | 'wireless' | 'loopback' | 'virtual' | 'other';
    readonly status: 'up' | 'down';
    readonly addresses: readonly {
        readonly address: string;
        readonly family: 'IPv4' | 'IPv6';
        readonly netmask: string;
        readonly broadcast?: string;
    }[];
    readonly mtu: number;
    readonly speed?: number; // Mbps
    readonly duplex?: 'full' | 'half';
    readonly statistics: {
        readonly bytesReceived: number;
        readonly bytesSent: number;
        readonly packetsReceived: number;
        readonly packetsSent: number;
        readonly errorsReceived: number;
        readonly errorsSent: number;
    };
}

/**
 * Security status information
 */
export interface SecurityStatus {
    /** Firewall status */
    readonly firewall: {
        readonly enabled: boolean;
        readonly rules: number;
        readonly defaultPolicy: 'accept' | 'drop' | 'reject';
    };

    /** Failed login attempts */
    readonly auth: {
        readonly failedLogins: number;
        readonly lastFailedLogin?: Date;
        readonly activeUsers: number;
        readonly lockedAccounts: number;
    };

    /** Security updates */
    readonly updates: {
        readonly available: number;
        readonly security: number;
        readonly lastUpdate?: Date;
    };

    /** SELinux/AppArmor status */
    readonly mandatory: {
        readonly type?: 'selinux' | 'apparmor' | 'none';
        readonly status?: 'enforcing' | 'permissive' | 'disabled';
    };
}

/**
 * Performance metrics
 */
export interface PerformanceMetrics {
    /** System uptime in seconds */
    readonly uptime: number;

    /** Boot time */
    readonly bootTime: Date;

    /** Process count */
    readonly processes: {
        readonly total: number;
        readonly running: number;
        readonly sleeping: number;
        readonly stopped: number;
        readonly zombie: number;
    };

    /** Thread count */
    readonly threads: number;

    /** File descriptor usage */
    readonly fileDescriptors: {
        readonly allocated: number;
        readonly maximum: number;
        readonly usage: number;
    };

    /** Context switches per second */
    readonly contextSwitches: number;

    /** Interrupts per second */
    readonly interrupts: number;
}

/**
 * System information
 */
export interface SystemInfo {
    readonly hostname: string;
    readonly os: {
        readonly name: string;
        readonly version: string;
        readonly release: string;
        readonly architecture: string;
        readonly kernel: string;
    };
    readonly hardware: {
        readonly vendor?: string;
        readonly model?: string;
        readonly serial?: string;
        readonly cpuModel: string;
        readonly cpuCores: number;
        readonly totalMemory: number;
    };
    readonly virtualization?: {
        readonly type: 'kvm' | 'vmware' | 'virtualbox' | 'xen' | 'docker' | 'lxc' | 'none';
        readonly role: 'host' | 'guest' | 'unknown';
    };
}

/**
 * Simplified server status for quick checks
 */
export interface QuickServerStatus {
    readonly serverId: string;
    readonly isOnline: boolean;
    readonly cpuUsage: number;
    readonly memoryUsage: number;
    readonly diskUsage: number;
    readonly uptime: number;
    readonly responseTime: number;
    readonly lastCheck: Date;
    readonly error?: string;
}

/**
 * Server status history entry
 */
export interface ServerStatusHistory {
    readonly timestamp: Date;
    readonly status: QuickServerStatus;
    readonly metrics: {
        readonly cpu: number;
        readonly memory: number;
        readonly disk: number;
        readonly network: {
            readonly bytesIn: number;
            readonly bytesOut: number;
        };
    };
}

/**
 * Alert thresholds for server monitoring
 */
export interface AlertThresholds {
    readonly cpu: {
        readonly warning: number;
        readonly critical: number;
    };
    readonly memory: {
        readonly warning: number;
        readonly critical: number;
    };
    readonly disk: {
        readonly warning: number;
        readonly critical: number;
    };
    readonly responseTime: {
        readonly warning: number;
        readonly critical: number;
    };
    readonly uptime: {
        readonly minimum: number;
    };
}

/**
 * Default alert thresholds
 */
export const DEFAULT_ALERT_THRESHOLDS: Readonly<AlertThresholds> = {
    cpu: {
        warning: 80,
        critical: 95
    },
    memory: {
        warning: 85,
        critical: 95
    },
    disk: {
        warning: 90,
        critical: 98
    },
    responseTime: {
        warning: 1000,
        critical: 5000
    },
    uptime: {
        minimum: 300 // 5 minutes
    }
} as const;