/**
 * 📊 Command Result Model
 * Defines the structure for SSH command execution results
 */

/**
 * Result of an SSH command execution
 */
export interface CommandResult {
    /** Unique identifier for this command execution */
    readonly id: string;

    /** The command that was executed */
    readonly command: string;

    /** Standard output from the command */
    readonly stdout: string;

    /** Standard error output from the command */
    readonly stderr: string;

    /** Exit code returned by the command */
    readonly exitCode: number;

    /** Whether the command was successful (exitCode === 0) */
    readonly success: boolean;

    /** Execution duration in milliseconds */
    readonly duration: number;

    /** Timestamp when command started */
    readonly startedAt: Date;

    /** Timestamp when command completed */
    readonly completedAt: Date;

    /** Server credentials used (without sensitive data) */
    readonly server: {
        readonly host: string;
        readonly username: string;
        readonly port: number;
    };

    /** Additional metadata */
    readonly metadata?: {
        readonly workingDirectory?: string;
        readonly environment?: Record<string, string>;
        readonly signal?: string;
        readonly memoryUsage?: number;
        readonly cpuUsage?: number;
    };
}

/**
 * Streaming command result for real-time output
 */
export interface StreamingCommandResult {
    /** Unique identifier for this command execution */
    readonly id: string;

    /** The command being executed */
    readonly command: string;

    /** Current status of the command */
    readonly status: 'running' | 'completed' | 'failed' | 'cancelled';

    /** Timestamp when command started */
    readonly startedAt: Date;

    /** Current output chunks */
    readonly outputChunks: readonly OutputChunk[];

    /** Current exit code (null if still running) */
    readonly exitCode: number | null;

    /** Current execution duration */
    readonly duration: number;

    /** Server information */
    readonly server: {
        readonly host: string;
        readonly username: string;
        readonly port: number;
    };
}

/**
 * Output chunk for streaming commands
 */
export interface OutputChunk {
    /** Type of output */
    readonly type: 'stdout' | 'stderr';

    /** Output content */
    readonly content: string;

    /** Timestamp when this chunk was received */
    readonly timestamp: Date;

    /** Sequence number for ordering */
    readonly sequence: number;
}

/**
 * Command execution options
 */
export interface CommandOptions {
    /** Working directory for command execution */
    readonly workingDirectory?: string;

    /** Environment variables */
    readonly environment?: Record<string, string>;

    /** Command timeout in milliseconds */
    readonly timeout?: number;

    /** Whether to capture output in real-time */
    readonly streaming?: boolean;

    /** Maximum output size in bytes */
    readonly maxOutputSize?: number;

    /** Whether to run as privileged user */
    readonly sudo?: boolean;

    /** Custom shell to use */
    readonly shell?: string;

    /** Whether to allocate a pseudo-terminal */
    readonly pty?: boolean;
}

/**
 * Command validation result
 */
export interface CommandValidation {
    /** Whether the command is valid and safe */
    readonly isValid: boolean;

    /** Whether the command is considered dangerous */
    readonly isDangerous: boolean;

    /** Risk level assessment */
    readonly riskLevel: 'low' | 'medium' | 'high' | 'critical';

    /** Validation errors */
    readonly errors: readonly string[];

    /** Security warnings */
    readonly warnings: readonly string[];

    /** Suggested safer alternatives */
    readonly alternatives?: readonly string[];
}

/**
 * Batch command execution result
 */
export interface BatchCommandResult {
    /** Unique identifier for the batch */
    readonly batchId: string;

    /** Individual command results */
    readonly results: readonly CommandResult[];

    /** Overall success status */
    readonly success: boolean;

    /** Total execution time */
    readonly totalDuration: number;

    /** Batch execution metadata */
    readonly metadata: {
        readonly totalCommands: number;
        readonly successfulCommands: number;
        readonly failedCommands: number;
        readonly skippedCommands: number;
        readonly executionMode: 'sequential' | 'parallel';
        readonly stopOnFailure: boolean;
    };

    /** Timestamp when batch started */
    readonly startedAt: Date;

    /** Timestamp when batch completed */
    readonly completedAt: Date;
}

/**
 * System information result
 */
export interface SystemInfoResult {
    /** System type and version */
    readonly system: {
        readonly type: string;
        readonly platform: string;
        readonly arch: string;
        readonly release: string;
        readonly version: string;
        readonly hostname: string;
    };

    /** CPU information */
    readonly cpu: {
        readonly model: string;
        readonly cores: number;
        readonly usage: number;
        readonly loadAverage: readonly number[];
    };

    /** Memory information */
    readonly memory: {
        readonly total: number;
        readonly free: number;
        readonly used: number;
        readonly available: number;
        readonly usage: number;
    };

    /** Disk information */
    readonly disk: {
        readonly total: number;
        readonly free: number;
        readonly used: number;
        readonly usage: number;
        readonly filesystems: readonly FileSystemInfo[];
    };

    /** Network information */
    readonly network: {
        readonly interfaces: readonly NetworkInterface[];
        readonly connections: number;
    };

    /** Process information */
    readonly processes: {
        readonly total: number;
        readonly running: number;
        readonly sleeping: number;
        readonly stopped: number;
        readonly zombie: number;
    };

    /** Uptime in seconds */
    readonly uptime: number;

    /** Timestamp when info was collected */
    readonly timestamp: Date;
}

/**
 * File system information
 */
export interface FileSystemInfo {
    readonly device: string;
    readonly mountpoint: string;
    readonly type: string;
    readonly size: number;
    readonly used: number;
    readonly available: number;
    readonly usage: number;
}

/**
 * Network interface information
 */
export interface NetworkInterface {
    readonly name: string;
    readonly type: string;
    readonly addresses: readonly {
        readonly address: string;
        readonly family: 'IPv4' | 'IPv6';
        readonly internal: boolean;
    }[];
    readonly status: 'up' | 'down';
    readonly mtu: number;
}

/**
 * Default command options
 */
export const DEFAULT_COMMAND_OPTIONS: Readonly<CommandOptions> = {
    timeout: 30000,
    streaming: false,
    maxOutputSize: 1024 * 1024, // 1MB
    sudo: false,
    shell: '/bin/bash',
    pty: false
} as const;

/**
 * Common dangerous command patterns
 */
export const DANGEROUS_COMMAND_PATTERNS: readonly RegExp[] = [
    /rm\s+(-rf?|--recursive|--force)/i,
    /sudo\s+rm/i,
    /format\s+/i,
    /mkfs\./i,
    /dd\s+if=/i,
    /:(){ :|:&};:/i, // Fork bomb
    /del\s+\/[sq]/i,
    /rmdir\s+\/s/i,
    />\/dev\/(null|zero|random)/i,
    /shutdown|halt|reboot\s+-/i,
    /kill\s+-9\s+1/i, // Kill init process
    /chmod\s+777\s+\//i,
    /chown\s+root:root\s+\//i
] as const;