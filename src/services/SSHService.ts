/**
 * 🔐 SSH Service
 * Core SSH functionality with connection management and command execution
 */

import { Client, ConnectConfig, ClientChannel } from 'ssh2';
import { EventEmitter } from 'events';
import NodeCache from 'node-cache';
import { v4 as uuidv4 } from 'uuid';

import { SSHCredentials, DEFAULT_SSH_OPTIONS } from '@/models/SSHCredentials';
import {
    CommandResult,
    CommandOptions,
    StreamingCommandResult,
    OutputChunk,
    BatchCommandResult,
    SystemInfoResult,
    DEFAULT_COMMAND_OPTIONS
} from '@/models/CommandResult';
import { ServerStatus, QuickServerStatus } from '@/models/ServerStatus';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';
import { validator } from '@/utils/validator';
import {
    SSHConnectionError,
    SSHCommandError,
    ValidationError,
    TimeoutError,
    QuotaExceededError
} from '@/utils/errorHandler';

/**
 * SSH connection pool entry
 */
interface SSHConnection {
    readonly id: string;
    readonly client: Client;
    readonly credentials: SSHCredentials;
    readonly connectedAt: Date;
    readonly lastUsedAt: Date;
    isActive: boolean;
    usageCount: number;
}

/**
 * Connection pool statistics
 */
interface PoolStats {
    readonly totalConnections: number;
    readonly activeConnections: number;
    readonly idleConnections: number;
    readonly totalUsage: number;
    readonly averageUsage: number;
}

/**
 * SSH Service class
 */
export class SSHService extends EventEmitter {
    private static instance: SSHService;
    private connectionPool: Map<string, SSHConnection>;
    private commandCache: NodeCache;
    private activeStreams: Map<string, StreamingCommandResult>;
    private connectionStats: Map<string, { attempts: number; lastAttempt: Date }>;
    private readonly maxConnections: number;
    private readonly connectionTimeout: number;
    private readonly commandTimeout: number;

    private constructor() {
        super();
        this.connectionPool = new Map();
        this.commandCache = new NodeCache({
            stdTTL: config.cache.ttl,
            checkperiod: config.cache.checkPeriod,
            maxKeys: config.cache.maxKeys
        });
        this.activeStreams = new Map();
        this.connectionStats = new Map();
        this.maxConnections = config.ssh.maxConcurrentConnections;
        this.connectionTimeout = config.ssh.connectionTimeout;
        this.commandTimeout = config.ssh.commandTimeout;

        // Setup cleanup intervals
        this.setupCleanupTasks();
    }

    /**
     * Get SSH service singleton instance
     */
    static getInstance(): SSHService {
        if (!SSHService.instance) {
            SSHService.instance = new SSHService();
        }
        return SSHService.instance;
    }

    /**
     * Setup periodic cleanup tasks
     */
    private setupCleanupTasks(): void {
        // Cleanup idle connections every 5 minutes
        setInterval(() => {
            this.cleanupIdleConnections();
        }, 300000);

        // Cleanup old command cache every 10 minutes
        setInterval(() => {
            this.commandCache.flushAll();
        }, 600000);

        // Cleanup old connection stats every hour
        setInterval(() => {
            this.cleanupConnectionStats();
        }, 3600000);
    }

    /**
     * Create SSH connection
     */
    async connect(credentials: SSHCredentials): Promise<string> {
        // Validate credentials
        const validation = validator.sshCredentials(credentials);
        if (!validation.isValid) {
            throw new ValidationError('Invalid SSH credentials', validation.errors);
        }

        // Check connection pool limits
        if (this.connectionPool.size >= this.maxConnections) {
            throw new QuotaExceededError('Maximum concurrent connections reached');
        }

        const connectionId = uuidv4();
        const host = credentials.host;

        try {
            // Check connection attempt limits
            this.checkConnectionAttempts(host);

            // Create SSH client
            const client = new Client();

            // Setup connection configuration
            const connectConfig: ConnectConfig = {
                host: credentials.host,
                port: credentials.port,
                username: credentials.username,
                password: credentials.password,
                privateKey: credentials.privateKey,
                passphrase: credentials.passphrase,
                readyTimeout: this.connectionTimeout,
                keepaliveInterval: credentials.keepaliveInterval || 30000,
                keepaliveCountMax: 3,
                algorithms: DEFAULT_SSH_OPTIONS.algorithms,
                debug: credentials.debug ? console.log : undefined
            };

            // Connect with timeout
            await this.connectWithTimeout(client, connectConfig, connectionId);

            // Create connection entry
            const connection: SSHConnection = {
                id: connectionId,
                client,
                credentials,
                connectedAt: new Date(),
                lastUsedAt: new Date(),
                isActive: true,
                usageCount: 0
            };

            // Add to pool
            this.connectionPool.set(connectionId, connection);

            // Update stats
            this.updateConnectionStats(host, true);

            // Log successful connection
            logger.sshConnection(
                credentials.host,
                credentials.username,
                true,
                Date.now() - connection.connectedAt.getTime(),
                { requestId: connectionId }
            );

            // Emit connection event
            this.emit('connection:established', { connectionId, host, username: credentials.username });

            return connectionId;

        } catch (error) {
            // Update stats for failed connection
            this.updateConnectionStats(host, false);

            // Log failed connection
            logger.sshConnection(
                credentials.host,
                credentials.username,
                false,
                0,
                { requestId: connectionId, error: error as Error }
            );

            // Convert to SSH connection error
            const message = error instanceof Error ? error.message : 'Unknown connection error';
            throw new SSHConnectionError(`Failed to connect to ${host}: ${message}`, error);
        }
    }

    /**
     * Connect with timeout promise
     */
    private connectWithTimeout(client: Client, config: ConnectConfig, connectionId: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                client.destroy();
                reject(new TimeoutError('SSH connection timeout'));
            }, this.connectionTimeout);

            client.on('ready', () => {
                clearTimeout(timeout);
                resolve();
            });

            client.on('error', (error) => {
                clearTimeout(timeout);
                reject(error);
            });

            client.on('close', () => {
                this.emit('connection:closed', { connectionId });
            });

            client.connect(config);
        });
    }

    /**
     * Execute command on SSH connection
     */
    async executeCommand(
        connectionId: string,
        command: string,
        options: CommandOptions = {}
    ): Promise<CommandResult> {
        // Validate command
        const commandValidation = validator.command(command);
        if (!commandValidation.isValid) {
            throw new ValidationError('Invalid command', commandValidation.errors);
        }

        // Validate options
        const optionsValidation = validator.commandOptions(options);
        if (!optionsValidation.isValid) {
            throw new ValidationError('Invalid command options', optionsValidation.errors);
        }

        // Get connection
        const connection = this.getConnection(connectionId);
        const mergedOptions = { ...DEFAULT_COMMAND_OPTIONS, ...options };
        const resultId = uuidv4();
        const startTime = new Date();

        try {
            // Check cache for read-only commands
            if (this.isReadOnlyCommand(command)) {
                const cacheKey = this.generateCacheKey(connectionId, command, mergedOptions);
                const cachedResult = this.commandCache.get<CommandResult>(cacheKey);
                if (cachedResult) {
                    logger.debug('Command result served from cache', {
                        requestId: resultId,
                        command: command.substring(0, 100)
                    });
                    return cachedResult;
                }
            }

            // Prepare command with options
            const fullCommand = this.prepareCommand(command, mergedOptions);

            // Execute command
            const result = await this.execCommand(connection, fullCommand, mergedOptions, resultId);

            // Cache result for read-only commands
            if (this.isReadOnlyCommand(command)) {
                const cacheKey = this.generateCacheKey(connectionId, command, mergedOptions);
                this.commandCache.set(cacheKey, result, 300); // 5 minutes
            }

            // Update connection usage
            connection.lastUsedAt = new Date();
            connection.usageCount++;

            // Log command execution
            logger.sshCommand(
                connection.credentials.host,
                command,
                result.success,
                result.duration,
                { requestId: resultId }
            );

            return result;

        } catch (error) {
            const duration = Date.now() - startTime.getTime();

            // Log failed command
            logger.sshCommand(
                connection.credentials.host,
                command,
                false,
                duration,
                { requestId: resultId, error: error as Error }
            );

            throw error instanceof SSHCommandError ? error :
                new SSHCommandError(`Command execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`, error);
        }
    }

    /**
     * Execute command with streaming output
     */
    async executeStreamingCommand(
        connectionId: string,
        command: string,
        options: CommandOptions = {}
    ): Promise<string> {
        const connection = this.getConnection(connectionId);
        const streamId = uuidv4();
        const startTime = new Date();

        // Create streaming result
        const streamingResult: StreamingCommandResult = {
            id: streamId,
            command,
            status: 'running',
            startedAt: startTime,
            outputChunks: [],
            exitCode: null,
            duration: 0,
            server: {
                host: connection.credentials.host,
                username: connection.credentials.username,
                port: connection.credentials.port
            }
        };

        this.activeStreams.set(streamId, streamingResult);

        try {
            const mergedOptions = { ...DEFAULT_COMMAND_OPTIONS, ...options };
            const fullCommand = this.prepareCommand(command, mergedOptions);

            await this.execStreamingCommand(connection, fullCommand, streamingResult);

            return streamId;

        } catch (error) {
            streamingResult.status = 'failed';
            this.activeStreams.set(streamId, streamingResult);
            throw error;
        }
    }

    /**
     * Get streaming command result
     */
    getStreamingResult(streamId: string): StreamingCommandResult | null {
        return this.activeStreams.get(streamId) || null;
    }

    /**
     * Cancel streaming command
     */
    cancelStreamingCommand(streamId: string): boolean {
        const result = this.activeStreams.get(streamId);
        if (!result || result.status !== 'running') {
            return false;
        }

        result.status = 'cancelled';
        this.activeStreams.set(streamId, result);
        return true;
    }

    /**
     * Execute batch commands
     */
    async executeBatchCommands(
        connectionId: string,
        commands: string[],
        options: {
            mode: 'sequential' | 'parallel';
            stopOnFailure: boolean;
            commandOptions?: CommandOptions;
        } = { mode: 'sequential', stopOnFailure: true }
    ): Promise<BatchCommandResult> {
        const batchId = uuidv4();
        const startTime = new Date();
        const results: CommandResult[] = [];

        try {
            if (options.mode === 'sequential') {
                for (const command of commands) {
                    try {
                        const result = await this.executeCommand(connectionId, command, options.commandOptions);
                        results.push(result);

                        if (!result.success && options.stopOnFailure) {
                            break;
                        }
                    } catch (error) {
                        if (options.stopOnFailure) {
                            throw error;
                        }
                        // Create error result for failed command
                        results.push({
                            id: uuidv4(),
                            command,
                            stdout: '',
                            stderr: error instanceof Error ? error.message : 'Unknown error',
                            exitCode: -1,
                            success: false,
                            duration: 0,
                            startedAt: new Date(),
                            completedAt: new Date(),
                            server: this.getConnection(connectionId).credentials
                        } as CommandResult);
                    }
                }
            } else {
                // Parallel execution
                const promises = commands.map(command =>
                    this.executeCommand(connectionId, command, options.commandOptions)
                        .catch(error => ({
                            id: uuidv4(),
                            command,
                            stdout: '',
                            stderr: error instanceof Error ? error.message : 'Unknown error',
                            exitCode: -1,
                            success: false,
                            duration: 0,
                            startedAt: new Date(),
                            completedAt: new Date(),
                            server: this.getConnection(connectionId).credentials
                        } as CommandResult))
                );

                results.push(...await Promise.all(promises));
            }

            const endTime = new Date();
            const successfulCommands = results.filter(r => r.success).length;
            const failedCommands = results.filter(r => !r.success).length;

            return {
                batchId,
                results,
                success: failedCommands === 0,
                totalDuration: endTime.getTime() - startTime.getTime(),
                metadata: {
                    totalCommands: commands.length,
                    successfulCommands,
                    failedCommands,
                    skippedCommands: commands.length - results.length,
                    executionMode: options.mode,
                    stopOnFailure: options.stopOnFailure
                },
                startedAt: startTime,
                completedAt: endTime
            };

        } catch (error) {
            throw new SSHCommandError(`Batch command execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`, error);
        }
    }

    /**
     * Get server status
     */
    async getServerStatus(connectionId: string): Promise<ServerStatus> {
        const connection = this.getConnection(connectionId);
        const statusId = uuidv4();

        try {
            // Execute system information commands
            const commands = {
                uptime: 'uptime',
                memory: 'free -m',
                disk: 'df -h',
                cpu: 'top -bn1 | grep "Cpu(s)"',
                processes: 'ps aux | wc -l',
                network: 'ss -tuln',
                system: 'uname -a'
            };

            const results: Record<string, CommandResult> = {};

            for (const [key, command] of Object.entries(commands)) {
                try {
                    results[key] = await this.executeCommand(connectionId, command, { timeout: 10000 });
                } catch (error) {
                    logger.warn(`Failed to get ${key} status`, { error: error as Error });
                }
            }

            // Parse results and build status
            const status = this.parseSystemStatus(connection.credentials, results, statusId);

            return status;

        } catch (error) {
            throw new SSHCommandError(`Failed to get server status: ${error instanceof Error ? error.message : 'Unknown error'}`, error);
        }
    }

    /**
     * Get quick server status
     */
    async getQuickServerStatus(connectionId: string): Promise<QuickServerStatus> {
        const connection = this.getConnection(connectionId);
        const startTime = Date.now();

        try {
            // Quick system check
            const result = await this.executeCommand(
                connectionId,
                'echo "alive"; uptime; free | grep Mem; df / | tail -1',
                { timeout: 5000 }
            );

            const responseTime = Date.now() - startTime;
            const lines = result.stdout.split('\n');

            // Parse quick metrics
            const cpuUsage = this.parseQuickCPU(lines[1] || '');
            const memoryUsage = this.parseQuickMemory(lines[2] || '');
            const diskUsage = this.parseQuickDisk(lines[3] || '');
            const uptime = this.parseUptime(lines[1] || '');

            return {
                serverId: connectionId,
                isOnline: result.success,
                cpuUsage,
                memoryUsage,
                diskUsage,
                uptime,
                responseTime,
                lastCheck: new Date(),
                error: result.success ? undefined : result.stderr
            };

        } catch (error) {
            return {
                serverId: connectionId,
                isOnline: false,
                cpuUsage: 0,
                memoryUsage: 0,
                diskUsage: 0,
                uptime: 0,
                responseTime: Date.now() - startTime,
                lastCheck: new Date(),
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    /**
     * Disconnect SSH connection
     */
    async disconnect(connectionId: string): Promise<void> {
        const connection = this.connectionPool.get(connectionId);

        if (!connection) {
            throw new ValidationError('Connection not found', { connectionId });
        }

        try {
            connection.isActive = false;
            connection.client.destroy();
            this.connectionPool.delete(connectionId);

            logger.info('SSH connection closed', {
                requestId: connectionId,
                action: 'SSH_DISCONNECT',
                resource: connection.credentials.host,
                metadata: {
                    usageCount: connection.usageCount,
                    duration: Date.now() - connection.connectedAt.getTime()
                }
            });

            this.emit('connection:disconnected', { connectionId });

        } catch (error) {
            logger.error('Error disconnecting SSH connection', {
                requestId: connectionId,
                error: error as Error
            });
            throw new SSHConnectionError('Failed to disconnect', error);
        }
    }

    /**
     * Disconnect all connections
     */
    async disconnectAll(): Promise<void> {
        const connectionIds = Array.from(this.connectionPool.keys());

        await Promise.allSettled(
            connectionIds.map(id => this.disconnect(id))
        );

        logger.info('All SSH connections closed', {
            action: 'SSH_DISCONNECT_ALL',
            metadata: { count: connectionIds.length }
        });
    }

    /**
     * Get connection pool statistics
     */
    getPoolStats(): PoolStats {
        const connections = Array.from(this.connectionPool.values());
        const activeConnections = connections.filter(c => c.isActive).length;
        const totalUsage = connections.reduce((sum, c) => sum + c.usageCount, 0);

        return {
            totalConnections: connections.length,
            activeConnections,
            idleConnections: connections.length - activeConnections,
            totalUsage,
            averageUsage: connections.length > 0 ? totalUsage / connections.length : 0
        };
    }

    /**
     * Test SSH connection
     */
    async testConnection(credentials: SSHCredentials): Promise<boolean> {
        try {
            const connectionId = await this.connect(credentials);
            await this.executeCommand(connectionId, 'echo "test"', { timeout: 5000 });
            await this.disconnect(connectionId);
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Private helper methods
     */

    private getConnection(connectionId: string): SSHConnection {
        const connection = this.connectionPool.get(connectionId);

        if (!connection) {
            throw new ValidationError('Connection not found', { connectionId });
        }

        if (!connection.isActive) {
            throw new SSHConnectionError('Connection is not active');
        }

        return connection;
    }

    private checkConnectionAttempts(host: string): void {
        const stats = this.connectionStats.get(host);
        const now = new Date();
        const maxAttempts = 5;
        const windowMs = 300000; // 5 minutes

        if (stats && stats.attempts >= maxAttempts) {
            const timeSinceLastAttempt = now.getTime() - stats.lastAttempt.getTime();
            if (timeSinceLastAttempt < windowMs) {
                throw new QuotaExceededError(`Too many connection attempts to ${host}. Try again later.`);
            }
        }
    }

    private updateConnectionStats(host: string, success: boolean): void {
        const stats = this.connectionStats.get(host) || { attempts: 0, lastAttempt: new Date() };

        if (success) {
            this.connectionStats.delete(host); // Reset on success
        } else {
            stats.attempts++;
            stats.lastAttempt = new Date();
            this.connectionStats.set(host, stats);
        }
    }

    private prepareCommand(command: string, options: CommandOptions): string {
        let fullCommand = command;

        // Add working directory
        if (options.workingDirectory) {
            fullCommand = `cd ${options.workingDirectory} && ${fullCommand}`;
        }

        // Add environment variables
        if (options.environment) {
            const envVars = Object.entries(options.environment)
                .map(([key, value]) => `${key}="${value}"`)
                .join(' ');
            fullCommand = `${envVars} ${fullCommand}`;
        }

        // Add sudo if required
        if (options.sudo) {
            fullCommand = `sudo ${fullCommand}`;
        }

        return fullCommand;
    }

    private execCommand(
        connection: SSHConnection,
        command: string,
        options: CommandOptions,
        resultId: string
    ): Promise<CommandResult> {
        return new Promise((resolve, reject) => {
            const startTime = new Date();
            let stdout = '';
            let stderr = '';

            const timeout = setTimeout(() => {
                reject(new TimeoutError('Command execution timeout'));
            }, options.timeout || this.commandTimeout);

            connection.client.exec(command, { pty: options.pty }, (err, stream) => {
                if (err) {
                    clearTimeout(timeout);
                    reject(new SSHCommandError('Failed to execute command', err));
                    return;
                }

                stream.on('close', (code: number, signal: string) => {
                    clearTimeout(timeout);
                    const endTime = new Date();

                    const result: CommandResult = {
                        id: resultId,
                        command,
                        stdout: stdout.trim(),
                        stderr: stderr.trim(),
                        exitCode: code || 0,
                        success: (code || 0) === 0,
                        duration: endTime.getTime() - startTime.getTime(),
                        startedAt: startTime,
                        completedAt: endTime,
                        server: {
                            host: connection.credentials.host,
                            username: connection.credentials.username,
                            port: connection.credentials.port
                        },
                        metadata: {
                            signal: signal || undefined
                        }
                    };

                    resolve(result);
                });

                stream.on('data', (data: Buffer) => {
                    const chunk = data.toString();
                    stdout += chunk;

                    // Check output size limit
                    if (stdout.length > (options.maxOutputSize || 1024 * 1024)) {
                        stream.close();
                        reject(new SSHCommandError('Command output too large'));
                    }
                });

                stream.stderr.on('data', (data: Buffer) => {
                    stderr += data.toString();
                });
            });
        });
    }

    private execStreamingCommand(
        connection: SSHConnection,
        command: string,
        streamingResult: StreamingCommandResult
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            let sequenceNumber = 0;

            connection.client.exec(command, { pty: true }, (err, stream) => {
                if (err) {
                    reject(new SSHCommandError('Failed to execute streaming command', err));
                    return;
                }

                stream.on('close', (code: number) => {
                    const endTime = new Date();
                    streamingResult.status = code === 0 ? 'completed' : 'failed';
                    streamingResult.exitCode = code;
                    streamingResult.duration = endTime.getTime() - streamingResult.startedAt.getTime();
                    this.activeStreams.set(streamingResult.id, streamingResult);
                    resolve();
                });

                stream.on('data', (data: Buffer) => {
                    const chunk: OutputChunk = {
                        type: 'stdout',
                        content: data.toString(),
                        timestamp: new Date(),
                        sequence: sequenceNumber++
                    };

                    streamingResult.outputChunks = [...streamingResult.outputChunks, chunk];
                    streamingResult.duration = Date.now() - streamingResult.startedAt.getTime();
                    this.activeStreams.set(streamingResult.id, streamingResult);

                    this.emit('stream:data', { streamId: streamingResult.id, chunk });
                });

                stream.stderr.on('data', (data: Buffer) => {
                    const chunk: OutputChunk = {
                        type: 'stderr',
                        content: data.toString(),
                        timestamp: new Date(),
                        sequence: sequenceNumber++
                    };

                    streamingResult.outputChunks = [...streamingResult.outputChunks, chunk];
                    this.activeStreams.set(streamingResult.id, streamingResult);

                    this.emit('stream:data', { streamId: streamingResult.id, chunk });
                });
            });
        });
    }

    private parseSystemStatus(
        credentials: SSHCredentials,
        results: Record<string, CommandResult>,
        statusId: string
    ): ServerStatus {
        // This is a simplified implementation
        // In a real application, you would parse each command result properly

        const now = new Date();

        return {
            serverId: statusId,
            isOnline: Object.values(results).some(r => r.success),
            connection: {
                connected: true,
                responseTime: 0,
                activeSessions: 1,
                quality: 100,
                lastConnected: now
            },
            resources: {
                cpu: {
                    overall: 0,
                    cores: [],
                    loadAverage: [0, 0, 0],
                    times: {
                        user: 0, nice: 0, system: 0, idle: 0,
                        iowait: 0, irq: 0, softirq: 0
                    }
                },
                memory: {
                    total: 0, used: 0, free: 0, available: 0,
                    usage: 0, buffers: 0, cached: 0, shared: 0
                },
                disk: {
                    overall: 0, filesystems: [], totalSpace: 0,
                    totalUsed: 0, totalFree: 0,
                    io: { readBytes: 0, writeBytes: 0, readOps: 0, writeOps: 0 }
                },
                swap: { total: 0, used: 0, free: 0, usage: 0 },
                io: {
                    read: { bytes: 0, operations: 0, time: 0 },
                    write: { bytes: 0, operations: 0, time: 0 }
                }
            },
            services: [],
            network: {
                interfaces: [],
                connections: { total: 0, established: 0, listening: 0, timeWait: 0 },
                traffic: {
                    bytesReceived: 0, bytesSent: 0,
                    packetsReceived: 0, packetsSent: 0,
                    errorsReceived: 0, errorsSent: 0
                },
                dns: { servers: [] }
            },
            security: {
                firewall: { enabled: false, rules: 0, defaultPolicy: 'accept' },
                auth: { failedLogins: 0, activeUsers: 0, lockedAccounts: 0 },
                updates: { available: 0, security: 0 },
                mandatory: { type: 'none' }
            },
            performance: {
                uptime: 0,
                bootTime: now,
                processes: { total: 0, running: 0, sleeping: 0, stopped: 0, zombie: 0 },
                threads: 0,
                fileDescriptors: { allocated: 0, maximum: 0, usage: 0 },
                contextSwitches: 0,
                interrupts: 0
            },
            system: {
                hostname: credentials.host,
                os: {
                    name: 'Unknown', version: 'Unknown', release: 'Unknown',
                    architecture: 'Unknown', kernel: 'Unknown'
                },
                hardware: {
                    cpuModel: 'Unknown', cpuCores: 0, totalMemory: 0
                }
            },
            lastCheck: now,
            checkDuration: 0
        };
    }

    private parseQuickCPU(uptimeOutput: string): number {
        // Parse CPU usage from uptime command
        const match = uptimeOutput.match(/load average:\s*([\d.]+)/);
        return match ? parseFloat(match[1]) * 100 : 0;
    }

    private parseQuickMemory(memOutput: string): number {
        // Parse memory usage from free command
        const parts = memOutput.split(/\s+/);
        if (parts.length >= 3) {
            const total = parseInt(parts[1]);
            const used = parseInt(parts[2]);
            return total > 0 ? (used / total) * 100 : 0;
        }
        return 0;
    }

    private parseQuickDisk(dfOutput: string): number {
        // Parse disk usage from df command
        const match = dfOutput.match(/(\d+)%/);
        return match ? parseInt(match[1]) : 0;
    }

    private parseUptime(uptimeOutput: string): number {
        // Parse uptime in seconds
        const match = uptimeOutput.match(/up\s+(?:(\d+)\s+days?,?\s*)?(?:(\d+):(\d+))?/);
        if (match) {
            const days = parseInt(match[1]) || 0;
            const hours = parseInt(match[2]) || 0;
            const minutes = parseInt(match[3]) || 0;
            return days * 86400 + hours * 3600 + minutes * 60;
        }
        return 0;
    }

    private isReadOnlyCommand(command: string): boolean {
        const readOnlyPatterns = [
            /^(ls|cat|head|tail|grep|find|ps|top|htop|free|df|du|uptime|whoami|id|pwd|echo|date|uname)/i,
            /^(systemctl status|service.*status)/i
        ];

        return readOnlyPatterns.some(pattern => pattern.test(command.trim()));
    }

    private generateCacheKey(connectionId: string, command: string, options: CommandOptions): string {
        const keyData = {
            connectionId,
            command,
            workingDirectory: options.workingDirectory,
            environment: options.environment
        };

        return Buffer.from(JSON.stringify(keyData)).toString('base64');
    }

    private cleanupIdleConnections(): void {
        const now = Date.now();
        const maxIdleTime = 600000; // 10 minutes

        for (const [connectionId, connection] of this.connectionPool.entries()) {
            const idleTime = now - connection.lastUsedAt.getTime();

            if (idleTime > maxIdleTime) {
                logger.info('Closing idle SSH connection', {
                    requestId: connectionId,
                    action: 'CLEANUP_IDLE_CONNECTION',
                    metadata: { idleTime, host: connection.credentials.host }
                });

                this.disconnect(connectionId).catch(error => {
                    logger.error('Error closing idle connection', { error });
                });
            }
        }
    }

    private cleanupConnectionStats(): void {
        const now = Date.now();
        const maxAge = 3600000; // 1 hour

        for (const [host, stats] of this.connectionStats.entries()) {
            const age = now - stats.lastAttempt.getTime();
            if (age > maxAge) {
                this.connectionStats.delete(host);
            }
        }
    }
}

/**
 * Export singleton instance
 */
export const sshService = SSHService.getInstance();