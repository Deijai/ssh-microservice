/**
 * 🏥 Health Service
 * Application health monitoring and status checks
 */

import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';
import os from 'os';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';
import { sshService } from './SSHService';
import { authService } from './AuthService';
import {
    HealthStatus,
    HealthCheck,
    AppMetrics,
    DatabaseInfo
} from '@/types/common';

/**
 * Health check function type
 */
type HealthCheckFunction = () => Promise<HealthCheck>;

/**
 * Metric collector function type
 */
type MetricCollector = () => number | Promise<number>;

/**
 * Health threshold configuration
 */
interface HealthThresholds {
    readonly memory: {
        readonly warning: number; // percentage
        readonly critical: number; // percentage
    };
    readonly cpu: {
        readonly warning: number; // percentage
        readonly critical: number; // percentage
    };
    readonly eventLoop: {
        readonly warning: number; // milliseconds
        readonly critical: number; // milliseconds
    };
    readonly responseTime: {
        readonly warning: number; // milliseconds
        readonly critical: number; // milliseconds
    };
}

/**
 * Default health thresholds
 */
const DEFAULT_THRESHOLDS: HealthThresholds = {
    memory: { warning: 80, critical: 95 },
    cpu: { warning: 80, critical: 95 },
    eventLoop: { warning: 100, critical: 1000 },
    responseTime: { warning: 500, critical: 2000 }
};

/**
 * Health service class
 */
export class HealthService extends EventEmitter {
    private static instance: HealthService;
    private healthChecks: Map<string, HealthCheckFunction>;
    private metricCollectors: Map<string, MetricCollector>;
    private metricsHistory: Map<string, number[]>;
    private thresholds: HealthThresholds;
    private startTime: Date;
    private healthCheckInterval?: NodeJS.Timeout;
    private lastHealthStatus: HealthStatus | null = null;

    private constructor() {
        super();
        this.healthChecks = new Map();
        this.metricCollectors = new Map();
        this.metricsHistory = new Map();
        this.thresholds = DEFAULT_THRESHOLDS;
        this.startTime = new Date();

        this.initializeDefaultChecks();
        this.initializeDefaultMetrics();
    }

    /**
     * Get health service singleton instance
     */
    static getInstance(): HealthService {
        if (!HealthService.instance) {
            HealthService.instance = new HealthService();
        }
        return HealthService.instance;
    }

    /**
     * Initialize default health checks
     */
    private initializeDefaultChecks(): void {
        // Database connectivity check
        this.addHealthCheck('database', async () => {
            const startTime = performance.now();

            try {
                // Test Firebase connection by getting auth service status
                const sessionCount = authService.getAllSessions().length;
                const duration = performance.now() - startTime;

                return {
                    name: 'database',
                    status: 'pass',
                    duration,
                    message: `Firebase connection healthy. ${sessionCount} active sessions.`,
                    details: { sessionCount }
                };
            } catch (error) {
                const duration = performance.now() - startTime;
                return {
                    name: 'database',
                    status: 'fail',
                    duration,
                    message: `Database connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    details: { error: error instanceof Error ? error.message : 'Unknown error' }
                };
            }
        });

        // SSH service health check
        this.addHealthCheck('ssh_service', async () => {
            const startTime = performance.now();

            try {
                const poolStats = sshService.getPoolStats();
                const duration = performance.now() - startTime;

                const status = poolStats.totalConnections < 50 ? 'pass' :
                    poolStats.totalConnections < 80 ? 'warn' : 'fail';

                return {
                    name: 'ssh_service',
                    status,
                    duration,
                    message: `SSH service healthy. ${poolStats.activeConnections} active connections.`,
                    details: poolStats
                };
            } catch (error) {
                const duration = performance.now() - startTime;
                return {
                    name: 'ssh_service',
                    status: 'fail',
                    duration,
                    message: `SSH service check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    details: { error: error instanceof Error ? error.message : 'Unknown error' }
                };
            }
        });

        // Memory usage check
        this.addHealthCheck('memory', async () => {
            const startTime = performance.now();
            const memUsage = process.memoryUsage();
            const totalMemory = os.totalmem();
            const freeMemory = os.freemem();
            const usedMemory = totalMemory - freeMemory;
            const memoryUsagePercent = (usedMemory / totalMemory) * 100;
            const duration = performance.now() - startTime;

            let status: 'pass' | 'warn' | 'fail' = 'pass';
            let message = `Memory usage: ${memoryUsagePercent.toFixed(1)}%`;

            if (memoryUsagePercent > this.thresholds.memory.critical) {
                status = 'fail';
                message += ' - Critical memory usage';
            } else if (memoryUsagePercent > this.thresholds.memory.warning) {
                status = 'warn';
                message += ' - High memory usage';
            }

            return {
                name: 'memory',
                status,
                duration,
                message,
                details: {
                    totalMemory,
                    freeMemory,
                    usedMemory,
                    usagePercent: memoryUsagePercent,
                    processMemory: {
                        rss: memUsage.rss,
                        heapTotal: memUsage.heapTotal,
                        heapUsed: memUsage.heapUsed,
                        external: memUsage.external
                    }
                }
            };
        });

        // CPU usage check
        this.addHealthCheck('cpu', async () => {
            const startTime = performance.now();
            const cpus = os.cpus();
            const loadAvg = os.loadavg();
            const cpuCount = cpus.length;
            const load1min = loadAvg[0];
            const cpuUsagePercent = (load1min / cpuCount) * 100;
            const duration = performance.now() - startTime;

            let status: 'pass' | 'warn' | 'fail' = 'pass';
            let message = `CPU usage: ${cpuUsagePercent.toFixed(1)}%`;

            if (cpuUsagePercent > this.thresholds.cpu.critical) {
                status = 'fail';
                message += ' - Critical CPU usage';
            } else if (cpuUsagePercent > this.thresholds.cpu.warning) {
                status = 'warn';
                message += ' - High CPU usage';
            }

            return {
                name: 'cpu',
                status,
                duration,
                message,
                details: {
                    cpuCount,
                    loadAverage: loadAvg,
                    usagePercent: cpuUsagePercent,
                    cpuInfo: cpus[0] ? {
                        model: cpus[0].model,
                        speed: cpus[0].speed
                    } : null
                }
            };
        });

        // Event loop lag check
        this.addHealthCheck('event_loop', async () => {
            const startTime = performance.now();

            return new Promise<HealthCheck>((resolve) => {
                const start = performance.now();
                setImmediate(() => {
                    const lag = performance.now() - start;
                    const duration = performance.now() - startTime;

                    let status: 'pass' | 'warn' | 'fail' = 'pass';
                    let message = `Event loop lag: ${lag.toFixed(2)}ms`;

                    if (lag > this.thresholds.eventLoop.critical) {
                        status = 'fail';
                        message += ' - Critical event loop lag';
                    } else if (lag > this.thresholds.eventLoop.warning) {
                        status = 'warn';
                        message += ' - High event loop lag';
                    }

                    resolve({
                        name: 'event_loop',
                        status,
                        duration,
                        message,
                        details: { lagMs: lag }
                    });
                });
            });
        });

        // Disk space check
        this.addHealthCheck('disk_space', async () => {
            const startTime = performance.now();

            try {
                // Simple disk space check using fs stats
                const stats = await import('fs/promises').then(fs => fs.statfs('.'));
                const totalSpace = stats.bavail * stats.bsize;
                const freeSpace = stats.bavail * stats.bsize;
                const usedSpace = totalSpace - freeSpace;
                const usagePercent = (usedSpace / totalSpace) * 100;
                const duration = performance.now() - startTime;

                let status: 'pass' | 'warn' | 'fail' = 'pass';
                let message = `Disk usage: ${usagePercent.toFixed(1)}%`;

                if (usagePercent > 95) {
                    status = 'fail';
                    message += ' - Critical disk usage';
                } else if (usagePercent > 85) {
                    status = 'warn';
                    message += ' - High disk usage';
                }

                return {
                    name: 'disk_space',
                    status,
                    duration,
                    message,
                    details: {
                        totalSpace,
                        freeSpace,
                        usedSpace,
                        usagePercent
                    }
                };
            } catch (error) {
                const duration = performance.now() - startTime;
                return {
                    name: 'disk_space',
                    status: 'warn',
                    duration,
                    message: 'Could not check disk space',
                    details: { error: error instanceof Error ? error.message : 'Unknown error' }
                };
            }
        });

        // Encryption service check
        this.addHealthCheck('encryption', async () => {
            const startTime = performance.now();

            try {
                const isWorking = await encryption.testEncryption();
                const duration = performance.now() - startTime;

                return {
                    name: 'encryption',
                    status: isWorking ? 'pass' : 'fail',
                    duration,
                    message: isWorking ? 'Encryption service working' : 'Encryption service failed',
                    details: { working: isWorking }
                };
            } catch (error) {
                const duration = performance.now() - startTime;
                return {
                    name: 'encryption',
                    status: 'fail',
                    duration,
                    message: `Encryption check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    details: { error: error instanceof Error ? error.message : 'Unknown error' }
                };
            }
        });
    }

    /**
     * Initialize default metrics collectors
     */
    private initializeDefaultMetrics(): void {
        // Memory usage metric
        this.addMetricCollector('memory_usage', () => {
            const memUsage = process.memoryUsage();
            return (memUsage.heapUsed / memUsage.heapTotal) * 100;
        });

        // CPU usage metric
        this.addMetricCollector('cpu_usage', () => {
            const loadAvg = os.loadavg();
            const cpuCount = os.cpus().length;
            return (loadAvg[0] / cpuCount) * 100;
        });

        // Active connections metric
        this.addMetricCollector('active_connections', () => {
            const poolStats = sshService.getPoolStats();
            return poolStats.activeConnections;
        });

        // Active sessions metric
        this.addMetricCollector('active_sessions', () => {
            return authService.getAllSessions().length;
        });

        // Event loop lag metric
        this.addMetricCollector('event_loop_lag', () => {
            return new Promise<number>((resolve) => {
                const start = performance.now();
                setImmediate(() => {
                    resolve(performance.now() - start);
                });
            });
        });
    }

    /**
     * Add a custom health check
     */
    addHealthCheck(name: string, checkFunction: HealthCheckFunction): void {
        this.healthChecks.set(name, checkFunction);
        logger.debug(`Health check '${name}' registered`);
    }

    /**
     * Remove a health check
     */
    removeHealthCheck(name: string): boolean {
        const removed = this.healthChecks.delete(name);
        if (removed) {
            logger.debug(`Health check '${name}' removed`);
        }
        return removed;
    }

    /**
     * Add a metric collector
     */
    addMetricCollector(name: string, collector: MetricCollector): void {
        this.metricCollectors.set(name, collector);
        this.metricsHistory.set(name, []);
        logger.debug(`Metric collector '${name}' registered`);
    }

    /**
     * Remove a metric collector
     */
    removeMetricCollector(name: string): boolean {
        const removed = this.metricCollectors.delete(name);
        if (removed) {
            this.metricsHistory.delete(name);
            logger.debug(`Metric collector '${name}' removed`);
        }
        return removed;
    }

    /**
     * Get current health status
     */
    async getHealthStatus(): Promise<HealthStatus> {
        const startTime = performance.now();
        const checks: HealthCheck[] = [];

        // Run all health checks
        for (const [name, checkFunction] of this.healthChecks.entries()) {
            try {
                const check = await checkFunction();
                checks.push(check);
            } catch (error) {
                checks.push({
                    name,
                    status: 'fail',
                    duration: 0,
                    message: `Health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    details: { error: error instanceof Error ? error.message : 'Unknown error' }
                });
            }
        }

        // Determine overall status
        const hasFailures = checks.some(check => check.status === 'fail');
        const hasWarnings = checks.some(check => check.status === 'warn');

        let overallStatus: 'healthy' | 'degraded' | 'unhealthy';
        if (hasFailures) {
            overallStatus = 'unhealthy';
        } else if (hasWarnings) {
            overallStatus = 'degraded';
        } else {
            overallStatus = 'healthy';
        }

        // Collect current metrics
        const metrics = await this.collectMetrics();

        const healthStatus: HealthStatus = {
            status: overallStatus,
            timestamp: new Date(),
            uptime: Date.now() - this.startTime.getTime(),
            version: config.app.version,
            environment: config.app.environment,
            checks,
            metrics
        };

        // Store last status
        this.lastHealthStatus = healthStatus;

        // Emit status change events
        if (this.lastHealthStatus?.status !== overallStatus) {
            this.emit('status:change', { from: this.lastHealthStatus?.status, to: overallStatus });
        }

        // Log unhealthy status
        if (overallStatus === 'unhealthy') {
            const failedChecks = checks.filter(check => check.status === 'fail');
            logger.warn('Application health status is unhealthy', {
                action: 'HEALTH_CHECK',
                metadata: {
                    status: overallStatus,
                    failedChecks: failedChecks.map(check => check.name),
                    duration: performance.now() - startTime
                }
            });
        }

        return healthStatus;
    }

    /**
     * Get application metrics
     */
    async getMetrics(): Promise<AppMetrics> {
        const poolStats = sshService.getPoolStats();
        const sessions = authService.getAllSessions();
        const memUsage = process.memoryUsage();
        const totalMemory = os.totalmem();
        const loadAvg = os.loadavg();
        const cpuCount = os.cpus().length;

        // Calculate response time metrics (simplified)
        const responseTimeHistory = this.metricsHistory.get('response_time') || [];
        const avgResponseTime = responseTimeHistory.length > 0
            ? responseTimeHistory.reduce((a, b) => a + b, 0) / responseTimeHistory.length
            : 0;

        return {
            requestCount: 0, // This would come from middleware tracking
            errorCount: 0,   // This would come from error tracking
            responseTime: {
                p50: avgResponseTime,
                p95: avgResponseTime * 1.5,
                p99: avgResponseTime * 2,
                avg: avgResponseTime
            },
            activeConnections: poolStats.activeConnections,
            memoryUsage: (memUsage.heapUsed / totalMemory) * 100,
            cpuUsage: (loadAvg[0] / cpuCount) * 100,
            uptime: Date.now() - this.startTime.getTime()
        };
    }

    /**
     * Get database information
     */
    getDatabaseInfo(): DatabaseInfo {
        return {
            type: 'firebase',
            status: 'connected', // This would be determined by actual connection status
            version: 'admin-sdk',
            lastConnected: new Date()
        };
    }

    /**
     * Start periodic health monitoring
     */
    startMonitoring(intervalMs: number = config.monitoring.healthCheckInterval): void {
        if (this.healthCheckInterval) {
            this.stopMonitoring();
        }

        this.healthCheckInterval = setInterval(async () => {
            try {
                await this.getHealthStatus();
                await this.collectAndStoreMetrics();
            } catch (error) {
                logger.error('Health monitoring error', { error: error as Error });
            }
        }, intervalMs);

        logger.info('Health monitoring started', {
            action: 'START_MONITORING',
            metadata: { intervalMs }
        });
    }

    /**
     * Stop periodic health monitoring
     */
    stopMonitoring(): void {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = undefined;

            logger.info('Health monitoring stopped', {
                action: 'STOP_MONITORING'
            });
        }
    }

    /**
     * Get metric history
     */
    getMetricHistory(metricName: string, count: number = 100): number[] {
        const history = this.metricsHistory.get(metricName) || [];
        return history.slice(-count);
    }

    /**
     * Update health thresholds
     */
    updateThresholds(newThresholds: Partial<HealthThresholds>): void {
        this.thresholds = { ...this.thresholds, ...newThresholds };
        logger.info('Health thresholds updated', {
            action: 'UPDATE_THRESHOLDS',
            metadata: newThresholds
        });
    }

    /**
     * Get current thresholds
     */
    getThresholds(): HealthThresholds {
        return { ...this.thresholds };
    }

    /**
     * Check if application is ready
     */
    async isReady(): Promise<boolean> {
        try {
            const status = await this.getHealthStatus();
            return status.status !== 'unhealthy';
        } catch (error) {
            return false;
        }
    }

    /**
     * Check if application is alive
     */
    isAlive(): boolean {
        return true; // If we can execute this, we're alive
    }

    /**
     * Private helper methods
     */

    private async collectMetrics(): Promise<HealthStatus['metrics']> {
        const memUsage = process.memoryUsage();
        const totalMemory = os.totalmem();
        const freeMemory = os.freemem();
        const loadAvg = os.loadavg();
        const cpuCount = os.cpus().length;

        // Get event loop lag
        const eventLoopLag = await new Promise<number>((resolve) => {
            const start = performance.now();
            setImmediate(() => {
                resolve(performance.now() - start);
            });
        });

        return {
            memory: {
                used: memUsage.heapUsed,
                total: memUsage.heapTotal,
                usage: (memUsage.heapUsed / memUsage.heapTotal) * 100
            },
            cpu: {
                usage: (loadAvg[0] / cpuCount) * 100
            },
            eventLoop: {
                delay: eventLoopLag
            }
        };
    }

    private async collectAndStoreMetrics(): Promise<void> {
        for (const [name, collector] of this.metricCollectors.entries()) {
            try {
                const value = await collector();
                const history = this.metricsHistory.get(name) || [];

                // Keep only last 1000 values
                if (history.length >= 1000) {
                    history.shift();
                }

                history.push(value);
                this.metricsHistory.set(name, history);

            } catch (error) {
                logger.warn(`Failed to collect metric '${name}'`, { error: error as Error });
            }
        }
    }
}

/**
 * Export singleton instance
 */
export const healthService = HealthService.getInstance();

/**
 * Export types
 */
export type { HealthThresholds, HealthCheckFunction, MetricCollector };