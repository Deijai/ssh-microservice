/**
 * 🏥 Health Controller
 * HTTP endpoints for health monitoring and status checks
 */

import { Request, Response } from 'express';
import { healthService } from '@/services/HealthService';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';
import { errorHandler } from '@/utils/errorHandler';
import { ValidationError, AuthorizationError } from '@/utils/errorHandler';
import { ApiResponse, AuthTokenPayload } from '@/types/common';

/**
 * Extended request interface with user information
 */
interface AuthenticatedRequest extends Request {
    user?: AuthTokenPayload;
    requestId?: string;
}

/**
 * Health Controller class
 */
export class HealthController {
    /**
     * Basic health check endpoint
     * Returns simple status for load balancers
     */
    static health = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        try {
            const isAlive = healthService.isAlive();

            if (isAlive) {
                res.status(200).json({
                    status: 'ok',
                    timestamp: new Date().toISOString(),
                    service: 'ssh-microservice'
                });
            } else {
                res.status(503).json({
                    status: 'error',
                    timestamp: new Date().toISOString(),
                    service: 'ssh-microservice'
                });
            }
        } catch (error) {
            logger.error('Health check failed', {
                requestId,
                error: error as Error
            });

            res.status(503).json({
                status: 'error',
                timestamp: new Date().toISOString(),
                service: 'ssh-microservice',
                error: 'Health check failed'
            });
        }
    });

    /**
     * Detailed health status endpoint
     * Returns comprehensive health information
     */
    static status = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        logger.debug('Detailed health status request', {
            requestId,
            action: 'HEALTH_STATUS_REQUEST'
        });

        try {
            const healthStatus = await healthService.getHealthStatus();

            const response: ApiResponse<typeof healthStatus> = {
                success: true,
                data: healthStatus,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            // Set appropriate HTTP status based on health
            let httpStatus = 200;
            if (healthStatus.status === 'degraded') {
                httpStatus = 206; // Partial Content
            } else if (healthStatus.status === 'unhealthy') {
                httpStatus = 503; // Service Unavailable
            }

            res.status(httpStatus).json(response);

        } catch (error) {
            logger.error('Health status check failed', {
                requestId,
                error: error as Error
            });

            const response: ApiResponse<never> = {
                success: false,
                error: 'Health status check failed',
                details: error instanceof Error ? error.message : 'Unknown error',
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(503).json(response);
        }
    });

    /**
     * Readiness check endpoint
     * Returns whether service is ready to accept traffic
     */
    static ready = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        try {
            const isReady = await healthService.isReady();

            if (isReady) {
                res.status(200).json({
                    status: 'ready',
                    timestamp: new Date().toISOString(),
                    service: 'ssh-microservice'
                });
            } else {
                res.status(503).json({
                    status: 'not ready',
                    timestamp: new Date().toISOString(),
                    service: 'ssh-microservice'
                });
            }
        } catch (error) {
            logger.error('Readiness check failed', {
                requestId,
                error: error as Error
            });

            res.status(503).json({
                status: 'not ready',
                timestamp: new Date().toISOString(),
                service: 'ssh-microservice',
                error: 'Readiness check failed'
            });
        }
    });

    /**
     * Liveness check endpoint
     * Returns whether service is alive
     */
    static live = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        try {
            const isAlive = healthService.isAlive();

            if (isAlive) {
                res.status(200).json({
                    status: 'alive',
                    timestamp: new Date().toISOString(),
                    service: 'ssh-microservice'
                });
            } else {
                res.status(503).json({
                    status: 'dead',
                    timestamp: new Date().toISOString(),
                    service: 'ssh-microservice'
                });
            }
        } catch (error) {
            logger.error('Liveness check failed', {
                requestId,
                error: error as Error
            });

            res.status(503).json({
                status: 'dead',
                timestamp: new Date().toISOString(),
                service: 'ssh-microservice',
                error: 'Liveness check failed'
            });
        }
    });

    /**
     * Get application metrics
     */
    static metrics = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        logger.debug('Metrics request', {
            requestId,
            userId,
            action: 'METRICS_REQUEST'
        });

        try {
            const metrics = await healthService.getMetrics();

            const response: ApiResponse<typeof metrics> = {
                success: true,
                data: metrics,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get metrics', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get database information (admin only)
     */
    static database = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.debug('Database info request', {
            requestId,
            userId,
            action: 'DATABASE_INFO_REQUEST'
        });

        try {
            const databaseInfo = healthService.getDatabaseInfo();

            const response: ApiResponse<typeof databaseInfo> = {
                success: true,
                data: databaseInfo,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get database info', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get metric history (admin only)
     */
    static metricHistory = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { metricName } = req.params;
        const { count = '100' } = req.query;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.debug('Metric history request', {
            requestId,
            userId,
            action: 'METRIC_HISTORY_REQUEST',
            metadata: { metricName, count }
        });

        // Validate parameters
        if (!metricName) {
            throw new ValidationError('Metric name is required');
        }

        const countNum = parseInt(count as string, 10);
        if (isNaN(countNum) || countNum < 1 || countNum > 1000) {
            throw new ValidationError('Count must be between 1 and 1000');
        }

        try {
            const history = healthService.getMetricHistory(metricName, countNum);

            const response: ApiResponse<{
                metric: string;
                history: number[];
                count: number;
            }> = {
                success: true,
                data: {
                    metric: metricName,
                    history,
                    count: history.length
                },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get metric history', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Update health thresholds (admin only)
     */
    static updateThresholds = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { body } = req;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.info('Update health thresholds request', {
            requestId,
            userId,
            action: 'UPDATE_THRESHOLDS_REQUEST',
            metadata: body
        });

        // Validate thresholds
        if (body.memory) {
            if (typeof body.memory.warning !== 'number' || body.memory.warning < 0 || body.memory.warning > 100) {
                throw new ValidationError('Memory warning threshold must be between 0 and 100');
            }
            if (typeof body.memory.critical !== 'number' || body.memory.critical < 0 || body.memory.critical > 100) {
                throw new ValidationError('Memory critical threshold must be between 0 and 100');
            }
            if (body.memory.warning >= body.memory.critical) {
                throw new ValidationError('Memory warning threshold must be less than critical threshold');
            }
        }

        if (body.cpu) {
            if (typeof body.cpu.warning !== 'number' || body.cpu.warning < 0 || body.cpu.warning > 100) {
                throw new ValidationError('CPU warning threshold must be between 0 and 100');
            }
            if (typeof body.cpu.critical !== 'number' || body.cpu.critical < 0 || body.cpu.critical > 100) {
                throw new ValidationError('CPU critical threshold must be between 0 and 100');
            }
            if (body.cpu.warning >= body.cpu.critical) {
                throw new ValidationError('CPU warning threshold must be less than critical threshold');
            }
        }

        if (body.eventLoop) {
            if (typeof body.eventLoop.warning !== 'number' || body.eventLoop.warning < 0) {
                throw new ValidationError('Event loop warning threshold must be positive');
            }
            if (typeof body.eventLoop.critical !== 'number' || body.eventLoop.critical < 0) {
                throw new ValidationError('Event loop critical threshold must be positive');
            }
            if (body.eventLoop.warning >= body.eventLoop.critical) {
                throw new ValidationError('Event loop warning threshold must be less than critical threshold');
            }
        }

        try {
            healthService.updateThresholds(body);

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Health thresholds updated successfully', {
                requestId,
                userId,
                action: 'THRESHOLDS_UPDATED',
                metadata: body
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to update health thresholds', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get current health thresholds (admin only)
     */
    static getThresholds = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.debug('Get health thresholds request', {
            requestId,
            userId,
            action: 'GET_THRESHOLDS_REQUEST'
        });

        try {
            const thresholds = healthService.getThresholds();

            const response: ApiResponse<typeof thresholds> = {
                success: true,
                data: thresholds,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get health thresholds', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Start health monitoring (admin only)
     */
    static startMonitoring = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { interval = 30000 } = req.body;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.info('Start health monitoring request', {
            requestId,
            userId,
            action: 'START_MONITORING_REQUEST',
            metadata: { interval }
        });

        // Validate interval
        if (typeof interval !== 'number' || interval < 5000 || interval > 300000) {
            throw new ValidationError('Interval must be between 5000ms (5s) and 300000ms (5m)');
        }

        try {
            healthService.startMonitoring(interval);

            const response: ApiResponse<{ monitoring: boolean; interval: number }> = {
                success: true,
                data: {
                    monitoring: true,
                    interval
                },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Health monitoring started', {
                requestId,
                userId,
                action: 'MONITORING_STARTED',
                metadata: { interval }
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to start health monitoring', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Stop health monitoring (admin only)
     */
    static stopMonitoring = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.info('Stop health monitoring request', {
            requestId,
            userId,
            action: 'STOP_MONITORING_REQUEST'
        });

        try {
            healthService.stopMonitoring();

            const response: ApiResponse<{ monitoring: boolean }> = {
                success: true,
                data: {
                    monitoring: false
                },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Health monitoring stopped', {
                requestId,
                userId,
                action: 'MONITORING_STOPPED'
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to stop health monitoring', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get service information
     */
    static info = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        logger.debug('Service info request', {
            requestId,
            action: 'SERVICE_INFO_REQUEST'
        });

        try {
            const packageInfo = require('../../package.json');

            const serviceInfo = {
                name: packageInfo.name,
                version: packageInfo.version,
                description: packageInfo.description,
                environment: process.env.NODE_ENV || 'development',
                nodeVersion: process.version,
                platform: process.platform,
                architecture: process.arch,
                uptime: process.uptime(),
                pid: process.pid,
                timestamp: new Date().toISOString()
            };

            const response: ApiResponse<typeof serviceInfo> = {
                success: true,
                data: serviceInfo,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get service info', {
                requestId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Prometheus metrics endpoint
     * Returns metrics in Prometheus format
     */
    static prometheus = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        try {
            const metrics = await healthService.getMetrics();
            const timestamp = Date.now();

            // Convert metrics to Prometheus format
            const prometheusMetrics = [
                `# HELP ssh_requests_total Total number of SSH requests`,
                `# TYPE ssh_requests_total counter`,
                `ssh_requests_total ${metrics.requestCount} ${timestamp}`,
                '',
                `# HELP ssh_errors_total Total number of SSH errors`,
                `# TYPE ssh_errors_total counter`,
                `ssh_errors_total ${metrics.errorCount} ${timestamp}`,
                '',
                `# HELP ssh_response_time_ms SSH response time in milliseconds`,
                `# TYPE ssh_response_time_ms histogram`,
                `ssh_response_time_ms_bucket{le="100"} ${metrics.responseTime.p50} ${timestamp}`,
                `ssh_response_time_ms_bucket{le="500"} ${metrics.responseTime.p95} ${timestamp}`,
                `ssh_response_time_ms_bucket{le="1000"} ${metrics.responseTime.p99} ${timestamp}`,
                `ssh_response_time_ms_bucket{le="+Inf"} ${metrics.responseTime.avg} ${timestamp}`,
                '',
                `# HELP ssh_active_connections Number of active SSH connections`,
                `# TYPE ssh_active_connections gauge`,
                `ssh_active_connections ${metrics.activeConnections} ${timestamp}`,
                '',
                `# HELP process_memory_usage_percent Process memory usage percentage`,
                `# TYPE process_memory_usage_percent gauge`,
                `process_memory_usage_percent ${metrics.memoryUsage} ${timestamp}`,
                '',
                `# HELP process_cpu_usage_percent Process CPU usage percentage`,
                `# TYPE process_cpu_usage_percent gauge`,
                `process_cpu_usage_percent ${metrics.cpuUsage} ${timestamp}`,
                '',
                `# HELP process_uptime_seconds Process uptime in seconds`,
                `# TYPE process_uptime_seconds counter`,
                `process_uptime_seconds ${Math.floor(metrics.uptime / 1000)} ${timestamp}`,
                ''
            ].join('\n');

            res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
            res.status(200).send(prometheusMetrics);

        } catch (error) {
            logger.error('Failed to generate Prometheus metrics', {
                requestId,
                error: error as Error
            });

            res.status(500).send('# Error generating metrics\n');
        }
    });

    /**
     * Performance diagnostic endpoint (admin only)
     */
    static diagnostics = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.info('Performance diagnostics request', {
            requestId,
            userId,
            action: 'DIAGNOSTICS_REQUEST'
        });

        try {
            const startTime = process.hrtime.bigint();

            // Collect detailed performance metrics
            const memUsage = process.memoryUsage();
            const cpuUsage = process.cpuUsage();
            const resourceUsage = process.resourceUsage();

            // Measure event loop lag
            const eventLoopStart = process.hrtime.bigint();
            await new Promise(resolve => setImmediate(resolve));
            const eventLoopLag = Number(process.hrtime.bigint() - eventLoopStart) / 1e6; // Convert to ms

            // Get garbage collection stats if available
            const gcStats = (global as any).gc ? {
                heapUsed: memUsage.heapUsed,
                heapTotal: memUsage.heapTotal,
                external: memUsage.external,
                rss: memUsage.rss
            } : null;

            const diagnostics = {
                timestamp: new Date().toISOString(),
                performance: {
                    eventLoopLag: eventLoopLag,
                    processingTime: Number(process.hrtime.bigint() - startTime) / 1e6
                },
                memory: {
                    rss: memUsage.rss,
                    heapTotal: memUsage.heapTotal,
                    heapUsed: memUsage.heapUsed,
                    external: memUsage.external,
                    arrayBuffers: memUsage.arrayBuffers
                },
                cpu: {
                    user: cpuUsage.user,
                    system: cpuUsage.system
                },
                resources: {
                    userCPUTime: resourceUsage.userCPUTime,
                    systemCPUTime: resourceUsage.systemCPUTime,
                    maxRSS: resourceUsage.maxRSS,
                    sharedMemorySize: resourceUsage.sharedMemorySize,
                    unsharedDataSize: resourceUsage.unsharedDataSize,
                    unsharedStackSize: resourceUsage.unsharedStackSize,
                    minorPageFault: resourceUsage.minorPageFault,
                    majorPageFault: resourceUsage.majorPageFault,
                    swappedOut: resourceUsage.swappedOut,
                    fsRead: resourceUsage.fsRead,
                    fsWrite: resourceUsage.fsWrite,
                    ipcSent: resourceUsage.ipcSent,
                    ipcReceived: resourceUsage.ipcReceived,
                    signalsCount: resourceUsage.signalsCount,
                    voluntaryContextSwitches: resourceUsage.voluntaryContextSwitches,
                    involuntaryContextSwitches: resourceUsage.involuntaryContextSwitches
                },
                gc: gcStats,
                process: {
                    pid: process.pid,
                    ppid: process.ppid,
                    platform: process.platform,
                    arch: process.arch,
                    version: process.version,
                    uptime: process.uptime(),
                    cwd: process.cwd(),
                    execPath: process.execPath,
                    argv: process.argv
                }
            };

            const response: ApiResponse<typeof diagnostics> = {
                success: true,
                data: diagnostics,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to generate diagnostics', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Force garbage collection (admin only)
     */
    static forceGC = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new ValidationError('Authentication required');
        }

        if (req.user.role !== 'admin') {
            throw new AuthorizationError('Admin access required');
        }

        logger.info('Force garbage collection request', {
            requestId,
            userId,
            action: 'FORCE_GC_REQUEST'
        });

        try {
            const beforeGC = process.memoryUsage();

            // Force garbage collection if available
            if ((global as any).gc) {
                (global as any).gc();
                logger.info('Garbage collection forced', {
                    requestId,
                    userId,
                    action: 'GC_FORCED'
                });
            } else {
                logger.warn('Garbage collection not available', {
                    requestId,
                    userId,
                    action: 'GC_NOT_AVAILABLE'
                });
            }

            const afterGC = process.memoryUsage();

            const gcResult = {
                forced: !!(global as any).gc,
                before: beforeGC,
                after: afterGC,
                freed: {
                    rss: beforeGC.rss - afterGC.rss,
                    heapTotal: beforeGC.heapTotal - afterGC.heapTotal,
                    heapUsed: beforeGC.heapUsed - afterGC.heapUsed,
                    external: beforeGC.external - afterGC.external
                }
            };

            const response: ApiResponse<typeof gcResult> = {
                success: true,
                data: gcResult,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to force garbage collection', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });
}

/**
 * Export controller methods
 */
export const healthController = {
    health: HealthController.health,
    status: HealthController.status,
    ready: HealthController.ready,
    live: HealthController.live,
    metrics: HealthController.metrics,
    database: HealthController.database,
    metricHistory: HealthController.metricHistory,
    updateThresholds: HealthController.updateThresholds,
    getThresholds: HealthController.getThresholds,
    startMonitoring: HealthController.startMonitoring,
    stopMonitoring: HealthController.stopMonitoring,
    info: HealthController.info,
    prometheus: HealthController.prometheus,
    diagnostics: HealthController.diagnostics,
    forceGC: HealthController.forceGC
};