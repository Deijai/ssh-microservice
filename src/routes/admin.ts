/**
 * 👑 Admin Routes
 * Administrative endpoints for system management
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { authMiddleware } from '@/middleware/auth';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';
import { errorHandler } from '@/utils/errorHandler';
import { ValidationError } from '@/utils/errorHandler';
import { ApiResponse } from '@/types/common';
import { config } from '@/config/environment';

const router = Router();

// Strict rate limiting for admin operations
const adminRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 admin operations per 5 minutes
    message: {
        success: false,
        error: 'Too many admin operations. Please try again later.',
        retryAfter: 300
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many admin operations. Please try again later.',
            retryAfter: 300,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * All admin routes require authentication and admin role
 */
router.use(authMiddleware.requireAuth);
router.use(authMiddleware.adminOnly);
router.use(adminRateLimit);

/**
 * User management endpoints
 */

// GET /admin/users - Get all users
router.get('/users', errorHandler.asyncHandler(async (req, res) => {
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin users list request', {
        requestId,
        userId,
        action: 'ADMIN_USERS_LIST'
    });

    // Mock user data - in real app, this would query the database
    const users = [
        {
            id: '1',
            email: 'admin@example.com',
            role: 'admin',
            isActive: true,
            createdAt: new Date('2024-01-01'),
            lastLoginAt: new Date(),
            metadata: {
                loginCount: 150,
                sshConnections: 45
            }
        },
        {
            id: '2',
            email: 'user@example.com',
            role: 'user',
            isActive: true,
            createdAt: new Date('2024-01-15'),
            lastLoginAt: new Date(Date.now() - 86400000), // Yesterday
            metadata: {
                loginCount: 23,
                sshConnections: 12
            }
        }
    ];

    const response: ApiResponse<typeof users> = {
        success: true,
        data: users,
        timestamp: new Date(),
        requestId,
        version: '1.0.0',
        meta: {
            total: users.length,
            page: 1,
            limit: 100
        }
    };

    res.json(response);
}));

// GET /admin/users/:userId - Get specific user
router.get('/users/:userId', errorHandler.asyncHandler(async (req, res) => {
    const { userId: targetUserId } = req.params;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    if (!targetUserId) {
        throw new ValidationError('User ID is required');
    }

    logger.info('Admin user details request', {
        requestId,
        userId,
        action: 'ADMIN_USER_DETAILS',
        metadata: { targetUserId }
    });

    // Mock user data
    const user = {
        id: targetUserId,
        email: targetUserId === '1' ? 'admin@example.com' : 'user@example.com',
        role: targetUserId === '1' ? 'admin' : 'user',
        isActive: true,
        createdAt: new Date('2024-01-01'),
        lastLoginAt: new Date(),
        permissions: targetUserId === '1' ?
            ['ssh:connect', 'ssh:execute', 'ssh:manage', 'user:manage'] :
            ['ssh:connect', 'ssh:execute'],
        metadata: {
            loginCount: 150,
            sshConnections: 45,
            lastIP: '192.168.1.100',
            failedLogins: 0
        }
    };

    const response: ApiResponse<typeof user> = {
        success: true,
        data: user,
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

// PUT /admin/users/:userId/status - Update user status
router.put('/users/:userId/status', errorHandler.asyncHandler(async (req, res) => {
    const { userId: targetUserId } = req.params;
    const { isActive } = req.body;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    if (!targetUserId) {
        throw new ValidationError('User ID is required');
    }

    if (typeof isActive !== 'boolean') {
        throw new ValidationError('isActive must be a boolean');
    }

    logger.info('Admin user status update', {
        requestId,
        userId,
        action: 'ADMIN_USER_STATUS_UPDATE',
        metadata: { targetUserId, isActive }
    });

    // In real app, update user status in database
    const response: ApiResponse<{ userId: string; isActive: boolean }> = {
        success: true,
        data: { userId: targetUserId, isActive },
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

/**
 * Session management endpoints
 */

// GET /admin/sessions - Get all active sessions
router.get('/sessions', errorHandler.asyncHandler(async (req, res) => {
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin sessions list request', {
        requestId,
        userId,
        action: 'ADMIN_SESSIONS_LIST'
    });

    const authService = require('@/services/AuthService').authService;
    const sessions = authService.getAllSessions();

    const response: ApiResponse<typeof sessions> = {
        success: true,
        data: sessions,
        timestamp: new Date(),
        requestId,
        version: '1.0.0',
        meta: {
            total: sessions.length
        }
    };

    res.json(response);
}));

// DELETE /admin/sessions/:sessionId - Terminate specific session
router.delete('/sessions/:sessionId', errorHandler.asyncHandler(async (req, res) => {
    const { sessionId } = req.params;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    if (!sessionId) {
        throw new ValidationError('Session ID is required');
    }

    logger.info('Admin session termination', {
        requestId,
        userId,
        action: 'ADMIN_SESSION_TERMINATE',
        metadata: { sessionId }
    });

    // In real app, terminate the session
    const response: ApiResponse<void> = {
        success: true,
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

/**
 * Connection management endpoints
 */

// GET /admin/connections - Get all SSH connections
router.get('/connections', errorHandler.asyncHandler(async (req, res) => {
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin connections list request', {
        requestId,
        userId,
        action: 'ADMIN_CONNECTIONS_LIST'
    });

    const sshService = require('@/services/SSHService').sshService;
    const poolStats = sshService.getPoolStats();

    // Mock connection details
    const connections = [
        {
            id: 'conn-1',
            host: 'server1.example.com',
            username: 'root',
            port: 22,
            userId: '2',
            createdAt: new Date(Date.now() - 3600000), // 1 hour ago
            lastUsedAt: new Date(Date.now() - 300000), // 5 minutes ago
            isActive: true,
            usageCount: 15,
            status: 'connected'
        },
        {
            id: 'conn-2',
            host: 'server2.example.com',
            username: 'ubuntu',
            port: 22,
            userId: '2',
            createdAt: new Date(Date.now() - 1800000), // 30 minutes ago
            lastUsedAt: new Date(Date.now() - 120000), // 2 minutes ago
            isActive: true,
            usageCount: 8,
            status: 'connected'
        }
    ];

    const response: ApiResponse<{
        connections: typeof connections;
        poolStats: typeof poolStats;
    }> = {
        success: true,
        data: {
            connections,
            poolStats
        },
        timestamp: new Date(),
        requestId,
        version: '1.0.0',
        meta: {
            total: connections.length,
            active: connections.filter(c => c.isActive).length
        }
    };

    res.json(response);
}));

// DELETE /admin/connections/:connectionId - Force disconnect connection
router.delete('/connections/:connectionId', errorHandler.asyncHandler(async (req, res) => {
    const { connectionId } = req.params;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    if (!connectionId) {
        throw new ValidationError('Connection ID is required');
    }

    logger.info('Admin force disconnect connection', {
        requestId,
        userId,
        action: 'ADMIN_FORCE_DISCONNECT',
        metadata: { connectionId }
    });

    const sshService = require('@/services/SSHService').sshService;
    await sshService.disconnect(connectionId);

    const response: ApiResponse<void> = {
        success: true,
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

// DELETE /admin/connections - Disconnect all connections
router.delete('/connections', errorHandler.asyncHandler(async (req, res) => {
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin disconnect all connections', {
        requestId,
        userId,
        action: 'ADMIN_DISCONNECT_ALL'
    });

    const sshService = require('@/services/SSHService').sshService;
    await sshService.disconnectAll();

    const response: ApiResponse<void> = {
        success: true,
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

/**
 * Logs and audit endpoints
 */

// GET /admin/logs - Get application logs
router.get('/logs', errorHandler.asyncHandler(async (req, res) => {
    const { level = 'info', limit = '100', since } = req.query;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin logs request', {
        requestId,
        userId,
        action: 'ADMIN_LOGS_REQUEST',
        metadata: { level, limit, since }
    });

    // Mock log entries
    const logs = [
        {
            timestamp: new Date(),
            level: 'info',
            message: 'SSH connection established successfully',
            metadata: {
                requestId: 'req-123',
                userId: '2',
                host: 'server1.example.com'
            }
        },
        {
            timestamp: new Date(Date.now() - 60000),
            level: 'warn',
            message: 'High memory usage detected',
            metadata: {
                memoryUsage: 85,
                threshold: 80
            }
        },
        {
            timestamp: new Date(Date.now() - 120000),
            level: 'error',
            message: 'SSH connection failed',
            metadata: {
                requestId: 'req-122',
                userId: '2',
                host: 'invalid.example.com',
                error: 'Connection timeout'
            }
        }
    ];

    const response: ApiResponse<typeof logs> = {
        success: true,
        data: logs,
        timestamp: new Date(),
        requestId,
        version: '1.0.0',
        meta: {
            total: logs.length,
            level: level as string,
            limit: parseInt(limit as string, 10)
        }
    };

    res.json(response);
}));

// GET /admin/audit - Get audit trail
router.get('/audit', errorHandler.asyncHandler(async (req, res) => {
    const { action, userId: targetUserId, limit = '50' } = req.query;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin audit trail request', {
        requestId,
        userId,
        action: 'ADMIN_AUDIT_REQUEST',
        metadata: { action, targetUserId, limit }
    });

    // Mock audit entries
    const auditEntries = [
        {
            id: 'audit-1',
            timestamp: new Date(),
            action: 'SSH_CONNECT',
            userId: '2',
            resource: 'server1.example.com',
            ipAddress: '192.168.1.100',
            userAgent: 'SSH-Client/1.0',
            success: true,
            metadata: {
                connectionId: 'conn-1',
                duration: 1250
            }
        },
        {
            id: 'audit-2',
            timestamp: new Date(Date.now() - 300000),
            action: 'SSH_COMMAND',
            userId: '2',
            resource: 'server1.example.com',
            ipAddress: '192.168.1.100',
            userAgent: 'SSH-Client/1.0',
            success: true,
            metadata: {
                command: 'ls -la',
                exitCode: 0,
                duration: 150
            }
        }
    ];

    const response: ApiResponse<typeof auditEntries> = {
        success: true,
        data: auditEntries,
        timestamp: new Date(),
        requestId,
        version: '1.0.0',
        meta: {
            total: auditEntries.length,
            filters: { action, userId: targetUserId }
        }
    };

    res.json(response);
}));

/**
 * Configuration management endpoints
 */

// GET /admin/config - Get application configuration
router.get('/config', errorHandler.asyncHandler(async (req, res) => {
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin config request', {
        requestId,
        userId,
        action: 'ADMIN_CONFIG_REQUEST'
    });

    // Return safe configuration (no secrets)
    const safeConfig = {
        app: {
            name: config.app.name,
            version: config.app.version,
            environment: config.app.environment,
            port: config.app.port,
            host: config.app.host
        },
        ssh: {
            connectionTimeout: config.ssh.connectionTimeout,
            commandTimeout: config.ssh.commandTimeout,
            keepaliveInterval: config.ssh.keepaliveInterval,
            maxConcurrentConnections: config.ssh.maxConcurrentConnections
        },
        rateLimit: {
            windowMs: config.rateLimit.windowMs,
            maxRequests: config.rateLimit.maxRequests,
            skipSuccessfulRequests: config.rateLimit.skipSuccessfulRequests
        },
        logging: {
            level: config.logging.level,
            enableRequestLogging: config.logging.enableRequestLogging
        },
        cache: {
            ttl: config.cache.ttl,
            maxKeys: config.cache.maxKeys
        },
        monitoring: {
            healthCheckInterval: config.monitoring.healthCheckInterval,
            enableMetrics: config.monitoring.enableMetrics
        }
    };

    const response: ApiResponse<typeof safeConfig> = {
        success: true,
        data: safeConfig,
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

// PUT /admin/config/logging - Update logging configuration
router.put('/config/logging', errorHandler.asyncHandler(async (req, res) => {
    const { level, enableRequestLogging } = req.body;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin logging config update', {
        requestId,
        userId,
        action: 'ADMIN_CONFIG_LOGGING_UPDATE',
        metadata: { level, enableRequestLogging }
    });

    // Validate log level
    const validLevels = ['error', 'warn', 'info', 'debug', 'verbose'];
    if (level && !validLevels.includes(level)) {
        throw new ValidationError(`Invalid log level. Must be one of: ${validLevels.join(', ')}`);
    }

    // In real app, update configuration
    const response: ApiResponse<{ level?: string; enableRequestLogging?: boolean }> = {
        success: true,
        data: { level, enableRequestLogging },
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

/**
 * System operations endpoints
 */

// GET /admin/stats - Get system statistics
router.get('/stats', errorHandler.asyncHandler(async (req, res) => {
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin stats request', {
        requestId,
        userId,
        action: 'ADMIN_STATS_REQUEST'
    });

    const sshService = require('@/services/SSHService').sshService;
    const authService = require('@/services/AuthService').authService;
    const healthService = require('@/services/HealthService').healthService;

    const [poolStats, sessions, metrics] = await Promise.all([
        sshService.getPoolStats(),
        authService.getAllSessions(),
        healthService.getMetrics()
    ]);

    const stats = {
        system: {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            cpu: process.cpuUsage(),
            platform: process.platform,
            nodeVersion: process.version
        },
        ssh: poolStats,
        auth: {
            activeSessions: sessions.length,
            totalUsers: 2 // Mock count
        },
        metrics
    };

    const response: ApiResponse<typeof stats> = {
        success: true,
        data: stats,
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

// POST /admin/maintenance - Enter maintenance mode
router.post('/maintenance', errorHandler.asyncHandler(async (req, res) => {
    const { enabled, message } = req.body;
    const requestId = (req as any).requestId;
    const userId = (req as any).user?.userId;

    logger.info('Admin maintenance mode toggle', {
        requestId,
        userId,
        action: 'ADMIN_MAINTENANCE_MODE',
        metadata: { enabled, message }
    });

    // In real app, implement maintenance mode
    const response: ApiResponse<{
        maintenanceMode: boolean;
        message?: string;
        enabledBy: string;
        enabledAt: Date;
    }> = {
        success: true,
        data: {
            maintenanceMode: enabled,
            message,
            enabledBy: userId,
            enabledAt: new Date()
        },
        timestamp: new Date(),
        requestId,
        version: '1.0.0'
    };

    res.json(response);
}));

export default router;