/**
 * 🔐 SSH Routes
 * Routes for SSH connection management and command execution
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { sshController } from '@/controllers/SSHController';
import { authMiddleware } from '@/middleware/auth';
import { config } from '@/config/environment';

const router = Router();

// Rate limiting for SSH operations
const sshRateLimit = rateLimit({
    windowMs: config.rateLimit.windowMs, // 15 minutes
    max: config.rateLimit.maxRequests, // 100 requests per windowMs
    message: {
        success: false,
        error: 'Too many SSH requests. Please try again later.',
        retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many SSH requests. Please try again later.',
            retryAfter: Math.ceil(config.rateLimit.windowMs / 1000),
            timestamp: new Date().toISOString()
        });
    }
});

// Stricter rate limiting for connection creation
const connectionRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // Limit each IP to 10 connection attempts per 5 minutes
    message: {
        success: false,
        error: 'Too many connection attempts. Please try again later.',
        retryAfter: 300
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many connection attempts. Please try again later.',
            retryAfter: 300,
            timestamp: new Date().toISOString()
        });
    }
});

// Moderate rate limiting for command execution
const commandRateLimit = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // Limit each IP to 30 commands per minute
    message: {
        success: false,
        error: 'Too many command executions. Please try again later.',
        retryAfter: 60
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many command executions. Please try again later.',
            retryAfter: 60,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * All SSH routes require authentication and SSH permissions
 */
router.use(authMiddleware.requireAuth);
router.use(sshRateLimit);

/**
 * Connection management routes
 */

// POST /ssh/connect - Create new SSH connection
router.post('/connect',
    connectionRateLimit,
    authMiddleware.sshPermission('connect'),
    sshController.connect
);

// POST /ssh/test - Test SSH connection without creating persistent connection
router.post('/test',
    connectionRateLimit,
    authMiddleware.sshPermission('connect'),
    sshController.testConnection
);

// DELETE /ssh/:connectionId - Disconnect SSH connection
router.delete('/:connectionId',
    authMiddleware.sshPermission('connect'),
    sshController.disconnect
);

/**
 * Command execution routes
 */

// POST /ssh/:connectionId/execute - Execute single command
router.post('/:connectionId/execute',
    commandRateLimit,
    authMiddleware.sshPermission('execute'),
    sshController.executeCommand
);

// POST /ssh/:connectionId/stream - Execute command with streaming output
router.post('/:connectionId/stream',
    commandRateLimit,
    authMiddleware.sshPermission('execute'),
    sshController.executeStreamingCommand
);

// POST /ssh/:connectionId/batch - Execute batch commands
router.post('/:connectionId/batch',
    commandRateLimit,
    authMiddleware.sshPermission('execute'),
    authMiddleware.userRateLimit(5, 60000), // Extra limit for batch operations
    sshController.executeBatchCommands
);

/**
 * Streaming command routes
 */

// GET /ssh/stream/:streamId - Get streaming command result
router.get('/stream/:streamId',
    authMiddleware.sshPermission('execute'),
    sshController.getStreamingResult
);

// DELETE /ssh/stream/:streamId - Cancel streaming command
router.delete('/stream/:streamId',
    authMiddleware.sshPermission('execute'),
    sshController.cancelStreamingCommand
);

/**
 * Server status and monitoring routes
 */

// GET /ssh/:connectionId/status - Get server status
router.get('/:connectionId/status',
    authMiddleware.sshPermission('connect'),
    sshController.getServerStatus
);

/**
 * Pool management routes
 */

// GET /ssh/pool/stats - Get connection pool statistics
router.get('/pool/stats',
    authMiddleware.sshPermission('connect'),
    sshController.getPoolStats
);

// DELETE /ssh/pool/disconnect-all - Disconnect all connections (admin only)
router.delete('/pool/disconnect-all',
    authMiddleware.adminOnly,
    sshController.disconnectAll
);

/**
 * Utility and information routes
 */

// GET /ssh/info - Get SSH service information
router.get('/info', (req, res) => {
    res.json({
        success: true,
        data: {
            service: 'SSH Management Service',
            version: '1.0.0',
            features: [
                'SSH connection pooling',
                'Command execution',
                'Streaming output',
                'Batch commands',
                'Server monitoring',
                'Security validation'
            ],
            limits: {
                maxConcurrentConnections: config.ssh.maxConcurrentConnections,
                connectionTimeout: config.ssh.connectionTimeout,
                commandTimeout: config.ssh.commandTimeout,
                maxOutputSize: '1MB',
                batchCommandLimit: 50
            },
            supportedAuthMethods: [
                'password',
                'publickey'
            ],
            supportedAlgorithms: {
                kex: [
                    'diffie-hellman-group14-sha256',
                    'diffie-hellman-group16-sha512',
                    'ecdh-sha2-nistp256',
                    'ecdh-sha2-nistp384',
                    'ecdh-sha2-nistp521'
                ],
                cipher: [
                    'aes128-gcm@openssh.com',
                    'aes256-gcm@openssh.com',
                    'aes128-ctr',
                    'aes192-ctr',
                    'aes256-ctr'
                ]
            }
        },
        timestamp: new Date().toISOString()
    });
});

// GET /ssh/limits - Get current rate limits and quotas
router.get('/limits', (req, res) => {
    const user = (req as any).user;

    res.json({
        success: true,
        data: {
            user: {
                id: user?.userId,
                role: user?.role
            },
            rateLimits: {
                connections: '10 per 5 minutes',
                commands: '30 per minute',
                batchCommands: '5 per minute',
                generalRequests: '100 per 15 minutes'
            },
            quotas: {
                maxConcurrentConnections: user?.role === 'admin' ? 'unlimited' : config.ssh.maxConcurrentConnections,
                maxBatchSize: 50,
                maxOutputSize: '1MB',
                commandTimeout: `${config.ssh.commandTimeout}ms`,
                connectionTimeout: `${config.ssh.connectionTimeout}ms`
            },
            permissions: user?.permissions || []
        },
        timestamp: new Date().toISOString()
    });
});

// GET /ssh/health - SSH service specific health check
router.get('/health', (req, res) => {
    try {
        const poolStats = require('@/services/SSHService').sshService.getPoolStats();

        const status = {
            status: poolStats.activeConnections < config.ssh.maxConcurrentConnections * 0.8 ? 'healthy' : 'degraded',
            service: 'SSH Service',
            metrics: {
                activeConnections: poolStats.activeConnections,
                totalConnections: poolStats.totalConnections,
                idleConnections: poolStats.idleConnections,
                averageUsage: poolStats.averageUsage,
                maxConnections: config.ssh.maxConcurrentConnections,
                utilizationPercent: Math.round((poolStats.activeConnections / config.ssh.maxConcurrentConnections) * 100)
            },
            timestamp: new Date().toISOString()
        };

        const httpStatus = status.status === 'healthy' ? 200 : 206;
        res.status(httpStatus).json({
            success: true,
            data: status,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        res.status(503).json({
            success: false,
            error: 'SSH service health check failed',
            timestamp: new Date().toISOString()
        });
    }
});

export default router;