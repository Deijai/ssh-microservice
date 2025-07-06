/**
 * 🏥 Health Routes
 * Routes for health monitoring and status checks
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { healthController } from '@/controllers/HealthController';
import { authMiddleware } from '@/middleware/auth';
import { config } from '@/config/environment';

const router = Router();

// Relaxed rate limiting for health endpoints (they're called frequently)
const healthRateLimit = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute
    message: {
        success: false,
        error: 'Too many health check requests',
        retryAfter: 60
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for basic health checks
        return req.path === '/' || req.path === '/live' || req.path === '/ready';
    },
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many health check requests',
            retryAfter: 60,
            timestamp: new Date().toISOString()
        });
    }
});

// Very strict rate limiting for admin health operations
const adminHealthRateLimit = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 admin operations per 5 minutes
    message: {
        success: false,
        error: 'Too many admin health operations',
        retryAfter: 300
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many admin health operations',
            retryAfter: 300,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * Public health endpoints (no authentication required)
 * These are typically used by load balancers and monitoring systems
 */

// GET /health - Basic health check
router.get('/', healthController.health);

// GET /health/live - Liveness probe (Kubernetes)
router.get('/live', healthController.live);

// GET /health/ready - Readiness probe (Kubernetes)
router.get('/ready', healthController.ready);

// GET /health/info - Service information
router.get('/info', healthController.info);

/**
 * Detailed health endpoints (authentication required)
 */

router.use(healthRateLimit);

// GET /health/status - Detailed health status
router.get('/status',
    authMiddleware.optionalAuth, // Optional auth for detailed status
    healthController.status
);

// GET /health/metrics - Application metrics
router.get('/metrics',
    authMiddleware.requireAuth,
    healthController.metrics
);

/**
 * Prometheus monitoring endpoint
 */

// GET /health/prometheus - Prometheus metrics format
router.get('/prometheus', healthController.prometheus);

/**
 * Admin only health endpoints
 */

// GET /health/database - Database information
router.get('/database',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.database
);

// GET /health/metrics/:metricName/history - Metric history
router.get('/metrics/:metricName/history',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.metricHistory
);

// GET /health/thresholds - Get health thresholds
router.get('/thresholds',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.getThresholds
);

// PUT /health/thresholds - Update health thresholds
router.put('/thresholds',
    adminHealthRateLimit,
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.updateThresholds
);

/**
 * Health monitoring control endpoints (admin only)
 */

// POST /health/monitoring/start - Start health monitoring
router.post('/monitoring/start',
    adminHealthRateLimit,
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.startMonitoring
);

// POST /health/monitoring/stop - Stop health monitoring
router.post('/monitoring/stop',
    adminHealthRateLimit,
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.stopMonitoring
);

/**
 * Advanced diagnostic endpoints (admin only)
 */

// GET /health/diagnostics - Performance diagnostics
router.get('/diagnostics',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.diagnostics
);

// POST /health/gc - Force garbage collection
router.post('/gc',
    adminHealthRateLimit,
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    healthController.forceGC
);

/**
 * Health configuration and limits
 */

// GET /health/config - Get health check configuration
router.get('/config',
    authMiddleware.optionalAuth,
    (req, res) => {
        const user = (req as any).user;

        res.json({
            success: true,
            data: {
                intervals: {
                    healthCheck: config.monitoring.healthCheckInterval,
                    metricsCollection: 60000, // 1 minute
                    cleanup: 300000 // 5 minutes
                },
                thresholds: {
                    memory: {
                        warning: 80,
                        critical: 95
                    },
                    cpu: {
                        warning: 80,
                        critical: 95
                    },
                    eventLoop: {
                        warning: 100,
                        critical: 1000
                    },
                    responseTime: {
                        warning: 500,
                        critical: 2000
                    }
                },
                features: {
                    prometheusMetrics: config.monitoring.enableMetrics,
                    detailedDiagnostics: user?.role === 'admin',
                    realTimeMonitoring: true,
                    historicalMetrics: user?.role === 'admin'
                },
                endpoints: {
                    public: [
                        'GET /health',
                        'GET /health/live',
                        'GET /health/ready',
                        'GET /health/info',
                        'GET /health/prometheus'
                    ],
                    authenticated: [
                        'GET /health/status',
                        'GET /health/metrics'
                    ],
                    admin: [
                        'GET /health/database',
                        'GET /health/metrics/:metric/history',
                        'GET /health/thresholds',
                        'PUT /health/thresholds',
                        'POST /health/monitoring/start',
                        'POST /health/monitoring/stop',
                        'GET /health/diagnostics',
                        'POST /health/gc'
                    ]
                }
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * Health check aggregation endpoint
 */

// GET /health/all - Aggregate all health information (admin only)
router.get('/all',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    async (req, res) => {
        try {
            const requestId = (req as any).requestId;

            // Collect all health information
            const [
                status,
                metrics,
                database,
                thresholds
            ] = await Promise.allSettled([
                require('@/services/HealthService').healthService.getHealthStatus(),
                require('@/services/HealthService').healthService.getMetrics(),
                require('@/services/HealthService').healthService.getDatabaseInfo(),
                require('@/services/HealthService').healthService.getThresholds()
            ]);

            const healthData = {
                status: status.status === 'fulfilled' ? status.value : null,
                metrics: metrics.status === 'fulfilled' ? metrics.value : null,
                database: database.status === 'fulfilled' ? database.value : null,
                thresholds: thresholds.status === 'fulfilled' ? thresholds.value : null,
                errors: [
                    ...(status.status === 'rejected' ? [{ component: 'status', error: status.reason }] : []),
                    ...(metrics.status === 'rejected' ? [{ component: 'metrics', error: metrics.reason }] : []),
                    ...(database.status === 'rejected' ? [{ component: 'database', error: database.reason }] : []),
                    ...(thresholds.status === 'rejected' ? [{ component: 'thresholds', error: thresholds.reason }] : [])
                ]
            };

            res.json({
                success: true,
                data: healthData,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            });

        } catch (error) {
            res.status(500).json({
                success: false,
                error: 'Failed to collect health information',
                details: error instanceof Error ? error.message : 'Unknown error',
                timestamp: new Date(),
                requestId: (req as any).requestId,
                version: '1.0.0'
            });
        }
    }
);

export default router;