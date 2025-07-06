/**
 * 🛣️ Main Routes
 * Central routing configuration
 */

import { Router } from 'express';
import { authMiddleware } from '@/middleware/auth';
import { logger } from '@/utils/logger';

// Import route modules
import authRoutes from './auth';
import sshRoutes from './ssh';
import healthRoutes from './health';
import adminRoutes from './admin';

/**
 * Create main router with middleware setup
 */
export function createRoutes(): Router {
    const router = Router();

    // Global middleware for all routes
    router.use(authMiddleware.requestId);
    router.use(authMiddleware.securityHeaders);

    // Request logging middleware
    router.use((req, res, next) => {
        const start = Date.now();

        res.on('finish', () => {
            const duration = Date.now() - start;
            const requestId = (req as any).requestId;
            const userId = (req as any).user?.userId;

            logger.httpRequest({
                requestId,
                userId,
                userRole: (req as any).user?.role,
                ip: req.ip,
                userAgent: req.get('User-Agent') || 'unknown',
                method: req.method as any,
                path: req.path,
                timestamp: new Date(),
                duration
            }, res.statusCode);
        });

        next();
    });

    // API version prefix
    const v1Router = Router();

    // Mount route modules
    v1Router.use('/auth', authRoutes);
    v1Router.use('/ssh', sshRoutes);
    v1Router.use('/health', healthRoutes);
    v1Router.use('/admin', adminRoutes);

    // Root endpoints
    v1Router.get('/', (req, res) => {
        res.json({
            service: 'SSH Microservice',
            version: '1.0.0',
            status: 'running',
            timestamp: new Date().toISOString(),
            endpoints: {
                auth: '/api/v1/auth',
                ssh: '/api/v1/ssh',
                health: '/api/v1/health',
                admin: '/api/v1/admin'
            }
        });
    });

    // API documentation endpoint
    v1Router.get('/docs', (req, res) => {
        res.json({
            title: 'SSH Microservice API Documentation',
            version: '1.0.0',
            description: 'REST API for SSH connection management and command execution',
            baseUrl: '/api/v1',
            endpoints: {
                auth: {
                    login: 'POST /auth/login',
                    loginFirebase: 'POST /auth/login/firebase',
                    refresh: 'POST /auth/refresh',
                    logout: 'POST /auth/logout',
                    profile: 'GET /auth/profile',
                    verify: 'GET /auth/verify',
                    permissions: 'GET /auth/permissions'
                },
                ssh: {
                    connect: 'POST /ssh/connect',
                    testConnection: 'POST /ssh/test',
                    executeCommand: 'POST /ssh/:connectionId/execute',
                    executeStreaming: 'POST /ssh/:connectionId/stream',
                    getStreamResult: 'GET /ssh/stream/:streamId',
                    cancelStream: 'DELETE /ssh/stream/:streamId',
                    executeBatch: 'POST /ssh/:connectionId/batch',
                    getStatus: 'GET /ssh/:connectionId/status',
                    disconnect: 'DELETE /ssh/:connectionId',
                    getPoolStats: 'GET /ssh/pool/stats'
                },
                health: {
                    basic: 'GET /health',
                    status: 'GET /health/status',
                    ready: 'GET /health/ready',
                    live: 'GET /health/live',
                    metrics: 'GET /health/metrics',
                    info: 'GET /health/info',
                    prometheus: 'GET /health/prometheus'
                },
                admin: {
                    users: 'GET /admin/users',
                    sessions: 'GET /admin/sessions',
                    connections: 'GET /admin/connections',
                    logs: 'GET /admin/logs',
                    config: 'GET /admin/config'
                }
            }
        });
    });

    // Mount v1 routes
    router.use('/api/v1', v1Router);

    // Global health check (outside versioning)
    router.get('/health', healthRoutes);

    // Catch-all for undefined routes
    router.use('*', (req, res) => {
        res.status(404).json({
            success: false,
            error: 'Endpoint not found',
            path: req.originalUrl,
            method: req.method,
            timestamp: new Date().toISOString(),
            availableEndpoints: [
                '/api/v1',
                '/api/v1/docs',
                '/health'
            ]
        });
    });

    return router;
}

export default createRoutes();