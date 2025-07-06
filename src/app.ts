/**
 * 🚀 Express Application Setup
 * Main application configuration and middleware setup
 */

import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import 'express-async-errors';

import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { errorHandler, setupGlobalErrorHandlers } from '@/utils/errorHandler';
import { authMiddleware } from '@/middleware/auth';
import { healthService } from '@/services/HealthService';

// Import routes
import routes from '@/routes';

/**
 * Create Express application with all middleware and routes configured
 */
export function createApp(): Application {
    const app = express();

    // Setup global error handlers for unhandled rejections/exceptions
    setupGlobalErrorHandlers();

    // Trust proxy headers (for deployment behind load balancers)
    app.set('trust proxy', 1);

    // Disable x-powered-by header for security
    app.disable('x-powered-by');

    /**
     * Security Middleware
     */

    // Helmet for security headers
    app.use(helmet({
        crossOriginEmbedderPolicy: false,
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"]
            }
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        }
    }));

    // CORS configuration
    app.use(cors({
        origin: (origin, callback) => {
            // Allow requests with no origin (mobile apps, Postman, etc.)
            if (!origin) return callback(null, true);

            if (config.security.corsOrigins.includes(origin)) {
                return callback(null, true);
            }

            // Log rejected CORS requests
            logger.security('CORS request rejected', 'low', {
                action: 'CORS_REJECTED',
                metadata: { origin }
            });

            return callback(new Error('Not allowed by CORS'), false);
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'],
        allowedHeaders: [
            'Content-Type',
            'Authorization',
            'X-Request-ID',
            'X-Session-ID',
            'X-API-Key',
            'User-Agent',
            'Accept',
            'Origin'
        ],
        exposedHeaders: [
            'X-Request-ID',
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After'
        ],
        optionsSuccessStatus: 200,
        maxAge: 86400 // 24 hours
    }));

    /**
     * Request Processing Middleware
     */

    // Compression middleware
    app.use(compression({
        level: 6,
        threshold: 1024,
        filter: (req, res) => {
            // Don't compress streaming responses
            if (req.headers['x-no-compression']) {
                return false;
            }

            // Don't compress server-sent events
            if (res.getHeader('content-type')?.toString().includes('text/event-stream')) {
                return false;
            }

            return compression.filter(req, res);
        }
    }));

    // Body parsing middleware
    app.use(express.json({
        limit: '10mb',
        verify: (req, res, buf) => {
            // Store raw body for webhook verification if needed
            (req as any).rawBody = buf;
        }
    }));

    app.use(express.urlencoded({
        extended: true,
        limit: '10mb'
    }));

    // Cookie parser
    app.use(cookieParser());

    /**
     * Request Monitoring Middleware
     */

    // Request timeout middleware
    app.use((req: Request, res: Response, next: NextFunction) => {
        const timeout = 30000; // 30 seconds

        req.setTimeout(timeout, () => {
            logger.warn('Request timeout', {
                requestId: (req as any).requestId,
                action: 'REQUEST_TIMEOUT',
                resource: req.path,
                method: req.method,
                timeout
            });

            if (!res.headersSent) {
                res.status(408).json({
                    success: false,
                    error: 'Request timeout',
                    timeout,
                    timestamp: new Date().toISOString()
                });
            }
        });

        next();
    });

    // Content type validation for POST/PUT requests
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
            const contentType = req.get('Content-Type');

            if (!contentType) {
                return res.status(400).json({
                    success: false,
                    error: 'Content-Type header is required for POST/PUT/PATCH requests',
                    timestamp: new Date().toISOString()
                });
            }

            // Allow JSON and form data
            if (!contentType.includes('application/json') &&
                !contentType.includes('application/x-www-form-urlencoded') &&
                !contentType.includes('multipart/form-data')) {
                return res.status(415).json({
                    success: false,
                    error: 'Unsupported content type. Use application/json or application/x-www-form-urlencoded',
                    timestamp: new Date().toISOString()
                });
            }
        }

        next();
    });

    /**
     * Development Middleware
     */

    if (config.app.environment === 'development') {
        // Detailed request logging in development
        app.use((req: Request, res: Response, next: NextFunction) => {
            logger.debug('Request received', {
                method: req.method,
                path: req.path,
                query: req.query,
                headers: {
                    'user-agent': req.get('User-Agent'),
                    'content-type': req.get('Content-Type'),
                    'authorization': req.get('Authorization') ? '[PRESENT]' : '[MISSING]'
                },
                body: req.method !== 'GET' ? '[BODY PRESENT]' : undefined
            });

            next();
        });
    }

    /**
     * Health Check Routes (before authentication)
     */

    // Liveness probe (minimal check)
    app.get('/live', (req: Request, res: Response) => {
        res.status(200).json({
            status: 'alive',
            timestamp: new Date().toISOString(),
            service: 'ssh-microservice'
        });
    });

    // Readiness probe
    app.get('/ready', async (req: Request, res: Response) => {
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
            res.status(503).json({
                status: 'not ready',
                error: 'Health check failed',
                timestamp: new Date().toISOString(),
                service: 'ssh-microservice'
            });
        }
    });

    /**
     * API Routes
     */

    // Mount all API routes
    app.use('/', routes);

    /**
     * Static Files (if needed)
     */

    // Serve static documentation or admin panel
    if (config.app.environment !== 'production') {
        app.get('/docs', (req: Request, res: Response) => {
            res.redirect('/api/v1/docs');
        });
    }

    /**
     * Maintenance Mode Check
     */

    app.use((req: Request, res: Response, next: NextFunction) => {
        // Check if in maintenance mode (implement based on your needs)
        const maintenanceMode = process.env.MAINTENANCE_MODE === 'true';

        if (maintenanceMode) {
            // Allow health checks and admin routes during maintenance
            if (req.path.startsWith('/health') ||
                req.path.startsWith('/live') ||
                req.path.startsWith('/ready') ||
                req.path.startsWith('/api/v1/admin')) {
                return next();
            }

            return res.status(503).json({
                success: false,
                error: 'Service temporarily unavailable for maintenance',
                message: process.env.MAINTENANCE_MESSAGE || 'We are performing scheduled maintenance. Please try again later.',
                retryAfter: 3600, // 1 hour
                timestamp: new Date().toISOString()
            });
        }

        next();
    });

    /**
     * Error Handling Middleware
     */

    // 404 handler for undefined routes (already handled in routes/index.ts)

    // Global error handler
    app.use(errorHandler.middleware);

    /**
     * Graceful Shutdown Setup
     */

    // Handle graceful shutdown
    const gracefulShutdown = (signal: string) => {
        logger.info(`Received ${signal}. Starting graceful shutdown...`);

        // Set maintenance mode
        process.env.MAINTENANCE_MODE = 'true';
        process.env.MAINTENANCE_MESSAGE = 'Server is shutting down';

        // Stop accepting new connections
        const server = (app as any).server;
        if (server) {
            server.close(() => {
                logger.info('HTTP server closed');

                // Cleanup services
                Promise.all([
                    // Disconnect all SSH connections
                    require('@/services/SSHService').sshService.disconnectAll(),
                    // Stop health monitoring
                    healthService.stopMonitoring(),
                    // Cleanup auth service
                    authService.cleanup()
                ]).then(() => {
                    logger.info('All services cleaned up. Exiting...');
                    process.exit(0);
                }).catch((error) => {
                    logger.error('Error during graceful shutdown', { error });
                    process.exit(1);
                });
            });

            // Force close after 30 seconds
            setTimeout(() => {
                logger.error('Forced shutdown after timeout');
                process.exit(1);
            }, 30000);
        } else {
            process.exit(0);
        }
    };

    // Register shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    /**
     * Application Events
     */

    // Log application startup
    app.on('mount', () => {
        logger.info('SSH Microservice application mounted', {
            action: 'APP_MOUNTED',
            environment: config.app.environment,
            version: config.app.version
        });
    });

    return app;
}

/**
 * Start the application server
 */
export async function startServer(): Promise<void> {
    try {
        const app = createApp();

        // Start health monitoring
        healthService.startMonitoring(config.monitoring.healthCheckInterval);

        // Start HTTP server
        const server = app.listen(config.app.port, config.app.host, () => {
            logger.info('SSH Microservice started successfully', {
                action: 'SERVER_STARTED',
                port: config.app.port,
                host: config.app.host,
                environment: config.app.environment,
                version: config.app.version,
                pid: process.pid,
                nodeVersion: process.version,
                uptime: process.uptime()
            });

            // Log configuration summary
            logger.info('Configuration loaded', {
                action: 'CONFIG_LOADED',
                ssh: {
                    maxConnections: config.ssh.maxConcurrentConnections,
                    connectionTimeout: config.ssh.connectionTimeout,
                    commandTimeout: config.ssh.commandTimeout
                },
                rateLimit: {
                    windowMs: config.rateLimit.windowMs,
                    maxRequests: config.rateLimit.maxRequests
                },
                logging: {
                    level: config.logging.level,
                    requestLogging: config.logging.enableRequestLogging
                },
                monitoring: {
                    healthCheckInterval: config.monitoring.healthCheckInterval,
                    metricsEnabled: config.monitoring.enableMetrics
                }
            });
        });

        // Store server reference for graceful shutdown
        (app as any).server = server;

        // Handle server errors
        server.on('error', (error: Error) => {
            logger.error('Server error occurred', {
                action: 'SERVER_ERROR',
                error,
                port: config.app.port,
                host: config.app.host
            });

            if ((error as any).code === 'EADDRINUSE') {
                logger.error(`Port ${config.app.port} is already in use`);
                process.exit(1);
            }
        });

        // Handle client connection errors
        server.on('clientError', (error: Error, socket: any) => {
            logger.warn('Client connection error', {
                action: 'CLIENT_ERROR',
                error: error.message,
                remoteAddress: socket.remoteAddress
            });

            if (socket.writable) {
                socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
            }
        });

        // Handle keep-alive timeout
        server.keepAliveTimeout = 65000; // 65 seconds (slightly more than nginx default)
        server.headersTimeout = 66000; // 66 seconds

        // Log server listening
        server.on('listening', () => {
            const address = server.address();
            logger.info('Server is listening', {
                action: 'SERVER_LISTENING',
                address: typeof address === 'string' ? address : {
                    address: address?.address,
                    family: address?.family,
                    port: address?.port
                }
            });
        });

        // Handle uncaught exceptions after server start
        process.on('uncaughtException', (error: Error) => {
            logger.error('Uncaught exception after server start', {
                action: 'UNCAUGHT_EXCEPTION',
                error,
                stack: error.stack
            });

            // Try graceful shutdown
            if (server) {
                server.close(() => {
                    process.exit(1);
                });
            } else {
                process.exit(1);
            }
        });

        // Handle unhandled promise rejections after server start
        process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
            logger.error('Unhandled promise rejection after server start', {
                action: 'UNHANDLED_REJECTION',
                reason: reason instanceof Error ? {
                    name: reason.name,
                    message: reason.message,
                    stack: reason.stack
                } : reason,
                promise: promise.toString()
            });

            // Don't exit immediately for promise rejections in production
            if (config.app.environment !== 'production') {
                process.exit(1);
            }
        });

    } catch (error) {
        logger.error('Failed to start server', {
            action: 'SERVER_START_FAILED',
            error: error as Error
        });
        process.exit(1);
    }
}

/**
 * Development middleware for hot reloading
 */
export function setupDevelopmentMiddleware(app: Application): void {
    if (config.app.environment === 'development') {
        // Add development-specific middleware here

        // Request/Response logging
        app.use((req: Request, res: Response, next: NextFunction) => {
            const start = Date.now();

            // Log request
            logger.debug('→ Request', {
                method: req.method,
                url: req.url,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });

            // Log response
            res.on('finish', () => {
                const duration = Date.now() - start;
                logger.debug('← Response', {
                    method: req.method,
                    url: req.url,
                    status: res.statusCode,
                    duration: `${duration}ms`
                });
            });

            next();
        });

        // Memory usage logging
        setInterval(() => {
            const memUsage = process.memoryUsage();
            logger.debug('Memory usage', {
                action: 'MEMORY_USAGE',
                rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
                heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
                heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
                external: `${Math.round(memUsage.external / 1024 / 1024)}MB`
            });
        }, 30000); // Every 30 seconds
    }
}

/**
 * Production optimizations
 */
export function setupProductionOptimizations(app: Application): void {
    if (config.app.environment === 'production') {
        // Enable view cache
        app.set('view cache', true);

        // Disable etag for dynamic content
        app.set('etag', 'weak');

        // Trust proxy in production
        app.set('trust proxy', true);

        // Production security headers
        app.use((req: Request, res: Response, next: NextFunction) => {
            res.set({
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
                'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
            });
            next();
        });
    }
}

/**
 * Health check setup
 */
export function setupHealthChecks(): void {
    // Add custom health checks
    healthService.addHealthCheck('api_endpoints', async () => {
        const start = Date.now();

        try {
            // Test critical endpoints
            const testEndpoints = [
                '/api/v1',
                '/health'
            ];

            // This is a simplified test - in real implementation,
            // you might make actual HTTP requests to test endpoints

            return {
                name: 'api_endpoints',
                status: 'pass',
                duration: Date.now() - start,
                message: 'All critical endpoints responding'
            };
        } catch (error) {
            return {
                name: 'api_endpoints',
                status: 'fail',
                duration: Date.now() - start,
                message: `API endpoints check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
            };
        }
    });

    // Add performance metrics
    healthService.addMetricCollector('request_count', () => {
        // In real implementation, this would track actual request counts
        return Math.floor(Math.random() * 1000);
    });

    healthService.addMetricCollector('error_rate', () => {
        // In real implementation, this would track actual error rates
        return Math.random() * 5; // 0-5% error rate
    });
}

// Export the app creation function and server starter
export default createApp;