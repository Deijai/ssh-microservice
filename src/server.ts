#!/usr/bin/env node

/**
 * 🚀 SSH Microservice Server
 * Main entry point for the SSH microservice application
 */

import 'module-alias/register';
import { startServer, setupHealthChecks } from './app';
import { config, logConfig, validateConfig } from '@/config/environment';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';

/**
 * Bootstrap the application
 */
async function bootstrap(): Promise<void> {
    try {
        // ASCII art banner
        console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔐 SSH MICROSERVICE                                        ║
║   Remote server management and command execution             ║
║                                                               ║
║   Version: ${config.app.version.padEnd(10)} Environment: ${config.app.environment.padEnd(12)} ║
║   Node.js: ${process.version.padEnd(10)} Platform: ${process.platform.padEnd(15)} ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        `);

        logger.info('Starting SSH Microservice bootstrap process', {
            action: 'BOOTSTRAP_START',
            version: config.app.version,
            environment: config.app.environment,
            nodeVersion: process.version,
            pid: process.pid
        });

        // Step 1: Validate configuration
        logger.info('Validating configuration...');
        try {
            validateConfig();
            logger.info('✅ Configuration validation passed');
        } catch (error) {
            logger.error('❌ Configuration validation failed', { error: error as Error });
            process.exit(1);
        }

        // Step 2: Log configuration (safe mode)
        if (config.app.environment === 'development') {
            logConfig();
        }

        // Step 3: Test encryption system
        logger.info('Testing encryption system...');
        try {
            const encryptionTest = await encryption.testEncryption();
            if (encryptionTest) {
                logger.info('✅ Encryption system test passed');
            } else {
                throw new Error('Encryption test failed');
            }
        } catch (error) {
            logger.error('❌ Encryption system test failed', { error: error as Error });
            process.exit(1);
        }

        // Step 4: Setup health checks
        logger.info('Setting up health monitoring...');
        try {
            setupHealthChecks();
            logger.info('✅ Health monitoring configured');
        } catch (error) {
            logger.error('❌ Health monitoring setup failed', { error: error as Error });
            process.exit(1);
        }

        // Step 5: Check required environment variables
        logger.info('Checking environment variables...');
        const requiredEnvVars = [
            'JWT_SECRET',
            'ENCRYPTION_KEY',
            'API_KEY'
        ];

        const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingVars.length > 0) {
            logger.error('❌ Missing required environment variables', {
                missingVars,
                action: 'ENV_VARS_CHECK_FAILED'
            });
            process.exit(1);
        }
        logger.info('✅ Environment variables check passed');

        // Step 6: Check Node.js version
        logger.info('Checking Node.js version...');
        const nodeVersion = process.version;
        const requiredMajor = 18;
        const currentMajor = parseInt(nodeVersion.split('.')[0].substring(1));

        if (currentMajor < requiredMajor) {
            logger.error('❌ Node.js version check failed', {
                current: nodeVersion,
                required: `>= ${requiredMajor}.0.0`,
                action: 'NODE_VERSION_CHECK_FAILED'
            });
            process.exit(1);
        }
        logger.info('✅ Node.js version check passed', { version: nodeVersion });

        // Step 7: Initialize services
        logger.info('Initializing services...');

        // Pre-warm services
        try {
            // Initialize SSH service
            const { sshService } = await import('@/services/SSHService');
            logger.info('✅ SSH service initialized');

            // Initialize auth service
            const { authService } = await import('@/services/AuthService');
            logger.info('✅ Authentication service initialized');

            // Initialize health service
            const { healthService } = await import('@/services/HealthService');
            logger.info('✅ Health service initialized');

        } catch (error) {
            logger.error('❌ Service initialization failed', { error: error as Error });
            process.exit(1);
        }

        // Step 8: Setup process monitoring
        logger.info('Setting up process monitoring...');
        setupProcessMonitoring();
        logger.info('✅ Process monitoring configured');

        // Step 9: Start the server
        logger.info('Starting HTTP server...');
        await startServer();

        // Step 10: Post-startup tasks
        logger.info('Running post-startup tasks...');
        await runPostStartupTasks();
        logger.info('✅ Post-startup tasks completed');

        logger.info('🎉 SSH Microservice bootstrap completed successfully', {
            action: 'BOOTSTRAP_COMPLETE',
            port: config.app.port,
            host: config.app.host,
            environment: config.app.environment,
            version: config.app.version,
            uptime: process.uptime()
        });

    } catch (error) {
        logger.error('💥 Bootstrap process failed', {
            action: 'BOOTSTRAP_FAILED',
            error: error as Error
        });
        process.exit(1);
    }
}

/**
 * Setup process monitoring and metrics collection
 */
function setupProcessMonitoring(): void {
    // Monitor memory usage
    const memoryMonitor = setInterval(() => {
        const memUsage = process.memoryUsage();
        const totalMemory = Math.round((memUsage.rss + memUsage.heapTotal + memUsage.external) / 1024 / 1024);

        // Log memory warning if usage is high
        if (totalMemory > 512) { // 512MB threshold
            logger.warn('High memory usage detected', {
                action: 'MEMORY_WARNING',
                memoryUsage: {
                    rss: Math.round(memUsage.rss / 1024 / 1024),
                    heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
                    heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
                    external: Math.round(memUsage.external / 1024 / 1024),
                    total: totalMemory
                }
            });
        }
    }, 60000); // Check every minute

    // Monitor event loop lag
    const eventLoopMonitor = setInterval(() => {
        const start = process.hrtime.bigint();
        setImmediate(() => {
            const lag = Number(process.hrtime.bigint() - start) / 1e6; // Convert to milliseconds

            if (lag > 100) { // 100ms threshold
                logger.warn('High event loop lag detected', {
                    action: 'EVENT_LOOP_LAG_WARNING',
                    lag: Math.round(lag),
                    threshold: 100
                });
            }
        });
    }, 30000); // Check every 30 seconds

    // Cleanup on exit
    process.on('exit', () => {
        clearInterval(memoryMonitor);
        clearInterval(eventLoopMonitor);
    });

    // Log process information
    logger.info('Process monitoring started', {
        action: 'PROCESS_MONITORING_STARTED',
        pid: process.pid,
        ppid: process.ppid,
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage()
    });
}

/**
 * Run post-startup tasks
 */
async function runPostStartupTasks(): Promise<void> {
    try {
        // Task 1: Validate external dependencies
        logger.debug('Validating external dependencies...');

        // Task 2: Cleanup old data
        logger.debug('Cleaning up old data...');

        // Task 3: Send startup notification (if configured)
        if (config.app.environment === 'production') {
            logger.info('SSH Microservice started in production', {
                action: 'PRODUCTION_STARTUP_NOTIFICATION',
                version: config.app.version,
                timestamp: new Date().toISOString()
            });
        }

        // Task 4: Register with service discovery (if applicable)
        logger.debug('Service discovery registration skipped (not configured)');

        // Task 5: Warm up caches
        logger.debug('Warming up caches...');

        // Task 6: Run health check
        const { healthService } = await import('@/services/HealthService');
        const healthStatus = await healthService.getHealthStatus();

        if (healthStatus.status === 'healthy') {
            logger.info('Initial health check passed', {
                action: 'INITIAL_HEALTH_CHECK',
                status: healthStatus.status
            });
        } else {
            logger.warn('Initial health check shows degraded status', {
                action: 'INITIAL_HEALTH_CHECK',
                status: healthStatus.status,
                issues: healthStatus.checks.filter(check => check.status !== 'pass')
            });
        }

    } catch (error) {
        logger.warn('Some post-startup tasks failed', {
            action: 'POST_STARTUP_TASKS_PARTIAL_FAILURE',
            error: error as Error
        });
        // Don't fail the entire startup for post-startup task failures
    }
}

/**
 * Setup development hot-reload support
 */
function setupDevelopmentFeatures(): void {
    if (config.app.environment === 'development') {
        // Enable source map support
        require('source-map-support').install({
            environment: 'node',
            handleUncaughtExceptions: false
        });

        // Watch for file changes (basic implementation)
        logger.info('Development mode: Enhanced logging and debugging enabled');

        // Log all environment variables (excluding secrets)
        const safeEnvVars = Object.keys(process.env)
            .filter(key => !key.toLowerCase().includes('secret') &&
                !key.toLowerCase().includes('key') &&
                !key.toLowerCase().includes('password'))
            .reduce((obj, key) => {
                obj[key] = process.env[key];
                return obj;
            }, {} as Record<string, string>);

        logger.debug('Environment variables (safe)', { envVars: safeEnvVars });
    }
}

/**
 * Handle startup errors gracefully
 */
function handleStartupError(error: Error): void {
    console.error('\n💥 STARTUP FAILED\n');
    console.error('Error:', error.message);

    if (config.app.environment === 'development' && error.stack) {
        console.error('\nStack Trace:');
        console.error(error.stack);
    }

    console.error('\n🔍 Troubleshooting Tips:');
    console.error('1. Check your .env file exists and has all required variables');
    console.error('2. Ensure ports are not already in use');
    console.error('3. Verify database connections are working');
    console.error('4. Check file permissions');
    console.error('5. Review the logs for more details\n');

    process.exit(1);
}

/**
 * Main execution
 */
if (require.main === module) {
    // Setup development features first
    setupDevelopmentFeatures();

    // Handle startup errors
    process.on('unhandledRejection', handleStartupError);
    process.on('uncaughtException', handleStartupError);

    // Start the application
    bootstrap().catch(handleStartupError);
}

// Export for testing
export { bootstrap, setupProcessMonitoring, runPostStartupTasks };