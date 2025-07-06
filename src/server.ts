/**
 * 🚀 SSH Microservice Server (Simplified)
 */

import { startServer } from './app';
import { logger } from './utils/logger';

/**
 * Bootstrap function
 */
async function bootstrap(): Promise<void> {
    try {
        console.log('🔐 SSH Microservice Starting...');

        // Check required env vars
        const requiredVars = ['JWT_SECRET', 'ENCRYPTION_KEY', 'API_KEY'];
        const missingVars = requiredVars.filter(varName => !process.env[varName]);

        if (missingVars.length > 0) {
            console.warn('⚠️ Missing environment variables:', missingVars);
            console.log('💡 Using default values for development');
        }

        // Start server
        await startServer();

        console.log('✅ Bootstrap completed successfully!');

    } catch (error) {
        console.error('💥 Bootstrap failed:', error);
        process.exit(1);
    }
}

// Handle errors
process.on('unhandledRejection', (error) => {
    logger.error('Unhandled rejection:', error);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught exception:', error);
    process.exit(1);
});

// Start if main module
if (require.main === module) {
    bootstrap();
}

export { bootstrap };