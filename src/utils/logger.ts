/**
 * 📝 Logger Utility (Simplified)
 */

import winston from 'winston';

/**
 * Log context interface (flexible)
 */
interface LogContext {
    [key: string]: any;
}

/**
 * Create simple logger
 */
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

export { logger, LogContext };