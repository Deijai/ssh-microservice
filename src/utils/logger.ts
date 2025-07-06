/**
 * 📝 Logger Utility
 * Centralized logging with Winston
 */

import winston from 'winston';
import { config } from '@/config/environment';
import { RequestContext, LogLevel } from '@/types/common';

/**
 * Log context interface
 */
interface LogContext {
    readonly requestId?: string;
    readonly userId?: string;
    readonly action?: string;
    readonly resource?: string;
    readonly ip?: string;
    readonly userAgent?: string;
    readonly duration?: number;
    readonly statusCode?: number;
    readonly error?: Error;
    readonly metadata?: Record<string, unknown>;
}

/**
 * Create logger instance
 */
function createLogger(): winston.Logger {
    const { level, file, maxSize, maxFiles } = config.logging;

    // Console format for development
    const consoleFormat = winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({ format: 'HH:mm:ss' }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
            return `${timestamp} [${level}] ${message}${metaStr}`;
        })
    );

    // File format for production
    const fileFormat = winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    );

    // Create transports
    const transports: winston.transport[] = [
        new winston.transports.Console({
            format: consoleFormat,
            level: config.app.environment === 'production' ? 'warn' : 'debug'
        })
    ];

    // Add file transport in production
    if (config.app.environment === 'production') {
        transports.push(
            new winston.transports.File({
                filename: file,
                format: fileFormat,
                level,
                maxsize: parseSize(maxSize),
                maxFiles,
                tailable: true
            })
        );

        // Separate error log
        transports.push(
            new winston.transports.File({
                filename: file.replace('.log', '-error.log'),
                format: fileFormat,
                level: 'error',
                maxsize: parseSize(maxSize),
                maxFiles,
                tailable: true
            })
        );
    }

    return winston.createLogger({
        level,
        transports,
        exitOnError: false,
        silent: config.app.environment === 'test'
    });
}

/**
 * Parse file size string to bytes
 */
function parseSize(size: string): number {
    const units: Record<string, number> = {
        b: 1,
        k: 1024,
        m: 1024 * 1024,
        g: 1024 * 1024 * 1024
    };

    const match = size.toLowerCase().match(/^(\d+)([bkmg]?)$/);
    if (!match) return 10 * 1024 * 1024; // Default 10MB

    const [, value, unit] = match;
    return parseInt(value, 10) * (units[unit] || 1);
}

/**
 * Format log message with context
 */
function formatMessage(message: string, context?: LogContext): [string, object] {
    if (!context) return [message, {}];

    const { requestId, userId, action, resource, error, metadata, ...rest } = context;

    let formattedMessage = message;
    if (requestId) formattedMessage = `[${requestId}] ${formattedMessage}`;
    if (action && resource) formattedMessage = `${action} ${resource}: ${formattedMessage}`;

    const logMeta = {
        ...rest,
        ...(userId && { userId }),
        ...(error && {
            error: {
                name: error.name,
                message: error.message,
                stack: error.stack
            }
        }),
        ...(metadata && { metadata })
    };

    return [formattedMessage, logMeta];
}

// Create logger instance
const logger = createLogger();

/**
 * Enhanced logger with context support
 */
export class Logger {
    private static instance: Logger;
    private logger: winston.Logger;

    private constructor() {
        this.logger = logger;
    }

    /**
     * Get logger singleton instance
     */
    static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    /**
     * Log error message
     */
    error(message: string, context?: LogContext): void {
        const [formattedMessage, meta] = formatMessage(message, context);
        this.logger.error(formattedMessage, meta);
    }

    /**
     * Log warning message
     */
    warn(message: string, context?: LogContext): void {
        const [formattedMessage, meta] = formatMessage(message, context);
        this.logger.warn(formattedMessage, meta);
    }

    /**
     * Log info message
     */
    info(message: string, context?: LogContext): void {
        const [formattedMessage, meta] = formatMessage(message, context);
        this.logger.info(formattedMessage, meta);
    }

    /**
     * Log debug message
     */
    debug(message: string, context?: LogContext): void {
        const [formattedMessage, meta] = formatMessage(message, context);
        this.logger.debug(formattedMessage, meta);
    }

    /**
     * Log verbose message
     */
    verbose(message: string, context?: LogContext): void {
        const [formattedMessage, meta] = formatMessage(message, context);
        this.logger.verbose(formattedMessage, meta);
    }

    /**
     * Create child logger with persistent context
     */
    child(context: Partial<LogContext>): ChildLogger {
        return new ChildLogger(this, context);
    }

    /**
     * Log HTTP request
     */
    httpRequest(req: RequestContext, statusCode: number, message?: string): void {
        const level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info';
        const defaultMessage = `${req.method} ${req.path} - ${statusCode}`;

        this[level](message || defaultMessage, {
            requestId: req.requestId,
            userId: req.userId,
            action: 'HTTP_REQUEST',
            resource: req.path,
            ip: req.ip,
            userAgent: req.userAgent,
            duration: req.duration,
            statusCode,
            metadata: {
                method: req.method,
                userRole: req.userRole
            }
        });
    }

    /**
     * Log SSH connection attempt
     */
    sshConnection(host: string, username: string, success: boolean, duration: number, context?: Partial<LogContext>): void {
        const message = `SSH connection to ${host} ${success ? 'successful' : 'failed'}`;
        const level = success ? 'info' : 'warn';

        this[level](message, {
            ...context,
            action: 'SSH_CONNECT',
            resource: `${username}@${host}`,
            duration,
            metadata: {
                host,
                username,
                success
            }
        });
    }

    /**
     * Log SSH command execution
     */
    sshCommand(host: string, command: string, success: boolean, duration: number, context?: Partial<LogContext>): void {
        const message = `SSH command executed: ${command.substring(0, 100)}${command.length > 100 ? '...' : ''}`;
        const level = success ? 'info' : 'warn';

        this[level](message, {
            ...context,
            action: 'SSH_COMMAND',
            resource: host,
            duration,
            metadata: {
                host,
                command: command.length > 200 ? `${command.substring(0, 200)}...` : command,
                success
            }
        });
    }

    /**
     * Log authentication attempt
     */
    authAttempt(userId: string, success: boolean, ip: string, context?: Partial<LogContext>): void {
        const message = `Authentication ${success ? 'successful' : 'failed'} for user ${userId}`;
        const level = success ? 'info' : 'warn';

        this[level](message, {
            ...context,
            userId,
            action: 'AUTH_ATTEMPT',
            resource: 'authentication',
            ip,
            metadata: {
                success
            }
        });
    }

    /**
     * Log security event
     */
    security(event: string, severity: 'low' | 'medium' | 'high' | 'critical', context?: LogContext): void {
        const level = severity === 'critical' ? 'error' : severity === 'high' ? 'warn' : 'info';

        this[level](`Security event: ${event}`, {
            ...context,
            action: 'SECURITY_EVENT',
            metadata: {
                severity,
                event
            }
        });
    }

    /**
     * Log performance metric
     */
    performance(metric: string, value: number, unit: string, context?: Partial<LogContext>): void {
        this.info(`Performance metric: ${metric} = ${value}${unit}`, {
            ...context,
            action: 'PERFORMANCE_METRIC',
            metadata: {
                metric,
                value,
                unit
            }
        });
    }

    /**
     * Get underlying Winston logger
     */
    getWinstonLogger(): winston.Logger {
        return this.logger;
    }
}

/**
 * Child logger with persistent context
 */
class ChildLogger {
    constructor(
        private parent: Logger,
        private context: Partial<LogContext>
    ) { }

    error(message: string, additionalContext?: Partial<LogContext>): void {
        this.parent.error(message, { ...this.context, ...additionalContext });
    }

    warn(message: string, additionalContext?: Partial<LogContext>): void {
        this.parent.warn(message, { ...this.context, ...additionalContext });
    }

    info(message: string, additionalContext?: Partial<LogContext>): void {
        this.parent.info(message, { ...this.context, ...additionalContext });
    }

    debug(message: string, additionalContext?: Partial<LogContext>): void {
        this.parent.debug(message, { ...this.context, ...additionalContext });
    }

    verbose(message: string, additionalContext?: Partial<LogContext>): void {
        this.parent.verbose(message, { ...this.context, ...additionalContext });
    }
}

// Export singleton instance
export const logger = Logger.getInstance();

// Export for testing
export { LogContext };