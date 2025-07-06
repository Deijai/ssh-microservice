/**
 * 🚨 Error Handler Utility
 * Centralized error handling with custom error types
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from './logger';
import { config } from '@/config/environment';
import { ApiResponse, ErrorResponse } from '@/types/common';

/**
 * Custom error types enumeration
 */
export enum ErrorType {
    VALIDATION_ERROR = 'VALIDATION_ERROR',
    AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
    AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
    SSH_CONNECTION_ERROR = 'SSH_CONNECTION_ERROR',
    SSH_COMMAND_ERROR = 'SSH_COMMAND_ERROR',
    ENCRYPTION_ERROR = 'ENCRYPTION_ERROR',
    RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR',
    NOT_FOUND_ERROR = 'NOT_FOUND_ERROR',
    INTERNAL_ERROR = 'INTERNAL_ERROR',
    EXTERNAL_SERVICE_ERROR = 'EXTERNAL_SERVICE_ERROR',
    TIMEOUT_ERROR = 'TIMEOUT_ERROR',
    NETWORK_ERROR = 'NETWORK_ERROR',
    CONFIGURATION_ERROR = 'CONFIGURATION_ERROR',
    RESOURCE_CONFLICT_ERROR = 'RESOURCE_CONFLICT_ERROR',
    QUOTA_EXCEEDED_ERROR = 'QUOTA_EXCEEDED_ERROR'
}

/**
 * Base application error class
 */
export abstract class AppError extends Error {
    abstract readonly type: ErrorType;
    abstract readonly statusCode: number;
    abstract readonly isOperational: boolean;

    constructor(
        message: string,
        public readonly details?: unknown,
        public readonly context?: Record<string, unknown>
    ) {
        super(message);
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }

    /**
     * Convert error to JSON representation
     */
    toJSON(): Record<string, unknown> {
        return {
            name: this.name,
            type: this.type,
            message: this.message,
            statusCode: this.statusCode,
            details: this.details,
            context: this.context,
            timestamp: new Date().toISOString()
        };
    }
}

/**
 * Validation error (400)
 */
export class ValidationError extends AppError {
    readonly type = ErrorType.VALIDATION_ERROR;
    readonly statusCode = 400;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Authentication error (401)
 */
export class AuthenticationError extends AppError {
    readonly type = ErrorType.AUTHENTICATION_ERROR;
    readonly statusCode = 401;
    readonly isOperational = true;

    constructor(message: string = 'Authentication required', details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Authorization error (403)
 */
export class AuthorizationError extends AppError {
    readonly type = ErrorType.AUTHORIZATION_ERROR;
    readonly statusCode = 403;
    readonly isOperational = true;

    constructor(message: string = 'Insufficient permissions', details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * SSH connection error (502)
 */
export class SSHConnectionError extends AppError {
    readonly type = ErrorType.SSH_CONNECTION_ERROR;
    readonly statusCode = 502;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * SSH command error (500)
 */
export class SSHCommandError extends AppError {
    readonly type = ErrorType.SSH_COMMAND_ERROR;
    readonly statusCode = 500;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Encryption error (500)
 */
export class EncryptionError extends AppError {
    readonly type = ErrorType.ENCRYPTION_ERROR;
    readonly statusCode = 500;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Rate limit error (429)
 */
export class RateLimitError extends AppError {
    readonly type = ErrorType.RATE_LIMIT_ERROR;
    readonly statusCode = 429;
    readonly isOperational = true;

    constructor(message: string = 'Rate limit exceeded', details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Not found error (404)
 */
export class NotFoundError extends AppError {
    readonly type = ErrorType.NOT_FOUND_ERROR;
    readonly statusCode = 404;
    readonly isOperational = true;

    constructor(message: string = 'Resource not found', details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Timeout error (408)
 */
export class TimeoutError extends AppError {
    readonly type = ErrorType.TIMEOUT_ERROR;
    readonly statusCode = 408;
    readonly isOperational = true;

    constructor(message: string = 'Operation timeout', details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Network error (503)
 */
export class NetworkError extends AppError {
    readonly type = ErrorType.NETWORK_ERROR;
    readonly statusCode = 503;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Resource conflict error (409)
 */
export class ResourceConflictError extends AppError {
    readonly type = ErrorType.RESOURCE_CONFLICT_ERROR;
    readonly statusCode = 409;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Quota exceeded error (429)
 */
export class QuotaExceededError extends AppError {
    readonly type = ErrorType.QUOTA_EXCEEDED_ERROR;
    readonly statusCode = 429;
    readonly isOperational = true;

    constructor(message: string, details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Internal server error (500)
 */
export class InternalError extends AppError {
    readonly type = ErrorType.INTERNAL_ERROR;
    readonly statusCode = 500;
    readonly isOperational = false;

    constructor(message: string = 'Internal server error', details?: unknown, context?: Record<string, unknown>) {
        super(message, details, context);
    }
}

/**
 * Error handler utility class
 */
export class ErrorHandlerUtil {
    /**
     * Handle async route errors
     */
    static asyncHandler<T extends Request, U extends Response>(
        fn: (req: T, res: U, next: NextFunction) => Promise<void>
    ) {
        return (req: T, res: U, next: NextFunction): void => {
            Promise.resolve(fn(req, res, next)).catch(next);
        };
    }

    /**
     * Express error middleware
     */
    static middleware(
        error: Error,
        req: Request,
        res: Response,
        next: NextFunction
    ): void {
        const requestId = req.get('X-Request-ID') || 'unknown';
        const userId = (req as any).user?.id;

        // Log error
        if (error instanceof AppError) {
            if (error.isOperational) {
                logger.warn(error.message, {
                    requestId,
                    userId,
                    action: 'ERROR_HANDLING',
                    resource: req.path,
                    error,
                    metadata: {
                        type: error.type,
                        statusCode: error.statusCode,
                        details: error.details,
                        context: error.context
                    }
                });
            } else {
                logger.error(error.message, {
                    requestId,
                    userId,
                    action: 'ERROR_HANDLING',
                    resource: req.path,
                    error,
                    metadata: {
                        type: error.type,
                        statusCode: error.statusCode,
                        details: error.details,
                        context: error.context
                    }
                });
            }
        } else {
            // Unknown error - log as error
            logger.error('Unhandled error occurred', {
                requestId,
                userId,
                action: 'ERROR_HANDLING',
                resource: req.path,
                error,
                metadata: {
                    name: error.name,
                    message: error.message,
                    stack: error.stack
                }
            });
        }

        // Send error response
        const errorResponse = ErrorHandlerUtil.formatErrorResponse(error, req);
        res.status(errorResponse.statusCode).json(errorResponse);
    }

    /**
     * Format error response
     */
    private static formatErrorResponse(error: Error, req: Request): ErrorResponse & { statusCode: number } {
        const requestId = req.get('X-Request-ID') || 'unknown';
        const isProduction = config.app.environment === 'production';

        if (error instanceof AppError) {
            return {
                error: isProduction && !error.isOperational ? 'Internal server error' : error.message,
                code: error.type,
                details: isProduction && !error.isOperational ? undefined : error.details,
                timestamp: new Date(),
                requestId,
                path: req.path,
                method: req.method as any,
                statusCode: error.statusCode,
                ...(isProduction ? {} : { stack: error.stack })
            };
        }

        // Handle specific error types
        if (error.name === 'ValidationError') {
            return {
                error: 'Validation failed',
                code: ErrorType.VALIDATION_ERROR,
                details: error.message,
                timestamp: new Date(),
                requestId,
                path: req.path,
                method: req.method as any,
                statusCode: 400
            };
        }

        if (error.name === 'CastError') {
            return {
                error: 'Invalid data format',
                code: ErrorType.VALIDATION_ERROR,
                details: error.message,
                timestamp: new Date(),
                requestId,
                path: req.path,
                method: req.method as any,
                statusCode: 400
            };
        }

        if (error.name === 'JsonWebTokenError') {
            return {
                error: 'Invalid token',
                code: ErrorType.AUTHENTICATION_ERROR,
                timestamp: new Date(),
                requestId,
                path: req.path,
                method: req.method as any,
                statusCode: 401
            };
        }

        if (error.name === 'TokenExpiredError') {
            return {
                error: 'Token expired',
                code: ErrorType.AUTHENTICATION_ERROR,
                timestamp: new Date(),
                requestId,
                path: req.path,
                method: req.method as any,
                statusCode: 401
            };
        }

        // Default internal error
        return {
            error: isProduction ? 'Internal server error' : error.message,
            code: ErrorType.INTERNAL_ERROR,
            timestamp: new Date(),
            requestId,
            path: req.path,
            method: req.method as any,
            statusCode: 500,
            ...(isProduction ? {} : { stack: error.stack })
        };
    }

    /**
     * Handle unhandled promise rejections
     */
    static handleUnhandledRejection(reason: unknown, promise: Promise<unknown>): void {
        logger.error('Unhandled promise rejection', {
            action: 'UNHANDLED_REJECTION',
            metadata: {
                reason: reason instanceof Error ? {
                    name: reason.name,
                    message: reason.message,
                    stack: reason.stack
                } : reason,
                promise: promise.toString()
            }
        });

        // In production, gracefully shut down
        if (config.app.environment === 'production') {
            process.exit(1);
        }
    }

    /**
     * Handle uncaught exceptions
     */
    static handleUncaughtException(error: Error): void {
        logger.error('Uncaught exception', {
            action: 'UNCAUGHT_EXCEPTION',
            error,
            metadata: {
                name: error.name,
                message: error.message,
                stack: error.stack
            }
        });

        // Always exit on uncaught exceptions
        process.exit(1);
    }

    /**
     * Create error response
     */
    static createErrorResponse<T = never>(
        message: string,
        error?: string,
        details?: unknown,
        requestId?: string
    ): ApiResponse<T> {
        return {
            success: false,
            error: error || message,
            details,
            timestamp: new Date(),
            requestId: requestId || 'unknown',
            version: config.app.version
        };
    }

    /**
     * Wrap async function with error handling
     */
    static wrapAsync<TArgs extends unknown[], TReturn>(
        fn: (...args: TArgs) => Promise<TReturn>
    ): (...args: TArgs) => Promise<TReturn> {
        return async (...args: TArgs): Promise<TReturn> => {
            try {
                return await fn(...args);
            } catch (error) {
                if (error instanceof AppError) {
                    throw error;
                }

                // Convert unknown errors to InternalError
                throw new InternalError(
                    error instanceof Error ? error.message : 'Unknown error occurred',
                    error instanceof Error ? {
                        name: error.name,
                        stack: error.stack
                    } : error
                );
            }
        };
    }

    /**
     * Check if error is operational
     */
    static isOperationalError(error: Error): boolean {
        return error instanceof AppError && error.isOperational;
    }

    /**
     * Get safe error message for client
     */
    static getSafeErrorMessage(error: Error): string {
        if (error instanceof AppError && error.isOperational) {
            return error.message;
        }

        if (config.app.environment === 'production') {
            return 'An internal error occurred';
        }

        return error.message;
    }
}

/**
 * Setup global error handlers
 */
export function setupGlobalErrorHandlers(): void {
    process.on('unhandledRejection', ErrorHandlerUtil.handleUnhandledRejection);
    process.on('uncaughtException', ErrorHandlerUtil.handleUncaughtException);
}

/**
 * Convenience functions
 */
export const errorHandler = {
    asyncHandler: ErrorHandlerUtil.asyncHandler,
    middleware: ErrorHandlerUtil.middleware,
    createErrorResponse: ErrorHandlerUtil.createErrorResponse,
    wrapAsync: ErrorHandlerUtil.wrapAsync,
    isOperationalError: ErrorHandlerUtil.isOperationalError,
    getSafeErrorMessage: ErrorHandlerUtil.getSafeErrorMessage
};