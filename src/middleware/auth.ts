/**
 * 🔐 Authentication Middleware
 * JWT token validation and user authentication
 */

import { Request, Response, NextFunction } from 'express';
import { authService } from '@/services/AuthService';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';
import {
    AuthenticationError,
    AuthorizationError,
    ValidationError
} from '@/utils/errorHandler';
import { AuthTokenPayload, UserRole } from '@/types/common';

/**
 * Extended request interface with user information
 */
interface AuthenticatedRequest extends Request {
    user?: AuthTokenPayload;
    requestId?: string;
}

/**
 * Authentication options interface
 */
interface AuthOptions {
    required?: boolean;
    roles?: UserRole[];
    permissions?: string[];
    allowApiKey?: boolean;
}

/**
 * Extract JWT token from request
 */
function extractToken(req: Request): string | null {
    const authHeader = req.get('Authorization');

    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }

    // Check for token in query parameters (not recommended for production)
    if (req.query.token && typeof req.query.token === 'string') {
        return req.query.token;
    }

    return null;
}

/**
 * Extract API key from request
 */
function extractApiKey(req: Request): string | null {
    // Check X-API-Key header
    const apiKeyHeader = req.get('X-API-Key');
    if (apiKeyHeader) {
        return apiKeyHeader;
    }

    // Check query parameter
    if (req.query.apiKey && typeof req.query.apiKey === 'string') {
        return req.query.apiKey;
    }

    return null;
}

/**
 * Validate API key
 */
function validateApiKey(apiKey: string): boolean {
    // In a real application, you would validate against a database
    // For this demo, we'll use a simple comparison with config
    return encryption.constantTimeCompare(apiKey, process.env.API_KEY || '');
}

/**
 * Generate request ID middleware
 */
export function requestId(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    req.requestId = req.get('X-Request-ID') || encryption.generateUUID();
    res.set('X-Request-ID', req.requestId);
    next();
}

/**
 * Basic authentication middleware
 * Validates JWT token and adds user information to request
 */
export function authenticate(options: AuthOptions = {}) {
    const { required = true, allowApiKey = false } = options;

    return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
        const requestId = req.requestId || encryption.generateUUID();

        try {
            let authenticated = false;
            let user: AuthTokenPayload | undefined;

            // Try JWT authentication first
            const token = extractToken(req);
            if (token) {
                try {
                    user = authService.verifyToken(token);

                    // Update session access time if session exists
                    const sessionId = req.get('X-Session-ID');
                    if (sessionId) {
                        authService.updateSessionAccess(sessionId);
                    }

                    authenticated = true;

                    logger.debug('JWT authentication successful', {
                        requestId,
                        userId: user.userId,
                        action: 'JWT_AUTH_SUCCESS',
                        metadata: {
                            role: user.role,
                            permissions: user.permissions.length
                        }
                    });

                } catch (error) {
                    logger.warn('JWT authentication failed', {
                        requestId,
                        action: 'JWT_AUTH_FAILED',
                        error: error as Error,
                        metadata: {
                            tokenLength: token.length,
                            tokenPrefix: token.substring(0, 10) + '...'
                        }
                    });

                    if (required) {
                        throw new AuthenticationError('Invalid or expired token');
                    }
                }
            }

            // Try API key authentication if JWT failed and API key is allowed
            if (!authenticated && allowApiKey) {
                const apiKey = extractApiKey(req);
                if (apiKey) {
                    if (validateApiKey(apiKey)) {
                        // Create a system user for API key authentication
                        user = {
                            userId: 'system',
                            email: 'system@api.com',
                            role: 'admin',
                            permissions: ['*'], // All permissions for API key
                            iat: Math.floor(Date.now() / 1000),
                            exp: Math.floor(Date.now() / 1000) + 3600,
                            iss: 'api-key',
                            aud: 'ssh-microservice'
                        };

                        authenticated = true;

                        logger.info('API key authentication successful', {
                            requestId,
                            action: 'API_KEY_AUTH_SUCCESS',
                            metadata: {
                                keyPrefix: apiKey.substring(0, 8) + '...'
                            }
                        });

                    } else {
                        logger.warn('API key authentication failed', {
                            requestId,
                            action: 'API_KEY_AUTH_FAILED',
                            metadata: {
                                keyPrefix: apiKey.substring(0, 8) + '...'
                            }
                        });

                        if (required) {
                            throw new AuthenticationError('Invalid API key');
                        }
                    }
                }
            }

            // Check if authentication is required
            if (required && !authenticated) {
                throw new AuthenticationError('Authentication required');
            }

            // Add user to request
            req.user = user;

            next();

        } catch (error) {
            if (error instanceof AuthenticationError) {
                logger.security('Authentication failed', 'medium', {
                    requestId,
                    action: 'AUTH_FAILED',
                    resource: req.path,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    error: error as Error
                });
            }

            next(error);
        }
    };
}

/**
 * Authorization middleware
 * Checks user roles and permissions
 */
export function authorize(options: AuthOptions = {}) {
    const { roles = [], permissions = [] } = options;

    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        const requestId = req.requestId || encryption.generateUUID();
        const user = req.user;

        if (!user) {
            logger.warn('Authorization check without authentication', {
                requestId,
                action: 'AUTH_CHECK_NO_USER',
                resource: req.path
            });

            return next(new AuthenticationError('Authentication required'));
        }

        try {
            // Check role requirements
            if (roles.length > 0) {
                const hasRequiredRole = roles.some(role => authService.hasRole(user, role));

                if (!hasRequiredRole) {
                    logger.warn('Authorization failed - insufficient role', {
                        requestId,
                        userId: user.userId,
                        action: 'AUTH_ROLE_FAILED',
                        resource: req.path,
                        metadata: {
                            userRole: user.role,
                            requiredRoles: roles
                        }
                    });

                    throw new AuthorizationError(`Required role: ${roles.join(' or ')}`);
                }
            }

            // Check permission requirements
            if (permissions.length > 0) {
                const hasRequiredPermission = permissions.some(permission =>
                    authService.hasPermission(user, permission)
                );

                if (!hasRequiredPermission) {
                    logger.warn('Authorization failed - insufficient permissions', {
                        requestId,
                        userId: user.userId,
                        action: 'AUTH_PERMISSION_FAILED',
                        resource: req.path,
                        metadata: {
                            userPermissions: user.permissions,
                            requiredPermissions: permissions
                        }
                    });

                    throw new AuthorizationError(`Required permission: ${permissions.join(' or ')}`);
                }
            }

            logger.debug('Authorization successful', {
                requestId,
                userId: user.userId,
                action: 'AUTH_SUCCESS',
                resource: req.path,
                metadata: {
                    role: user.role,
                    checkedRoles: roles,
                    checkedPermissions: permissions
                }
            });

            next();

        } catch (error) {
            if (error instanceof AuthorizationError) {
                logger.security('Authorization failed', 'medium', {
                    requestId,
                    userId: user.userId,
                    action: 'AUTHZ_FAILED',
                    resource: req.path,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    error: error as Error
                });
            }

            next(error);
        }
    };
}

/**
 * Admin only middleware
 * Shorthand for requiring admin role
 */
export function adminOnly(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    return authorize({ roles: ['admin'] })(req, res, next);
}

/**
 * User or admin middleware
 * Shorthand for requiring user or admin role
 */
export function userOrAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    return authorize({ roles: ['user', 'admin'] })(req, res, next);
}

/**
 * SSH permission middleware
 * Checks SSH-related permissions
 */
export function sshPermission(action: 'connect' | 'execute' | 'manage') {
    const permissionMap = {
        connect: 'ssh:connect',
        execute: 'ssh:execute',
        manage: 'ssh:manage'
    };

    return authorize({ permissions: [permissionMap[action]] });
}

/**
 * Optional authentication middleware
 * Authenticates if token is present but doesn't require it
 */
export const optionalAuth = authenticate({ required: false });

/**
 * Required authentication middleware
 * Requires valid authentication
 */
export const requireAuth = authenticate({ required: true });

/**
 * API key authentication middleware
 * Allows API key or JWT authentication
 */
export const apiKeyAuth = authenticate({ required: true, allowApiKey: true });

/**
 * Session validation middleware
 * Validates session information
 */
export function validateSession(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    const requestId = req.requestId || encryption.generateUUID();
    const sessionId = req.get('X-Session-ID');
    const user = req.user;

    if (!user) {
        return next();
    }

    if (sessionId) {
        try {
            const session = authService.getSession(sessionId);

            if (!session) {
                logger.warn('Invalid session ID', {
                    requestId,
                    userId: user.userId,
                    action: 'INVALID_SESSION',
                    metadata: { sessionId }
                });

                return next(new AuthenticationError('Invalid session'));
            }

            if (session.userId !== user.userId) {
                logger.warn('Session user mismatch', {
                    requestId,
                    userId: user.userId,
                    action: 'SESSION_USER_MISMATCH',
                    metadata: {
                        sessionId,
                        sessionUserId: session.userId
                    }
                });

                return next(new AuthenticationError('Session user mismatch'));
            }

            if (!session.isActive) {
                logger.warn('Inactive session', {
                    requestId,
                    userId: user.userId,
                    action: 'INACTIVE_SESSION',
                    metadata: { sessionId }
                });

                return next(new AuthenticationError('Session is inactive'));
            }

            // Update session access time
            authService.updateSessionAccess(sessionId);

        } catch (error) {
            logger.error('Session validation error', {
                requestId,
                userId: user.userId,
                error: error as Error
            });

            return next(new AuthenticationError('Session validation failed'));
        }
    }

    next();
}

/**
 * Rate limiting by user middleware
 */
export function userRateLimit(maxRequests: number = 100, windowMs: number = 60000) {
    const userRequests = new Map<string, { count: number; resetTime: number }>();

    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        const requestId = req.requestId || encryption.generateUUID();
        const user = req.user;

        if (!user) {
            return next();
        }

        const now = Date.now();
        const userId = user.userId;
        const userLimit = userRequests.get(userId);

        if (!userLimit || now > userLimit.resetTime) {
            // Reset or create new limit
            userRequests.set(userId, {
                count: 1,
                resetTime: now + windowMs
            });

            logger.debug('User rate limit reset', {
                requestId,
                userId,
                action: 'RATE_LIMIT_RESET'
            });

            return next();
        }

        if (userLimit.count >= maxRequests) {
            logger.warn('User rate limit exceeded', {
                requestId,
                userId,
                action: 'RATE_LIMIT_EXCEEDED',
                metadata: {
                    count: userLimit.count,
                    maxRequests,
                    resetTime: userLimit.resetTime
                }
            });

            const retryAfter = Math.ceil((userLimit.resetTime - now) / 1000);

            res.set('Retry-After', retryAfter.toString());
            res.set('X-RateLimit-Limit', maxRequests.toString());
            res.set('X-RateLimit-Remaining', '0');
            res.set('X-RateLimit-Reset', userLimit.resetTime.toString());

            return next(new AuthorizationError('User rate limit exceeded'));
        }

        // Increment count
        userLimit.count++;
        userRequests.set(userId, userLimit);

        // Set rate limit headers
        res.set('X-RateLimit-Limit', maxRequests.toString());
        res.set('X-RateLimit-Remaining', (maxRequests - userLimit.count).toString());
        res.set('X-RateLimit-Reset', userLimit.resetTime.toString());

        next();
    };
}

/**
 * Security headers middleware
 */
export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
    // Remove server information
    res.removeHeader('X-Powered-By');

    // Set security headers
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; frame-src 'none'; worker-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; manifest-src 'self';"
    });

    next();
}

/**
 * CORS configuration
 */
export function configureCORS(allowedOrigins: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const origin = req.get('Origin');

        // Check if origin is allowed
        if (origin && allowedOrigins.includes(origin)) {
            res.set('Access-Control-Allow-Origin', origin);
        }

        res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, X-Session-ID, X-API-Key');
        res.set('Access-Control-Allow-Credentials', 'true');
        res.set('Access-Control-Max-Age', '86400'); // 24 hours

        // Handle preflight requests
        if (req.method === 'OPTIONS') {
            res.status(204).end();
            return;
        }

        next();
    };
}

/**
 * Export middleware functions
 */
export const authMiddleware = {
    requestId,
    authenticate,
    authorize,
    adminOnly,
    userOrAdmin,
    sshPermission,
    optionalAuth,
    requireAuth,
    apiKeyAuth,
    validateSession,
    userRateLimit,
    securityHeaders,
    configureCORS
};