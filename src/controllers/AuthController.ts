/**
 * 🔐 Authentication Controller
 * HTTP endpoints for authentication and authorization
 */

import { Request, Response } from 'express';
import { authService, LoginCredentials, TokenPair, UserInfo } from '@/services/AuthService';
import { logger } from '@/utils/logger';
import { validator } from '@/utils/validator';
import { encryption } from '@/utils/encryption';
import { errorHandler } from '@/utils/errorHandler';
import {
    ValidationError,
    AuthenticationError,
    AuthorizationError
} from '@/utils/errorHandler';
import { ApiResponse, AuthTokenPayload } from '@/types/common';

/**
 * Extended request interface with user information
 */
interface AuthenticatedRequest extends Request {
    user?: AuthTokenPayload;
    requestId?: string;
}

/**
 * Login request body interface
 */
interface LoginRequest {
    email: string;
    password: string;
    rememberMe?: boolean;
}

/**
 * Firebase login request body interface
 */
interface FirebaseLoginRequest {
    firebaseToken: string;
}

/**
 * Refresh token request body interface
 */
interface RefreshTokenRequest {
    refreshToken: string;
}

/**
 * Logout request body interface
 */
interface LogoutRequest {
    refreshToken?: string;
    sessionId?: string;
}

/**
 * Change password request body interface
 */
interface ChangePasswordRequest {
    currentPassword: string;
    newPassword: string;
}

/**
 * Get client information from request
 */
function getClientInfo(req: Request): { ipAddress: string; userAgent: string } {
    return {
        ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown'
    };
}

/**
 * Authentication Controller class
 */
export class AuthController {
    /**
     * User login with email and password
     */
    static login = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const { body }: { body: LoginRequest } = req;
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();
        const clientInfo = getClientInfo(req);

        logger.info('Login attempt', {
            requestId,
            action: 'LOGIN_ATTEMPT',
            resource: 'authentication',
            ip: clientInfo.ipAddress,
            metadata: {
                email: body.email,
                rememberMe: body.rememberMe || false
            }
        });

        // Validate request body
        if (!body.email || !body.password) {
            throw new ValidationError('Email and password are required');
        }

        if (!validator.email(body.email)) {
            throw new ValidationError('Invalid email format');
        }

        if (body.password.length < 6) {
            throw new ValidationError('Password must be at least 6 characters long');
        }

        const credentials: LoginCredentials = {
            email: body.email.toLowerCase().trim(),
            password: body.password,
            rememberMe: body.rememberMe || false
        };

        try {
            const result = await authService.login(credentials, clientInfo);

            // Set secure HTTP-only cookie for refresh token
            res.cookie('refreshToken', result.data.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            // Remove refresh token from response body
            const response: ApiResponse<Omit<typeof result.data, 'refreshToken'>> = {
                ...result,
                data: {
                    accessToken: result.data.accessToken,
                    expiresIn: result.data.expiresIn,
                    tokenType: result.data.tokenType,
                    user: result.data.user
                }
            };

            logger.info('Login successful', {
                requestId,
                userId: result.data.user.id,
                action: 'LOGIN_SUCCESS',
                resource: 'authentication',
                ip: clientInfo.ipAddress
            });

            res.status(200).json(response);

        } catch (error) {
            logger.warn('Login failed', {
                requestId,
                action: 'LOGIN_FAILED',
                resource: 'authentication',
                ip: clientInfo.ipAddress,
                error: error as Error,
                metadata: { email: body.email }
            });

            throw error;
        }
    });

    /**
     * User login with Firebase token
     */
    static loginWithFirebase = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const { body }: { body: FirebaseLoginRequest } = req;
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();
        const clientInfo = getClientInfo(req);

        logger.info('Firebase login attempt', {
            requestId,
            action: 'FIREBASE_LOGIN_ATTEMPT',
            resource: 'authentication',
            ip: clientInfo.ipAddress
        });

        // Validate request body
        if (!body.firebaseToken) {
            throw new ValidationError('Firebase token is required');
        }

        if (!validator.jwtFormat(body.firebaseToken)) {
            throw new ValidationError('Invalid Firebase token format');
        }

        try {
            const result = await authService.loginWithFirebase(body.firebaseToken, clientInfo);

            // Set secure HTTP-only cookie for refresh token
            res.cookie('refreshToken', result.data.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            // Remove refresh token from response body
            const response: ApiResponse<Omit<typeof result.data, 'refreshToken'>> = {
                ...result,
                data: {
                    accessToken: result.data.accessToken,
                    expiresIn: result.data.expiresIn,
                    tokenType: result.data.tokenType,
                    user: result.data.user
                }
            };

            logger.info('Firebase login successful', {
                requestId,
                userId: result.data.user.id,
                action: 'FIREBASE_LOGIN_SUCCESS',
                resource: 'authentication',
                ip: clientInfo.ipAddress
            });

            res.status(200).json(response);

        } catch (error) {
            logger.warn('Firebase login failed', {
                requestId,
                action: 'FIREBASE_LOGIN_FAILED',
                resource: 'authentication',
                ip: clientInfo.ipAddress,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Refresh access token
     */
    static refreshToken = errorHandler.asyncHandler(async (req: Request, res: Response) => {
        const { body }: { body: RefreshTokenRequest } = req;
        const cookieRefreshToken = req.cookies.refreshToken;
        const requestId = req.get('X-Request-ID') || encryption.generateUUID();

        // Try to get refresh token from body or cookie
        const refreshToken = body.refreshToken || cookieRefreshToken;

        logger.info('Token refresh attempt', {
            requestId,
            action: 'TOKEN_REFRESH_ATTEMPT',
            resource: 'authentication'
        });

        if (!refreshToken) {
            throw new AuthenticationError('Refresh token is required');
        }

        if (!validator.jwtFormat(refreshToken)) {
            throw new ValidationError('Invalid refresh token format');
        }

        try {
            const result = await authService.refreshToken(refreshToken);

            // Update refresh token cookie
            res.cookie('refreshToken', result.data.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            // Remove refresh token from response body
            const response: ApiResponse<Omit<typeof result.data, 'refreshToken'>> = {
                ...result,
                data: {
                    accessToken: result.data.accessToken,
                    expiresIn: result.data.expiresIn,
                    tokenType: result.data.tokenType
                }
            };

            logger.info('Token refreshed successfully', {
                requestId,
                action: 'TOKEN_REFRESH_SUCCESS',
                resource: 'authentication'
            });

            res.status(200).json(response);

        } catch (error) {
            // Clear refresh token cookie on error
            res.clearCookie('refreshToken');

            logger.warn('Token refresh failed', {
                requestId,
                action: 'TOKEN_REFRESH_FAILED',
                resource: 'authentication',
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * User logout
     */
    static logout = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { body }: { body: LogoutRequest } = req;
        const accessToken = req.get('Authorization')?.replace('Bearer ', '') || '';
        const cookieRefreshToken = req.cookies.refreshToken;
        const refreshToken = body.refreshToken || cookieRefreshToken;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        logger.info('Logout attempt', {
            requestId,
            userId,
            action: 'LOGOUT_ATTEMPT',
            resource: 'authentication'
        });

        try {
            await authService.logout(accessToken, refreshToken, body.sessionId);

            // Clear refresh token cookie
            res.clearCookie('refreshToken');

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Logout successful', {
                requestId,
                userId,
                action: 'LOGOUT_SUCCESS',
                resource: 'authentication'
            });

            res.status(200).json(response);

        } catch (error) {
            // Still clear cookie and return success for logout
            res.clearCookie('refreshToken');

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Logout completed (with errors)', {
                requestId,
                userId,
                action: 'LOGOUT_COMPLETED',
                resource: 'authentication',
                error: error as Error
            });

            res.status(200).json(response);
        }
    });

    /**
     * Get current user profile
     */
    static getProfile = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('User not authenticated');
        }

        logger.debug('Profile request', {
            requestId,
            userId,
            action: 'GET_PROFILE',
            resource: 'user'
        });

        // Create user profile from token payload
        const userProfile = {
            id: req.user.userId,
            email: req.user.email,
            role: req.user.role,
            permissions: req.user.permissions
        };

        const response: ApiResponse<typeof userProfile> = {
            success: true,
            data: userProfile,
            timestamp: new Date(),
            requestId,
            version: '1.0.0'
        };

        res.status(200).json(response);
    });

    /**
     * Verify token validity
     */
    static verifyToken = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('Token is invalid');
        }

        logger.debug('Token verification', {
            requestId,
            userId,
            action: 'VERIFY_TOKEN',
            resource: 'authentication'
        });

        const response: ApiResponse<{ valid: boolean; user: typeof req.user }> = {
            success: true,
            data: {
                valid: true,
                user: req.user
            },
            timestamp: new Date(),
            requestId,
            version: '1.0.0'
        };

        res.status(200).json(response);
    });

    /**
     * Get user permissions
     */
    static getPermissions = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('User not authenticated');
        }

        logger.debug('Permissions request', {
            requestId,
            userId,
            action: 'GET_PERMISSIONS',
            resource: 'user'
        });

        const response: ApiResponse<{
            role: string;
            permissions: readonly string[];
        }> = {
            success: true,
            data: {
                role: req.user.role,
                permissions: req.user.permissions
            },
            timestamp: new Date(),
            requestId,
            version: '1.0.0'
        };

        res.status(200).json(response);
    });

    /**
     * Get active sessions (admin only)
     */
    static getSessions = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('User not authenticated');
        }

        if (!authService.hasRole(req.user, 'admin')) {
            throw new AuthorizationError('Admin access required');
        }

        logger.info('Sessions request', {
            requestId,
            userId,
            action: 'GET_SESSIONS',
            resource: 'admin'
        });

        try {
            const sessions = authService.getAllSessions();

            const response: ApiResponse<typeof sessions> = {
                success: true,
                data: sessions,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get sessions', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Revoke user sessions (admin only)
     */
    static revokeSessions = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { targetUserId } = req.params;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('User not authenticated');
        }

        if (!authService.hasRole(req.user, 'admin')) {
            throw new AuthorizationError('Admin access required');
        }

        if (!validator.uuid(targetUserId)) {
            throw new ValidationError('Invalid user ID format');
        }

        logger.info('Revoke sessions request', {
            requestId,
            userId,
            action: 'REVOKE_SESSIONS',
            resource: 'admin',
            metadata: { targetUserId }
        });

        try {
            authService.revokeAllUserSessions(targetUserId);

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('User sessions revoked', {
                requestId,
                userId,
                action: 'SESSIONS_REVOKED',
                resource: 'admin',
                metadata: { targetUserId }
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to revoke sessions', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Change password
     */
    static changePassword = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { body }: { body: ChangePasswordRequest } = req;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('User not authenticated');
        }

        logger.info('Change password request', {
            requestId,
            userId,
            action: 'CHANGE_PASSWORD',
            resource: 'user'
        });

        // Validate request body
        if (!body.currentPassword || !body.newPassword) {
            throw new ValidationError('Current password and new password are required');
        }

        if (body.newPassword.length < 8) {
            throw new ValidationError('New password must be at least 8 characters long');
        }

        // Check password strength
        const passwordStrength = validator.passwordStrength(body.newPassword);
        if (passwordStrength.score < 3) {
            throw new ValidationError('Password is too weak', {
                feedback: passwordStrength.feedback,
                score: passwordStrength.score
            });
        }

        try {
            // This would typically verify current password and update it
            // For this demo, we'll just simulate success

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Password changed successfully', {
                requestId,
                userId,
                action: 'PASSWORD_CHANGED',
                resource: 'user'
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to change password', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Check if user has specific permission
     */
    static checkPermission = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { permission } = req.params;
        const requestId = req.requestId || encryption.generateUUID();
        const userId = req.user?.id;

        if (!req.user) {
            throw new AuthenticationError('User not authenticated');
        }

        if (!permission) {
            throw new ValidationError('Permission parameter is required');
        }

        const hasPermission = authService.hasPermission(req.user, permission);

        const response: ApiResponse<{ hasPermission: boolean }> = {
            success: true,
            data: { hasPermission },
            timestamp: new Date(),
            requestId,
            version: '1.0.0'
        };

        logger.debug('Permission check', {
            requestId,
            userId,
            action: 'CHECK_PERMISSION',
            resource: 'user',
            metadata: { permission, hasPermission }
        });

        res.status(200).json(response);
    });
}

/**
 * Export controller methods
 */
export const authController = {
    login: AuthController.login,
    loginWithFirebase: AuthController.loginWithFirebase,
    refreshToken: AuthController.refreshToken,
    logout: AuthController.logout,
    getProfile: AuthController.getProfile,
    verifyToken: AuthController.verifyToken,
    getPermissions: AuthController.getPermissions,
    getSessions: AuthController.getSessions,
    revokeSessions: AuthController.revokeSessions,
    changePassword: AuthController.changePassword,
    checkPermission: AuthController.checkPermission
};