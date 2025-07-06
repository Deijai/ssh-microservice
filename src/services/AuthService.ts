/**
 * 🔐 Authentication Service
 * JWT and Firebase authentication management
 */

import jwt from 'jsonwebtoken';
import admin from 'firebase-admin';
import NodeCache from 'node-cache';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';
import { encryption } from '@/utils/encryption';
import {
    AuthTokenPayload,
    UserRole,
    ApiResponse
} from '@/types/common';
import {
    AuthenticationError,
    AuthorizationError,
    ValidationError
} from '@/utils/errorHandler';

/**
 * User information interface
 */
interface UserInfo {
    readonly id: string;
    readonly email: string;
    readonly role: UserRole;
    readonly permissions: readonly string[];
    readonly createdAt: Date;
    readonly lastLoginAt?: Date;
    readonly isActive: boolean;
    readonly metadata?: Record<string, unknown>;
}

/**
 * Token pair interface
 */
interface TokenPair {
    readonly accessToken: string;
    readonly refreshToken: string;
    readonly expiresIn: number;
    readonly tokenType: 'Bearer';
}

/**
 * Login credentials interface
 */
interface LoginCredentials {
    readonly email: string;
    readonly password: string;
    readonly rememberMe?: boolean;
}

/**
 * Firebase token verification result
 */
interface FirebaseTokenResult {
    readonly uid: string;
    readonly email?: string;
    readonly emailVerified: boolean;
    readonly customClaims?: Record<string, unknown>;
}

/**
 * Session information
 */
interface SessionInfo {
    readonly userId: string;
    readonly sessionId: string;
    readonly createdAt: Date;
    readonly lastAccessedAt: Date;
    readonly ipAddress: string;
    readonly userAgent: string;
    readonly isActive: boolean;
}

/**
 * Authentication service class
 */
export class AuthService {
    private static instance: AuthService;
    private sessionCache: NodeCache;
    private blacklistCache: NodeCache;
    private rateLimitCache: NodeCache;
    private readonly jwtSecret: string;
    private readonly tokenExpiry: string;
    private readonly refreshTokenExpiry: string;

    private constructor() {
        this.sessionCache = new NodeCache({
            stdTTL: 86400, // 24 hours
            checkperiod: 3600 // Check every hour
        });

        this.blacklistCache = new NodeCache({
            stdTTL: 86400, // 24 hours
            checkperiod: 3600
        });

        this.rateLimitCache = new NodeCache({
            stdTTL: 900, // 15 minutes
            checkperiod: 300 // Check every 5 minutes
        });

        this.jwtSecret = config.security.jwtSecret;
        this.tokenExpiry = '1h';
        this.refreshTokenExpiry = '7d';

        this.initializeFirebase();
    }

    /**
     * Get authentication service singleton instance
     */
    static getInstance(): AuthService {
        if (!AuthService.instance) {
            AuthService.instance = new AuthService();
        }
        return AuthService.instance;
    }

    /**
     * Initialize Firebase Admin SDK
     */
    private initializeFirebase(): void {
        try {
            if (!admin.apps.length) {
                admin.initializeApp({
                    credential: admin.credential.cert({
                        projectId: config.firebase.projectId,
                        clientEmail: config.firebase.clientEmail,
                        privateKey: config.firebase.privateKey
                    }),
                    projectId: config.firebase.projectId
                });

                logger.info('Firebase Admin SDK initialized successfully');
            }
        } catch (error) {
            logger.error('Failed to initialize Firebase Admin SDK', { error: error as Error });
            throw new Error('Firebase initialization failed');
        }
    }

    /**
     * Authenticate user with email and password
     */
    async login(credentials: LoginCredentials, clientInfo: {
        ipAddress: string;
        userAgent: string;
    }): Promise<ApiResponse<TokenPair & { user: UserInfo }>> {
        try {
            // Rate limiting check
            this.checkRateLimit(credentials.email, clientInfo.ipAddress);

            // Validate credentials format
            if (!this.isValidEmail(credentials.email)) {
                throw new ValidationError('Invalid email format');
            }

            if (!credentials.password || credentials.password.length < 6) {
                throw new ValidationError('Invalid password');
            }

            // For demo purposes, we'll use a simple hardcoded check
            // In a real app, you'd verify against your user database
            const user = await this.verifyUserCredentials(credentials);

            if (!user) {
                this.recordFailedAttempt(credentials.email, clientInfo.ipAddress);
                throw new AuthenticationError('Invalid credentials');
            }

            if (!user.isActive) {
                throw new AuthenticationError('Account is disabled');
            }

            // Generate tokens
            const tokenPair = await this.generateTokenPair(user, credentials.rememberMe);

            // Create session
            const sessionId = encryption.generateUUID();
            const session: SessionInfo = {
                userId: user.id,
                sessionId,
                createdAt: new Date(),
                lastAccessedAt: new Date(),
                ipAddress: clientInfo.ipAddress,
                userAgent: clientInfo.userAgent,
                isActive: true
            };

            this.sessionCache.set(sessionId, session);

            // Update last login
            await this.updateLastLogin(user.id);

            // Log successful login
            logger.authAttempt(user.id, true, clientInfo.ipAddress, {
                action: 'LOGIN',
                metadata: {
                    email: user.email,
                    role: user.role,
                    sessionId
                }
            });

            // Clear failed attempts
            this.clearFailedAttempts(credentials.email, clientInfo.ipAddress);

            return {
                success: true,
                data: {
                    ...tokenPair,
                    user: {
                        ...user,
                        lastLoginAt: new Date()
                    }
                },
                timestamp: new Date(),
                requestId: encryption.generateUUID(),
                version: config.app.version
            };

        } catch (error) {
            if (error instanceof AuthenticationError || error instanceof ValidationError) {
                throw error;
            }

            logger.error('Login failed', {
                error: error as Error,
                email: credentials.email,
                ip: clientInfo.ipAddress
            });

            throw new AuthenticationError('Login failed');
        }
    }

    /**
     * Authenticate with Firebase token
     */
    async loginWithFirebase(
        firebaseToken: string,
        clientInfo: { ipAddress: string; userAgent: string }
    ): Promise<ApiResponse<TokenPair & { user: UserInfo }>> {
        try {
            // Verify Firebase token
            const firebaseResult = await this.verifyFirebaseToken(firebaseToken);

            if (!firebaseResult.emailVerified) {
                throw new AuthenticationError('Email not verified');
            }

            // Get or create user
            let user = await this.getUserByFirebaseUid(firebaseResult.uid);

            if (!user) {
                user = await this.createUserFromFirebase(firebaseResult);
            }

            if (!user.isActive) {
                throw new AuthenticationError('Account is disabled');
            }

            // Generate tokens
            const tokenPair = await this.generateTokenPair(user);

            // Create session
            const sessionId = encryption.generateUUID();
            const session: SessionInfo = {
                userId: user.id,
                sessionId,
                createdAt: new Date(),
                lastAccessedAt: new Date(),
                ipAddress: clientInfo.ipAddress,
                userAgent: clientInfo.userAgent,
                isActive: true
            };

            this.sessionCache.set(sessionId, session);

            // Update last login
            await this.updateLastLogin(user.id);

            // Log successful login
            logger.authAttempt(user.id, true, clientInfo.ipAddress, {
                action: 'FIREBASE_LOGIN',
                metadata: {
                    email: user.email,
                    role: user.role,
                    sessionId,
                    firebaseUid: firebaseResult.uid
                }
            });

            return {
                success: true,
                data: {
                    ...tokenPair,
                    user: {
                        ...user,
                        lastLoginAt: new Date()
                    }
                },
                timestamp: new Date(),
                requestId: encryption.generateUUID(),
                version: config.app.version
            };

        } catch (error) {
            if (error instanceof AuthenticationError) {
                throw error;
            }

            logger.error('Firebase login failed', {
                error: error as Error,
                ip: clientInfo.ipAddress
            });

            throw new AuthenticationError('Firebase authentication failed');
        }
    }

    /**
     * Refresh access token
     */
    async refreshToken(refreshToken: string): Promise<ApiResponse<TokenPair>> {
        try {
            // Verify refresh token
            const decoded = this.verifyToken(refreshToken, 'refresh');

            // Check if token is blacklisted
            if (this.isTokenBlacklisted(refreshToken)) {
                throw new AuthenticationError('Token has been revoked');
            }

            // Get user
            const user = await this.getUserById(decoded.userId);

            if (!user || !user.isActive) {
                throw new AuthenticationError('User not found or inactive');
            }

            // Generate new token pair
            const tokenPair = await this.generateTokenPair(user);

            // Blacklist old refresh token
            this.blacklistToken(refreshToken);

            logger.info('Token refreshed successfully', {
                userId: user.id,
                action: 'TOKEN_REFRESH'
            });

            return {
                success: true,
                data: tokenPair,
                timestamp: new Date(),
                requestId: encryption.generateUUID(),
                version: config.app.version
            };

        } catch (error) {
            if (error instanceof AuthenticationError) {
                throw error;
            }

            logger.error('Token refresh failed', { error: error as Error });
            throw new AuthenticationError('Invalid refresh token');
        }
    }

    /**
     * Logout user
     */
    async logout(
        accessToken: string,
        refreshToken?: string,
        sessionId?: string
    ): Promise<ApiResponse<void>> {
        try {
            // Verify access token
            const decoded = this.verifyToken(accessToken, 'access');

            // Blacklist tokens
            this.blacklistToken(accessToken);
            if (refreshToken) {
                this.blacklistToken(refreshToken);
            }

            // Remove session
            if (sessionId) {
                this.sessionCache.del(sessionId);
            }

            logger.info('User logged out successfully', {
                userId: decoded.userId,
                action: 'LOGOUT',
                sessionId
            });

            return {
                success: true,
                timestamp: new Date(),
                requestId: encryption.generateUUID(),
                version: config.app.version
            };

        } catch (error) {
            logger.warn('Logout attempt with invalid token', { error: error as Error });

            // Still return success for logout
            return {
                success: true,
                timestamp: new Date(),
                requestId: encryption.generateUUID(),
                version: config.app.version
            };
        }
    }

    /**
     * Verify JWT token
     */
    verifyToken(token: string, type: 'access' | 'refresh' = 'access'): AuthTokenPayload {
        try {
            // Check if token is blacklisted
            if (this.isTokenBlacklisted(token)) {
                throw new AuthenticationError('Token has been revoked');
            }

            const decoded = jwt.verify(token, this.jwtSecret) as any;

            // Verify token type
            if (decoded.type !== type) {
                throw new AuthenticationError(`Invalid token type. Expected ${type}`);
            }

            // Verify required fields
            if (!decoded.userId || !decoded.email || !decoded.role) {
                throw new AuthenticationError('Invalid token payload');
            }

            return {
                userId: decoded.userId,
                email: decoded.email,
                role: decoded.role,
                permissions: decoded.permissions || [],
                iat: decoded.iat,
                exp: decoded.exp,
                iss: decoded.iss,
                aud: decoded.aud
            };

        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw new AuthenticationError('Invalid token');
            }

            if (error instanceof jwt.TokenExpiredError) {
                throw new AuthenticationError('Token expired');
            }

            throw error;
        }
    }

    /**
     * Check user permissions
     */
    hasPermission(user: AuthTokenPayload, permission: string): boolean {
        // Admin has all permissions
        if (user.role === 'admin') {
            return true;
        }

        return user.permissions.includes(permission);
    }

    /**
     * Check if user has required role
     */
    hasRole(user: AuthTokenPayload, requiredRole: UserRole): boolean {
        const roleHierarchy: Record<UserRole, number> = {
            readonly: 1,
            user: 2,
            admin: 3
        };

        return roleHierarchy[user.role] >= roleHierarchy[requiredRole];
    }

    /**
     * Get session information
     */
    getSession(sessionId: string): SessionInfo | null {
        return this.sessionCache.get<SessionInfo>(sessionId) || null;
    }

    /**
     * Update session last accessed time
     */
    updateSessionAccess(sessionId: string): void {
        const session = this.getSession(sessionId);
        if (session) {
            const updatedSession: SessionInfo = {
                ...session,
                lastAccessedAt: new Date()
            };
            this.sessionCache.set(sessionId, updatedSession);
        }
    }

    /**
     * Revoke all user sessions
     */
    revokeAllUserSessions(userId: string): void {
        const sessions = this.getAllSessions();
        const userSessions = sessions.filter(session => session.userId === userId);

        userSessions.forEach(session => {
            this.sessionCache.del(session.sessionId);
        });

        logger.info('All user sessions revoked', {
            userId,
            action: 'REVOKE_ALL_SESSIONS',
            metadata: { sessionCount: userSessions.length }
        });
    }

    /**
     * Get all active sessions
     */
    getAllSessions(): SessionInfo[] {
        const keys = this.sessionCache.keys();
        return keys.map(key => this.sessionCache.get<SessionInfo>(key))
            .filter(Boolean) as SessionInfo[];
    }

    /**
     * Clean up expired sessions and tokens
     */
    cleanup(): void {
        // Sessions are auto-cleaned by NodeCache TTL
        // Blacklist is auto-cleaned by NodeCache TTL
        // Rate limit cache is auto-cleaned by NodeCache TTL

        logger.debug('Auth service cleanup completed');
    }

    /**
     * Private helper methods
     */

    private async generateTokenPair(user: UserInfo, rememberMe?: boolean): Promise<TokenPair> {
        const now = Math.floor(Date.now() / 1000);
        const accessTokenExpiry = rememberMe ? '24h' : this.tokenExpiry;
        const refreshTokenExpiry = rememberMe ? '30d' : this.refreshTokenExpiry;

        const basePayload = {
            userId: user.id,
            email: user.email,
            role: user.role,
            permissions: user.permissions,
            iss: config.app.name,
            aud: config.app.name,
            iat: now
        };

        const accessToken = jwt.sign(
            { ...basePayload, type: 'access' },
            this.jwtSecret,
            { expiresIn: accessTokenExpiry }
        );

        const refreshToken = jwt.sign(
            { ...basePayload, type: 'refresh' },
            this.jwtSecret,
            { expiresIn: refreshTokenExpiry }
        );

        // Calculate expires in seconds
        const accessTokenDecoded = jwt.decode(accessToken) as any;
        const expiresIn = accessTokenDecoded.exp - now;

        return {
            accessToken,
            refreshToken,
            expiresIn,
            tokenType: 'Bearer'
        };
    }

    private async verifyFirebaseToken(token: string): Promise<FirebaseTokenResult> {
        try {
            const decodedToken = await admin.auth().verifyIdToken(token);

            return {
                uid: decodedToken.uid,
                email: decodedToken.email,
                emailVerified: decodedToken.email_verified || false,
                customClaims: decodedToken.customClaims
            };

        } catch (error) {
            throw new AuthenticationError('Invalid Firebase token');
        }
    }

    private async verifyUserCredentials(credentials: LoginCredentials): Promise<UserInfo | null> {
        // This is a simplified implementation
        // In a real app, you'd query your user database

        if (credentials.email === 'admin@example.com' && credentials.password === 'admin123') {
            return {
                id: '1',
                email: 'admin@example.com',
                role: 'admin',
                permissions: ['ssh:connect', 'ssh:execute', 'server:manage', 'user:manage'],
                createdAt: new Date(),
                isActive: true
            };
        }

        if (credentials.email === 'user@example.com' && credentials.password === 'user123') {
            return {
                id: '2',
                email: 'user@example.com',
                role: 'user',
                permissions: ['ssh:connect', 'ssh:execute'],
                createdAt: new Date(),
                isActive: true
            };
        }

        return null;
    }

    private async getUserByFirebaseUid(uid: string): Promise<UserInfo | null> {
        // This would query your user database by Firebase UID
        // For demo, return null to trigger user creation
        return null;
    }

    private async createUserFromFirebase(firebaseResult: FirebaseTokenResult): Promise<UserInfo> {
        // This would create a new user in your database
        // For demo, create a basic user
        return {
            id: encryption.generateUUID(),
            email: firebaseResult.email || 'unknown@firebase.com',
            role: 'user',
            permissions: ['ssh:connect', 'ssh:execute'],
            createdAt: new Date(),
            isActive: true,
            metadata: {
                firebaseUid: firebaseResult.uid,
                provider: 'firebase'
            }
        };
    }

    private async getUserById(userId: string): Promise<UserInfo | null> {
        // This would query your user database
        // For demo, return mock users
        if (userId === '1') {
            return {
                id: '1',
                email: 'admin@example.com',
                role: 'admin',
                permissions: ['ssh:connect', 'ssh:execute', 'server:manage', 'user:manage'],
                createdAt: new Date(),
                isActive: true
            };
        }

        if (userId === '2') {
            return {
                id: '2',
                email: 'user@example.com',
                role: 'user',
                permissions: ['ssh:connect', 'ssh:execute'],
                createdAt: new Date(),
                isActive: true
            };
        }

        return null;
    }

    private async updateLastLogin(userId: string): Promise<void> {
        // This would update the user's last login time in your database
        logger.debug('User last login updated', { userId });
    }

    private isValidEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    private checkRateLimit(email: string, ipAddress: string): void {
        const emailKey = `email:${email}`;
        const ipKey = `ip:${ipAddress}`;

        const emailAttempts = this.rateLimitCache.get<number>(emailKey) || 0;
        const ipAttempts = this.rateLimitCache.get<number>(ipKey) || 0;

        if (emailAttempts >= 5 || ipAttempts >= 10) {
            throw new AuthenticationError('Too many login attempts. Please try again later.');
        }
    }

    private recordFailedAttempt(email: string, ipAddress: string): void {
        const emailKey = `email:${email}`;
        const ipKey = `ip:${ipAddress}`;

        const emailAttempts = this.rateLimitCache.get<number>(emailKey) || 0;
        const ipAttempts = this.rateLimitCache.get<number>(ipKey) || 0;

        this.rateLimitCache.set(emailKey, emailAttempts + 1);
        this.rateLimitCache.set(ipKey, ipAttempts + 1);
    }

    private clearFailedAttempts(email: string, ipAddress: string): void {
        const emailKey = `email:${email}`;
        const ipKey = `ip:${ipAddress}`;

        this.rateLimitCache.del(emailKey);
        this.rateLimitCache.del(ipKey);
    }

    private blacklistToken(token: string): void {
        // Store token hash to save memory
        const tokenHash = encryption.generateHash(token, { algorithm: 'sha256' });
        this.blacklistCache.set(tokenHash, true);
    }

    private isTokenBlacklisted(token: string): boolean {
        const tokenHash = encryption.generateHash(token, { algorithm: 'sha256' });
        return this.blacklistCache.get<boolean>(tokenHash) === true;
    }
}

/**
 * Export singleton instance
 */
export const authService = AuthService.getInstance();

/**
 * Export types for external use
 */
export type {
    UserInfo,
    TokenPair,
    LoginCredentials,
    SessionInfo,
    FirebaseTokenResult
};