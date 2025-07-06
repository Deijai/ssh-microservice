/**
 * 🔐 Authentication Routes
 * Routes for user authentication and authorization
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { authController } from '@/controllers/AuthController';
import { authMiddleware } from '@/middleware/auth';
import { config } from '@/config/environment';

const router = Router();

// Rate limiting for auth endpoints
const authRateLimit = rateLimit({
    windowMs: config.rateLimit.windowMs, // 15 minutes
    max: 20, // Limit each IP to 20 requests per windowMs for auth
    message: {
        success: false,
        error: 'Too many authentication attempts. Please try again later.',
        retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many authentication attempts. Please try again later.',
            retryAfter: Math.ceil(config.rateLimit.windowMs / 1000),
            timestamp: new Date().toISOString()
        });
    }
});

// Strict rate limiting for login endpoints
const loginRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per windowMs
    message: {
        success: false,
        error: 'Too many login attempts. Please try again later.',
        retryAfter: 900 // 15 minutes in seconds
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many login attempts. Please try again later.',
            retryAfter: 900,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * Public authentication routes
 */

// POST /auth/login - User login with email/password
router.post('/login',
    loginRateLimit,
    authController.login
);

// POST /auth/login/firebase - User login with Firebase token
router.post('/login/firebase',
    loginRateLimit,
    authController.loginWithFirebase
);

// POST /auth/refresh - Refresh access token
router.post('/refresh',
    authRateLimit,
    authController.refreshToken
);

// POST /auth/logout - User logout
router.post('/logout',
    authMiddleware.optionalAuth, // Optional because token might be expired
    authController.logout
);

/**
 * Protected authentication routes
 */

// GET /auth/verify - Verify token validity
router.get('/verify',
    authMiddleware.requireAuth,
    authController.verifyToken
);

// GET /auth/profile - Get current user profile
router.get('/profile',
    authMiddleware.requireAuth,
    authController.getProfile
);

// GET /auth/permissions - Get user permissions
router.get('/permissions',
    authMiddleware.requireAuth,
    authController.getPermissions
);

// PUT /auth/password - Change password
router.put('/password',
    authMiddleware.requireAuth,
    authRateLimit,
    authController.changePassword
);

// GET /auth/permissions/:permission - Check specific permission
router.get('/permissions/:permission',
    authMiddleware.requireAuth,
    authController.checkPermission
);

/**
 * Admin only routes
 */

// GET /auth/sessions - Get all active sessions (admin only)
router.get('/sessions',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    authController.getSessions
);

// DELETE /auth/sessions/:userId - Revoke user sessions (admin only)
router.delete('/sessions/:userId',
    authMiddleware.requireAuth,
    authMiddleware.adminOnly,
    authController.revokeSessions
);

/**
 * Additional utility routes
 */

// GET /auth/me - Alias for profile endpoint
router.get('/me',
    authMiddleware.requireAuth,
    authController.getProfile
);

// POST /auth/validate - Validate credentials without logging in
router.post('/validate',
    authRateLimit,
    (req, res) => {
        // This could be used for password validation, etc.
        res.json({
            success: true,
            message: 'Validation endpoint',
            timestamp: new Date().toISOString()
        });
    }
);

// GET /auth/config - Get authentication configuration (public info only)
router.get('/config', (req, res) => {
    res.json({
        success: true,
        data: {
            providers: ['email', 'firebase'],
            passwordRequirements: {
                minLength: 6,
                requireUppercase: false,
                requireLowercase: false,
                requireNumbers: false,
                requireSpecialChars: false
            },
            sessionTimeout: '1h',
            refreshTokenTimeout: '7d',
            rateLimit: {
                login: '5 attempts per 15 minutes',
                general: '20 attempts per 15 minutes'
            }
        },
        timestamp: new Date().toISOString()
    });
});

export default router;