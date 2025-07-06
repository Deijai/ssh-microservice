/**
 * 🌍 Environment Configuration
 * Centralized configuration management with validation
 */

import dotenv from 'dotenv';
import { Environment, LogLevel } from '@/types/common';

// Load environment variables
dotenv.config();

/**
 * Application configuration interface
 */
interface Config {
    readonly app: {
        readonly name: string;
        readonly version: string;
        readonly environment: Environment;
        readonly port: number;
        readonly host: string;
        readonly baseUrl: string;
    };

    readonly security: {
        readonly jwtSecret: string;
        readonly encryptionKey: string;
        readonly apiKey: string;
        readonly bcryptSaltRounds: number;
        readonly corsOrigins: readonly string[];
    };

    readonly ssh: {
        readonly connectionTimeout: number;
        readonly commandTimeout: number;
        readonly keepaliveInterval: number;
        readonly maxConcurrentConnections: number;
        readonly debugLevel: number;
    };

    readonly rateLimit: {
        readonly windowMs: number;
        readonly maxRequests: number;
        readonly skipSuccessfulRequests: boolean;
        readonly standardHeaders: boolean;
        readonly legacyHeaders: boolean;
    };

    readonly logging: {
        readonly level: LogLevel;
        readonly file: string;
        readonly maxSize: string;
        readonly maxFiles: number;
        readonly enableRequestLogging: boolean;
    };

    readonly cache: {
        readonly ttl: number;
        readonly checkPeriod: number;
        readonly maxKeys: number;
    };

    readonly monitoring: {
        readonly healthCheckInterval: number;
        readonly enableMetrics: boolean;
        readonly metricsPort: number;
    };

    readonly firebase: {
        readonly projectId: string;
        readonly privateKeyId: string;
        readonly privateKey: string;
        readonly clientEmail: string;
        readonly clientId: string;
        readonly authUri: string;
        readonly tokenUri: string;
        readonly authProviderX509CertUrl: string;
        readonly clientX509CertUrl: string;
    };
}

/**
 * Validate required environment variables
 */
function validateEnvironment(): void {
    const required = [
        'JWT_SECRET',
        'ENCRYPTION_KEY',
        'API_KEY',
        'FIREBASE_PROJECT_ID',
        'FIREBASE_PRIVATE_KEY',
        'FIREBASE_CLIENT_EMAIL'
    ];

    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }

    // Validate JWT secret length
    if (process.env.JWT_SECRET!.length < 32) {
        throw new Error('JWT_SECRET must be at least 32 characters long');
    }

    // Validate encryption key length
    if (process.env.ENCRYPTION_KEY!.length !== 32) {
        throw new Error('ENCRYPTION_KEY must be exactly 32 characters long');
    }
}

/**
 * Parse boolean environment variable
 */
function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
    if (!value) return defaultValue;
    return value.toLowerCase() === 'true';
}

/**
 * Parse integer environment variable
 */
function parseInt(value: string | undefined, defaultValue: number): number {
    if (!value) return defaultValue;
    const parsed = Number.parseInt(value, 10);
    return Number.isNaN(parsed) ? defaultValue : parsed;
}

/**
 * Parse array environment variable
 */
function parseArray(value: string | undefined, defaultValue: readonly string[]): readonly string[] {
    if (!value) return defaultValue;
    return value.split(',').map(item => item.trim()).filter(Boolean);
}

/**
 * Parse log level
 */
function parseLogLevel(value: string | undefined): LogLevel {
    const validLevels: readonly LogLevel[] = ['error', 'warn', 'info', 'debug', 'verbose'];
    const level = (value?.toLowerCase() as LogLevel) || 'info';
    return validLevels.includes(level) ? level : 'info';
}

/**
 * Parse environment type
 */
function parseEnvironment(value: string | undefined): Environment {
    const validEnvs: readonly Environment[] = ['development', 'staging', 'production', 'test'];
    const env = (value?.toLowerCase() as Environment) || 'development';
    return validEnvs.includes(env) ? env : 'development';
}

/**
 * Get package.json information
 */
function getPackageInfo(): { name: string; version: string } {
    try {
        const pkg = require('../../package.json');
        return {
            name: pkg.name || 'ssh-microservice',
            version: pkg.version || '1.0.0'
        };
    } catch {
        return {
            name: 'ssh-microservice',
            version: '1.0.0'
        };
    }
}

// Validate environment on module load
validateEnvironment();

const packageInfo = getPackageInfo();

/**
 * Application configuration
 */
export const config: Config = {
    app: {
        name: packageInfo.name,
        version: packageInfo.version,
        environment: parseEnvironment(process.env.NODE_ENV),
        port: parseInt(process.env.PORT, 3000),
        host: process.env.HOST || '0.0.0.0',
        baseUrl: process.env.BASE_URL || `http://localhost:${parseInt(process.env.PORT, 3000)}`
    },

    security: {
        jwtSecret: process.env.JWT_SECRET!,
        encryptionKey: process.env.ENCRYPTION_KEY!,
        apiKey: process.env.API_KEY!,
        bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 12),
        corsOrigins: parseArray(process.env.ALLOWED_ORIGINS, [
            'http://localhost:8081',
            'exp://192.168.1.100:8081'
        ])
    },

    ssh: {
        connectionTimeout: parseInt(process.env.SSH_CONNECTION_TIMEOUT, 10000),
        commandTimeout: parseInt(process.env.SSH_COMMAND_TIMEOUT, 30000),
        keepaliveInterval: parseInt(process.env.SSH_KEEPALIVE_INTERVAL, 1000),
        maxConcurrentConnections: parseInt(process.env.MAX_CONCURRENT_CONNECTIONS, 10),
        debugLevel: parseInt(process.env.SSH_DEBUG_LEVEL, 0)
    },

    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 900000), // 15 minutes
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 100),
        skipSuccessfulRequests: parseBoolean(process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS, false),
        standardHeaders: true,
        legacyHeaders: false
    },

    logging: {
        level: parseLogLevel(process.env.LOG_LEVEL),
        file: process.env.LOG_FILE || 'logs/ssh-microservice.log',
        maxSize: process.env.LOG_MAX_SIZE || '10m',
        maxFiles: parseInt(process.env.LOG_MAX_FILES, 5),
        enableRequestLogging: parseBoolean(process.env.ENABLE_REQUEST_LOGGING, true)
    },

    cache: {
        ttl: parseInt(process.env.CACHE_TTL, 300), // 5 minutes
        checkPeriod: parseInt(process.env.CACHE_CHECK_PERIOD, 600), // 10 minutes
        maxKeys: parseInt(process.env.MAX_CACHE_KEYS, 1000)
    },

    monitoring: {
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL, 30000), // 30 seconds
        enableMetrics: parseBoolean(process.env.ENABLE_METRICS, true),
        metricsPort: parseInt(process.env.METRICS_PORT, 9090)
    },

    firebase: {
        projectId: process.env.FIREBASE_PROJECT_ID!,
        privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID!,
        privateKey: process.env.FIREBASE_PRIVATE_KEY!.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL!,
        clientId: process.env.FIREBASE_CLIENT_ID!,
        authUri: process.env.FIREBASE_AUTH_URI || 'https://accounts.google.com/o/oauth2/auth',
        tokenUri: process.env.FIREBASE_TOKEN_URI || 'https://oauth2.googleapis.com/token',
        authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL ||
            'https://www.googleapis.com/oauth2/v1/certs',
        clientX509CertUrl: process.env.FIREBASE_CLIENT_X509_CERT_URL ||
            `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL!)}`
    }
} as const;

/**
 * Determine if running in production
 */
export const isProduction = config.app.environment === 'production';

/**
 * Determine if running in development
 */
export const isDevelopment = config.app.environment === 'development';

/**
 * Determine if running in test
 */
export const isTest = config.app.environment === 'test';

/**
 * Get configuration for specific environment
 */
export function getConfig(): Config {
    return config;
}

/**
 * Validate configuration
 */
export function validateConfig(): void {
    const errors: string[] = [];

    // Validate port range
    if (config.app.port < 1 || config.app.port > 65535) {
        errors.push('Port must be between 1 and 65535');
    }

    // Validate timeouts
    if (config.ssh.connectionTimeout < 1000) {
        errors.push('SSH connection timeout must be at least 1000ms');
    }

    if (config.ssh.commandTimeout < 1000) {
        errors.push('SSH command timeout must be at least 1000ms');
    }

    // Validate rate limiting
    if (config.rateLimit.windowMs < 1000) {
        errors.push('Rate limit window must be at least 1000ms');
    }

    if (config.rateLimit.maxRequests < 1) {
        errors.push('Rate limit max requests must be at least 1');
    }

    // Validate cache settings
    if (config.cache.ttl < 0) {
        errors.push('Cache TTL must be non-negative');
    }

    if (config.cache.maxKeys < 1) {
        errors.push('Cache max keys must be at least 1');
    }

    if (errors.length > 0) {
        throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
    }
}

/**
 * Log configuration (without sensitive data)
 */
export function logConfig(): void {
    const safeConfig = {
        app: config.app,
        ssh: {
            ...config.ssh,
            // Don't log sensitive timeout values in production
            connectionTimeout: isProduction ? '[HIDDEN]' : config.ssh.connectionTimeout,
            commandTimeout: isProduction ? '[HIDDEN]' : config.ssh.commandTimeout
        },
        rateLimit: config.rateLimit,
        logging: config.logging,
        cache: config.cache,
        monitoring: config.monitoring,
        security: {
            bcryptSaltRounds: config.security.bcryptSaltRounds,
            corsOrigins: config.security.corsOrigins,
            // Hide sensitive keys
            jwtSecret: '[HIDDEN]',
            encryptionKey: '[HIDDEN]',
            apiKey: '[HIDDEN]'
        },
        firebase: {
            projectId: config.firebase.projectId,
            clientEmail: config.firebase.clientEmail,
            // Hide sensitive keys
            privateKey: '[HIDDEN]',
            privateKeyId: '[HIDDEN]',
            clientId: '[HIDDEN]'
        }
    };

    console.log('📋 Application Configuration:');
    console.log(JSON.stringify(safeConfig, null, 2));
}

// Validate configuration on module load
validateConfig();