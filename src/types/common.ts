/**
 * 🔧 Common Types
 * Shared type definitions used across the application
 */

/**
 * Generic API Response wrapper
 */
export interface ApiResponse<T = unknown> {
    /** Whether the request was successful */
    readonly success: boolean;

    /** Response data */
    readonly data?: T;

    /** Error message if request failed */
    readonly error?: string;

    /** Additional error details */
    readonly details?: unknown;

    /** Response timestamp */
    readonly timestamp: Date;

    /** Request ID for tracking */
    readonly requestId: string;

    /** API version */
    readonly version: string;

    /** Response metadata */
    readonly meta?: {
        readonly page?: number;
        readonly limit?: number;
        readonly total?: number;
        readonly hasNext?: boolean;
        readonly hasPrev?: boolean;
    };
}

/**
 * Error response structure
 */
export interface ErrorResponse {
    readonly error: string;
    readonly code: string;
    readonly details?: unknown;
    readonly timestamp: Date;
    readonly requestId: string;
    readonly path: string;
    readonly method: string;
    readonly stack?: string; // Only in development
}

/**
 * Pagination parameters
 */
export interface PaginationParams {
    readonly page: number;
    readonly limit: number;
    readonly sortBy?: string;
    readonly sortOrder?: 'asc' | 'desc';
    readonly filter?: Record<string, unknown>;
}

/**
 * Authentication token payload
 */
export interface AuthTokenPayload {
    readonly userId: string;
    readonly email: string;
    readonly role: UserRole;
    readonly permissions: readonly string[];
    readonly iat: number;
    readonly exp: number;
    readonly iss: string;
    readonly aud: string;
}

/**
 * User role enumeration
 */
export type UserRole = 'admin' | 'user' | 'readonly';

/**
 * Environment enumeration
 */
export type Environment = 'development' | 'staging' | 'production' | 'test';

/**
 * Log level enumeration
 */
export type LogLevel = 'error' | 'warn' | 'info' | 'debug' | 'verbose';

/**
 * HTTP methods
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * Request context information
 */
export interface RequestContext {
    readonly requestId: string;
    readonly userId?: string;
    readonly userRole?: UserRole;
    readonly ip: string;
    readonly userAgent: string;
    readonly method: HttpMethod;
    readonly path: string;
    readonly timestamp: Date;
    readonly duration?: number;
}

/**
 * Rate limiting information
 */
export interface RateLimitInfo {
    readonly limit: number;
    readonly remaining: number;
    readonly resetTime: Date;
    readonly retryAfter?: number;
}

/**
 * Health check status
 */
export interface HealthStatus {
    readonly status: 'healthy' | 'degraded' | 'unhealthy';
    readonly timestamp: Date;
    readonly uptime: number;
    readonly version: string;
    readonly environment: Environment;
    readonly checks: readonly HealthCheck[];
    readonly metrics?: {
        readonly memory: {
            readonly used: number;
            readonly total: number;
            readonly usage: number;
        };
        readonly cpu: {
            readonly usage: number;
        };
        readonly eventLoop: {
            readonly delay: number;
        };
    };
}

/**
 * Individual health check
 */
export interface HealthCheck {
    readonly name: string;
    readonly status: 'pass' | 'fail' | 'warn';
    readonly duration: number;
    readonly message?: string;
    readonly details?: unknown;
}

/**
 * Cache entry
 */
export interface CacheEntry<T = unknown> {
    readonly key: string;
    readonly value: T;
    readonly ttl: number;
    readonly createdAt: Date;
    readonly accessedAt: Date;
    readonly hitCount: number;
}

/**
 * Cache statistics
 */
export interface CacheStats {
    readonly hits: number;
    readonly misses: number;
    readonly keys: number;
    readonly ksize: number;
    readonly vsize: number;
    readonly hitRate: number;
}

/**
 * Validation error
 */
export interface ValidationError {
    readonly field: string;
    readonly message: string;
    readonly code: string;
    readonly value?: unknown;
}

/**
 * Validation result
 */
export interface ValidationResult {
    readonly isValid: boolean;
    readonly errors: readonly ValidationError[];
}

/**
 * Database connection information
 */
export interface DatabaseInfo {
    readonly type: 'firebase' | 'mongodb' | 'postgresql' | 'mysql';
    readonly status: 'connected' | 'disconnected' | 'error';
    readonly host?: string;
    readonly database?: string;
    readonly version?: string;
    readonly connectionCount?: number;
    readonly lastConnected?: Date;
}

/**
 * Metrics data point
 */
export interface MetricDataPoint {
    readonly timestamp: Date;
    readonly value: number;
    readonly tags?: Record<string, string>;
}

/**
 * Time series metric
 */
export interface TimeSeries {
    readonly name: string;
    readonly points: readonly MetricDataPoint[];
    readonly aggregation: 'sum' | 'avg' | 'min' | 'max' | 'count';
    readonly interval: string;
}

/**
 * Application metrics
 */
export interface AppMetrics {
    readonly requestCount: number;
    readonly errorCount: number;
    readonly responseTime: {
        readonly p50: number;
        readonly p95: number;
        readonly p99: number;
        readonly avg: number;
    };
    readonly activeConnections: number;
    readonly memoryUsage: number;
    readonly cpuUsage: number;
    readonly uptime: number;
}

/**
 * Service configuration
 */
export interface ServiceConfig {
    readonly name: string;
    readonly version: string;
    readonly environment: Environment;
    readonly port: number;
    readonly host: string;
    readonly logLevel: LogLevel;
    readonly timeout: number;
    readonly retries: number;
    readonly rateLimit: {
        readonly windowMs: number;
        readonly maxRequests: number;
    };
}

/**
 * Utility type for making properties optional
 */
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

/**
 * Utility type for making properties required
 */
export type Required<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>;

/**
 * Utility type for readonly arrays
 */
export type ReadonlyArray<T> = readonly T[];

/**
 * Utility type for readonly records
 */
export type ReadonlyRecord<K extends string | number | symbol, T> = {
    readonly [P in K]: T;
};

/**
 * Promise-based function type
 */
export type AsyncFunction<TArgs extends readonly unknown[] = readonly unknown[], TReturn = unknown> =
    (...args: TArgs) => Promise<TReturn>;

/**
 * Event handler function type
 */
export type EventHandler<TEvent = unknown> = (event: TEvent) => void | Promise<void>;

/**
 * Constructor type
 */
export type Constructor<T = {}> = new (...args: readonly unknown[]) => T;

/**
 * Deep partial type
 */
export type DeepPartial<T> = {
    [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

/**
 * Deep readonly type
 */
export type DeepReadonly<T> = {
    readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

/**
 * Extract promise type
 */
export type PromiseType<T> = T extends Promise<infer U> ? U : never;

/**
 * Function parameters type
 */
export type Parameters<T extends (...args: any) => any> = T extends (...args: infer P) => any ? P : never;

/**
 * Function return type
 */
export type ReturnType<T extends (...args: any) => any> = T extends (...args: any) => infer R ? R : any;