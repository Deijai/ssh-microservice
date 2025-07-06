/**
 * ✅ Validator Utility
 * Comprehensive validation using Joi with custom rules
 */

import Joi from 'joi';
import { SSHCredentials } from '@/models/SSHCredentials';
import { CommandOptions, DANGEROUS_COMMAND_PATTERNS } from '@/models/CommandResult';
import { ValidationResult, ValidationError } from '@/types/common';

/**
 * SSH Credentials validation schema
 */
const sshCredentialsSchema = Joi.object<SSHCredentials>({
    host: Joi.string()
        .hostname()
        .required()
        .messages({
            'string.hostname': 'Host must be a valid hostname or IP address',
            'any.required': 'Host is required'
        }),

    port: Joi.number()
        .integer()
        .min(1)
        .max(65535)
        .default(22)
        .messages({
            'number.base': 'Port must be a number',
            'number.integer': 'Port must be an integer',
            'number.min': 'Port must be between 1 and 65535',
            'number.max': 'Port must be between 1 and 65535'
        }),

    username: Joi.string()
        .alphanum()
        .min(1)
        .max(32)
        .required()
        .messages({
            'string.alphanum': 'Username can only contain alphanumeric characters',
            'string.min': 'Username must be at least 1 character',
            'string.max': 'Username cannot exceed 32 characters',
            'any.required': 'Username is required'
        }),

    password: Joi.string()
        .min(1)
        .max(128)
        .when('privateKey', {
            is: Joi.exist(),
            then: Joi.optional(),
            otherwise: Joi.required()
        })
        .messages({
            'string.min': 'Password must be at least 1 character',
            'string.max': 'Password cannot exceed 128 characters',
            'any.required': 'Password is required when private key is not provided'
        }),

    privateKey: Joi.string()
        .min(200)
        .max(8192)
        .pattern(/^-----BEGIN .* PRIVATE KEY-----[\s\S]*-----END .* PRIVATE KEY-----$/)
        .optional()
        .messages({
            'string.min': 'Private key seems too short',
            'string.max': 'Private key is too long',
            'string.pattern.base': 'Invalid private key format'
        }),

    passphrase: Joi.string()
        .min(1)
        .max(128)
        .when('privateKey', {
            is: Joi.exist(),
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
        .messages({
            'string.min': 'Passphrase must be at least 1 character',
            'string.max': 'Passphrase cannot exceed 128 characters',
            'any.unknown': 'Passphrase should only be provided with private key'
        }),

    timeout: Joi.number()
        .integer()
        .min(1000)
        .max(300000)
        .default(10000)
        .messages({
            'number.base': 'Timeout must be a number',
            'number.integer': 'Timeout must be an integer',
            'number.min': 'Timeout must be at least 1000ms',
            'number.max': 'Timeout cannot exceed 300000ms (5 minutes)'
        }),

    keepaliveInterval: Joi.number()
        .integer()
        .min(1000)
        .max(60000)
        .default(30000)
        .messages({
            'number.base': 'Keep-alive interval must be a number',
            'number.integer': 'Keep-alive interval must be an integer',
            'number.min': 'Keep-alive interval must be at least 1000ms',
            'number.max': 'Keep-alive interval cannot exceed 60000ms'
        }),

    debug: Joi.boolean()
        .default(false)
}).xor('password', 'privateKey')
    .messages({
        'object.xor': 'Either password or private key must be provided, but not both'
    });

/**
 * Command options validation schema
 */
const commandOptionsSchema = Joi.object<CommandOptions>({
    workingDirectory: Joi.string()
        .pattern(/^\/[^<>:"|?*]*$/)
        .max(1024)
        .optional()
        .messages({
            'string.pattern.base': 'Working directory must be a valid Unix path',
            'string.max': 'Working directory path too long'
        }),

    environment: Joi.object()
        .pattern(
            /^[A-Z_][A-Z0-9_]*$/,
            Joi.string().max(1024)
        )
        .max(50)
        .optional()
        .messages({
            'object.pattern.match': 'Environment variable names must be uppercase with underscores',
            'string.max': 'Environment variable value too long',
            'object.max': 'Too many environment variables'
        }),

    timeout: Joi.number()
        .integer()
        .min(1000)
        .max(600000)
        .default(30000)
        .messages({
            'number.min': 'Command timeout must be at least 1000ms',
            'number.max': 'Command timeout cannot exceed 600000ms (10 minutes)'
        }),

    streaming: Joi.boolean().default(false),

    maxOutputSize: Joi.number()
        .integer()
        .min(1024)
        .max(10 * 1024 * 1024)
        .default(1024 * 1024)
        .messages({
            'number.min': 'Max output size must be at least 1024 bytes',
            'number.max': 'Max output size cannot exceed 10MB'
        }),

    sudo: Joi.boolean().default(false),

    shell: Joi.string()
        .valid('/bin/bash', '/bin/sh', '/usr/bin/zsh', '/bin/dash')
        .default('/bin/bash')
        .messages({
            'any.only': 'Shell must be one of: /bin/bash, /bin/sh, /usr/bin/zsh, /bin/dash'
        }),

    pty: Joi.boolean().default(false)
});

/**
 * Command validation schema
 */
const commandSchema = Joi.string()
    .min(1)
    .max(4096)
    .pattern(/^[^<>"|&;`$(){}[\]\\]*$/)
    .required()
    .messages({
        'string.min': 'Command cannot be empty',
        'string.max': 'Command too long (max 4096 characters)',
        'string.pattern.base': 'Command contains potentially dangerous characters',
        'any.required': 'Command is required'
    });

/**
 * Pagination validation schema
 */
const paginationSchema = Joi.object({
    page: Joi.number()
        .integer()
        .min(1)
        .default(1)
        .messages({
            'number.min': 'Page must be at least 1'
        }),

    limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(20)
        .messages({
            'number.min': 'Limit must be at least 1',
            'number.max': 'Limit cannot exceed 100'
        }),

    sortBy: Joi.string()
        .alphanum()
        .max(50)
        .optional()
        .messages({
            'string.alphanum': 'Sort field can only contain alphanumeric characters',
            'string.max': 'Sort field name too long'
        }),

    sortOrder: Joi.string()
        .valid('asc', 'desc')
        .default('asc')
        .messages({
            'any.only': 'Sort order must be either "asc" or "desc"'
        })
});

/**
 * Custom Joi extensions
 */
const customJoi = Joi.extend({
    type: 'ip',
    base: Joi.string(),
    messages: {
        'ip.base': '{{#label}} must be a valid IP address'
    },
    validate(value, helpers) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;

        if (!ipv4Regex.test(value) && !ipv6Regex.test(value)) {
            return { value, errors: helpers.error('ip.base') };
        }

        return { value };
    }
});

/**
 * Validator utility class
 */
export class ValidatorUtil {
    /**
     * Validate SSH credentials
     */
    static validateSSHCredentials(credentials: unknown): ValidationResult {
        return this.validate(credentials, sshCredentialsSchema);
    }

    /**
     * Validate command options
     */
    static validateCommandOptions(options: unknown): ValidationResult {
        return this.validate(options, commandOptionsSchema);
    }

    /**
     * Validate command string
     */
    static validateCommand(command: unknown): ValidationResult {
        const basicValidation = this.validate(command, commandSchema);

        if (!basicValidation.isValid) {
            return basicValidation;
        }

        // Additional security checks
        const commandStr = command as string;
        const securityErrors = this.checkCommandSecurity(commandStr);

        if (securityErrors.length > 0) {
            return {
                isValid: false,
                errors: [...basicValidation.errors, ...securityErrors]
            };
        }

        return basicValidation;
    }

    /**
     * Validate pagination parameters
     */
    static validatePagination(params: unknown): ValidationResult {
        return this.validate(params, paginationSchema);
    }

    /**
     * Check command security
     */
    private static checkCommandSecurity(command: string): ValidationError[] {
        const errors: ValidationError[] = [];

        // Check against dangerous patterns
        for (const pattern of DANGEROUS_COMMAND_PATTERNS) {
            if (pattern.test(command)) {
                errors.push({
                    field: 'command',
                    message: 'Command contains potentially dangerous operations',
                    code: 'DANGEROUS_COMMAND',
                    value: command
                });
                break;
            }
        }

        // Check for command injection patterns
        const injectionPatterns = [
            /[;&|`$(){}[\]\\]/,
            /\|\s*\w+/,
            /&&\s*\w+/,
            /;\s*\w+/,
            /`[^`]*`/,
            /\$\([^)]*\)/,
            /\$\{[^}]*\}/
        ];

        for (const pattern of injectionPatterns) {
            if (pattern.test(command)) {
                errors.push({
                    field: 'command',
                    message: 'Command contains potential injection patterns',
                    code: 'INJECTION_RISK',
                    value: command
                });
                break;
            }
        }

        // Check command length and complexity
        if (command.length > 1000) {
            errors.push({
                field: 'command',
                message: 'Command is unusually long and may be suspicious',
                code: 'SUSPICIOUS_LENGTH',
                value: command.length
            });
        }

        return errors;
    }

    /**
     * Generic validation helper
     */
    private static validate(data: unknown, schema: Joi.Schema): ValidationResult {
        const { error, value } = schema.validate(data, {
            abortEarly: false,
            allowUnknown: false,
            stripUnknown: true
        });

        if (!error) {
            return { isValid: true, errors: [] };
        }

        const errors: ValidationError[] = error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            code: detail.type,
            value: detail.context?.value
        }));

        return { isValid: false, errors };
    }

    /**
     * Validate email address
     */
    static validateEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && email.length <= 254;
    }

    /**
     * Validate hostname
     */
    static validateHostname(hostname: string): boolean {
        if (hostname.length > 255) return false;

        const hostnameRegex = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*[A-Za-z0-9-]{1,63}(?<!-)$/;
        return hostnameRegex.test(hostname);
    }

    /**
     * Validate IP address
     */
    static validateIP(ip: string): boolean {
        const result = customJoi.ip().validate(ip);
        return !result.error;
    }

    /**
     * Validate port number
     */
    static validatePort(port: number): boolean {
        return Number.isInteger(port) && port >= 1 && port <= 65535;
    }

    /**
     * Validate UUID
     */
    static validateUUID(uuid: string): boolean {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
    }

    /**
     * Validate JWT token format
     */
    static validateJWTFormat(token: string): boolean {
        const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
        return jwtRegex.test(token);
    }

    /**
     * Sanitize string input
     */
    static sanitizeString(input: string, maxLength: number = 1000): string {
        return input
            .trim()
            .replace(/[\x00-\x1f\x7f-\x9f]/g, '') // Remove control characters
            .substring(0, maxLength);
    }

    /**
     * Validate file path
     */
    static validateFilePath(path: string): boolean {
        // Unix path validation
        if (!/^\/[^<>:"|?*]*$/.test(path)) return false;

        // Check for directory traversal
        if (path.includes('..')) return false;

        // Check for null bytes
        if (path.includes('\0')) return false;

        return path.length <= 4096;
    }

    /**
     * Validate environment variable name
     */
    static validateEnvVarName(name: string): boolean {
        return /^[A-Z_][A-Z0-9_]*$/.test(name) && name.length <= 64;
    }

    /**
     * Check password strength
     */
    static checkPasswordStrength(password: string): {
        score: number;
        feedback: string[];
    } {
        const feedback: string[] = [];
        let score = 0;

        if (password.length >= 8) score += 1;
        else feedback.push('Password should be at least 8 characters long');

        if (password.length >= 12) score += 1;

        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Password should contain lowercase letters');

        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Password should contain uppercase letters');

        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Password should contain numbers');

        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        else feedback.push('Password should contain special characters');

        if (!/(.)\1{2,}/.test(password)) score += 1;
        else feedback.push('Password should not contain repeated characters');

        return { score, feedback };
    }

    /**
     * Validate rate limit configuration
     */
    static validateRateLimit(windowMs: number, maxRequests: number): ValidationResult {
        const errors: ValidationError[] = [];

        if (!Number.isInteger(windowMs) || windowMs < 1000) {
            errors.push({
                field: 'windowMs',
                message: 'Window must be at least 1000ms',
                code: 'INVALID_WINDOW',
                value: windowMs
            });
        }

        if (!Number.isInteger(maxRequests) || maxRequests < 1) {
            errors.push({
                field: 'maxRequests',
                message: 'Max requests must be at least 1',
                code: 'INVALID_MAX_REQUESTS',
                value: maxRequests
            });
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }
}

/**
 * Convenience validation functions
 */
export const validator = {
    sshCredentials: ValidatorUtil.validateSSHCredentials,
    commandOptions: ValidatorUtil.validateCommandOptions,
    command: ValidatorUtil.validateCommand,
    pagination: ValidatorUtil.validatePagination,
    email: ValidatorUtil.validateEmail,
    hostname: ValidatorUtil.validateHostname,
    ip: ValidatorUtil.validateIP,
    port: ValidatorUtil.validatePort,
    uuid: ValidatorUtil.validateUUID,
    jwtFormat: ValidatorUtil.validateJWTFormat,
    sanitizeString: ValidatorUtil.sanitizeString,
    filePath: ValidatorUtil.validateFilePath,
    envVarName: ValidatorUtil.validateEnvVarName,
    passwordStrength: ValidatorUtil.checkPasswordStrength,
    rateLimit: ValidatorUtil.validateRateLimit
};

// Export schemas for reuse
export {
    sshCredentialsSchema,
    commandOptionsSchema,
    commandSchema,
    paginationSchema
};