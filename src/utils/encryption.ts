/**
 * 🔐 Encryption Utility
 * AES-256-GCM encryption for sensitive data
 */

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { config } from '@/config/environment';
import { EncryptedSSHCredentials, SSHCredentials } from '@/models/SSHCredentials';

/**
 * Encryption result interface
 */
interface EncryptionResult {
    readonly encryptedData: string;
    readonly iv: string;
    readonly authTag: string;
}

/**
 * Decryption input interface
 */
interface DecryptionInput {
    readonly encryptedData: string;
    readonly iv: string;
    readonly authTag: string;
}

/**
 * Hash options interface
 */
interface HashOptions {
    readonly saltRounds?: number;
    readonly algorithm?: 'bcrypt' | 'sha256' | 'sha512';
    readonly encoding?: 'hex' | 'base64';
}

/**
 * Encryption utility class
 */
export class EncryptionUtil {
    private static readonly ALGORITHM = 'aes-256-gcm' as const;
    private static readonly IV_LENGTH = 16; // 128 bits
    private static readonly TAG_LENGTH = 16; // 128 bits
    private static readonly KEY_LENGTH = 32; // 256 bits

    private readonly encryptionKey: Buffer;

    constructor() {
        this.encryptionKey = this.deriveKey(config.security.encryptionKey);
    }

    /**
     * Derive encryption key from string
     */
    private deriveKey(keyString: string): Buffer {
        return crypto.scryptSync(keyString, 'salt', EncryptionUtil.KEY_LENGTH);
    }

    /**
     * Encrypt data using AES-256-GCM
     */
    encrypt(data: string): EncryptionResult {
        try {
            const iv = crypto.randomBytes(EncryptionUtil.IV_LENGTH);
            const cipher = crypto.createCipherGCM(EncryptionUtil.ALGORITHM, this.encryptionKey, iv);

            let encryptedData = cipher.update(data, 'utf8', 'base64');
            encryptedData += cipher.final('base64');

            const authTag = cipher.getAuthTag();

            return {
                encryptedData,
                iv: iv.toString('base64'),
                authTag: authTag.toString('base64')
            };
        } catch (error) {
            throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Decrypt data using AES-256-GCM
     */
    decrypt(input: DecryptionInput): string {
        try {
            const { encryptedData, iv, authTag } = input;

            const ivBuffer = Buffer.from(iv, 'base64');
            const authTagBuffer = Buffer.from(authTag, 'base64');

            const decipher = crypto.createDecipherGCM(EncryptionUtil.ALGORITHM, this.encryptionKey, ivBuffer);
            decipher.setAuthTag(authTagBuffer);

            let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
            decryptedData += decipher.final('utf8');

            return decryptedData;
        } catch (error) {
            throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Encrypt SSH credentials
     */
    encryptSSHCredentials(credentials: SSHCredentials): EncryptedSSHCredentials {
        try {
            // Extract sensitive data
            const sensitiveData = {
                password: credentials.password,
                privateKey: credentials.privateKey,
                passphrase: credentials.passphrase,
                port: credentials.port,
                timeout: credentials.timeout,
                keepaliveInterval: credentials.keepaliveInterval,
                debug: credentials.debug
            };

            // Remove undefined values
            const cleanData = Object.fromEntries(
                Object.entries(sensitiveData).filter(([, value]) => value !== undefined)
            );

            const dataToEncrypt = JSON.stringify(cleanData);
            const encrypted = this.encrypt(dataToEncrypt);

            return {
                encryptedData: encrypted.encryptedData,
                iv: encrypted.iv,
                authTag: encrypted.authTag,
                encryptedAt: new Date(),
                host: credentials.host,
                username: credentials.username
            };
        } catch (error) {
            throw new Error(`Failed to encrypt SSH credentials: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Decrypt SSH credentials
     */
    decryptSSHCredentials(encryptedCredentials: EncryptedSSHCredentials): SSHCredentials {
        try {
            const decrypted = this.decrypt({
                encryptedData: encryptedCredentials.encryptedData,
                iv: encryptedCredentials.iv,
                authTag: encryptedCredentials.authTag
            });

            const sensitiveData = JSON.parse(decrypted);

            return {
                host: encryptedCredentials.host,
                username: encryptedCredentials.username,
                port: sensitiveData.port || 22,
                ...sensitiveData
            };
        } catch (error) {
            throw new Error(`Failed to decrypt SSH credentials: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Hash password using bcrypt
     */
    async hashPassword(password: string, options: HashOptions = {}): Promise<string> {
        const { saltRounds = config.security.bcryptSaltRounds } = options;

        try {
            return await bcrypt.hash(password, saltRounds);
        } catch (error) {
            throw new Error(`Password hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Verify password against hash
     */
    async verifyPassword(password: string, hash: string): Promise<boolean> {
        try {
            return await bcrypt.compare(password, hash);
        } catch (error) {
            throw new Error(`Password verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Generate hash using specified algorithm
     */
    generateHash(data: string, options: HashOptions = {}): string {
        const { algorithm = 'sha256', encoding = 'hex' } = options;

        try {
            if (algorithm === 'bcrypt') {
                throw new Error('Use hashPassword method for bcrypt');
            }

            return crypto
                .createHash(algorithm)
                .update(data)
                .digest(encoding);
        } catch (error) {
            throw new Error(`Hash generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Generate cryptographically secure random bytes
     */
    generateRandomBytes(length: number, encoding: 'hex' | 'base64' = 'hex'): string {
        try {
            return crypto.randomBytes(length).toString(encoding);
        } catch (error) {
            throw new Error(`Random bytes generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Generate secure random string
     */
    generateRandomString(length: number): string {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';

        for (let i = 0; i < length; i++) {
            const randomIndex = crypto.randomInt(0, chars.length);
            result += chars[randomIndex];
        }

        return result;
    }

    /**
     * Generate UUID v4
     */
    generateUUID(): string {
        return crypto.randomUUID();
    }

    /**
     * Create HMAC signature
     */
    createHMAC(data: string, secret?: string, algorithm: string = 'sha256'): string {
        try {
            const key = secret || config.security.encryptionKey;
            return crypto
                .createHmac(algorithm, key)
                .update(data)
                .digest('hex');
        } catch (error) {
            throw new Error(`HMAC creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Verify HMAC signature
     */
    verifyHMAC(data: string, signature: string, secret?: string, algorithm: string = 'sha256'): boolean {
        try {
            const expectedSignature = this.createHMAC(data, secret, algorithm);
            return crypto.timingSafeEqual(
                Buffer.from(signature, 'hex'),
                Buffer.from(expectedSignature, 'hex')
            );
        } catch (error) {
            return false;
        }
    }

    /**
     * Constant time string comparison
     */
    constantTimeCompare(a: string, b: string): boolean {
        try {
            if (a.length !== b.length) {
                return false;
            }

            return crypto.timingSafeEqual(
                Buffer.from(a, 'utf8'),
                Buffer.from(b, 'utf8')
            );
        } catch (error) {
            return false;
        }
    }

    /**
     * Mask sensitive data for logging
     */
    maskSensitiveData(data: string, visibleChars: number = 4): string {
        if (data.length <= visibleChars * 2) {
            return '*'.repeat(data.length);
        }

        const start = data.substring(0, visibleChars);
        const end = data.substring(data.length - visibleChars);
        const middle = '*'.repeat(data.length - visibleChars * 2);

        return `${start}${middle}${end}`;
    }

    /**
     * Sanitize string for safe logging
     */
    sanitizeForLogging(value: unknown): string {
        if (typeof value !== 'string') {
            return String(value);
        }

        // Remove potential log injection patterns
        return value
            .replace(/[\r\n\t]/g, ' ')
            .replace(/\x00/g, '')
            .substring(0, 1000); // Limit length
    }

    /**
     * Check if encryption is working correctly
     */
    async testEncryption(): Promise<boolean> {
        try {
            const testData = 'test-encryption-' + Date.now();
            const encrypted = this.encrypt(testData);
            const decrypted = this.decrypt(encrypted);

            return testData === decrypted;
        } catch (error) {
            return false;
        }
    }
}

/**
 * Singleton instance
 */
let encryptionInstance: EncryptionUtil | null = null;

/**
 * Get encryption utility instance
 */
export function getEncryptionUtil(): EncryptionUtil {
    if (!encryptionInstance) {
        encryptionInstance = new EncryptionUtil();
    }
    return encryptionInstance;
}

/**
 * Convenience functions
 */
export const encryption = {
    encrypt: (data: string) => getEncryptionUtil().encrypt(data),
    decrypt: (input: DecryptionInput) => getEncryptionUtil().decrypt(input),
    encryptSSHCredentials: (credentials: SSHCredentials) => 
        getEncryptionUtil().encryptSSHCredentials(credentials),
    decryptSSHCredentials: (encryptedCredentials: EncryptedSSHCredentials) => 
        getEncryptionUtil().decryptSSHCredentials(encryptedCredentials),
    hashPassword: (password: string, options?: HashOptions) => 
        getEncryptionUtil().hashPassword(password, options),
    verifyPassword: (password: string, hash: string) => 
        getEncryptionUtil().verifyPassword(password, hash),
    generateHash: (data: string, options?: HashOptions) => 
        getEncryptionUtil().generateHash(data, options),
    generateRandomBytes: (length: number, encoding?: 'hex' | 'base64') => 
        getEncryptionUtil().generateRandomBytes(length, encoding),
    generateRandomString: (length: number) => 
        getEncryptionUtil().generateRandomString(length),
    generateUUID: () => getEncryptionUtil().generateUUID(),
    createHMAC: (data: string, secret?: string, algorithm?: string) => 
        getEncryptionUtil().createHMAC(data, secret, algorithm),
    verifyHMAC: (data: string, signature: string, secret?: string, algorithm?: string) => 
        getEncryptionUtil().verifyHMAC(data, signature, secret, algorithm),
    constantTimeCompare: (a: string, b: string) => 
        getEncryptionUtil().constantTimeCompare(a, b),
    maskSensitiveData: (data: string, visibleChars?: number) => 
        getEncryptionUtil().maskSensitiveData(data, visibleChars),
    sanitizeForLogging: (value: unknown) => 
        getEncryptionUtil().sanitizeForLogging(value),
    testEncryption: () => getEncryptionUtil().testEncryption()
};

// Export types
export type { EncryptionResult, DecryptionInput, HashOptions };