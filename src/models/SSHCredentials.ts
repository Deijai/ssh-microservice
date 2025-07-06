/**
 * 🔐 SSH Credentials Model
 * Defines the structure for SSH connection credentials
 */

export interface SSHCredentials {
    /** Server hostname or IP address */
    readonly host: string;

    /** SSH port (default: 22) */
    readonly port: number;

    /** Username for SSH authentication */
    readonly username: string;

    /** Password for password-based authentication (optional) */
    readonly password?: string;

    /** Private key for key-based authentication (optional) */
    readonly privateKey?: string;

    /** Passphrase for encrypted private keys (optional) */
    readonly passphrase?: string;

    /** Connection timeout in milliseconds (optional) */
    readonly timeout?: number;

    /** Keep-alive interval in milliseconds (optional) */
    readonly keepaliveInterval?: number;

    /** SSH protocol debug level (optional) */
    readonly debug?: boolean;
}

/**
 * SSH Connection Options for advanced configuration
 */
export interface SSHConnectionOptions {
    /** Maximum connection attempts */
    readonly maxRetries: number;

    /** Delay between retry attempts (ms) */
    readonly retryDelay: number;

    /** Enable keep-alive packets */
    readonly keepAlive: boolean;

    /** Supported authentication methods */
    readonly authMethods: readonly ('password' | 'publickey' | 'keyboard-interactive')[];

    /** Client identification string */
    readonly clientName: string;

    /** Supported algorithms */
    readonly algorithms?: {
        readonly kex?: readonly string[];
        readonly cipher?: readonly string[];
        readonly serverHostKey?: readonly string[];
        readonly hmac?: readonly string[];
    };
}

/**
 * Encrypted SSH Credentials for secure storage
 */
export interface EncryptedSSHCredentials {
    /** Encrypted credentials data */
    readonly encryptedData: string;

    /** Initialization vector for decryption */
    readonly iv: string;

    /** Authentication tag for verification */
    readonly authTag: string;

    /** Timestamp when encrypted */
    readonly encryptedAt: Date;

    /** Host (kept unencrypted for identification) */
    readonly host: string;

    /** Username (kept unencrypted for identification) */
    readonly username: string;
}

/**
 * SSH Credentials Validation Result
 */
export interface SSHCredentialsValidation {
    /** Whether credentials are valid */
    readonly isValid: boolean;

    /** Validation errors if any */
    readonly errors: readonly string[];

    /** Warnings that don't prevent connection */
    readonly warnings: readonly string[];

    /** Validation timestamp */
    readonly validatedAt: Date;
}

/**
 * Default SSH connection options
 */
export const DEFAULT_SSH_OPTIONS: Readonly<SSHConnectionOptions> = {
    maxRetries: 3,
    retryDelay: 1000,
    keepAlive: true,
    authMethods: ['publickey', 'password'] as const,
    clientName: 'ServerManager-SSH-Client',
    algorithms: {
        kex: [
            'diffie-hellman-group14-sha256',
            'diffie-hellman-group16-sha512',
            'ecdh-sha2-nistp256',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp521'
        ] as const,
        cipher: [
            'aes128-gcm@openssh.com',
            'aes256-gcm@openssh.com',
            'aes128-ctr',
            'aes192-ctr',
            'aes256-ctr'
        ] as const,
        serverHostKey: [
            'ssh-ed25519',
            'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521',
            'rsa-sha2-512',
            'rsa-sha2-256'
        ] as const,
        hmac: [
            'hmac-sha2-256-etm@openssh.com',
            'hmac-sha2-512-etm@openssh.com',
            'hmac-sha2-256',
            'hmac-sha2-512'
        ] as const
    }
} as const;

/**
 * Default SSH credentials template
 */
export const DEFAULT_SSH_CREDENTIALS: Partial<SSHCredentials> = {
    port: 22,
    timeout: 10000,
    keepaliveInterval: 30000,
    debug: false
} as const;