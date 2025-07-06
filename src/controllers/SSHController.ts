/**
 * 🔐 SSH Controller
 * HTTP endpoints for SSH operations
 */

import { Request, Response } from 'express';
import { sshService } from '@/services/SSHService';
import { logger } from '@/utils/logger';
import { validator } from '@/utils/validator';
import { encryption } from '@/utils/encryption';
import { errorHandler } from '@/utils/errorHandler';
import {
    ValidationError,
    NotFoundError,
    SSHConnectionError,
    QuotaExceededError
} from '@/utils/errorHandler';
import { ApiResponse, AuthTokenPayload } from '@/types/common';
import { SSHCredentials } from '@/models/SSHCredentials';
import {
    CommandResult,
    CommandOptions,
    StreamingCommandResult,
    BatchCommandResult
} from '@/models/CommandResult';
import { ServerStatus, QuickServerStatus } from '@/models/ServerStatus';

/**
 * Extended request interface with user information
 */
interface AuthenticatedRequest extends Request {
    user?: AuthTokenPayload;
    requestId?: string;
}

/**
 * Connection request body
 */
interface ConnectRequest {
    host: string;
    port?: number;
    username: string;
    password?: string;
    privateKey?: string;
    passphrase?: string;
    timeout?: number;
    keepaliveInterval?: number;
    debug?: boolean;
}

/**
 * Command execution request body
 */
interface ExecuteCommandRequest {
    command: string;
    options?: {
        workingDirectory?: string;
        environment?: Record<string, string>;
        timeout?: number;
        streaming?: boolean;
        maxOutputSize?: number;
        sudo?: boolean;
        shell?: string;
        pty?: boolean;
    };
}

/**
 * Batch command execution request body
 */
interface BatchCommandRequest {
    commands: string[];
    options?: {
        mode: 'sequential' | 'parallel';
        stopOnFailure: boolean;
        commandOptions?: CommandOptions;
    };
}

/**
 * SSH Controller class
 */
export class SSHController {
    /**
     * Create SSH connection
     */
    static connect = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { body }: { body: ConnectRequest } = req;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('SSH connection request received', {
            requestId,
            userId,
            action: 'SSH_CONNECT_REQUEST',
            resource: body.host,
            metadata: {
                host: body.host,
                username: body.username,
                port: body.port || 22
            }
        });

        // Validate request body
        const validation = validator.sshCredentials(body);
        if (!validation.isValid) {
            throw new ValidationError('Invalid connection parameters', validation.errors);
        }

        // Create SSH credentials object
        const credentials: SSHCredentials = {
            host: body.host,
            port: body.port || 22,
            username: body.username,
            password: body.password,
            privateKey: body.privateKey,
            passphrase: body.passphrase,
            timeout: body.timeout || 10000,
            keepaliveInterval: body.keepaliveInterval || 30000,
            debug: body.debug || false
        };

        try {
            const connectionId = await sshService.connect(credentials);

            const response: ApiResponse<{ connectionId: string }> = {
                success: true,
                data: { connectionId },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('SSH connection established successfully', {
                requestId,
                userId,
                action: 'SSH_CONNECT_SUCCESS',
                resource: body.host,
                metadata: { connectionId }
            });

            res.status(201).json(response);

        } catch (error) {
            logger.error('SSH connection failed', {
                requestId,
                userId,
                action: 'SSH_CONNECT_FAILED',
                resource: body.host,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Test SSH connection without creating persistent connection
     */
    static testConnection = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { body }: { body: ConnectRequest } = req;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('SSH connection test request', {
            requestId,
            userId,
            action: 'SSH_TEST_REQUEST',
            resource: body.host
        });

        // Validate request body
        const validation = validator.sshCredentials(body);
        if (!validation.isValid) {
            throw new ValidationError('Invalid connection parameters', validation.errors);
        }

        const credentials: SSHCredentials = {
            host: body.host,
            port: body.port || 22,
            username: body.username,
            password: body.password,
            privateKey: body.privateKey,
            passphrase: body.passphrase,
            timeout: body.timeout || 5000,
            keepaliveInterval: body.keepaliveInterval || 30000,
            debug: body.debug || false
        };

        try {
            const isSuccessful = await sshService.testConnection(credentials);

            const response: ApiResponse<{ success: boolean }> = {
                success: true,
                data: { success: isSuccessful },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('SSH connection test failed', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Execute command on SSH connection
     */
    static executeCommand = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { connectionId } = req.params;
        const { body }: { body: ExecuteCommandRequest } = req;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('SSH command execution request', {
            requestId,
            userId,
            action: 'SSH_COMMAND_REQUEST',
            resource: connectionId,
            metadata: {
                command: body.command.substring(0, 100) + (body.command.length > 100 ? '...' : ''),
                connectionId
            }
        });

        // Validate connection ID
        if (!validator.uuid(connectionId)) {
            throw new ValidationError('Invalid connection ID format');
        }

        // Validate command
        const commandValidation = validator.command(body.command);
        if (!commandValidation.isValid) {
            throw new ValidationError('Invalid command', commandValidation.errors);
        }

        // Validate options if provided
        let options: CommandOptions = {};
        if (body.options) {
            const optionsValidation = validator.commandOptions(body.options);
            if (!optionsValidation.isValid) {
                throw new ValidationError('Invalid command options', optionsValidation.errors);
            }
            options = body.options;
        }

        try {
            const result = await sshService.executeCommand(connectionId, body.command, options);

            const response: ApiResponse<CommandResult> = {
                success: true,
                data: result,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('SSH command executed successfully', {
                requestId,
                userId,
                action: 'SSH_COMMAND_SUCCESS',
                resource: connectionId,
                metadata: {
                    exitCode: result.exitCode,
                    duration: result.duration,
                    success: result.success
                }
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('SSH command execution failed', {
                requestId,
                userId,
                action: 'SSH_COMMAND_FAILED',
                resource: connectionId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Execute streaming command
     */
    static executeStreamingCommand = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { connectionId } = req.params;
        const { body }: { body: ExecuteCommandRequest } = req;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('SSH streaming command request', {
            requestId,
            userId,
            action: 'SSH_STREAMING_REQUEST',
            resource: connectionId
        });

        // Validate inputs
        if (!validator.uuid(connectionId)) {
            throw new ValidationError('Invalid connection ID format');
        }

        const commandValidation = validator.command(body.command);
        if (!commandValidation.isValid) {
            throw new ValidationError('Invalid command', commandValidation.errors);
        }

        let options: CommandOptions = { streaming: true };
        if (body.options) {
            const optionsValidation = validator.commandOptions({ ...body.options, streaming: true });
            if (!optionsValidation.isValid) {
                throw new ValidationError('Invalid command options', optionsValidation.errors);
            }
            options = { ...body.options, streaming: true };
        }

        try {
            const streamId = await sshService.executeStreamingCommand(connectionId, body.command, options);

            const response: ApiResponse<{ streamId: string }> = {
                success: true,
                data: { streamId },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(201).json(response);

        } catch (error) {
            logger.error('SSH streaming command failed', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get streaming command result
     */
    static getStreamingResult = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { streamId } = req.params;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        if (!validator.uuid(streamId)) {
            throw new ValidationError('Invalid stream ID format');
        }

        try {
            const result = sshService.getStreamingResult(streamId);

            if (!result) {
                throw new NotFoundError('Stream not found');
            }

            const response: ApiResponse<StreamingCommandResult> = {
                success: true,
                data: result,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            if (error instanceof NotFoundError) {
                throw error;
            }

            logger.error('Failed to get streaming result', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Cancel streaming command
     */
    static cancelStreamingCommand = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { streamId } = req.params;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        if (!validator.uuid(streamId)) {
            throw new ValidationError('Invalid stream ID format');
        }

        try {
            const cancelled = sshService.cancelStreamingCommand(streamId);

            const response: ApiResponse<{ cancelled: boolean }> = {
                success: true,
                data: { cancelled },
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('Streaming command cancelled', {
                requestId,
                userId,
                action: 'SSH_STREAMING_CANCEL',
                metadata: { streamId, cancelled }
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to cancel streaming command', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Execute batch commands
     */
    static executeBatchCommands = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { connectionId } = req.params;
        const { body }: { body: BatchCommandRequest } = req;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('SSH batch command request', {
            requestId,
            userId,
            action: 'SSH_BATCH_REQUEST',
            resource: connectionId,
            metadata: {
                commandCount: body.commands.length,
                mode: body.options?.mode || 'sequential'
            }
        });

        // Validate inputs
        if (!validator.uuid(connectionId)) {
            throw new ValidationError('Invalid connection ID format');
        }

        if (!Array.isArray(body.commands) || body.commands.length === 0) {
            throw new ValidationError('Commands array is required and cannot be empty');
        }

        if (body.commands.length > 50) {
            throw new ValidationError('Too many commands. Maximum is 50 commands per batch.');
        }

        // Validate each command
        for (const command of body.commands) {
            const commandValidation = validator.command(command);
            if (!commandValidation.isValid) {
                throw new ValidationError(`Invalid command: ${command}`, commandValidation.errors);
            }
        }

        const options = {
            mode: body.options?.mode || 'sequential' as const,
            stopOnFailure: body.options?.stopOnFailure ?? true,
            commandOptions: body.options?.commandOptions
        };

        try {
            const result = await sshService.executeBatchCommands(connectionId, body.commands, options);

            const response: ApiResponse<BatchCommandResult> = {
                success: true,
                data: result,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('SSH batch commands completed', {
                requestId,
                userId,
                action: 'SSH_BATCH_SUCCESS',
                resource: connectionId,
                metadata: {
                    totalCommands: result.metadata.totalCommands,
                    successfulCommands: result.metadata.successfulCommands,
                    failedCommands: result.metadata.failedCommands,
                    duration: result.totalDuration
                }
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('SSH batch commands failed', {
                requestId,
                userId,
                action: 'SSH_BATCH_FAILED',
                resource: connectionId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get server status
     */
    static getServerStatus = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { connectionId } = req.params;
        const { quick = 'false' } = req.query;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('Server status request', {
            requestId,
            userId,
            action: 'SERVER_STATUS_REQUEST',
            resource: connectionId,
            metadata: { quick: quick === 'true' }
        });

        if (!validator.uuid(connectionId)) {
            throw new ValidationError('Invalid connection ID format');
        }

        try {
            if (quick === 'true') {
                const status = await sshService.getQuickServerStatus(connectionId);

                const response: ApiResponse<QuickServerStatus> = {
                    success: true,
                    data: status,
                    timestamp: new Date(),
                    requestId,
                    version: '1.0.0'
                };

                res.status(200).json(response);
            } else {
                const status = await sshService.getServerStatus(connectionId);

                const response: ApiResponse<ServerStatus> = {
                    success: true,
                    data: status,
                    timestamp: new Date(),
                    requestId,
                    version: '1.0.0'
                };

                res.status(200).json(response);
            }

        } catch (error) {
            logger.error('Failed to get server status', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Disconnect SSH connection
     */
    static disconnect = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const { connectionId } = req.params;
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('SSH disconnect request', {
            requestId,
            userId,
            action: 'SSH_DISCONNECT_REQUEST',
            resource: connectionId
        });

        if (!validator.uuid(connectionId)) {
            throw new ValidationError('Invalid connection ID format');
        }

        try {
            await sshService.disconnect(connectionId);

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('SSH connection disconnected successfully', {
                requestId,
                userId,
                action: 'SSH_DISCONNECT_SUCCESS',
                resource: connectionId
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('SSH disconnect failed', {
                requestId,
                userId,
                action: 'SSH_DISCONNECT_FAILED',
                resource: connectionId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Get connection pool statistics
     */
    static getPoolStats = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.debug('Pool stats request', {
            requestId,
            userId,
            action: 'POOL_STATS_REQUEST'
        });

        try {
            const stats = sshService.getPoolStats();

            const response: ApiResponse<typeof stats> = {
                success: true,
                data: stats,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to get pool stats', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });

    /**
     * Disconnect all connections (admin only)
     */
    static disconnectAll = errorHandler.asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
        const userId = req.user?.id;
        const requestId = req.requestId || encryption.generateUUID();

        logger.info('Disconnect all connections request', {
            requestId,
            userId,
            action: 'SSH_DISCONNECT_ALL_REQUEST'
        });

        // This endpoint should be restricted to admin users
        if (req.user?.role !== 'admin') {
            throw new ValidationError('Admin access required');
        }

        try {
            await sshService.disconnectAll();

            const response: ApiResponse<void> = {
                success: true,
                timestamp: new Date(),
                requestId,
                version: '1.0.0'
            };

            logger.info('All SSH connections disconnected', {
                requestId,
                userId,
                action: 'SSH_DISCONNECT_ALL_SUCCESS'
            });

            res.status(200).json(response);

        } catch (error) {
            logger.error('Failed to disconnect all connections', {
                requestId,
                userId,
                error: error as Error
            });

            throw error;
        }
    });
}

/**
 * Export controller methods
 */
export const sshController = {
    connect: SSHController.connect,
    testConnection: SSHController.testConnection,
    executeCommand: SSHController.executeCommand,
    executeStreamingCommand: SSHController.executeStreamingCommand,
    getStreamingResult: SSHController.getStreamingResult,
    cancelStreamingCommand: SSHController.cancelStreamingCommand,
    executeBatchCommands: SSHController.executeBatchCommands,
    getServerStatus: SSHController.getServerStatus,
    disconnect: SSHController.disconnect,
    getPoolStats: SSHController.getPoolStats,
    disconnectAll: SSHController.disconnectAll
};