/**
 * 🚀 Express Application Setup (Simplified with auto-port)
 */

import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';

import { logger } from './utils/logger';

/**
 * Create Express application
 */
export function createApp(): Application {
    const app = express();

    // Basic middleware
    app.use(helmet());
    app.use(cors({
        origin: true,
        credentials: true
    }));
    app.use(compression());
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    app.use(cookieParser());

    // Basic logging
    app.use((req: Request, res: Response, next: NextFunction) => {
        const start = Date.now();

        res.on('finish', () => {
            const duration = Date.now() - start;
            logger.info(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
        });

        next();
    });

    // Health check routes
    app.get('/health', (_req: Request, res: Response) => {
        res.json({
            status: 'ok',
            timestamp: new Date().toISOString(),
            service: 'ssh-microservice'
        });
    });

    app.get('/live', (_req: Request, res: Response) => {
        res.status(200).json({
            status: 'alive',
            timestamp: new Date().toISOString()
        });
    });

    app.get('/ready', (_req: Request, res: Response) => {
        res.status(200).json({
            status: 'ready',
            timestamp: new Date().toISOString()
        });
    });

    // API routes
    app.get('/api/v1', (_req: Request, res: Response) => {
        res.json({
            service: 'SSH Microservice',
            version: '1.0.0',
            status: 'running',
            timestamp: new Date().toISOString()
        });
    });

    // Basic auth route
    app.post('/api/v1/auth/login', (req: Request, res: Response) => {
        const { email, password } = req.body;

        // Mock authentication
        if (email === 'admin@example.com' && password === 'admin123') {
            res.json({
                success: true,
                data: {
                    accessToken: 'mock-jwt-token',
                    user: {
                        id: '1',
                        email: 'admin@example.com',
                        role: 'admin'
                    }
                }
            });
        } else {
            res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
    });

    // Catch all other routes
    app.use('*', (_req: Request, res: Response) => {
        res.status(404).json({
            success: false,
            error: 'Endpoint not found'
        });
    });

    // Error handler
    app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
        logger.error('Server error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    });

    return app;
}

/**
 * Find available port and start server
 */
export async function startServer(): Promise<void> {
    const app = createApp();

    // Try ports starting from 3000
    const findAvailablePort = async (startPort: number): Promise<number> => {
        return new Promise((resolve, reject) => {
            const server = app.listen(startPort, () => {
                server.close();
                resolve(startPort);
            });

            server.on('error', (err: any) => {
                if (err.code === 'EADDRINUSE') {
                    console.log(`Port ${startPort} is busy, trying ${startPort + 1}...`);
                    findAvailablePort(startPort + 1).then(resolve).catch(reject);
                } else {
                    reject(err);
                }
            });
        });
    };

    try {
        const startPort = parseInt(process.env.PORT || '3000');
        const availablePort = await findAvailablePort(startPort);

        const server = app.listen(availablePort, () => {
            console.log(`
🎉 SSH Microservice está rodando!
📍 Porta: ${availablePort}
🌍 Ambiente: ${process.env.NODE_ENV || 'development'}

🔗 URLs para testar:
   ✅ Health: http://localhost:${availablePort}/health
   📋 API Info: http://localhost:${availablePort}/api/v1
   🔐 Login: http://localhost:${availablePort}/api/v1/auth/login

📝 Exemplo de login:
curl -X POST http://localhost:${availablePort}/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"admin@example.com","password":"admin123"}'
            `);

            logger.info('Server started successfully', {
                port: availablePort,
                environment: process.env.NODE_ENV || 'development'
            });
        });

        // Graceful shutdown
        const gracefulShutdown = () => {
            console.log('\n🔄 Shutting down gracefully...');
            server.close(() => {
                console.log('✅ Server closed');
                process.exit(0);
            });
        };

        process.on('SIGTERM', gracefulShutdown);
        process.on('SIGINT', gracefulShutdown);

    } catch (error) {
        console.error('💥 Failed to start server:', error);
        process.exit(1);
    }
}

export default createApp;