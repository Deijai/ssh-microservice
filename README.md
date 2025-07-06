# 🔐 SSH Microservice

> **Enterprise-grade SSH connection management and command execution microservice**

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/Security-Enterprise-red.svg)](#security)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Características](#-características)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Uso](#-uso)
- [API Documentation](#-api-documentation)
- [Arquitetura](#-arquitetura)
- [Segurança](#-segurança)
- [Monitoramento](#-monitoramento)
- [Deploy](#-deploy)
- [Desenvolvimento](#-desenvolvimento)
- [Troubleshooting](#-troubleshooting)

## 🎯 Visão Geral

O **SSH Microservice** é uma solução robusta para gerenciamento de conexões SSH e execução de comandos remotos em servidores. Projetado para ambientes empresariais com foco em **segurança**, **performance** e **escalabilidade**.

### 🏗️ Principais Funcionalidades

- **🔐 Autenticação Segura**: JWT + Firebase Auth + API Keys
- **⚡ Pool de Conexões**: Gerenciamento inteligente de conexões SSH
- **📊 Monitoramento**: Health checks + Métricas + Logs estruturados
- **🛡️ Segurança**: Criptografia AES-256-GCM + Rate limiting + Validação
- **🔄 Streaming**: Execução de comandos com output em tempo real
- **📦 Batch Processing**: Execução de múltiplos comandos
- **🏥 Health Monitoring**: Sistema completo de monitoramento

## ✨ Características

### 🔒 Segurança Enterprise

- **Autenticação Multi-factor**: JWT, Firebase, API Keys
- **Criptografia**: AES-256-GCM para dados sensíveis
- **Rate Limiting**: Proteção contra ataques
- **Validação**: Comandos perigosos bloqueados
- **Audit Trail**: Log completo de ações
- **CORS Configurável**: Controle de origem

### ⚡ Performance

- **Connection Pooling**: Reutilização de conexões SSH
- **Cache Inteligente**: Cache de comandos read-only
- **Async/Await**: Operações não-bloqueantes
- **Compression**: Compressão de responses
- **Keep-alive**: Conexões persistentes

### 📊 Observabilidade

- **Structured Logging**: Winston com contexto
- **Prometheus Metrics**: Métricas para monitoring
- **Health Checks**: Kubernetes-ready probes
- **Performance Monitoring**: CPU, Memory, Event Loop
- **Request Tracing**: Request ID tracking

### 🔄 Operações SSH

- **Conexão Segura**: Suporte a password e chaves SSH
- **Comando Único**: Execução com timeout e validação
- **Streaming**: Output em tempo real via Server-Sent Events
- **Batch Commands**: Execução sequencial ou paralela
- **Server Status**: Monitoramento completo do servidor

## 🚀 Instalação

### Pré-requisitos

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0
- **Docker** (opcional)
- **Conta Firebase** (para autenticação)

### 1. Clone o Repositório

```bash
git clone https://github.com/your-org/ssh-microservice.git
cd ssh-microservice
```

### 2. Instale Dependências

```bash
npm install
```

### 3. Configure Ambiente

```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

### 4. Build da Aplicação

```bash
npm run build
```

### 5. Inicie o Serviço

```bash
# Desenvolvimento
npm run dev

# Produção
npm start
```

## ⚙️ Configuração

### Variáveis de Ambiente

```bash
# ==============================================================================
# 🔒 SEGURANÇA
# ==============================================================================
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long-here
ENCRYPTION_KEY=your-32-character-encryption-key
API_KEY=your-api-key-for-client-authentication
BCRYPT_SALT_ROUNDS=12

# ==============================================================================
# 🔥 FIREBASE
# ==============================================================================
FIREBASE_PROJECT_ID=your-firebase-project-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYOUR_KEY\n-----END PRIVATE KEY-----"
FIREBASE_CLIENT_EMAIL=service-account@project.iam.gserviceaccount.com

# ==============================================================================
# 🔌 SSH CONFIGURATION
# ==============================================================================
SSH_CONNECTION_TIMEOUT=10000
SSH_COMMAND_TIMEOUT=30000
MAX_CONCURRENT_CONNECTIONS=10

# ==============================================================================
# 🚦 RATE LIMITING
# ==============================================================================
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# ==============================================================================
# 📝 LOGGING
# ==============================================================================
LOG_LEVEL=info
ENABLE_REQUEST_LOGGING=true
```

### Firebase Setup

1. **Crie um projeto Firebase**
2. **Ative Authentication**
3. **Gere Service Account Key**
4. **Configure as variáveis de ambiente**

## 📚 Uso

### Autenticação

```bash
# Login com email/senha
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# Login com Firebase
curl -X POST http://localhost:3000/api/v1/auth/login/firebase \
  -H "Content-Type: application/json" \
  -d '{
    "firebaseToken": "your-firebase-token"
  }'
```

### Conexão SSH

```bash
# Criar conexão
curl -X POST http://localhost:3000/api/v1/ssh/connect \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "server.example.com",
    "username": "root",
    "password": "password123",
    "port": 22
  }'
```

### Execução de Comandos

```bash
# Comando simples
curl -X POST http://localhost:3000/api/v1/ssh/CONNECTION_ID/execute \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "ls -la /home",
    "options": {
      "timeout": 10000,
      "workingDirectory": "/home"
    }
  }'

# Comando com streaming
curl -X POST http://localhost:3000/api/v1/ssh/CONNECTION_ID/stream \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "tail -f /var/log/nginx/access.log"
  }'
```

### Batch Commands

```bash
curl -X POST http://localhost:3000/api/v1/ssh/CONNECTION_ID/batch \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      "whoami",
      "pwd",
      "ls -la"
    ],
    "options": {
      "mode": "sequential",
      "stopOnFailure": true
    }
  }'
```

## 📖 API Documentation

### Endpoints Principais

#### 🔐 Authentication
- `POST /api/v1/auth/login` - Login com email/senha
- `POST /api/v1/auth/login/firebase` - Login com Firebase
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/profile` - Perfil do usuário

#### 🔌 SSH Operations
- `POST /api/v1/ssh/connect` - Criar conexão SSH
- `POST /api/v1/ssh/test` - Testar conexão
- `POST /api/v1/ssh/:id/execute` - Executar comando
- `POST /api/v1/ssh/:id/stream` - Comando com streaming
- `POST /api/v1/ssh/:id/batch` - Batch commands
- `GET /api/v1/ssh/:id/status` - Status do servidor
- `DELETE /api/v1/ssh/:id` - Desconectar

#### 🏥 Health & Monitoring
- `GET /health` - Health check básico
- `GET /api/v1/health/status` - Status detalhado
- `GET /api/v1/health/metrics` - Métricas da aplicação
- `GET /api/v1/health/prometheus` - Métricas Prometheus

#### 👑 Admin
- `GET /api/v1/admin/users` - Listar usuários
- `GET /api/v1/admin/sessions` - Sessões ativas
- `GET /api/v1/admin/connections` - Conexões SSH
- `GET /api/v1/admin/logs` - Logs da aplicação

### Swagger Documentation

Acesse `http://localhost:3000/api/v1/docs` para documentação interativa.

## 🏗️ Arquitetura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │    │  Load Balancer  │    │     Nginx       │
│  (React/Vue)    │────│   (Optional)    │────│  Reverse Proxy  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         │                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │ SSH Microservice│    │ SSH Microservice│    │ SSH Microservice│
                    │   Instance 1    │    │   Instance 2    │    │   Instance N    │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                         │                         │
                              └─────────────────────────┼─────────────────────────┘
                                                        │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │    Firebase     │    │      Redis      │    │   Prometheus    │
                    │      Auth       │    │     Cache       │    │    Metrics      │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                              ┌─────────────────────────┼─────────────────────────┐
                              │                         │                         │
                    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
                    │  Target SSH     │    │  Target SSH     │    │  Target SSH     │
                    │   Server 1      │    │   Server 2      │    │   Server N      │
                    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Componentes

#### 🎯 Core Services
- **SSHService**: Gerenciamento de conexões e pool
- **AuthService**: Autenticação JWT + Firebase
- **HealthService**: Monitoramento e métricas

#### 🛡️ Middleware
- **Authentication**: Validação de tokens
- **Authorization**: Controle de permissões
- **Rate Limiting**: Proteção contra abuse
- **Validation**: Sanitização de inputs

#### 🗄️ Models
- **SSHCredentials**: Credenciais de conexão
- **CommandResult**: Resultado de comandos
- **ServerStatus**: Status do servidor

#### ⚙️ Utilities
- **Logger**: Logging estruturado
- **Encryption**: Criptografia de dados
- **Validator**: Validação de inputs
- **Error Handler**: Tratamento de erros

## 🛡️ Segurança

### Autenticação e Autorização

```typescript
// JWT Token Structure
{
  "userId": "user-id",
  "email": "user@example.com",
  "role": "admin|user|readonly",
  "permissions": ["ssh:connect", "ssh:execute"],
  "iat": 1234567890,
  "exp": 1234567890
}
```

### Criptografia

- **AES-256-GCM**: Para dados sensíveis (credenciais SSH)
- **bcrypt**: Para hashes de senhas
- **JWT**: Para tokens de autenticação
- **HMAC-SHA256**: Para assinaturas

### Rate Limiting

```typescript
// Rate Limits
{
  "auth": "5 login attempts per 15 minutes",
  "ssh": "100 requests per 15 minutes",
  "commands": "30 commands per minute",
  "admin": "30 operations per 5 minutes"
}
```

### Validação de Comandos

```typescript
// Comandos Perigosos Bloqueados
const dangerousPatterns = [
  /rm\s+(-rf?|--recursive|--force)/i,
  /sudo\s+rm/i,
  /format\s+/i,
  /mkfs\./i,
  /dd\s+if=/i,
  // ... mais padrões
];
```

## 📊 Monitoramento

### Health Checks

```bash
# Liveness Probe
GET /live

# Readiness Probe  
GET /ready

# Detailed Health
GET /api/v1/health/status
```

### Métricas Prometheus

```bash
# Métricas disponíveis
ssh_requests_total
ssh_errors_total
ssh_response_time_ms
ssh_active_connections
process_memory_usage_percent
process_cpu_usage_percent
```

### Logs Estruturados

```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "info",
  "message": "SSH connection established",
  "requestId": "req-123",
  "userId": "user-456",
  "action": "SSH_CONNECT",
  "resource": "server.example.com",
  "duration": 1250,
  "metadata": {
    "host": "server.example.com",
    "username": "root"
  }
}
```

## 🐳 Deploy

### Docker

```bash
# Build
docker build -t ssh-microservice .

# Run
docker run -p 3000:3000 \
  -e JWT_SECRET=your-secret \
  -e ENCRYPTION_KEY=your-key \
  ssh-microservice
```

### Docker Compose

```bash
# Produção
docker-compose up -d

# Desenvolvimento
docker-compose --profile development up -d

# Com monitoramento
docker-compose --profile monitoring up -d
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ssh-microservice
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ssh-microservice
  template:
    metadata:
      labels:
        app: ssh-microservice
    spec:
      containers:
      - name: ssh-microservice
        image: ssh-microservice:latest
        ports:
        - containerPort: 3000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: ssh-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /live
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 🛠️ Desenvolvimento

### Setup Local

```bash
# Clone
git clone https://github.com/your-org/ssh-microservice.git
cd ssh-microservice

# Install
npm install

# Setup environment
cp .env.example .env

# Run in development
npm run dev
```

### Scripts Disponíveis

```bash
npm run dev          # Desenvolvimento com hot-reload
npm run build        # Build para produção
npm run start        # Iniciar produção
npm run test         # Executar testes
npm run test:watch   # Testes em watch mode
npm run lint         # Linting
npm run format       # Formatação de código
```

### Estrutura do Projeto

```
src/
├── app.ts                 # Express app setup
├── server.ts             # Main server entry point
├── config/
│   └── environment.ts    # Environment configuration
├── controllers/          # HTTP controllers
│   ├── AuthController.ts
│   ├── SSHController.ts
│   └── HealthController.ts
├── services/            # Business logic
│   ├── SSHService.ts
│   ├── AuthService.ts
│   └── HealthService.ts
├── middleware/          # Express middleware
│   └── auth.ts
├── models/             # Data models
│   ├── SSHCredentials.ts
│   ├── CommandResult.ts
│   └── ServerStatus.ts
├── routes/            # Route definitions
│   ├── index.ts
│   ├── auth.ts
│   ├── ssh.ts
│   ├── health.ts
│   └── admin.ts
├── utils/            # Utilities
│   ├── logger.ts
│   ├── encryption.ts
│   ├── validator.ts
│   └── errorHandler.ts
└── types/           # Type definitions
    └── common.ts
```

### Testing

```bash
# Unit tests
npm run test

# Integration tests
npm run test:integration

# Coverage
npm run test:coverage

# Test específico
npm test -- --grep "SSH Service"
```

## 🔧 Troubleshooting

### Problemas Comuns

#### 1. Erro de Conexão SSH

```bash
# Verificar conectividade
telnet target-server 22

# Verificar credenciais
ssh username@target-server

# Logs do serviço
docker logs ssh-microservice-app
```

#### 2. Erro de Autenticação

```bash
# Verificar JWT secret
echo $JWT_SECRET

# Verificar Firebase config
curl -X GET http://localhost:3000/api/v1/auth/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### 3. Problemas de Performance

```bash
# Verificar métricas
curl http://localhost:3000/api/v1/health/metrics

# Verificar pool de conexões
curl http://localhost:3000/api/v1/ssh/pool/stats
```

#### 4. Rate Limiting

```bash
# Verificar headers de rate limit
curl -I http://localhost:3000/api/v1/ssh/connect

# Headers retornados:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 99
# X-RateLimit-Reset: 1234567890
```

### Logs de Debug

```bash
# Habilitar debug logs
export LOG_LEVEL=debug

# Logs específicos
export DEBUG=ssh:*,auth:*

# Logs estruturados
tail -f logs/ssh-microservice.log | jq
```

### Health Checks

```bash
# Verificar saúde completa
curl http://localhost:3000/api/v1/health/status | jq

# Verificar métricas específicas
curl http://localhost:3000/api/v1/health/metrics | jq '.data.memory'

# Forçar garbage collection (admin)
curl -X POST http://localhost:3000/api/v1/health/gc \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

## 📄 Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📞 Suporte

- **📧 Email**: support@ssh-microservice.com
- **📖 Docs**: https://docs.ssh-microservice.com
- **🐛 Issues**: https://github.com/your-org/ssh-microservice/issues
- **💬 Discord**: https://discord.gg/ssh-microservice

---

**Desenvolvido com ❤️ pela equipe SSH Microservice**