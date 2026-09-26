# EPM WebXterm Auth

Production-ready authentication service with Keycloak integration for multi-tenant RBAC (Role-Based Access Control).

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────────┐
│   Frontend  │─────>│  vsay-auth  │─────>│  vsay-agent-     │
│   (UI/CLI)  │      │   (Port     │      │  backend         │
│             │      │    8081)    │      │  (Port 8082)     │
└─────────────┘      └─────────────┘      └──────────────────┘
                            │
                            ├─────> Keycloak (Identity)
                            ├─────> Redis (OTP Storage)
                            └─────> SMTP (Email)
```

## Features

- **Multi-Tenancy**: Each company gets its own isolated tenant (Keycloak realm)
- **Three-Tier RBAC**:
  - Super Admin: Can manage all organizations
  - Company Admin: Can manage users, groups, and machines within their company
  - User: Regular user with limited permissions
- **OTP Authentication**: Email-based OTP for UI logins (CLI/VSCode bypass)
- **Username-based Login**: Unique usernames across all tenants
- **Email Verification**: Automatic email verification on signup
- **API Gateway**: Proxies requests to backend services after authentication
- **Machine Roles**: Sudo and non-sudo access control for machines

## Quick Start

### 1. Prerequisites

- Docker and Docker Compose
- Go 1.23+
- Node.js 18+ (for frontend)

### 2. Start Infrastructure

```bash
# Start Keycloak, PostgreSQL, and Redis
docker-compose up -d

# Wait for services to be healthy
docker-compose ps
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Run Auth Service

```bash
go mod download
go run cmd/server/main.go
```

### 5. Run Backend Service

```bash
cd ../vsay-agent-backend
go run cmd/server/main.go
```

## API Endpoints

### Authentication

#### Signup (Creates New Organization + Admin User)
```bash
POST /api/auth/signup
{
  "company_name": "acme-corp",
  "username": "johndoe",
  "email": "john@acme.com",
  "password": "SecurePass123",
  "confirm_password": "SecurePass123"
}
```

#### Login (Step 1: Username + Password)
```bash
POST /api/auth/login
{
  "username": "johndoe",
  "password": "SecurePass123"
}

Response:
{
  "requires_otp": true,
  "message": "OTP sent to email"
}
```

#### Verify OTP (Step 2: OTP Verification - UI Only)
```bash
POST /api/auth/verify-otp
{
  "username": "johndoe",
  "otp": "123456"
}

Response:
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "id": "uuid",
    "username": "johndoe",
    "email": "john@acme.com",
    "role": "company_admin",
    "tenant_id": "acme-corp"
  }
}
```

#### CLI/VSCode Login (Direct - No OTP)
```bash
POST /api/auth/login/cli
{
  "username": "johndoe",
  "password": "SecurePass123"
}

Response:
{
  "access_token": "eyJhbGc...",
  "user": { ... }
}
```

### Super Admin Endpoints

#### List All Organizations
```bash
GET /api/admin/organizations
Authorization: Bearer <super_admin_token>
```

#### Create Organization
```bash
POST /api/admin/organizations
Authorization: Bearer <super_admin_token>
{
  "name": "newcompany",
  "display_name": "New Company Inc",
  "description": "A new organization"
}
```

#### Get Organization Details
```bash
GET /api/admin/organizations/:id
Authorization: Bearer <super_admin_token>
```

### Company Admin Endpoints

#### List Users in Company
```bash
GET /api/users
Authorization: Bearer <company_admin_token>
```

#### Create User
```bash
POST /api/users
Authorization: Bearer <company_admin_token>
{
  "username": "newuser",
  "email": "newuser@company.com",
  "password": "SecurePass123",
  "first_name": "New",
  "last_name": "User",
  "role": "user"
}
```

#### Delete User
```bash
DELETE /api/users/:id
Authorization: Bearer <company_admin_token>
```

#### List Groups
```bash
GET /api/groups
Authorization: Bearer <company_admin_token>
```

#### Create Group
```bash
POST /api/groups
Authorization: Bearer <company_admin_token>
{
  "name": "Engineering Team",
  "description": "Engineering department"
}
```

#### Add Users to Group
```bash
POST /api/groups/:id/members
Authorization: Bearer <company_admin_token>
{
  "user_ids": ["user-uuid-1", "user-uuid-2"]
}
```

#### Assign Machine Role to User
```bash
POST /api/users/:id/roles
Authorization: Bearer <company_admin_token>
{
  "machine_role": "allow_sudo"
}
```

### Proxy Endpoints

All requests to backend services are proxied through auth service:

```bash
# Proxied to vsay-agent-backend
GET /api/machines
Authorization: Bearer <token>

# Proxied to vsay-agent-backend
POST /api/machines/:id/command
Authorization: Bearer <token>
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Auth service port | `8081` |
| `KEYCLOAK_URL` | Keycloak server URL | `http://localhost:8080` |
| `SUPER_ADMIN_USERNAME` | Super admin username | `superadmin` |
| `SUPER_ADMIN_EMAIL` | Super admin email | `admin@example.com` |
| `SUPER_ADMIN_PASSWORD` | Super admin password | `adminpassword` |
| `VSAY_AGENT_BACKEND_URL` | Backend service URL | `http://localhost:8082` |
| `SMTP_HOST` | SMTP server host | `smtp.gmail.com` |
| `SMTP_USERNAME` | SMTP username | - |
| `SMTP_PASSWORD` | SMTP password | - |
| `REDIS_URL` | Redis server URL | `localhost:6379` |

## User Flows

### 1. Signup Flow
1. User submits signup form with company name, username, email, password
2. System checks if username exists across all tenants (must be globally unique)
3. Creates new Keycloak realm (tenant) for the company
4. Creates admin user in the new realm
5. Sends email verification link
6. User verifies email and can login

### 2. UI Login Flow
1. User enters username + password
2. System validates credentials with Keycloak
3. Generates 6-digit OTP and stores in Redis (10-minute expiry)
4. Sends OTP to user's email
5. User enters OTP
6. System validates OTP
7. Returns JWT access token

### 3. CLI/VSCode Login Flow
1. User enters username + password
2. System validates credentials with Keycloak
3. Returns JWT access token immediately (no OTP required)

## Development

### Project Structure

```
vsay-auth/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── api/                     # HTTP handlers
│   │   ├── auth.go              # Authentication endpoints
│   │   ├── admin.go             # Super admin endpoints
│   │   ├── users.go             # User management endpoints
│   │   ├── groups.go            # Group management endpoints
│   │   └── organizations.go     # Organization endpoints
│   ├── middleware/              # HTTP middleware
│   │   ├── auth.go              # Authentication middleware
│   │   └── rbac.go              # RBAC middleware
│   ├── keycloak/                # Keycloak client wrapper
│   │   └── client.go
│   ├── models/                  # Data models
│   │   └── models.go
│   ├── proxy/                   # Proxy to backend services
│   │   └── proxy.go
│   └── config/                  # Configuration
│       └── config.go
├── docker-compose.yml           # Infrastructure services
├── .env.example                 # Environment variables template
├── go.mod
└── README.md
```

### Adding New Backend Service

1. Add service URL to `.env`:
```
NEW_SERVICE_URL=http://localhost:8083
```

2. Add proxy route in `main.go`:
```go
proxy.SetupRoutes(router, cfg, middleware)
```

3. The auth service will automatically proxy authenticated requests

## Security

- All passwords are hashed by Keycloak (bcrypt)
- JWT tokens are signed and verified
- OTP codes are securely generated and stored in Redis with expiration
- Email verification required for new accounts
- HTTPS recommended for production
- CORS configured for allowed origins
- Rate limiting on authentication endpoints (TODO)

## Testing

```bash
# Run tests
go test ./...

# Test with curl
curl -X POST http://localhost:8081/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "company_name": "testcorp",
    "username": "testuser",
    "email": "test@test.com",
    "password": "Test123456",
    "confirm_password": "Test123456"
  }'
```

## Troubleshooting

### Keycloak not starting
```bash
docker-compose logs keycloak
# Check if PostgreSQL is healthy first
docker-compose ps postgres
```

### Cannot create user
- Check if username already exists: `GET /api/auth/check-username/:username`
- Verify Keycloak is accessible: `curl http://localhost:8080`

### OTP not received
- Check SMTP configuration in `.env`
- Check email service logs
- Verify Redis is running: `redis-cli ping`

## Docker

### Build Single-Arch Image

```bash
docker build -t vsay-auth:latest .
```

### Build & Push Multi-Arch Image (linux/amd64 + linux/arm64)

> Requires Docker Buildx. Run once to create a builder if you haven't already:
> ```bash
> docker buildx create --name multiarch --use
> docker buildx inspect --bootstrap
> ```

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag your-registry/vsay-auth:latest \
  --push \
  .
```

Replace `your-registry/vsay-auth` with your actual registry path (e.g. `ghcr.io/yourorg/vsay-auth`).

---

### Run the Image — Override Env Vars with `-e`

All environment variables have defaults baked into the image. Override any of them at runtime:

```bash
docker run -d \
  -p 8081:8081 \
  -e MONGO_URI="mongodb+srv://user:pass@cluster.mongodb.net/?appName=vsay" \
  -e MONGO_DATABASE="vsay-prod" \
  -e KEYCLOAK_URL="http://keycloak:8080" \
  -e KEYCLOAK_CLIENT_SECRET="your-client-secret" \
  -e KEYCLOAK_ADMIN_PASSWORD="your-keycloak-admin-pass" \
  -e SUPER_ADMIN_EMAIL="admin@yourcompany.com" \
  -e SUPER_ADMIN_PASSWORD="StrongPassword123" \
  -e JWT_SECRET="your-jwt-secret-change-in-prod" \
  -e GATEWAY_SECRET="your-gateway-secret" \
  -e SMTP_USERNAME="you@gmail.com" \
  -e SMTP_PASSWORD="your-smtp-app-password" \
  -e SMTP_FROM="you@gmail.com" \
  -e VSAY_AGENT_BACKEND_URL="http://vsay-backend:8082" \
  -e ALLOWED_ORIGINS="https://yourfrontend.com" \
  your-registry/vsay-auth:latest
```

Or pass an env file:

```bash
docker run -d -p 8081:8081 --env-file .env your-registry/vsay-auth:latest
```

---

### Kubernetes — Pass Env Vars via Pod Spec

**Inline in Deployment:**

```yaml
containers:
  - name: vsay-auth
    image: your-registry/vsay-auth:latest
    ports:
      - containerPort: 8081
    env:
      - name: MONGO_URI
        valueFrom:
          secretKeyRef:
            name: vsay-auth-secrets
            key: mongo-uri
      - name: JWT_SECRET
        valueFrom:
          secretKeyRef:
            name: vsay-auth-secrets
            key: jwt-secret
      - name: KEYCLOAK_URL
        value: "http://keycloak-service:8080"
      - name: VSAY_AGENT_BACKEND_URL
        value: "http://vsay-backend-service:8082"
      - name: ENVIRONMENT
        value: "production"
```

**From a Secret (recommended for sensitive values):**

```bash
# Create secret
kubectl create secret generic vsay-auth-secrets \
  --from-literal=mongo-uri="mongodb+srv://user:pass@cluster.mongodb.net/" \
  --from-literal=jwt-secret="your-jwt-secret" \
  --from-literal=gateway-secret="your-gateway-secret" \
  --from-literal=smtp-password="your-smtp-password" \
  --from-literal=super-admin-password="StrongPassword123"
```

**From a ConfigMap (non-sensitive values):**

```bash
kubectl create configmap vsay-auth-config \
  --from-literal=KEYCLOAK_URL="http://keycloak-service:8080" \
  --from-literal=MONGO_DATABASE="vsay-prod" \
  --from-literal=ENVIRONMENT="production" \
  --from-literal=ALLOWED_ORIGINS="https://yourfrontend.com"
```

Then reference in Deployment:

```yaml
envFrom:
  - configMapRef:
      name: vsay-auth-config
  - secretRef:
      name: vsay-auth-secrets
```

---

### Run with Docker Compose

The `docker-compose.yml` runs **only the vsay-auth service**. It reads all config from your `.env` file and connects to your existing external services (MongoDB Atlas, Keycloak, etc.) — it does **not** spin up its own database or Keycloak.

**Start vsay-auth:**

```bash
docker-compose up -d
```

**View logs:**

```bash
docker-compose logs -f
```

**Stop and remove container:**

```bash
docker-compose down
```

---

## Production Deployment

1. **Use strong secrets**: Change all default passwords and secrets
2. **Enable HTTPS**: Configure SSL/TLS certificates
3. **Use managed services**:
   - Managed Keycloak (Red Hat SSO, Auth0, etc.)
   - Managed Redis (AWS ElastiCache, Redis Cloud, etc.)
   - Managed SMTP (SendGrid, AWS SES, etc.)
4. **Configure firewall**: Only expose necessary ports
5. **Enable monitoring**: Add Prometheus metrics
6. **Add rate limiting**: Prevent brute-force attacks
7. **Backup strategy**: Regular backups of Keycloak database

## License

MIT
