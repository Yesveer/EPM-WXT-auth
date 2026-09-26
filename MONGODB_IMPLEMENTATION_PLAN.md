# 🔄 MongoDB Integration & Auth Refactor Plan

## 🎯 Goal
Move all auth to `vsay-auth` service, use MongoDB for user data & audit logs, sync with Keycloak, and remove auth from `vsay-agent-backend`.

## 📊 Architecture

```
Frontend/CLI/VSCode
        ↓
   vsay-auth:8081
   ├─ MongoDB (users, audit_logs, otp_sessions)
   ├─ Keycloak (identity, RBAC)
   └─ Reconciler (sync KC ↔ MongoDB)
        ↓ (Proxy with JWT)
   vsay-agent-backend:8082
   ├─ MongoDB (machines, logs, sessions)
   └─ Only validates JWT (no auth endpoints)
```

## 🗂️ MongoDB Collections

### vsay-auth Database

#### 1. `users` Collection
```json
{
  "_id": ObjectId,
  "username": "string (unique globally)",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "password_hash": "string (bcrypt)",
  "keycloak_id": "string (UUID from Keycloak)",
  "tenant_id": "string (Keycloak realm)",
  "tenant_name": "string (Organization name)",
  "role": "super_admin | company_admin | user",
  "machine_role": "allow_sudo | non_sudo",
  "groups": ["group_id1", "group_id2"],
  "email_verified": boolean,
  "enabled": boolean,
  "api_key": "string (for CLI/VSCode)",
  "created_at": ISODate,
  "updated_at": ISODate,
  "last_login_at": ISODate,
  "last_sync_at": ISODate  // Last KC sync time
}
```

#### 2. `organizations` Collection
```json
{
  "_id": ObjectId,
  "name": "string (unique, lowercase)",
  "display_name": "string",
  "keycloak_realm": "string (Keycloak realm name)",
  "description": "string",
  "enabled": boolean,
  "created_at": ISODate,
  "updated_at": ISODate
}
```

#### 3. `groups` Collection
```json
{
  "_id": ObjectId,
  "name": "string",
  "tenant_id": "string",
  "keycloak_id": "string (UUID from Keycloak)",
  "description": "string",
  "member_ids": ["user_id1", "user_id2"],
  "machine_ids": ["machine_id1", "machine_id2"],
  "created_at": ISODate,
  "updated_at": ISODate
}
```

#### 4. `audit_logs` Collection
```json
{
  "_id": ObjectId,
  "user_id": ObjectId,
  "username": "string",
  "tenant_id": "string",
  "action": "string (signup, login, create_user, delete_user, etc.)",
  "resource_type": "string (user, organization, group, machine, etc.)",
  "resource_id": "string",
  "method": "GET|POST|PUT|DELETE",
  "endpoint": "string (/api/users/:id)",
  "request_body": object (sanitized, no passwords),
  "response_status": number,
  "source": "ui | cli | vscode",
  "ip_address": "string",
  "user_agent": "string",
  "browser": "string",
  "os": "string",
  "error": "string (if failed)",
  "timestamp": ISODate
}
```

#### 5. `otp_sessions` Collection (Replace Redis)
```json
{
  "_id": ObjectId,
  "username": "string",
  "otp_code": "string (6-digit)",
  "tenant_id": "string",
  "attempts": number,
  "created_at": ISODate,
  "expires_at": ISODate (TTL index)
}
```

## 📝 Implementation Steps

### Phase 1: vsay-auth MongoDB Integration

#### Files to Create/Modify:

1. **internal/database/mongodb.go** (NEW)
   - MongoDB client wrapper
   - Connection management
   - Health checks

2. **internal/database/models.go** (NEW)
   - MongoDB models (User, Organization, Group, AuditLog, OTPSession)
   - Matches collections above

3. **internal/database/store.go** (NEW)
   - CRUD operations for all collections
   - Queries and indexes

4. **internal/services/reconciler.go** (NEW)
   - Sync Keycloak → MongoDB (on user creation in KC)
   - Sync MongoDB → Keycloak (on user update in MongoDB)
   - Periodic reconciliation job
   - Conflict resolution

5. **internal/services/audit.go** (NEW)
   - Log all API calls
   - Extract user, source, IP, etc.
   - Store in audit_logs collection

6. **internal/services/otp.go** (NEW)
   - Replace Redis with MongoDB for OTP
   - Generate 6-digit OTP
   - Store in otp_sessions with TTL
   - Validate OTP

7. **internal/middleware/audit.go** (NEW)
   - Gin middleware to log all requests
   - Extract request context (user, source, IP)
   - Call audit service

8. **Update config.go**
   - Add MongoDB configuration
   - Remove Redis configuration

9. **Update go.mod**
   - Add `go.mongodb.org/mongo-driver`

### Phase 2: vsay-auth API Implementation

10. **internal/api/auth.go** (NEW)
    ```go
    POST /api/auth/signup
    POST /api/auth/login (UI - sends OTP)
    POST /api/auth/verify-otp
    POST /api/auth/login/cli (Direct - no OTP)
    POST /api/auth/logout
    GET /api/auth/check-username/:username
    ```

11. **internal/api/users.go** (NEW)
    ```go
    GET /api/users
    POST /api/users
    GET /api/users/:id
    PUT /api/users/:id
    DELETE /api/users/:id
    POST /api/users/:id/sync (Force sync with KC)
    ```

12. **internal/api/admin.go** (NEW)
    ```go
    GET /api/admin/organizations
    POST /api/admin/organizations
    GET /api/admin/organizations/:id
    DELETE /api/admin/organizations/:id
    ```

13. **internal/api/groups.go** (NEW)
    ```go
    GET /api/groups
    POST /api/groups
    GET /api/groups/:id
    PUT /api/groups/:id
    DELETE /api/groups/:id
    POST /api/groups/:id/members
    DELETE /api/groups/:id/members/:userId
    ```

14. **internal/api/audit.go** (NEW)
    ```go
    GET /api/audit/logs (Admin only)
    GET /api/audit/logs/:user_id
    GET /api/audit/stats
    ```

15. **internal/middleware/auth.go** (NEW)
    - JWT validation
    - Extract user from token
    - Set user context

16. **internal/middleware/rbac.go** (NEW)
    - RequireSuperAdmin()
    - RequireCompanyAdmin()
    - RequireAdmin()

17. **internal/proxy/proxy.go** (NEW)
    - Proxy to vsay-agent-backend
    - Add user context to headers
    - Forward responses

### Phase 3: vsay-agent-backend Changes

18. **Remove Auth Endpoints** (MODIFY)
    - Remove `/api/signup`
    - Remove `/api/login`
    - Keep `/api/profile` but validate JWT from vsay-auth

19. **Update AuthMiddleware** (MODIFY)
    - Change to validate JWT from vsay-auth
    - Extract user_id from token
    - No database lookup (trust vsay-auth token)

20. **Add Audit Logging** (MODIFY)
    - Log all machine commands
    - Track source (ui, cli, vscode)
    - Store in existing logs collection

21. **Update .env** (MODIFY)
    ```env
    # Add vsay-auth URL for token validation
    VSAY_AUTH_URL=http://localhost:8081
    JWT_SECRET=<same-as-vsay-auth>
    ```

### Phase 4: Reconciliation

22. **Reconciler Implementation**
    ```go
    // On Keycloak user create → Create in MongoDB
    func (r *Reconciler) OnKeycloakUserCreated(kcUser) {
        // Create user in MongoDB with keycloak_id
    }

    // On MongoDB user update → Update Keycloak
    func (r *Reconciler) OnMongoDBUserUpdated(user) {
        // Update KC user attributes
    }

    // Periodic full sync (every 5 minutes)
    func (r *Reconciler) FullSync() {
        // Compare KC users with MongoDB users
        // Sync any differences
        // Mark last_sync_at
    }

    // On user deletion in KC → Mark disabled in MongoDB
    func (r *Reconciler) OnKeycloakUserDeleted(kcUserId) {
        // Soft delete: set enabled=false
    }
    ```

### Phase 5: Frontend Changes

23. **Update API Client** (vsay-terminal-next)
    - Change base URL to vsay-auth:8081
    - All auth APIs go to vsay-auth
    - All machine APIs go through vsay-auth (proxy)

24. **Update Auth Context**
    - Handle new auth flow
    - Support OTP verification
    - Track source (always "ui")

## 🔐 JWT Token Structure

```json
{
  "user_id": "mongodb_object_id",
  "username": "johndoe",
  "email": "john@example.com",
  "tenant_id": "acme-corp",
  "tenant_name": "Acme Corporation",
  "role": "company_admin",
  "machine_role": "allow_sudo",
  "groups": ["group_id1", "group_id2"],
  "keycloak_id": "uuid-from-keycloak",
  "source": "ui | cli | vscode",
  "iat": 1234567890,
  "exp": 1234654290
}
```

## 📊 Data Flow

### Signup Flow:
```
1. User → vsay-auth: POST /api/auth/signup
2. vsay-auth: Create realm in Keycloak
3. vsay-auth: Create user in Keycloak
4. vsay-auth: Create user in MongoDB (with keycloak_id)
5. vsay-auth: Send verification email
6. vsay-auth → User: Success response
7. Audit Log: Record signup action
```

### Login Flow (UI):
```
1. User → vsay-auth: POST /api/auth/login {username, password}
2. vsay-auth: Validate with Keycloak
3. vsay-auth: Generate 6-digit OTP
4. vsay-auth: Store OTP in MongoDB (otp_sessions)
5. vsay-auth: Send OTP email
6. vsay-auth → User: {requires_otp: true}
7. User → vsay-auth: POST /api/auth/verify-otp {username, otp}
8. vsay-auth: Validate OTP from MongoDB
9. vsay-auth: Generate JWT
10. vsay-auth: Update last_login_at in MongoDB
11. vsay-auth → User: {access_token, user}
12. Audit Log: Record login action
```

### CLI/VSCode Login Flow:
```
1. CLI → vsay-auth: POST /api/auth/login/cli {username, password}
2. vsay-auth: Validate with Keycloak
3. vsay-auth: Generate JWT (source: "cli" or "vscode")
4. vsay-auth: Update last_login_at
5. vsay-auth → CLI: {access_token, user}
6. Audit Log: Record CLI login
```

### Machine Command Flow:
```
1. User → vsay-auth: POST /api/machines/:id/command
2. vsay-auth: Validate JWT
3. vsay-auth: Proxy to vsay-agent-backend with headers:
   - Authorization: Bearer <token>
   - X-User-ID: <user_id>
   - X-Username: <username>
   - X-Source: <source>
4. vsay-agent-backend: Execute command
5. vsay-agent-backend: Log to MongoDB (with source)
6. vsay-agent-backend → vsay-auth: Response
7. vsay-auth → User: Response
8. Audit Log: Record command execution
```

### Reconciliation Flow:
```
Every 5 minutes:
1. Reconciler: Get all users from Keycloak
2. Reconciler: Get all users from MongoDB
3. Reconciler: Compare by keycloak_id
4. Reconciler: Sync differences
   - KC has user, MongoDB doesn't → Create in MongoDB
   - MongoDB has user, KC doesn't → Mark disabled in MongoDB
   - Attributes differ → Update MongoDB from KC (KC is source of truth)
5. Reconciler: Update last_sync_at
6. Reconciler: Log sync results
```

## 🚀 Implementation Priority

### Week 1: Core Infrastructure
- [ ] MongoDB integration in vsay-auth
- [ ] Database models and store
- [ ] Basic reconciler
- [ ] OTP with MongoDB (replace Redis)

### Week 2: Auth APIs
- [ ] Signup/Login/Logout endpoints
- [ ] JWT generation and validation
- [ ] OTP verification
- [ ] CLI login (no OTP)

### Week 3: User Management
- [ ] User CRUD APIs
- [ ] Organization CRUD APIs
- [ ] Group management APIs
- [ ] RBAC middleware

### Week 4: Integration & Testing
- [ ] Proxy to vsay-agent-backend
- [ ] Remove auth from backend
- [ ] Audit logging everywhere
- [ ] Frontend integration
- [ ] End-to-end testing

## 📈 Success Metrics

- ✅ All auth flows work (UI, CLI, VSCode)
- ✅ Keycloak ↔ MongoDB stay in sync
- ✅ Audit logs capture all actions
- ✅ No auth code left in vsay-agent-backend
- ✅ JWT tokens work across services
- ✅ OTP works with MongoDB
- ✅ Source tracking works (ui, cli, vscode)

## 🎯 Next Step

Should I start implementing this? I can begin with:
1. MongoDB integration in vsay-auth
2. Database models and store
3. Basic reconciler

Bolo bhai, kya shuru karein? 🚀
