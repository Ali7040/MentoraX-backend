# 🎓 MentoraX Backend

A **production-ready backend** built with NestJS, featuring **enterprise-grade authentication** with JWT refresh token rotation, rate limiting, and OWASP security best practices.

---

## ✨ Features

- ✅ **Secure JWT Authentication** with access & refresh tokens
- ✅ **Refresh Token Rotation** (single-use tokens)
- ✅ **HttpOnly Secure Cookies** preventing XSS attacks
- ✅ **Token Theft Detection** with family tracking
- ✅ **Global Rate Limiting** preventing DDoS & brute force
- ✅ **Proper Logout** with token invalidation
- ✅ **CORS Configuration** for cookie-based auth
- ✅ **OWASP Security Best Practices** implementation

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| **Framework** | NestJS 11.x (Node.js/TypeScript) |
| **Authentication** | JWT (JSON Web Tokens) |
| **Security** | @nestjs/throttler, cookie-parser, bcrypt |
| **API Validation** | Passport-JWT |
| **Package Manager** | pnpm |

---

## 🏗️ Architecture Overview

```
Entry Point (main.ts)
    ↓
Root Module (app.module.ts) ← Global Rate Limiting
    ↓
Authentication Module (auth/)
    ├─ Controller (HTTP endpoints)
    ├─ Service (Business logic)
    ├─ JwtStrategy (Token validation)
    └─ RefreshTokenStore (Token management)
```

💡 **For detailed architecture explanation, see [ARCHITECTURE.md](ARCHITECTURE.md)**

---

## 🚀 Getting Started

### **Prerequisites**
- Node.js 18+
- pnpm (or npm/yarn)

### **Installation**

```bash
# Clone repository
git clone <your-repo-url>
cd MentoraX-backend

# Install dependencies
pnpm install

# Setup environment
cp .env.example .env
# Edit .env with your secrets
```

### **Running the Application**

```bash
# Development with hot-reload
pnpm run start:dev

# Production
pnpm run build
pnpm run start:prod

# Tests
pnpm run test
```

Server runs on: **http://localhost:3000**

---

## 📚 API Endpoints

### **Authentication**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/auth/signup` | POST | No | Create new account |
| `/auth/login` | POST | No | Login (sets httpOnly cookie) |
| `/auth/refresh-token` | POST | No | Get new access token |
| `/auth/logout` | POST | Yes | Logout current session |
| `/auth/logout-all` | POST | Yes | Logout all devices |
| `/auth/profile` | GET | Yes | Get user profile |

### **Request Examples**

#### **Signup**
```bash
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

#### **Login**
```bash
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response:
{
  "user": { "id": 1, "email": "user@example.com" },
  "token": { "accessToken": "eyJhbGc..." }
}
Set-Cookie: refreshToken=...; HttpOnly; Secure; SameSite=Strict
```

#### **Protected Request**
```bash
GET /auth/profile
Authorization: Bearer eyJhbGc...

Response:
{
  "id": 1,
  "email": "user@example.com"
}
```

#### **Refresh Token**
```bash
POST /auth/refresh-token
Cookie: refreshToken=...

Response:
{
  "accessToken": "eyJhbGc..."
}
Set-Cookie: refreshToken=...; HttpOnly; Secure; SameSite=Strict
```

---

## 📁 Project Structure

```
src/
├── main.ts                    # 🚀 Entry point
├── app.module.ts              # 📦 Root module
├── app.controller.ts          # 🎯 Basic endpoints
├── app.service.ts             # 💼 App service
│
└── auth/                      # 🔐 Authentication module
    ├── auth.module.ts         # Module config
    ├── auth.controller.ts     # Endpoints (login, refresh, logout)
    ├── auth.service.ts        # Business logic
    ├── jwt.strategy.ts        # JWT validation
    ├── jwt-auth.guard.ts      # Route protection
    ├── refresh-token.store.ts # Token storage
    │
    └── dto/                   # Validation objects
        ├── login/
        └── signup/
```

---

## 🔒 Security Features

### **OWASP Compliance**

| Security Feature | Implementation | Protection Against |
|------------------|----------------|---------------------|
| **HttpOnly Cookies** | Refresh tokens in httpOnly cookies | XSS attacks |
| **Secure Flag** | HTTPS-only in production | Man-in-the-middle |
| **SameSite=Strict** | Cookie attribute | CSRF attacks |
| **Short-lived Tokens** | Access tokens expire in 15min | Token theft impact |
| **Token Rotation** | Single-use refresh tokens | Replay attacks |
| **Token Families** | Track token chains | Theft detection |
| **bcrypt Hashing** | Password & token hashing | Database breaches |
| **Rate Limiting** | 10 req/sec, 100 req/min, 1000 req/hr | Brute force, DDoS |
| **JWT Signatures** | HMAC verification | Token forgery |
| **Token Whitelist** | Revocable refresh tokens | Stolen tokens |

### **How Token Rotation Works**

```
1. User logs in → Token A issued
2. User refreshes → Token B issued, Token A revoked
3. User refreshes → Token C issued, Token B revoked
4. Attacker tries Token A → DENIED (revoked)
5. Server detects reuse → Revokes entire family (A, B, C)
6. User must re-login → Alerted to breach
```

💡 **For complete security documentation, see [SECURITY.md](SECURITY.md)**

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | **Complete step-by-step guide** explaining how everything works from entry point to production |
| [SECURITY.md](SECURITY.md) | Security features, authentication flows, client implementation guide |
| [.env.example](.env.example) | Environment variable template |

---

## ✅ What We've Built

### **Completed Features**

- ✅ User signup with bcrypt password hashing
- ✅ Login with JWT access & refresh tokens
- ✅ Protected routes with JwtAuthGuard
- ✅ Token refresh with automatic rotation
- ✅ Single session logout
- ✅ All-device logout
- ✅ HttpOnly cookie security
- ✅ Token theft detection
- ✅ Global rate limiting
- ✅ CORS configuration
- ✅ Comprehensive documentation

### **Current Limitations** (Quick Fixes for Production)

| Component | Current | Production-Ready | Fix Required |
|-----------|---------|------------------|--------------|
| User Storage | In-memory array | Database | Add PostgreSQL/MongoDB |
| Token Storage | In-memory array | Redis/Database | Add Redis |
| Secrets | Hardcoded | Environment | Use strong secrets |
| Email Verification | Not implemented | Recommended | Add email service |

---

## 🚀 Next Steps

### **Required for Production**

1. **Database Integration**
   ```bash
   pnpm add @prisma/client prisma
   # Replace in-memory storage with PostgreSQL
   ```

2. **Redis for Token Storage**
   ```bash
   pnpm add ioredis
   # Replace RefreshTokenStore with Redis
   ```

3. **Environment Secrets**
   ```bash
   # Generate strong secrets
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   ```

### **Recommended Enhancements**

- 📧 Email verification on signup
- 🔄 Password reset via email
- 🔐 Multi-factor authentication (MFA)
- 🛡️ Security headers (Helmet.js)
- 📊 Logging & monitoring (Winston)
- 📝 API documentation (Swagger)
- ✅ Unit & E2E tests

---

## 🎯 Quick Start Guide

### **1. Install & Setup**
```bash
pnpm install
cp .env.example .env
# Edit .env with your configuration
```

### **2. Run Development Server**
```bash
pnpm run start:dev
```

### **3. Test Authentication**
```bash
# Signup
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!"}'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!"}' \
  -c cookies.txt

# Get Profile (requires access token from login response)
curl http://localhost:3000/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Refresh Token
curl -X POST http://localhost:3000/auth/refresh-token \
  -b cookies.txt
```

---

## 🔧 Configuration

### **Environment Variables**

Create a `.env` file:

```env
NODE_ENV=development
PORT=3000
FRONTEND_URL=http://localhost:3000
ACCESS_SECRET=your-super-secret-access-key
REFRESH_SECRET=your-super-secret-refresh-key
```

### **CORS Settings**

Configure allowed origins in [main.ts](src/main.ts):

```typescript
app.enableCors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
});
```

### **Rate Limiting**

Adjust limits in [app.module.ts](src/app.module.ts):

```typescript
ThrottlerModule.forRoot([
  { name: 'short', ttl: 1000, limit: 10 },
  { name: 'medium', ttl: 60000, limit: 100 },
  { name: 'long', ttl: 3600000, limit: 1000 },
])
```

---

## 🧪 Testing

```bash
# Unit tests
pnpm run test

# E2E tests
pnpm run test:e2e

# Test coverage
pnpm run test:cov
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is [MIT licensed](LICENSE).

---

## 🙏 Acknowledgments

- Built with [NestJS](https://nestjs.com)
- Security practices from [OWASP](https://owasp.org)
- Inspired by industry best practices

---

## 📞 Support

- 📖 Read the [ARCHITECTURE.md](ARCHITECTURE.md) for detailed explanations
- 🔒 Check [SECURITY.md](SECURITY.md) for security documentation
- 💬 Open an issue for bugs or questions
- ⭐ Star the repo if you found it helpful!

---

**Built with ❤️ using NestJS and TypeScript**
