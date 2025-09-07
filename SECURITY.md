# Security Configuration Guide

## 🔒 Environment Variables Security

### Why Environment Variables?

Moving sensitive configuration to environment variables provides several security benefits:

1. **Separation of Code and Configuration**: Secrets are not stored in source code
2. **Environment-Specific Configuration**: Different secrets for dev/staging/production
3. **Reduced Attack Surface**: Secrets not exposed in version control
4. **Easier Secret Rotation**: Update secrets without code changes
5. **Compliance**: Meets security standards and best practices

### Sensitive Information Moved

The following sensitive information has been moved to environment variables:

| Configuration | Environment Variable | Description |
|--------------|---------------------|-------------|
| MongoDB URI | `MONGODB_URI` | Database connection string with credentials |
| Database Name | `MONGODB_DATABASE` | Database name |
| Google Client ID | `GOOGLE_CLIENT_ID` | OAuth2 client identifier |
| Google Client Secret | `GOOGLE_CLIENT_SECRET` | OAuth2 client secret |
| JWT Secret | `JWT_SECRET` | Secret key for signing JWT tokens |
| Frontend URL | `FRONTEND_URL` | Allowed CORS origin |
| Admin Email | `ADMIN_EMAIL` | Administrator email address |

## 🛡️ Security Best Practices Implemented

### 1. Environment File Security

```bash
# .env file is added to .gitignore
.env
.env.local
.env.production
.env.staging
*.env
```

### 2. JWT Secret Security

- **Minimum Length**: 256 bits (32 characters) enforced
- **Cryptographically Secure**: Generated using secure random methods
- **Environment Specific**: Different secrets per environment
- **Regular Rotation**: Secrets should be rotated periodically

### 3. Database Security

- **Connection Encryption**: MongoDB Atlas uses TLS/SSL
- **Authentication**: Username/password based authentication
- **Network Security**: IP whitelist and VPC peering support
- **Connection Pooling**: Optimized connection management

### 4. OAuth2 Security

- **Secure Storage**: Client secrets stored as environment variables
- **Scope Limitation**: Limited to profile and email scopes
- **Redirect URI Validation**: Strict redirect URI validation
- **State Parameter**: CSRF protection for OAuth2 flow

## 🔧 Development vs Production Security

### Development Environment

```bash
ENVIRONMENT=development
SECURITY_LOG_LEVEL=DEBUG
```

**Features:**
- Debug logging enabled for troubleshooting
- Detailed error messages
- Full health check information
- CORS allowing localhost origins

### Production Environment

```bash
ENVIRONMENT=production
SECURITY_LOG_LEVEL=INFO
```

**Features:**
- Minimal logging to prevent information leakage
- Generic error messages
- Restricted health check information
- Strict CORS policy
- Security headers enforced

## 🚀 Deployment Security

### Container Security

```dockerfile
# Use non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

USER appuser

# Environment variables at runtime
ENV ENVIRONMENT=production
```

### Secret Management

#### Option 1: Docker Secrets
```bash
# Create secrets
echo "your-jwt-secret" | docker secret create jwt_secret -
echo "your-db-uri" | docker secret create mongodb_uri -

# Use in compose
version: '3.8'
services:
  app:
    secrets:
      - jwt_secret
      - mongodb_uri
    environment:
      JWT_SECRET_FILE: /run/secrets/jwt_secret
      MONGODB_URI_FILE: /run/secrets/mongodb_uri
```

#### Option 2: Kubernetes Secrets
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vibecoder-secrets
type: Opaque
data:
  jwt-secret: <base64-encoded-secret>
  mongodb-uri: <base64-encoded-uri>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vibecoder-app
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: vibecoder-secrets
              key: jwt-secret
```

#### Option 3: Cloud Secret Managers

**AWS Secrets Manager:**
```yaml
# AWS Systems Manager Parameter Store
AWS_REGION: us-west-2
JWT_SECRET_PARAM: /vibecoder/prod/jwt-secret
MONGODB_URI_PARAM: /vibecoder/prod/mongodb-uri
```

**Azure Key Vault:**
```yaml
AZURE_KEY_VAULT_URL: https://vibecoder-vault.vault.azure.net/
JWT_SECRET_NAME: jwt-secret
MONGODB_URI_NAME: mongodb-uri
```

**Google Secret Manager:**
```yaml
GOOGLE_CLOUD_PROJECT: vibecoder-prod
JWT_SECRET_NAME: projects/vibecoder-prod/secrets/jwt-secret/versions/latest
```

## 🔍 Security Monitoring

### Audit Logging

The application logs security-relevant events:

```java
// Authentication events
log.info("User login attempt: email={}, ip={}", email, clientIp);
log.warn("Failed login attempt: email={}, ip={}", email, clientIp);

// Authorization events  
log.info("Access granted: user={}, resource={}", userId, resource);
log.warn("Access denied: user={}, resource={}", userId, resource);

// Token events
log.info("Token issued: user={}, device={}", userId, deviceFingerprint);
log.warn("Token validation failed: reason={}", reason);
```

### Health Checks

```bash
# Production health check (minimal info)
curl https://api.vibecoder.com/actuator/health

# Development health check (detailed info)
curl http://localhost:8080/actuator/health
```

### Metrics Monitoring

```bash
# Application metrics
curl http://localhost:8080/actuator/metrics

# Security metrics
curl http://localhost:8080/actuator/metrics/security.authentication.success
curl http://localhost:8080/actuator/metrics/security.authentication.failure
```

## 🚨 Security Incident Response

### Environment Variable Compromise

1. **Immediate Actions:**
   ```bash
   # Rotate JWT secret immediately
   NEW_JWT_SECRET=$(openssl rand -base64 64)
   
   # Update environment variable
   # Restart application
   # Invalidate all existing tokens
   ```

2. **Database Credential Compromise:**
   ```bash
   # Change database password immediately
   # Update MONGODB_URI
   # Restart application
   # Monitor for unauthorized access
   ```

3. **OAuth2 Credential Compromise:**
   ```bash
   # Revoke OAuth2 credentials in Google Console
   # Generate new client ID and secret
   # Update GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET
   # Restart application
   ```

## 📋 Security Checklist

### Pre-Deployment

- [ ] All secrets moved to environment variables
- [ ] `.env` file added to `.gitignore`
- [ ] Strong JWT secret generated (256+ bits)
- [ ] Database credentials are secure
- [ ] OAuth2 credentials configured correctly
- [ ] CORS origins properly configured
- [ ] Production profile configured
- [ ] Security logging enabled
- [ ] Health checks secured

### Post-Deployment

- [ ] Secrets properly injected at runtime
- [ ] Application starts without errors
- [ ] Authentication flow works correctly
- [ ] Authorization enforced properly
- [ ] Logs show no credential exposure
- [ ] Health checks return expected results
- [ ] Metrics collection working
- [ ] Security headers present in responses

### Ongoing Security

- [ ] Regular secret rotation schedule
- [ ] Security log monitoring
- [ ] Dependency vulnerability scanning
- [ ] Security audit reviews
- [ ] Incident response plan updated
- [ ] Backup and recovery procedures tested

## 📚 Additional Resources

- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
