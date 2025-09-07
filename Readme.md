# VibeCoder REST Backend

## Overview

VibeCoder REST Backend is a comprehensive Spring Boot-based microservice designed for an online learning platform. The application provides a robust, secure, and scalable backend solution for managing courses, users, orders, and authentication in an e-learning environment.

## 🏗️ Architecture & Engineering Excellence

### Technology Stack

- **Framework**: Spring Boot 3.x with Spring Security 6
- **Database**: MongoDB with Spring Data MongoDB
- **Authentication**: OAuth2 (Google) + JWT with refresh token rotation
- **Security**: Advanced security with device binding, rate limiting, and audit trails
- **Build Tool**: Maven
- **Java Version**: Java 17+
- **Documentation**: OpenAPI/Swagger integration ready

### Key Engineering Features

#### 🔒 Advanced Security Implementation
- **Multi-layer Security Architecture**
  - OAuth2 integration with Google
  - JWT with access/refresh token rotation
  - Device fingerprinting and binding
  - Rate limiting with IP-based throttling
  - CSRF protection and security headers
  - Method-level security with @PreAuthorize

#### 🏢 Domain-Driven Design (DDD)
- **Modular Architecture**: Organized into distinct business modules
- **Clean Separation**: Clear boundaries between modules
- **Domain Models**: Rich domain entities with business logic encapsulation

#### 📊 Database Design Excellence
- **Optimized MongoDB Schema**: Strategic indexing for performance
- **Compound Indexes**: Multi-field indexes for complex queries
- **Text Indexing**: Full-text search capabilities for courses
- **Audit Trail**: Automatic tracking of creation and modification timestamps

#### 🔄 Advanced Session Management
- **Single Session Per User**: Prevents concurrent sessions
- **Device Security**: Device fingerprinting for additional security
- **Session Registry**: Centralized session tracking
- **Graceful Logout**: Proper cleanup of tokens and sessions

## 📁 Project Structure

```
src/main/java/com/notvibecoder/backend/
├── VibecoderRestBackendApplication.java          # Main application class
├── config/                                       # Configuration classes
│   ├── SecurityConfig.java                      # Security configuration
│   ├── WebConfig.java                           # Web & CORS configuration
│   └── properties/                              # Configuration properties
│       ├── AppProperties.java                   # App-specific properties
│       ├── JwtProperties.java                   # JWT configuration
│       └── JwtSecurityProperties.java           # JWT security settings
├── core/                                        # Core utilities and DTOs
│   ├── dto/                                     # Data Transfer Objects
│   │   ├── ApiResponse.java                    # Standardized API responses
│   │   ├── DeviceInfo.java                     # Device information DTO
│   │   └── ErrorResponse.java                  # Error response structure
│   ├── exception/                               # Custom exceptions
│   │   ├── BusinessException.java              # Base business exception
│   │   ├── auth/                                # Authentication exceptions
│   │   ├── course/                              # Course-related exceptions
│   │   ├── order/                               # Order-related exceptions
│   │   └── user/                                # User-related exceptions
│   └── utils/                                   # Utility classes
│       └── SecurityUtils.java                  # Security utility methods
├── modules/                                     # Business modules
│   ├── auth/                                    # Authentication module
│   │   ├── controller/AuthController.java      # Auth endpoints
│   │   ├── entity/                             # Auth entities
│   │   │   ├── RefreshToken.java               # Refresh token entity
│   │   │   ├── BlacklistedToken.java           # Blacklisted tokens
│   │   │   └── AuthProvider.java               # Authentication providers
│   │   ├── repository/                         # Auth repositories
│   │   ├── security/                           # Security components
│   │   │   ├── CustomOAuth2UserService.java    # OAuth2 user service
│   │   │   ├── DeviceSecurityService.java      # Device security
│   │   │   ├── JwtAuthenticationFilter.java    # JWT filter
│   │   │   └── OAuth2AuthenticationSuccessHandler.java
│   │   └── service/                            # Auth services
│   │       ├── AuthService.java                # Main auth service
│   │       ├── JwtService.java                 # JWT operations
│   │       ├── RefreshTokenService.java        # Token management
│   │       └── JwtBlacklistService.java        # Token blacklisting
│   ├── courses/                                 # Course management module
│   │   ├── controller/CourseController.java    # Course endpoints
│   │   ├── entity/                             # Course entities
│   │   │   ├── Course.java                     # Main course entity
│   │   │   ├── VideoLesson.java                # Video lesson entity
│   │   │   └── CourseStatus.java               # Course status enum
│   │   ├── repository/                         # Course repositories
│   │   └── service/                            # Course services
│   │       ├── CourseService.java              # Course business logic
│   │       ├── CourseAccessService.java        # Access control
│   │       └── VideoLessonService.java         # Lesson management
│   ├── order/                                   # Order management module
│   │   ├── controller/OrderController.java     # Order endpoints
│   │   ├── entity/                             # Order entities
│   │   │   ├── Order.java                      # Main order entity
│   │   │   ├── OrderStatus.java                # Order status enum
│   │   │   └── PaymentConfig.java              # Payment configuration
│   │   ├── repository/                         # Order repositories
│   │   └── service/                            # Order services
│   ├── user/                                    # User management module
│   │   ├── controller/                         # User controllers
│   │   │   ├── UserController.java             # User endpoints
│   │   │   └── UserAdminController.java        # Admin user management
│   │   ├── entity/                             # User entities
│   │   │   ├── User.java                       # Main user entity
│   │   │   └── Role.java                       # User roles enum
│   │   ├── repository/                         # User repositories
│   │   └── service/                            # User services
│   ├── system/                                  # System utilities
│   │   ├── constants/SecurityConstants.java    # Security constants
│   │   └── service/                            # System services
│   │       ├── AdminService.java               # Admin operations
│   │       ├── SessionManagementService.java   # Session management
│   │       └── SecurityAuditService.java       # Security auditing
│   ├── notification/                           # Notification module
│   └── common/                                 # Common utilities
│       └── controller/advice/
│           └── GlobalExceptionHandler.java     # Global error handling
└── shared/                                     # Shared components
    ├── config/                                 # Shared configurations
    └── filter/                                 # Custom filters
        └── RateLimitingFilter.java             # Rate limiting
```

## 🚀 Features

### 👤 User Management
- **OAuth2 Authentication**: Google OAuth2 integration
- **Role-based Access Control**: USER and ADMIN roles
- **Profile Management**: User profile CRUD operations
- **Admin Controls**: User management by administrators

### 📚 Course Management
- **Course CRUD**: Complete course lifecycle management
- **Content Access Control**: Purchase-based content access
- **Video Lessons**: Structured lesson management
- **Course Discovery**: Public course browsing and search

### 🛒 Order Management
- **Order Processing**: Complete order workflow
- **Payment Tracking**: Transaction and payment management
- **Admin Verification**: Manual order approval system
- **Order History**: Comprehensive order tracking

### 🔐 Security Features
- **JWT Authentication**: Secure token-based authentication
- **Token Rotation**: Automatic refresh token rotation
- **Device Binding**: Enhanced security with device fingerprinting
- **Rate Limiting**: API rate limiting and abuse prevention
- **Audit Logging**: Comprehensive security audit trails

## 📊 Database Schema

### Core Entities

#### User Entity
```javascript
{
  "_id": "ObjectId",
  "email": "user@example.com",           // Unique, indexed
  "name": "User Name",
  "picture_url": "https://...",
  "provider": "GOOGLE",                  // OAuth2 provider
  "provider_id": "google_user_id",
  "roles": ["USER"],                     // Role-based access
  "enabled": true,
  "purchased_course_ids": ["course1"],   // Owned courses
  "created_at": "ISODate",
  "updated_at": "ISODate",
  "version": 1                          // Optimistic locking
}
```

#### Course Entity
```javascript
{
  "_id": "ObjectId",
  "title": "Course Title",               // Text indexed
  "description": "Course Description",   // Text indexed
  "short_description": "Brief desc",
  "instructor_name": "Instructor",       // Indexed
  "price": 99.99,                       // Indexed
  "discount_price": 79.99,
  "thumbnail_url": "https://...",
  "preview_video_url": "https://...",
  "status": "PUBLISHED",                // Indexed
  "video_lesson_ids": ["lesson1"],      // References
  "what_you_will_learn": ["skill1"],
  "requirements": ["prerequisite1"],
  "total_lessons": 10,
  "total_duration_minutes": 600,
  "enrollment_count": 150,              // Indexed
  "category": "Programming",
  "tags": ["java", "spring"],           // Indexed
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

#### Order Entity
```javascript
{
  "_id": "ObjectId",
  "user_id": "user_id",                 // Indexed
  "course_id": "course_id",             // Indexed
  "status": "COMPLETED",                // Indexed
  "course_price": 99.99,
  "discount_amount": 20.00,
  "total_amount": 79.99,
  // Course snapshot for historical reference
  "course_title": "Course Title",
  "course_instructor": "Instructor",
  "course_thumbnail_url": "https://...",
  // User snapshot
  "user_name": "User Name",
  "user_email": "user@example.com",
  // Payment details
  "payment_method": "MOBILE_BANKING",
  "transaction_id": "TXN123456",
  "phone_number": "+1234567890",
  "payment_reference": "REF123",
  // Verification
  "verified_by": "admin_id",
  "verified_at": "ISODate",
  "admin_notes": "Verified payment",
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

### Optimized Indexing Strategy

#### Compound Indexes
```javascript
// User indexes
{ "email": 1, "provider": 1 }          // Unique user identification
{ "roles": 1, "enabled": 1 }           // Role-based queries
{ "purchased_course_ids": 1, "enabled": 1 } // Course access

// Course indexes  
{ "status": 1, "created_at": -1 }      // Published courses by date
{ "status": 1, "price": 1 }            // Price-based filtering
{ "status": 1, "enrollment_count": -1 } // Popular courses

// Order indexes
{ "user_id": 1, "course_id": 1 }       // Unique constraint
{ "status": 1, "created_at": -1 }      // Order management
{ "payment_method": 1, "transaction_id": 1 } // Payment tracking
```

## 🔧 API Documentation

### Authentication Endpoints

#### POST /api/v1/auth/refresh
Refresh access token using refresh token
```json
// Cookie: refreshToken=<refresh_token>
// Response
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiJ9..."
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### POST /api/v1/auth/logout
Logout user and invalidate tokens
```json
// Response
{
  "success": true,
  "message": "Logged out successfully",
  "data": {
    "sessionType": "single_device"
  }
}
```

### User Management Endpoints

#### GET /api/v1/users/profile
Get current user profile (Authenticated)
```json
{
  "success": true,
  "data": {
    "id": "user123",
    "email": "user@example.com",
    "name": "John Doe",
    "pictureUrl": "https://...",
    "roles": ["USER"],
    "purchasedCourseIds": ["course1", "course2"]
  }
}
```

#### PUT /api/v1/users/profile
Update user profile (Authenticated)
```json
// Request
{
  "name": "Updated Name",
  "pictureUrl": "https://new-picture.com"
}

// Response
{
  "success": true,
  "message": "Profile updated successfully",
  "data": { /* updated user object */ }
}
```

#### POST /api/v1/users/exists
Check if user exists by email (Public)
```json
// Request
{
  "email": "user@example.com"
}

// Response
{
  "success": true,
  "data": {
    "exists": true,
    "provider": "GOOGLE"
  }
}
```

### Course Management Endpoints

#### GET /api/v1/courses/
Get public courses (Public)
```json
{
  "success": true,
  "data": [
    {
      "id": "course123",
      "title": "Spring Boot Masterclass",
      "description": "Complete Spring Boot course",
      "instructorName": "John Teacher",
      "price": 99.99,
      "discountPrice": 79.99,
      "thumbnailUrl": "https://...",
      "status": "PUBLISHED",
      "enrollmentCount": 150,
      "totalLessons": 25,
      "category": "Programming",
      "tags": ["spring", "java"]
    }
  ]
}
```

#### GET /api/v1/courses/{courseId}/
Get course details (Public)
```json
{
  "success": true,
  "data": {
    "id": "course123",
    "title": "Spring Boot Masterclass",
    "description": "Complete course description...",
    "whatYouWillLearn": [
      "Build REST APIs",
      "Spring Security implementation",
      "Database integration"
    ],
    "requirements": [
      "Basic Java knowledge",
      "Understanding of web development"
    ],
    "totalDurationMinutes": 1200,
    "previewVideoUrl": "https://preview-video.com"
  }
}
```

#### GET /api/v1/courses/my-courses
Get user's purchased courses (Authenticated)
```json
{
  "success": true,
  "data": [
    {
      "id": "course123",
      "title": "Spring Boot Masterclass",
      "progress": 75,
      "lastAccessedAt": "2024-01-01T10:00:00Z"
    }
  ]
}
```

#### GET /api/v1/courses/{courseId}/content
Get course content (Requires purchase or admin)
```json
{
  "success": true,
  "data": {
    "courseId": "course123",
    "lessons": [
      {
        "id": "lesson1",
        "title": "Introduction to Spring Boot",
        "duration": 300,
        "videoUrl": "https://secure-video.com",
        "order": 1
      }
    ]
  }
}
```

### Order Management Endpoints

#### POST /api/v1/orders
Create new order (Authenticated - USER role)
```json
// Request
{
  "courseId": "course123",
  "paymentMethod": "MOBILE_BANKING",
  "phoneNumber": "+1234567890",
  "transactionId": "TXN123456",
  "paymentReference": "REF123"
}

// Response
{
  "success": true,
  "message": "Order created successfully",
  "data": {
    "id": "order123",
    "status": "PENDING_VERIFICATION",
    "totalAmount": 79.99,
    "courseName": "Spring Boot Masterclass"
  }
}
```

#### GET /api/v1/orders/my-orders
Get user's orders (Authenticated)
```json
{
  "success": true,
  "data": [
    {
      "id": "order123",
      "courseTitle": "Spring Boot Masterclass",
      "status": "COMPLETED",
      "totalAmount": 79.99,
      "createdAt": "2024-01-01T10:00:00Z",
      "verifiedAt": "2024-01-01T11:00:00Z"
    }
  ]
}
```

#### PUT /api/v1/orders/{orderId}/approve
Approve order (Admin only)
```json
// Request
{
  "adminNotes": "Payment verified manually"
}

// Response
{
  "success": true,
  "message": "Order approved successfully",
  "data": {
    "orderId": "order123",
    "status": "COMPLETED",
    "verifiedBy": "admin123"
  }
}
```

### Admin Endpoints

#### GET /api/v1/admin/users
Get all users (Admin only)
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user123",
        "email": "user@example.com",
        "name": "John Doe",
        "roles": ["USER"],
        "enabled": true,
        "purchasedCoursesCount": 3,
        "totalSpent": 299.97
      }
    ],
    "pagination": {
      "page": 0,
      "size": 20,
      "totalElements": 150
    }
  }
}
```

#### PUT /api/v1/admin/users/{userId}/role
Update user role (Admin only)
```json
// Request
{
  "roles": ["USER", "ADMIN"]
}

// Response
{
  "success": true,
  "message": "User role updated successfully"
}
```

## 🔒 Security Implementation

### JWT Token Structure
```json
{
  "sub": "user123",
  "iss": "vibecoder-backend",
  "aud": "vibecoder-frontend", 
  "roles": ["USER"],
  "device": "device_fingerprint",
  "iat": 1640995200,
  "exp": 1640998800
}
```

### Device Security
- **Device Fingerprinting**: User-Agent + IP-based fingerprinting
- **Token Binding**: Refresh tokens bound to specific devices
- **Session Validation**: Device consistency checks on token refresh

### Rate Limiting
- **IP-based throttling**: 100 requests per minute per IP
- **Authentication endpoints**: 10 requests per minute
- **Sliding window algorithm**: Precise rate limit enforcement

## 🚀 Getting Started

### Prerequisites
- Java 17 or higher
- Maven 3.6+
- MongoDB 4.4+
- Google OAuth2 credentials

### Environment Setup

#### 1. Environment Variables Configuration

The application uses environment variables for sensitive configuration. Follow these steps:

**Step 1: Create Environment File**
```bash
# Copy the example environment file
cp .env.example .env
```

**Step 2: Configure Environment Variables**
Edit the `.env` file with your actual values:

```bash
# Database Configuration
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority&appName=YourApp
MONGODB_DATABASE=your_database_name

# OAuth2 Configuration  
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# JWT Configuration - Generate a secure 256+ bit secret
JWT_SECRET=your_jwt_secret_key_minimum_256_bits

# Application Configuration
FRONTEND_URL=http://localhost:3000
ADMIN_EMAIL=admin@yourdomain.com

# Environment
ENVIRONMENT=development
```

**Step 3: Generate JWT Secret**
```bash
# Generate a secure JWT secret (256+ bits)
openssl rand -base64 64
```

#### 2. Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth2 credentials:
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:8080/login/oauth2/code/google`
5. Copy Client ID and Client Secret to your `.env` file

#### 3. MongoDB Setup

**Option A: MongoDB Atlas (Recommended)**
1. Create account at [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Create a cluster
3. Get connection string and add to `MONGODB_URI`
4. Create database and set `MONGODB_DATABASE`

**Option B: Local MongoDB**
```bash
# Install MongoDB locally
# Update .env file:
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=vibecoder_local
```

### Configuration Profiles

The application supports multiple profiles:

#### Development Profile (default)
```bash
ENVIRONMENT=development
```
- Debug logging enabled
- Detailed health check information
- Security logging for troubleshooting

#### Production Profile
```bash
ENVIRONMENT=production
```
- Optimized logging levels
- Security-focused health checks
- Error details hidden from responses

#### Test Profile
```bash
ENVIRONMENT=test
```
- Uses local test database
- Minimal logging
- Fast startup for testing

### Security Best Practices

#### Environment Variables Security
```bash
# Never commit .env files to version control
echo ".env" >> .gitignore

# Use different secrets for each environment
# Rotate JWT secrets regularly in production
# Use strong, unique passwords for database
```

#### JWT Secret Generation
```bash
# Generate cryptographically secure secret
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"

# Or using OpenSSL
openssl rand -base64 64

# Or using Python
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

### Running the Application

```bash
# Clone the repository
git clone <repository-url>

# Navigate to project directory
cd vibecoder-rest-backend

# Set up environment variables (see Environment Setup above)
cp .env.example .env
# Edit .env with your actual values

# Build the project
mvn clean install

# Run with development profile (default)
mvn spring-boot:run

# Run with specific profile
mvn spring-boot:run -Dspring.profiles.active=production

# Or using environment variable
ENVIRONMENT=production mvn spring-boot:run
```

The application will start on `http://localhost:8080`

### Docker Setup (Optional)

Create a `docker-compose.yml` for local development:

```yaml
version: '3.8'
services:
  mongodb:
    image: mongo:6.0
    container_name: vibecoder-mongo
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: root
      MONGO_INITDB_ROOT_PASSWORD: root
      MONGO_INITDB_DATABASE: vibecoder
    volumes:
      - mongodb_data:/data/db

  app:
    build: .
    container_name: vibecoder-app
    ports:
      - "8080:8080"
    depends_on:
      - mongodb
    env_file:
      - .env
    environment:
      MONGODB_URI: mongodb://root:root@mongodb:27017/vibecoder?authSource=admin

volumes:
  mongodb_data:
```

```bash
# Run with Docker Compose
docker-compose up -d
```

### Health Check
```bash
# Check application health
curl http://localhost:8080/actuator/health

# Check with authentication
curl -H "Authorization: Bearer <your-jwt-token>" \
     http://localhost:8080/actuator/health
```

### Troubleshooting

#### Common Issues

**1. MongoDB Connection Issues**
```bash
# Check MongoDB URI format
# Ensure network access from your IP (MongoDB Atlas)
# Verify username/password
# Check database name
```

**2. OAuth2 Configuration Issues**
```bash
# Verify Google Client ID/Secret
# Check redirect URI configuration
# Ensure Google+ API is enabled
```

**3. JWT Secret Issues**
```bash
# Ensure JWT secret is at least 256 bits (32 characters)
# Generate new secret if needed
# Check for special characters in secret
```

**4. Environment Variable Issues**
```bash
# Verify .env file exists and is readable
# Check variable names match exactly
# Ensure no trailing spaces in values
# Verify file encoding (UTF-8)
```

#### Enable Debug Logging
```bash
# Add to .env for troubleshooting
SECURITY_LOG_LEVEL=DEBUG
DB_LOG_LEVEL=DEBUG
ENVIRONMENT=development
```

## 🧪 Testing

### Test Structure
- **Unit Tests**: Service layer testing
- **Integration Tests**: Repository and API testing
- **Security Tests**: Authentication and authorization testing

### Running Tests
```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=UserServiceTest

# Generate test coverage report
mvn jacoco:report
```

## 📈 Performance Considerations

### Database Optimization
- **Strategic Indexing**: Compound indexes for complex queries
- **Connection Pooling**: Optimized MongoDB connection management
- **Query Optimization**: Efficient aggregation pipelines

### Caching Strategy
- **In-Memory Caching**: Spring Cache abstraction ready
- **Redis Integration**: External cache support prepared
- **Cache Invalidation**: Event-driven cache management

### Security Performance
- **JWT Stateless**: No server-side session storage
- **Efficient Token Validation**: Optimized JWT processing
- **Rate Limiting**: Minimal overhead implementation

## 🔍 Monitoring & Observability

### Logging
- **Structured Logging**: JSON-formatted logs
- **Security Audit**: Authentication and authorization logging
- **Performance Metrics**: Request/response time tracking

### Health Checks
- **Database Health**: MongoDB connectivity monitoring
- **Application Health**: Spring Boot Actuator endpoints
- **Custom Health Indicators**: Business-specific health checks

## 🛡️ Security Best Practices Implemented

1. **Input Validation**: Comprehensive request validation
2. **SQL Injection Prevention**: MongoDB query parameterization
3. **XSS Protection**: Response encoding and CSP headers
4. **CSRF Protection**: Token-based CSRF prevention
5. **Secure Headers**: HSTS, X-Frame-Options, etc.
6. **Password Security**: OAuth2 eliminates password storage
7. **Audit Logging**: Comprehensive security event logging
8. **Rate Limiting**: API abuse prevention
9. **Token Security**: Short-lived access tokens with rotation

## 📝 Development Guidelines

### Code Quality
- **Clean Code**: Consistent naming and structure
- **SOLID Principles**: Maintainable architecture
- **Design Patterns**: Appropriate pattern usage
- **Exception Handling**: Comprehensive error management

### Git Workflow
- **Feature Branches**: Feature-based development
- **Code Reviews**: Mandatory peer reviews
- **Commit Messages**: Conventional commit format
- **Automated Testing**: CI/CD pipeline integration

## 🚦 API Response Standards

All API responses follow a consistent format:

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { /* response data */ },
  "errorCode": null,
  "correlationId": "uuid-correlation-id",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response Example
```json
{
  "success": false,
  "message": "Course not found",
  "data": null,
  "errorCode": "COURSE_NOT_FOUND",
  "correlationId": "abc-123-def",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For support and questions:
- **Email**: support@vibecoder.com
- **Documentation**: [API Documentation](http://localhost:8080/swagger-ui.html)
- **Issues**: [GitHub Issues](https://github.com/username/vibecoder-rest-backend/issues)

---

**Built with ❤️ by the VibeCoder Team**