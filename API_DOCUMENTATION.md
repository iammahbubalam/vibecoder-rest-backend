# VibeCoder REST API Documentation

## Overview
VibeCoder is a comprehensive course selling platform backend built with Spring Boot 3, MongoDB, and OAuth2 authentication. The platform supports course management, order processing, payment verification, and user management with role-based access control.

## Base URL
```
https://api.vibecoder.com/api/v1
```

## Authentication
The API uses JWT-based authentication with Google OAuth2 integration. Include the access token in the Authorization header:
```
Authorization: Bearer <access_token>
```

## User Roles
- **PUBLIC**: Unauthenticated users
- **USER**: Authenticated users who can purchase courses
- **TEACHER**: Can create and manage courses (future implementation)
- **ADMIN**: Full system access including user management and payment verification

## API Status Legend
- ✅ **Implemented**: API endpoint is fully implemented and working
- ⚠️ **Needs Fix**: Service implemented but controller endpoint missing or has issues
- ❌ **Missing**: Complete implementation needed
- 🔧 **Partial**: Partially implemented, needs completion

---

## 🔓 Public Endpoints

### Courses (Public)
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/courses/` | Get all published courses | Public | - |
| ✅ | `GET` | `/courses/{courseId}/` | Get public course details | Public | - |
| ❌ | `GET` | `/courses/{courseId}/preview-lessons` | Get free preview lessons | Public | **Missing Controller** |
| ❌ | `GET` | `/courses/search` | Search courses by category/tags | Public | **Missing Implementation** |
| ❌ | `GET` | `/courses/categories` | Get course categories | Public | **Missing Implementation** |

### Database Status
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/db/status` | Get database connection status | Public | - |

### OAuth2 Authentication
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/oauth2/authorization/google` | Initiate Google OAuth2 login | Public | Spring Security handled |
| ✅ | `GET` | `/login/oauth2/code/google` | OAuth2 callback endpoint | Public | Spring Security handled |

---

## 🔐 Authentication Endpoints

### Auth Management
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/auth/refresh` | Refresh access token using refresh token | Public | - |
| ✅ | `POST` | `/auth/logout` | Logout and invalidate tokens | Public | - |
| ✅ | `GET` | `/auth/validate` | Validate current access token | User | - |
| ✅ | `GET` | `/auth/session-info` | Get current session information | User | - |

---

## 👤 User Endpoints

### Profile Management
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/users/profile` | Get current user profile | User | - |
| ✅ | `PUT` | `/users/profile` | Update user profile | User | - |
| ❌ | `GET` | `/users/{userId}/purchased-courses` | Get user's purchased course IDs | User/Admin | **Missing Controller** |
| ❌ | `DELETE` | `/users/account` | Delete user account | User | **Missing Implementation** |
| ❌ | `PUT` | `/users/password` | Change password | User | **Missing for OAuth users** |

### Admin User Management
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ❌ | `GET` | `/users/admin/all` | Get all users with pagination | Admin | **Missing Controller** |
| ❌ | `GET` | `/users/admin/search` | Search users by email/name | Admin | **Missing Controller** |
| ❌ | `PUT` | `/users/admin/{userId}/status` | Enable/disable user account | Admin | **Missing Controller** |
| ❌ | `POST` | `/users/admin/{userId}/purchased-courses` | Manually grant course access | Admin | **Missing Controller** |
| ❌ | `DELETE` | `/users/admin/{userId}/purchased-courses/{courseId}` | Revoke course access | Admin | **Missing Controller** |

---

## 📚 Course Management

### User Course Access
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/courses/my-courses` | Get user's purchased courses | User | - |
| ✅ | `GET` | `/courses/{courseId}/content` | Access course content (requires purchase) | User (Purchased) | - |
| ❌ | `GET` | `/courses/{courseId}/lessons` | Get all lessons for purchased course | User (Purchased) | **Missing Controller** |
| ❌ | `GET` | `/courses/{courseId}/lessons/{lessonId}` | Get specific lesson details | User (Purchased) | **Missing Controller** |
| ❌ | `POST` | `/courses/{courseId}/progress` | Update course progress | User (Purchased) | **Missing Implementation** |
| ❌ | `GET` | `/courses/{courseId}/progress` | Get course progress | User (Purchased) | **Missing Implementation** |

### Admin Course Management
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `POST` | `/courses` | Create new course | Admin | - |
| ✅ | `PUT` | `/courses/{courseId}` | Update course details | Admin | - |
| ✅ | `DELETE` | `/courses/{courseId}` | Delete course | Admin | - |
| ✅ | `GET` | `/courses/admin/all` | Get all courses (including unpublished) | Admin | - |
| ✅ | `POST` | `/courses/{courseId}/lessons` | Add video lessons to course | Admin | - |
| ❌ | `PUT` | `/courses/{courseId}/lessons/{lessonId}` | Update specific video lesson | Admin | **Missing Controller** |
| ❌ | `DELETE` | `/courses/{courseId}/lessons/{lessonId}` | Delete specific video lesson | Admin | **Missing Controller** |
| ❌ | `PUT` | `/courses/{courseId}/status` | Change course status (DRAFT/PUBLISHED/ARCHIVED) | Admin | **Missing Controller** |
| ❌ | `GET` | `/courses/{courseId}/analytics` | Get course analytics (enrollments, revenue) | Admin | **Missing Controller** |

---

## 🛒 Order Management

### User Orders
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ⚠️ | `POST` | `/orders` | Create new order for a course | User | **Missing Controller** |
| ⚠️ | `PUT` | `/orders/{orderId}/payment` | Submit payment information | User | **Missing Controller** |
| ⚠️ | `PUT` | `/orders/{orderId}/cancel` | Cancel pending order | User | **Missing Controller** |
| ⚠️ | `GET` | `/orders/{orderId}` | Get specific order details | User (Owner) | **Missing Controller** |
| ✅ | `GET` | `/orders/my-orders` | Get user's order history with filters | User | - |

#### My Orders Query Parameters
- `status`: Filter by order status (PENDING, SUBMITTED, VERIFIED, REJECTED)
- `courseId`: Filter by specific course
- `searchText`: Search in course title, instructor name
- `dateFrom`: Start date filter (YYYY-MM-DD)
- `dateTo`: End date filter (YYYY-MM-DD)
- `page`: Page number (default: 0)
- `size`: Page size (default: 10)

### Admin Order Management
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/orders/search` | Advanced order search with filters | Admin | - |
| ⚠️ | `PUT` | `/orders/{orderId}/approve` | Approve payment and grant access | Admin | **Missing Controller** |
| ⚠️ | `PUT` | `/orders/{orderId}/reject` | Reject payment with reason | Admin | **Missing Controller** |
| ✅ | `GET` | `/orders/pending-verification` | Get orders pending verification | Admin | - |
| ✅ | `GET` | `/orders/by-transaction/{transactionId}` | Search orders by transaction ID | Admin | - |
| ✅ | `GET` | `/orders/status/{status}` | Get orders by status | Admin | - |
| ⚠️ | `GET` | `/orders/statistics` | Get order statistics for dashboard | Admin | **Missing Controller** |
| ⚠️ | `GET` | `/orders/daily-summary` | Get daily order summary report | Admin | **Missing Controller** |

#### Admin Order Search Parameters
- `userId`: Filter by specific user ID
- `courseId`: Filter by specific course ID
- `status`: Filter by order status
- `paymentMethod`: Filter by payment method (BKASH, NAGAD, ROCKET, BANK_TRANSFER)
- `transactionId`: Search by transaction ID (partial match)
- `phoneNumber`: Search by phone number (partial match)
- `searchText`: Text search across user name, email, course title, instructor
- `dateFrom`: Start date filter
- `dateTo`: End date filter
- `page`: Page number (default: 0)
- `size`: Page size (default: 20)
- `sortBy`: Sort field (default: createdAt)
- `sortDir`: Sort direction (asc/desc, default: desc)

---

## � Notification System (Not Implemented)

### User Notifications
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ❌ | `GET` | `/notifications` | Get user notifications | User | **Missing Implementation** |
| ❌ | `PUT` | `/notifications/{notificationId}/read` | Mark notification as read | User | **Missing Implementation** |
| ❌ | `PUT` | `/notifications/mark-all-read` | Mark all notifications as read | User | **Missing Implementation** |
| ❌ | `DELETE` | `/notifications/{notificationId}` | Delete notification | User | **Missing Implementation** |

### Admin Notifications
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ❌ | `POST` | `/notifications/broadcast` | Send broadcast notification | Admin | **Missing Implementation** |
| ❌ | `POST` | `/notifications/user/{userId}` | Send notification to specific user | Admin | **Missing Implementation** |

---

## 📊 Analytics & Reports (Partially Implemented)

### Course Analytics
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ❌ | `GET` | `/analytics/courses/popular` | Get popular courses | Admin | **Missing Implementation** |
| ❌ | `GET` | `/analytics/courses/{courseId}/revenue` | Get course revenue | Admin | **Service exists, missing controller** |
| ❌ | `GET` | `/analytics/revenue/monthly` | Get monthly revenue report | Admin | **Missing Implementation** |
| ❌ | `GET` | `/analytics/users/growth` | Get user growth analytics | Admin | **Missing Implementation** |

### Dashboard APIs
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ❌ | `GET` | `/dashboard/admin/summary` | Get admin dashboard summary | Admin | **Missing Implementation** |
| ❌ | `GET` | `/dashboard/admin/recent-orders` | Get recent orders for dashboard | Admin | **Missing Implementation** |
| ❌ | `GET` | `/dashboard/admin/alerts` | Get system alerts | Admin | **Missing Implementation** |

---

## 🛠️ System Management

### Health & Monitoring
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ✅ | `GET` | `/actuator/health` | Application health check | Public | - |
| ❌ | `GET` | `/system/info` | Get system information | Admin | **Missing Implementation** |
| ❌ | `GET` | `/system/logs` | Get application logs | Admin | **Missing Implementation** |

### Configuration
| Status | Method | Endpoint | Description | Access | Issues |
|--------|--------|----------|-------------|---------|---------|
| ❌ | `GET` | `/config/payment-methods` | Get available payment methods | Admin | **Missing Controller** |
| ❌ | `PUT` | `/config/payment-methods` | Update payment method settings | Admin | **Missing Implementation** |
| ❌ | `GET` | `/config/app-settings` | Get application settings | Admin | **Missing Implementation** |
| ❌ | `PUT` | `/config/app-settings` | Update application settings | Admin | **Missing Implementation** |

---

## 🚨 Critical Issues Found

### 1. Missing Core Order Controllers
**Problem**: Order service methods are implemented but controller endpoints are missing
- `POST /orders` - Create order
- `PUT /orders/{orderId}/payment` - Submit payment  
- `PUT /orders/{orderId}/approve` - Approve payment
- `PUT /orders/{orderId}/reject` - Reject payment
- `PUT /orders/{orderId}/cancel` - Cancel order
- `GET /orders/{orderId}` - Get order by ID

**Impact**: Core business functionality is broken - users cannot create orders or submit payments

### 2. Missing Statistics Endpoints
**Problem**: Statistics services implemented but no controller endpoints
- `GET /orders/statistics` - Order statistics
- `GET /orders/daily-summary` - Daily order summary

### 3. Video Lesson Management Incomplete
**Problem**: Only bulk lesson creation exists, missing individual lesson CRUD
- Missing: Update single lesson
- Missing: Delete single lesson
- Missing: Get lesson details

### 4. Course Status Management Missing
**Problem**: Course status enum exists but no endpoint to change status
- Missing: Publish/unpublish courses
- Missing: Archive courses

### 5. User Management Incomplete
**Problem**: Limited user management capabilities
- Missing: Admin user search and management
- Missing: Manual course access management
- Missing: User account controls

### 6. Order Status Issues
**Problem**: Order status flow confusion in cancellation
```java
// In OrderServiceImpl.cancelOrder()
order.setStatus(OrderStatus.REJECTED); // Should be CANCELLED status
```

### 7. Missing Notification System
**Problem**: Complete notification system is missing
- No notification controllers
- No real-time notifications
- No email/SMS integration

### 8. Security Gaps
**Problem**: Some endpoints lack proper authorization
- Course deletion endpoint has no @PreAuthorize annotation
- Missing rate limiting on critical endpoints

---

## 📋 Data Models

### Order Status Flow
```
PENDING → SUBMITTED → VERIFIED/REJECTED
    ↓
CANCELLED (currently using REJECTED - needs fix)
```

**Recommended Fix**: Add `CANCELLED` status to OrderStatus enum

### Payment Methods
- `BKASH`: bKash mobile payment
- `NAGAD`: Nagad mobile payment  
- `ROCKET`: Rocket mobile payment
- `BANK_TRANSFER`: Direct bank transfer

### Course Status
- `DRAFT`: Course is being created
- `PUBLISHED`: Course is available for purchase
- `ARCHIVED`: Course is no longer available

---

## � Priority Implementation Roadmap

### Phase 1: Critical Fixes (Immediate)
1. **Create missing Order controller endpoints**
2. **Fix order cancellation status logic**
3. **Add missing security annotations**
4. **Implement statistics endpoints**

### Phase 2: Core Features (Week 1-2)
1. **Complete video lesson management**
2. **Add course status management**
3. **Implement basic user management**
4. **Add course analytics endpoints**

### Phase 3: Enhanced Features (Week 3-4)
1. **Notification system implementation**
2. **Advanced analytics and reporting**
3. **System configuration management**
4. **Admin dashboard APIs**

### Phase 4: Advanced Features (Month 2)
1. **Real-time notifications**
2. **Advanced search and filtering**
3. **Bulk operations**
4. **Integration with external payment gateways**

---

## �🚨 Error Responses

### Standard Error Format
```json
{
  "success": false,
  "message": "Error description",
  "errorCode": "ERROR_CODE",
  "timestamp": "2025-09-03T10:30:00Z"
}
```

### Common Error Codes
- `VALIDATION_ERROR`: Input validation failed
- `UNAUTHORIZED`: Authentication required
- `FORBIDDEN`: Insufficient permissions
- `NOT_FOUND`: Resource not found
- `BUSINESS_ERROR`: Business logic violation
- `DUPLICATE_ORDER`: Order already exists for this course
- `PAYMENT_VERIFICATION_FAILED`: Payment verification failed
- `COURSE_ACCESS_DENIED`: User doesn't have access to course
- `ORDER_NOT_CANCELLABLE`: Order cannot be cancelled in current status

---

## 🔄 Business Workflows

### Course Purchase Flow
1. **Browse Courses**: `GET /courses/` (Public)
2. **Create Order**: `POST /orders` (User) - ⚠️ **MISSING**
3. **Submit Payment**: `PUT /orders/{orderId}/payment` (User) - ⚠️ **MISSING**
4. **Admin Verification**: `PUT /orders/{orderId}/approve` (Admin) - ⚠️ **MISSING**
5. **Access Course**: `GET /courses/{courseId}/content` (User)

### Payment Verification Flow
1. **User submits payment info** with transaction ID and phone number
2. **Admin searches orders**: `GET /orders/search?status=PENDING_VERIFICATION`
3. **Admin reviews payment details** and external payment system
4. **Admin approves**: `PUT /orders/{orderId}/approve` OR **Admin rejects**: `PUT /orders/{orderId}/reject`
5. **System automatically grants/denies course access**

---

## 📊 Rate Limiting
- **General API**: 100 requests per minute per IP
- **Authentication endpoints**: 10 requests per minute per IP
- **Payment submission**: 5 requests per minute per user

---

## 🔒 Security Features
- JWT access tokens (15 minutes expiry)
- Refresh tokens (7 days expiry)
- Secure HTTP-only refresh token cookies
- CORS protection
- Rate limiting with Bucket4j
- Input validation and sanitization
- MongoDB injection protection
- Role-based access control

---

## 📝 Request/Response Examples

### Create Order (Missing Implementation)
```http
POST /api/v1/orders
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "courseId": "64abc123def456789"
}
```

### Submit Payment (Missing Implementation)
```http
PUT /api/v1/orders/64def789abc123456/payment
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "paymentMethod": "BKASH",
  "transactionId": "TXN123456789",
  "phoneNumber": "01712345678",
  "paymentNote": "Payment for React Course"
}
```

### Approve Payment (Missing Implementation)
```http
PUT /api/v1/orders/64def789abc123456/approve
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "adminNote": "Payment verified successfully"
}
```

---

## 🎯 Admin Dashboard Endpoints

### Statistics (Need Controller Implementation)
- `GET /orders/statistics` - Order counts by status, total revenue
- `GET /orders/daily-summary?days=30` - Daily order and revenue summary
- `GET /courses/admin/all` - All courses with management options

### Management Workflows
- **Order Management**: Search, filter, approve/reject payments
- **Course Management**: Create, update, delete courses and lessons
- **User Management**: View user profiles and purchase history (through order search)

---

## 📱 Mobile App Support
All endpoints support mobile applications with:
- JWT token-based authentication
- Standardized JSON responses
- Proper HTTP status codes
- Comprehensive error handling
- Optimized payload sizes

---

## 🔧 Development Notes
- **Database**: MongoDB with optimized indexes
- **Framework**: Spring Boot 3.5.4 with Java 21
- **Security**: Spring Security with OAuth2
- **Documentation**: Self-documenting with comprehensive validation
- **Testing**: Unit and integration tests included
- **Monitoring**: Health checks and metrics endpoints
