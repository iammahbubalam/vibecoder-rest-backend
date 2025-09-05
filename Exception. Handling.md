# VibeCoder Rest Backend - Complete Exception Handling Strategy

## Table of Contents
1. [Current Issues Analysis](#current-issues-analysis)
2. [Recommended Custom Exceptions](#recommended-custom-exceptions)
3. [Exception Code Cleanup](#exception-code-cleanup)
4. [Enhanced Global Exception Handler](#enhanced-global-exception-handler)
5. [Implementation Guide](#implementation-guide)

---

## Current Issues Analysis

### 🚨 Major Problems Identified:

1. **Inconsistent Exception Usage**: 
   - Using `ValidationException` for business logic errors
   - Using `IllegalArgumentException` instead of custom exceptions
   - Missing specialized exceptions for specific domains

2. **Poor Exception Granularity**:
   - `ValidationException` is overused for different types of errors
   - No distinction between validation, authorization, and business rule violations

3. **Incomplete Exception Hierarchy**:
   - Missing exceptions for Orders, Auth, Courses, and System operations
   - No proper error codes for different scenarios

4. **Controller Exception Handling**:
   - Manual try-catch blocks instead of relying on global handler
   - Inconsistent error responses

---

## Recommended Custom Exceptions

### Core Exception Hierarchy

```java
// Base exception
BusinessException (already exists - good foundation)
├── ValidationException (exists but needs refactoring)
├── ResourceNotFoundException
├── DuplicateResourceException  
├── UnauthorizedAccessException
├── InsufficientPermissionException
└── OperationNotAllowedException

// Domain-specific exceptions
AuthenticationException
├── InvalidCredentialsException
├── TokenExpiredException  
├── TokenRevokedException
├── AccountDisabledException
└── SessionExpiredException

CourseException
├── CourseNotFoundException
├── CourseNotPublishedException
├── CourseAccessDeniedException
├── LessonNotFoundException
└── InvalidCourseStateException

OrderException
├── OrderNotFoundException
├── InvalidOrderStateException
├── PaymentException
│   ├── DuplicateTransactionException
│   ├── InvalidPaymentMethodException
│   └── PaymentVerificationException
└── OrderAuthorizationException

UserException
├── UserNotFoundException (exists)
├── EmailAlreadyExistsException
├── InvalidUserStateException
└── ProfileUpdateException

SystemException
├── ExternalServiceException
├── DatabaseException
├── CacheException
└── SchedulerException
```

### 1. Core Exceptions

```java
package com.notvibecoder.backend.core.exception;

import lombok.Getter;

// Resource Not Found Exception
@Getter
public class ResourceNotFoundException extends BusinessException {
    private final String resourceType;
    private final String resourceId;

    public ResourceNotFoundException(String resourceType, String resourceId) {
        super(String.format("%s not found with ID: %s", resourceType, resourceId), "RESOURCE_NOT_FOUND");
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }

    public ResourceNotFoundException(String resourceType, String resourceId, String message) {
        super(message, "RESOURCE_NOT_FOUND", resourceType, resourceId);
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }
}

// Duplicate Resource Exception
@Getter
public class DuplicateResourceException extends BusinessException {
    private final String resourceType;
    private final String conflictingField;
    private final String conflictingValue;

    public DuplicateResourceException(String resourceType, String conflictingField, String conflictingValue) {
        super(String.format("%s already exists with %s: %s", resourceType, conflictingField, conflictingValue), 
              "DUPLICATE_RESOURCE");
        this.resourceType = resourceType;
        this.conflictingField = conflictingField;
        this.conflictingValue = conflictingValue;
    }
}

// Unauthorized Access Exception
@Getter
public class UnauthorizedAccessException extends BusinessException {
    private final String resource;
    private final String action;
    private final String userId;

    public UnauthorizedAccessException(String resource, String action, String userId) {
        super(String.format("User %s is not authorized to %s resource: %s", userId, action, resource), 
              "UNAUTHORIZED_ACCESS");
        this.resource = resource;
        this.action = action;
        this.userId = userId;
    }
}

// Insufficient Permission Exception
@Getter
public class InsufficientPermissionException extends BusinessException {
    private final String requiredPermission;
    private final String currentPermission;

    public InsufficientPermissionException(String requiredPermission, String currentPermission) {
        super(String.format("Insufficient permission. Required: %s, Current: %s", requiredPermission, currentPermission), 
              "INSUFFICIENT_PERMISSION");
        this.requiredPermission = requiredPermission;
        this.currentPermission = currentPermission;
    }
}

// Operation Not Allowed Exception
@Getter
public class OperationNotAllowedException extends BusinessException {
    private final String operation;
    private final String currentState;
    private final String reason;

    public OperationNotAllowedException(String operation, String currentState, String reason) {
        super(String.format("Operation '%s' not allowed in current state '%s': %s", operation, currentState, reason), 
              "OPERATION_NOT_ALLOWED");
        this.operation = operation;
        this.currentState = currentState;
        this.reason = reason;
    }
}
```

### 2. Authentication Exceptions

```java
package com.notvibecoder.backend.core.exception.auth;

import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

// Invalid Credentials Exception
@Getter
public class InvalidCredentialsException extends BusinessException {
    private final String identifier;

    public InvalidCredentialsException(String identifier) {
        super("Invalid credentials provided", "INVALID_CREDENTIALS");
        this.identifier = identifier;
    }
}

// Token Expired Exception
@Getter
public class TokenExpiredException extends BusinessException {
    private final String tokenType;

    public TokenExpiredException(String tokenType) {
        super(String.format("%s token has expired", tokenType), "TOKEN_EXPIRED");
        this.tokenType = tokenType;
    }
}

// Token Revoked Exception
@Getter
public class TokenRevokedException extends BusinessException {
    private final String tokenType;
    private final String reason;

    public TokenRevokedException(String tokenType, String reason) {
        super(String.format("%s token has been revoked: %s", tokenType, reason), "TOKEN_REVOKED");
        this.tokenType = tokenType;
        this.reason = reason;
    }
}

// Account Disabled Exception
@Getter
public class AccountDisabledException extends BusinessException {
    private final String userId;

    public AccountDisabledException(String userId) {
        super("Account is disabled", "ACCOUNT_DISABLED");
        this.userId = userId;
    }
}

// Session Expired Exception
@Getter
public class SessionExpiredException extends BusinessException {
    private final String sessionId;

    public SessionExpiredException(String sessionId) {
        super("Session has expired. Please login again", "SESSION_EXPIRED");
        this.sessionId = sessionId;
    }
}
```

### 3. Course Exceptions

```java
package com.notvibecoder.backend.core.exception.course;

import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

// Course Not Found Exception
@Getter
public class CourseNotFoundException extends BusinessException {
    private final String courseId;

    public CourseNotFoundException(String courseId) {
        super(String.format("Course not found with ID: %s", courseId), "COURSE_NOT_FOUND");
        this.courseId = courseId;
    }
}

// Course Not Published Exception
@Getter
public class CourseNotPublishedException extends BusinessException {
    private final String courseId;

    public CourseNotPublishedException(String courseId) {
        super(String.format("Course %s is not published", courseId), "COURSE_NOT_PUBLISHED");
        this.courseId = courseId;
    }
}

// Course Access Denied Exception
@Getter
public class CourseAccessDeniedException extends BusinessException {
    private final String courseId;
    private final String userId;

    public CourseAccessDeniedException(String courseId, String userId) {
        super(String.format("User %s does not have access to course %s", userId, courseId), "COURSE_ACCESS_DENIED");
        this.courseId = courseId;
        this.userId = userId;
    }
}

// Lesson Not Found Exception
@Getter
public class LessonNotFoundException extends BusinessException {
    private final String lessonId;
    private final String courseId;

    public LessonNotFoundException(String lessonId, String courseId) {
        super(String.format("Lesson %s not found in course %s", lessonId, courseId), "LESSON_NOT_FOUND");
        this.lessonId = lessonId;
        this.courseId = courseId;
    }
}

// Invalid Course State Exception
@Getter
public class InvalidCourseStateException extends BusinessException {
    private final String courseId;
    private final String currentState;
    private final String requiredState;

    public InvalidCourseStateException(String courseId, String currentState, String requiredState) {
        super(String.format("Course %s is in state %s, but %s is required", courseId, currentState, requiredState), 
              "INVALID_COURSE_STATE");
        this.courseId = courseId;
        this.currentState = currentState;
        this.requiredState = requiredState;
    }
}
```

### 4. Order Exceptions

```java
package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

// Order Not Found Exception
@Getter
public class OrderNotFoundException extends BusinessException {
    private final String orderId;

    public OrderNotFoundException(String orderId) {
        super(String.format("Order not found with ID: %s", orderId), "ORDER_NOT_FOUND");
        this.orderId = orderId;
    }
}

// Invalid Order State Exception
@Getter
public class InvalidOrderStateException extends BusinessException {
    private final String orderId;
    private final String currentState;
    private final String requiredState;
    private final String operation;

    public InvalidOrderStateException(String orderId, String currentState, String requiredState, String operation) {
        super(String.format("Cannot %s order %s. Current state: %s, Required: %s", 
              operation, orderId, currentState, requiredState), "INVALID_ORDER_STATE");
        this.orderId = orderId;
        this.currentState = currentState;
        this.requiredState = requiredState;
        this.operation = operation;
    }
}

// Duplicate Transaction Exception
@Getter
public class DuplicateTransactionException extends BusinessException {
    private final String transactionId;

    public DuplicateTransactionException(String transactionId) {
        super(String.format("Transaction ID %s already exists", transactionId), "DUPLICATE_TRANSACTION");
        this.transactionId = transactionId;
    }
}

// Invalid Payment Method Exception
@Getter
public class InvalidPaymentMethodException extends BusinessException {
    private final String paymentMethod;

    public InvalidPaymentMethodException(String paymentMethod) {
        super(String.format("Invalid payment method: %s", paymentMethod), "INVALID_PAYMENT_METHOD");
        this.paymentMethod = paymentMethod;
    }
}

// Payment Verification Exception
@Getter
public class PaymentVerificationException extends BusinessException {
    private final String orderId;
    private final String reason;

    public PaymentVerificationException(String orderId, String reason) {
        super(String.format("Payment verification failed for order %s: %s", orderId, reason), 
              "PAYMENT_VERIFICATION_FAILED");
        this.orderId = orderId;
        this.reason = reason;
    }
}

// Order Authorization Exception
@Getter
public class OrderAuthorizationException extends BusinessException {
    private final String orderId;
    private final String userId;
    private final String action;

    public OrderAuthorizationException(String orderId, String userId, String action) {
        super(String.format("User %s is not authorized to %s order %s", userId, action, orderId), 
              "ORDER_AUTHORIZATION_FAILED");
        this.orderId = orderId;
        this.userId = userId;
        this.action = action;
    }
}
```

### 5. User Exceptions

```java
package com.notvibecoder.backend.core.exception.user;

import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

// Email Already Exists Exception
@Getter
public class EmailAlreadyExistsException extends BusinessException {
    private final String email;

    public EmailAlreadyExistsException(String email) {
        super(String.format("Email already exists: %s", email), "EMAIL_ALREADY_EXISTS");
        this.email = email;
    }
}

// Invalid User State Exception
@Getter
public class InvalidUserStateException extends BusinessException {
    private final String userId;
    private final String currentState;
    private final String operation;

    public InvalidUserStateException(String userId, String currentState, String operation) {
        super(String.format("Cannot %s user %s. Current state: %s", operation, userId, currentState), 
              "INVALID_USER_STATE");
        this.userId = userId;
        this.currentState = currentState;
        this.operation = operation;
    }
}

// Profile Update Exception
@Getter
public class ProfileUpdateException extends BusinessException {
    private final String userId;
    private final String field;

    public ProfileUpdateException(String userId, String field, String reason) {
        super(String.format("Failed to update %s for user %s: %s", field, userId, reason), "PROFILE_UPDATE_FAILED");
        this.userId = userId;
        this.field = field;
    }
}
```

### 6. System Exceptions

```java
package com.notvibecoder.backend.core.exception.system;

import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

// External Service Exception
@Getter
public class ExternalServiceException extends BusinessException {
    private final String serviceName;
    private final String operation;

    public ExternalServiceException(String serviceName, String operation, String message) {
        super(String.format("External service %s failed during %s: %s", serviceName, operation, message), 
              "EXTERNAL_SERVICE_ERROR");
        this.serviceName = serviceName;
        this.operation = operation;
    }

    public ExternalServiceException(String serviceName, String operation, Throwable cause) {
        super(String.format("External service %s failed during %s", serviceName, operation), 
              "EXTERNAL_SERVICE_ERROR", cause);
        this.serviceName = serviceName;
        this.operation = operation;
    }
}

// Database Exception
@Getter
public class DatabaseException extends BusinessException {
    private final String operation;
    private final String entity;

    public DatabaseException(String operation, String entity, String message) {
        super(String.format("Database operation %s failed for %s: %s", operation, entity, message), 
              "DATABASE_ERROR");
        this.operation = operation;
        this.entity = entity;
    }

    public DatabaseException(String operation, String entity, Throwable cause) {
        super(String.format("Database operation %s failed for %s", operation, entity), 
              "DATABASE_ERROR", cause);
        this.operation = operation;
        this.entity = entity;
    }
}

// Cache Exception
@Getter
public class CacheException extends BusinessException {
    private final String cacheKey;
    private final String operation;

    public CacheException(String operation, String cacheKey, String message) {
        super(String.format("Cache operation %s failed for key %s: %s", operation, cacheKey, message), 
              "CACHE_ERROR");
        this.operation = operation;
        this.cacheKey = cacheKey;
    }
}

// Scheduler Exception
@Getter
public class SchedulerException extends BusinessException {
    private final String jobName;

    public SchedulerException(String jobName, String message) {
        super(String.format("Scheduled job %s failed: %s", jobName, message), "SCHEDULER_ERROR");
        this.jobName = jobName;
    }

    public SchedulerException(String jobName, Throwable cause) {
        super(String.format("Scheduled job %s failed", jobName), "SCHEDULER_ERROR", cause);
        this.jobName = jobName;
    }
}
```

---

## Exception Code Cleanup

### Detailed Method-by-Method Exception Changes

#### 1. UserServiceImpl.java

**File**: `src/main/java/com/notvibecoder/backend/modules/user/service/UserServiceImpl.java`

##### Method: `findByEmail(String email)`
```java
// CURRENT (Line ~30):
return userRepository.findByEmail(email)
    .orElseThrow(() -> new UserNotFoundException("User not found: " + email));

// CHANGE TO:
return userRepository.findByEmail(email)
    .orElseThrow(() -> new UserNotFoundException(email));
```

##### Method: `findById(String id)`
```java
// CURRENT (Line ~49):
return userRepository.findById(id)
    .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + id));

// CHANGE TO:
return userRepository.findById(id)
    .orElseThrow(() -> new UserNotFoundException(id));
```

##### Method: `updateUserRole(String userId, String newRole)`
```java
// CURRENT (Lines 109-120):
if (userId == null || userId.trim().isEmpty()) {
    throw new IllegalArgumentException("User ID cannot be null or empty");
}
if (newRole == null || newRole.trim().isEmpty()) {
    throw new IllegalArgumentException("Role cannot be null or empty");
}
try {
    Role.valueOf(newRole.toUpperCase());
} catch (IllegalArgumentException e) {
    throw new IllegalArgumentException("Invalid role: " + newRole + ". Valid roles are: USER, ADMIN");
}

// CHANGE TO:
if (userId == null || userId.trim().isEmpty()) {
    throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
}
if (newRole == null || newRole.trim().isEmpty()) {
    throw new ValidationException("Role cannot be null or empty", "ROLE_REQUIRED");
}
try {
    Role.valueOf(newRole.toUpperCase());
} catch (IllegalArgumentException e) {
    throw new ValidationException("Invalid role: " + newRole + ". Valid roles are: USER, ADMIN", "INVALID_ROLE");
}
```

##### Method: `deleteUser(String userId)`
```java
// CURRENT (Line 146):
if (userId == null || userId.trim().isEmpty()) {
    throw new IllegalArgumentException("User ID cannot be null or empty");
}

// CHANGE TO:
if (userId == null || userId.trim().isEmpty()) {
    throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
}
```

##### Method: `getAllUsers(Pageable pageable)`
```java
// CURRENT (Line 177):
if (pageable == null) {
    throw new IllegalArgumentException("Pageable cannot be null");
}

// CHANGE TO:
if (pageable == null) {
    throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");
}
```

---

#### 2. OrderServiceImpl.java

**File**: `src/main/java/com/notvibecoder/backend/modules/order/service/OrderServiceImpl.java`

##### Method: `createOrder(String userId, String courseId)`
```java
// CURRENT (Lines 38-62):
if (userId == null || userId.trim().isEmpty()) {
    throw new ValidationException("User ID cannot be null or empty");
}
if (courseId == null || courseId.trim().isEmpty()) {
    throw new ValidationException("Course ID cannot be null or empty");
}

User user = userServiceImpl.findById(userId);
if (!user.getEnabled()) {
    throw new ValidationException("User account is disabled");
}

Course course = courseService.getCourse(courseId);
if (course == null || course.getStatus() != CourseStatus.PUBLISHED) {
    throw new ValidationException("Course is not available for purchase");
}

// Check if user already has access to this course
if (user.getPurchasedCourseIds().contains(courseId)) {
    throw new ValidationException("User already has access to this course");
}

// CHANGE TO:
if (userId == null || userId.trim().isEmpty()) {
    throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
}
if (courseId == null || courseId.trim().isEmpty()) {
    throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");
}

User user = userServiceImpl.findById(userId);
if (!user.getEnabled()) {
    throw new InvalidUserStateException(userId, "DISABLED", "create order");
}

Course course = courseService.getCourse(courseId);
if (course == null || course.getStatus() != CourseStatus.PUBLISHED) {
    throw new CourseNotPublishedException(courseId);
}

// Check if user already has access to this course
if (user.getPurchasedCourseIds().contains(courseId)) {
    throw new DuplicateResourceException("Order", "courseId", courseId);
}
```

##### Method: `createOrder(String userId, String courseId)` - Exception Handling
```java
// CURRENT (Lines 102-112):
} catch (DataIntegrityViolationException e) {
    log.warn("Duplicate order attempt for user: {} and course: {}", userId, courseId);
    throw new ValidationException("An order for this course already exists");
} catch (ValidationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error creating order for user: {} and course: {}: {}",
            userId, courseId, e.getMessage(), e);
    throw new ValidationException("Failed to create order: " + e.getMessage());
}

// CHANGE TO:
} catch (DataIntegrityViolationException e) {
    log.warn("Duplicate order attempt for user: {} and course: {}", userId, courseId);
    throw new DuplicateResourceException("Order", "courseId", courseId);
} catch (ValidationException | InvalidUserStateException | CourseNotPublishedException | DuplicateResourceException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error creating order for user: {} and course: {}: {}",
            userId, courseId, e.getMessage(), e);
    throw new DatabaseException("create", "Order", e);
}
```

##### Method: `submitPayment(String orderId, PaymentMethod paymentMethod, String transactionId, String phoneNumber, String paymentNote)`
```java
// CURRENT (Lines 123-149):
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty");
}
if (paymentMethod == null) {
    throw new ValidationException("Payment method is required");
}
if (transactionId == null || transactionId.trim().isEmpty()) {
    throw new ValidationException("Transaction ID is required");
}
if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
    throw new ValidationException("Phone number is required");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

if (order.getStatus() != OrderStatus.PENDING) {
    throw new ValidationException("Order is not in pending status. Current status: " + order.getStatus());
}

if (orderRepository.existsByTransactionIdAndStatus(transactionId, OrderStatus.PENDING)) {
    throw new ValidationException("Transaction ID already exists for another pending order");
}

// CHANGE TO:
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");
}
if (paymentMethod == null) {
    throw new ValidationException("Payment method is required", "PAYMENT_METHOD_REQUIRED");
}
if (transactionId == null || transactionId.trim().isEmpty()) {
    throw new ValidationException("Transaction ID is required", "TRANSACTION_ID_REQUIRED");
}
if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
    throw new ValidationException("Phone number is required", "PHONE_NUMBER_REQUIRED");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new OrderNotFoundException(orderId));

if (order.getStatus() != OrderStatus.PENDING) {
    throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "PENDING", "submit payment");
}

if (orderRepository.existsByTransactionIdAndStatus(transactionId, OrderStatus.PENDING)) {
    throw new DuplicateTransactionException(transactionId);
}
```

##### Method: `submitPayment(String orderId, ...)` - Exception Handling
```java
// CURRENT (Lines 170-180):
} catch (DataIntegrityViolationException e) {
    log.warn("Data integrity violation when submitting payment for order: {}", orderId);
    throw new ValidationException("Transaction ID already exists or duplicate payment submission");
} catch (ValidationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error submitting payment for order: {}: {}",
            orderId, e.getMessage(), e);
    throw new ValidationException("Failed to submit payment: " + e.getMessage());
}

// CHANGE TO:
} catch (DataIntegrityViolationException e) {
    log.warn("Data integrity violation when submitting payment for order: {}", orderId);
    throw new DuplicateTransactionException(transactionId);
} catch (ValidationException | OrderNotFoundException | InvalidOrderStateException | DuplicateTransactionException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error submitting payment for order: {}: {}",
            orderId, e.getMessage(), e);
    throw new DatabaseException("update", "Order", e);
}
```

##### Method: `cancelOrder(String orderId, String userId)`
```java
// CURRENT (Lines 189-210):
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty");
}
if (userId == null || userId.trim().isEmpty()) {
    throw new ValidationException("User ID cannot be null or empty");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

if (!order.getUserId().equals(userId)) {
    throw new ValidationException("You are not authorized to cancel this order");
}

if (order.getStatus() != OrderStatus.PENDING) {
    throw new ValidationException("Order cannot be cancelled. Current status: " + order.getStatus());
}

// CHANGE TO:
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");
}
if (userId == null || userId.trim().isEmpty()) {
    throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new OrderNotFoundException(orderId));

if (!order.getUserId().equals(userId)) {
    throw new OrderAuthorizationException(orderId, userId, "cancel");
}

if (order.getStatus() != OrderStatus.PENDING) {
    throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "PENDING", "cancel");
}
```

##### Method: `cancelOrder(String orderId, String userId)` - Exception Handling
```java
// CURRENT (Lines 223-228):
} catch (ValidationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error cancelling order: {}: {}",
            orderId, e.getMessage(), e);
    throw new ValidationException("Failed to cancel order: " + e.getMessage());
}

// CHANGE TO:
} catch (ValidationException | OrderNotFoundException | OrderAuthorizationException | InvalidOrderStateException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error cancelling order: {}: {}",
            orderId, e.getMessage(), e);
    throw new DatabaseException("update", "Order", e);
}
```

##### Method: `approvePayment(String orderId, String adminId, String adminNote)`
```java
// CURRENT (Lines 237-265):
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty");
}
if (adminId == null || adminId.trim().isEmpty()) {
    throw new ValidationException("Admin ID cannot be null or empty");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

User admin = userServiceImpl.findById(adminId);
if (!admin.getEnabled()) {
    throw new ValidationException("Admin account is disabled");
}

if (order.getStatus() != OrderStatus.SUBMITTED) {
    throw new ValidationException("Order cannot be approved. Current status: " + order.getStatus() +
            ". Only SUBMITTED orders can be approved.");
}

if (order.getTransactionId() == null || order.getTransactionId().trim().isEmpty()) {
    throw new ValidationException("Order does not have payment information to approve");
}

// CHANGE TO:
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");
}
if (adminId == null || adminId.trim().isEmpty()) {
    throw new ValidationException("Admin ID cannot be null or empty", "ADMIN_ID_REQUIRED");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new OrderNotFoundException(orderId));

User admin = userServiceImpl.findById(adminId);
if (!admin.getEnabled()) {
    throw new InvalidUserStateException(adminId, "DISABLED", "approve payment");
}

if (order.getStatus() != OrderStatus.SUBMITTED) {
    throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "SUBMITTED", "approve");
}

if (order.getTransactionId() == null || order.getTransactionId().trim().isEmpty()) {
    throw new PaymentVerificationException(orderId, "No payment information available");
}
```

##### Method: `approvePayment(String orderId, String adminId, String adminNote)` - Exception Handling
```java
// CURRENT (Lines 293-298):
} catch (ValidationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error approving payment for order: {} by admin: {}: {}",
            orderId, adminId, e.getMessage(), e);
    throw new ValidationException("Failed to approve payment: " + e.getMessage());
}

// CHANGE TO:
} catch (ValidationException | OrderNotFoundException | InvalidUserStateException | InvalidOrderStateException | PaymentVerificationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error approving payment for order: {} by admin: {}: {}",
            orderId, adminId, e.getMessage(), e);
    throw new DatabaseException("update", "Order", e);
}
```

##### Method: `rejectPayment(String orderId, String adminId, String rejectionReason)`
```java
// CURRENT (Lines 307-332):
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty");
}
if (adminId == null || adminId.trim().isEmpty()) {
    throw new ValidationException("Admin ID cannot be null or empty");
}
if (rejectionReason == null || rejectionReason.trim().isEmpty()) {
    throw new ValidationException("Rejection reason is required");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

User admin = userServiceImpl.findById(adminId);
if (!admin.getEnabled()) {
    throw new ValidationException("Admin account is disabled");
}

if (order.getStatus() != OrderStatus.SUBMITTED) {
    throw new ValidationException("Order cannot be rejected. Current status: " + order.getStatus() +
            ". Only SUBMITTED orders can be rejected.");
}

// CHANGE TO:
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");
}
if (adminId == null || adminId.trim().isEmpty()) {
    throw new ValidationException("Admin ID cannot be null or empty", "ADMIN_ID_REQUIRED");
}
if (rejectionReason == null || rejectionReason.trim().isEmpty()) {
    throw new ValidationException("Rejection reason is required", "REJECTION_REASON_REQUIRED");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new OrderNotFoundException(orderId));

User admin = userServiceImpl.findById(adminId);
if (!admin.getEnabled()) {
    throw new InvalidUserStateException(adminId, "DISABLED", "reject payment");
}

if (order.getStatus() != OrderStatus.SUBMITTED) {
    throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "SUBMITTED", "reject");
}
```

##### Method: `rejectPayment(String orderId, String adminId, String rejectionReason)` - Exception Handling
```java
// CURRENT (Lines 358-364):
} catch (ValidationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error rejecting payment for order: {} by admin: {}: {}",
            orderId, adminId, e.getMessage(), e);
    throw new ValidationException("Failed to reject payment: " + e.getMessage());
}

// CHANGE TO:
} catch (ValidationException | OrderNotFoundException | InvalidUserStateException | InvalidOrderStateException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error rejecting payment for order: {} by admin: {}: {}",
            orderId, adminId, e.getMessage(), e);
    throw new DatabaseException("update", "Order", e);
}
```

##### Method: `getOrder(String orderId, String userId)`
```java
// CURRENT (Lines 460-465):
Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

if (!order.getUserId().equals(userId)) {
    throw new ValidationException("You are not authorized to view this order");
}

// CHANGE TO:
Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new OrderNotFoundException(orderId));

if (!order.getUserId().equals(userId)) {
    throw new OrderAuthorizationException(orderId, userId, "view");
}
```

##### Method: `getOrder(String orderId, String userId)` - Exception Handling
```java
// CURRENT (Lines 469-475):
} catch (ValidationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error retrieving order: {} for user: {}: {}",
            orderId, userId, e.getMessage(), e);
    throw new ValidationException("Failed to retrieve order: " + e.getMessage());
}

// CHANGE TO:
} catch (OrderNotFoundException | OrderAuthorizationException e) {
    throw e;
} catch (Exception e) {
    log.error("Unexpected error retrieving order: {} for user: {}: {}",
            orderId, userId, e.getMessage(), e);
    throw new DatabaseException("retrieve", "Order", e);
}
```

---

#### 3. CourseServiceImpl.java

**File**: `src/main/java/com/notvibecoder/backend/modules/courses/service/CourseServiceImpl.java`

##### Method: `getCourse(String courseId)`
```java
// CURRENT (Line 57):
return courseRepository.findById(courseId).orElseThrow(() -> new ValidationException("Course not found with ID: " + courseId));

// CHANGE TO:
return courseRepository.findById(courseId).orElseThrow(() -> new CourseNotFoundException(courseId));
```

##### Method: `updateCourse(String courseId, Course course)`
```java
// CURRENT (Lines 89-104):
if (courseId == null || courseId.trim().isEmpty()) {
    throw new ValidationException("Course ID cannot be null or empty");
}
if (course == null) {
    throw new ValidationException("Course data cannot be null");
}
if (course.getPrice() != null && course.getPrice().compareTo(BigDecimal.ZERO) < 0) {
    throw new ValidationException("Price cannot be negative");
}

Course existingCourse = courseRepository.findById(courseId)
    .orElseThrow(() -> new ValidationException("Course not found with ID: " + courseId));

// CHANGE TO:
if (courseId == null || courseId.trim().isEmpty()) {
    throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");
}
if (course == null) {
    throw new ValidationException("Course data cannot be null", "COURSE_DATA_REQUIRED");
}
if (course.getPrice() != null && course.getPrice().compareTo(BigDecimal.ZERO) < 0) {
    throw new ValidationException("Price cannot be negative", "INVALID_PRICE");
}

Course existingCourse = courseRepository.findById(courseId)
    .orElseThrow(() -> new CourseNotFoundException(courseId));
```

##### Method: `updateCourse(String courseId, Course course)` - Exception Handling
```java
// CURRENT (Lines 117-126):
} catch (DataAccessException e) {
    log.error("Failed to update course with ID {}: {}", courseId, e.getMessage());
    throw new CourseCreationException("Failed to update course", e);
} catch (Exception e) {
    log.error("Unexpected error while updating course with ID {}: {}", courseId, e.getMessage());
    throw new CourseCreationException("Unexpected error occurred while updating course", e);
}

// CHANGE TO:
} catch (DataAccessException e) {
    log.error("Failed to update course with ID {}: {}", courseId, e.getMessage());
    throw new DatabaseException("update", "Course", e);
} catch (Exception e) {
    log.error("Unexpected error while updating course with ID {}: {}", courseId, e.getMessage());
    throw new DatabaseException("update", "Course", e);
}
```

##### Method: `saveVideoLessonsAndUpdateCourse(String courseId, List<VideoLesson> lessons)`
```java
// CURRENT (Line 150):
.orElseThrow(() -> new ValidationException("Course not found with ID: " + courseId));

// CHANGE TO:
.orElseThrow(() -> new CourseNotFoundException(courseId));
```

##### Method: `deleteCourse(String courseId)` - Exception Handling
```java
// CURRENT (Lines 157-166):
} catch (DataAccessException e) {
    log.error("Failed to delete course with ID {}: {}", courseId, e.getMessage());
    throw new CourseCreationException("Failed to delete course", e);
} catch (Exception e) {
    log.error("Unexpected error while deleting course with ID {}: {}", courseId, e.getMessage());
    throw new CourseCreationException("Unexpected error occurred while deleting course", e);
}

// CHANGE TO:
} catch (DataAccessException e) {
    log.error("Failed to delete course with ID {}: {}", courseId, e.getMessage());
    throw new DatabaseException("delete", "Course", e);
} catch (Exception e) {
    log.error("Unexpected error while deleting course with ID {}: {}", courseId, e.getMessage());
    throw new DatabaseException("delete", "Course", e);
}
```

##### Method: `getAllCourses()` - Exception Handling
```java
// CURRENT (Lines 172-179):
} catch (DataAccessException e) {
    log.error("Failed to retrieve all courses: {}", e.getMessage());
    throw new CourseCreationException("Failed to retrieve all courses", e);
} catch (Exception e) {
    log.error("Unexpected error while retrieving all courses: {}", e.getMessage());
    throw new CourseCreationException("Unexpected error occurred while retrieving all courses", e);
}

// CHANGE TO:
} catch (DataAccessException e) {
    log.error("Failed to retrieve all courses: {}", e.getMessage());
    throw new DatabaseException("retrieve", "Course", e);
} catch (Exception e) {
    log.error("Unexpected error while retrieving all courses: {}", e.getMessage());
    throw new DatabaseException("retrieve", "Course", e);
}
```

##### Method: `getVideoLesson(String courseId, String lessonId)`
```java
// CURRENT (Line 185):
.orElseThrow(() -> new ValidationException("Video lesson not found with courseId: " + courseId + " and lessonId: " + lessonId));

// CHANGE TO:
.orElseThrow(() -> new LessonNotFoundException(lessonId, courseId));
```

##### Method: `getAllLessonsByCourseId(String courseId)`
```java
// CURRENT (Lines 195-199):
if (lessons.isEmpty()) {
    throw new ValidationException("No lessons found for course ID: " + courseId);
} else {
    return lessons;
}

// CHANGE TO:
if (lessons.isEmpty()) {
    throw new LessonNotFoundException("any", courseId);
} else {
    return lessons;
}
```

##### Method: `updateVideoLesson(String courseId, String lessonId, VideoLesson lesson)`
```java
// CURRENT (Line 212):
).orElseThrow(() -> new ValidationException("Video lesson not found with courseId: " + courseId + " and lessonId: " + lessonId));

// CHANGE TO:
).orElseThrow(() -> new LessonNotFoundException(lessonId, courseId));
```

##### Method: `getVideoLessonsWithFreePreview(String courseId)`
```java
// CURRENT (Lines 220-222):
if (lessons.isEmpty()) {
    throw new ValidationException("No free preview lessons found for course ID: " + courseId);
}

// CHANGE TO:
if (lessons.isEmpty()) {
    throw new LessonNotFoundException("free preview", courseId);
}
```

##### Method: `updateCourseStatus(String courseId, CourseStatus status)`
```java
// CURRENT (Lines 38-41):
Course course = courseRepository.findById(courseId)
    .orElseThrow(() -> new ValidationException("Course not found with ID: " + courseId));

// CHANGE TO:
Course course = courseRepository.findById(courseId)
    .orElseThrow(() -> new CourseNotFoundException(courseId));
```

##### Method: `createCourse(Course course)` - Exception Handling
```java
// CURRENT (Lines 74-77):
} catch (DataAccessException e) {
    log.error("Failed to create course: {}", e.getMessage());
    throw new CourseCreationException("Failed to create course", e);
}

// CHANGE TO:
} catch (DataAccessException e) {
    log.error("Failed to create course: {}", e.getMessage());
    throw new DatabaseException("create", "Course", e);
}
```

---

#### 4. AuthService.java and Related Classes

**File**: `src/main/java/com/notvibecoder/backend/modules/auth/service/AuthService.java`

##### Method: `refreshUser(String requestRefreshToken, HttpServletRequest request)`
```java
// CURRENT (Lines 33-38):
.map(oldToken -> {
    var user = userRepository.findById(oldToken.getUserId())
        .orElseThrow(() -> new TokenRefreshException("User not found for refresh token."));
    if (!user.getEnabled()) {
        sessionManagementService.revokeUserSessions(oldToken);
        throw new TokenRefreshException("User account is disabled.");
    }

// CHANGE TO:
.map(oldToken -> {
    var user = userRepository.findById(oldToken.getUserId())
        .orElseThrow(() -> new UserNotFoundException(oldToken.getUserId()));
    if (!user.getEnabled()) {
        sessionManagementService.revokeUserSessions(oldToken);
        throw new AccountDisabledException(oldToken.getUserId());
    }
```

##### Method: `refreshUser(String requestRefreshToken, HttpServletRequest request)` - Final Exception
```java
// CURRENT (Line 44):
.orElseThrow(() -> new TokenRefreshException("Refresh token not found in database."));

// CHANGE TO:
.orElseThrow(() -> new TokenExpiredException("refresh"));
```

**File**: `src/main/java/com/notvibecoder/backend/modules/auth/service/RefreshTokenService.java`

##### Method: `verifyRefreshToken(RefreshToken token, HttpServletRequest request)`
```java
// CURRENT (Lines 59-61):
String reason = isRevoked(token) ? "revoked" : isExpired(token) ? "expired" : "invalid_device";
log.warn("Invalid refresh token for user {}: {}", token.getUserId(), reason);
throw new TokenRefreshException("Refresh token is " + reason + ". Please log in again.");

// CHANGE TO:
if (isRevoked(token)) {
    throw new TokenRevokedException("refresh", "User session was terminated");
} else if (isExpired(token)) {
    throw new TokenExpiredException("refresh");
} else {
    throw new SessionExpiredException(token.getToken().substring(0, 8));
}
```

**File**: `src/main/java/com/notvibecoder/backend/modules/auth/security/CustomOAuth2UserService.java`

##### Method: `createNewUser(OAuth2UserInfo userInfo, String registrationId)` - Exception Handling
```java
// CURRENT (Lines 159-163):
} catch (DuplicateKeyException e) {
    log.warn("Duplicate key detected for email: {}. Attempting to find existing user.", email);
    return userRepository.findByEmail(email)
        .orElseThrow(() -> new OAuth2AuthenticationProcessingException(
                "User creation failed due to race condition", e));

// CHANGE TO:
} catch (DuplicateKeyException e) {
    log.warn("Duplicate key detected for email: {}. Attempting to find existing user.", email);
    return userRepository.findByEmail(email)
        .orElseThrow(() -> new EmailAlreadyExistsException(email));
```

##### Method: `createNewUser(OAuth2UserInfo userInfo, String registrationId)` - Final Exception
```java
// CURRENT (Lines 164-166):
} catch (Exception e) {
    log.error("Failed to create new user: {}", email, e);
    throw new OAuth2AuthenticationProcessingException("User creation failed", e);
}

// CHANGE TO:
} catch (Exception e) {
    log.error("Failed to create new user: {}", email, e);
    throw new DatabaseException("create", "User", e);
}
```

---

#### 5. System and Scheduler Classes

**File**: `src/main/java/com/notvibecoder/backend/modules/system/schedular/TokenCleanupScheduler.java`

##### Method: `cleanupExpiredTokens()`
```java
// CURRENT (Lines 31-33):
} catch (Exception e) {
    log.error("Error during token cleanup: {}", e.getMessage());
}

// CHANGE TO:
} catch (Exception e) {
    log.error("Error during token cleanup: {}", e.getMessage());
    throw new SchedulerException("token-cleanup", e);
}
```

**File**: `src/main/java/com/notvibecoder/backend/modules/auth/service/JwtBlacklistService.java`

##### Method: `cleanupExpiredTokens()`
```java
// CURRENT (Lines 70-72):
} catch (Exception e) {
    log.error("Error cleaning up expired blacklisted tokens: {}", e.getMessage());
}

// CHANGE TO:
} catch (Exception e) {
    log.error("Error cleaning up expired blacklisted tokens: {}", e.getMessage());
    throw new CacheException("cleanup", "blacklisted-tokens", e.getMessage());
}
```

---

### Import Statements to Add

For each modified file, you'll need to add these imports:

#### UserServiceImpl.java
```java
import com.notvibecoder.backend.core.exception.user.InvalidUserStateException;
```

#### OrderServiceImpl.java
```java
import com.notvibecoder.backend.core.exception.order.*;
import com.notvibecoder.backend.core.exception.course.CourseNotPublishedException;
import com.notvibecoder.backend.core.exception.user.InvalidUserStateException;
import com.notvibecoder.backend.core.exception.system.DatabaseException;
```

#### CourseServiceImpl.java
```java
import com.notvibecoder.backend.core.exception.course.*;
import com.notvibecoder.backend.core.exception.system.DatabaseException;
```

#### AuthService.java
```java
import com.notvibecoder.backend.core.exception.auth.*;
import com.notvibecoder.backend.core.exception.user.EmailAlreadyExistsException;
import com.notvibecoder.backend.core.exception.system.DatabaseException;
```

#### RefreshTokenService.java
```java
import com.notvibecoder.backend.core.exception.auth.*;
```

#### CustomOAuth2UserService.java
```java
import com.notvibecoder.backend.core.exception.user.EmailAlreadyExistsException;
import com.notvibecoder.backend.core.exception.system.DatabaseException;
```

#### TokenCleanupScheduler.java
```java
import com.notvibecoder.backend.core.exception.system.SchedulerException;
```

#### JwtBlacklistService.java
```java
import com.notvibecoder.backend.core.exception.system.CacheException;
```

---

### Files to Replace/Remove:

1. **Replace ValidationException Usage**:
   - `UserServiceImpl.java` lines 109, 113, 120, 146, 177
   - `OrderServiceImpl.java` - Almost all ValidationException usage
   - `CourseServiceImpl.java` - ValidationException for business rules

2. **Remove IllegalArgumentException Usage**:
   - `UserServiceImpl.java` - Replace with proper validation exceptions

3. **Update Exception Throws**:
   - `CourseCreationException` → `CourseException` hierarchy
   - `DuplicateCourseException` → `DuplicateResourceException`
   - `TokenRefreshException` → Auth exception hierarchy

### Specific Replacements:

#### In UserServiceImpl.java:
```java
// BEFORE:
throw new IllegalArgumentException("User ID cannot be null or empty");

// AFTER:
throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
```

#### In OrderServiceImpl.java:
```java
// BEFORE:
throw new ValidationException("Order not found with ID: " + orderId);

// AFTER:
throw new OrderNotFoundException(orderId);

// BEFORE:
throw new ValidationException("You are not authorized to cancel this order");

// AFTER:
throw new OrderAuthorizationException(orderId, userId, "cancel");

// BEFORE:
throw new ValidationException("Order cannot be cancelled. Current status: " + order.getStatus());

// AFTER:
throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "PENDING", "cancel");
```

#### In CourseServiceImpl.java:
```java
// BEFORE:
throw new ValidationException("Course not found with ID: " + courseId);

// AFTER:
throw new CourseNotFoundException(courseId);

// BEFORE:
throw new ValidationException("Video lesson not found with courseId: " + courseId + " and lessonId: " + lessonId);

// AFTER:
throw new LessonNotFoundException(lessonId, courseId);
```

---

## Enhanced Global Exception Handler

```java
package com.notvibecoder.backend.modules.common.controller.advice;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.core.exception.*;
import com.notvibecoder.backend.core.exception.auth.*;
import com.notvibecoder.backend.core.exception.course.*;
import com.notvibecoder.backend.core.exception.order.*;
import com.notvibecoder.backend.core.exception.user.*;
import com.notvibecoder.backend.core.exception.system.*;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    // ==================== BUSINESS EXCEPTIONS ====================

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBusinessException(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Business exception [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== RESOURCE EXCEPTIONS ====================

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleResourceNotFound(
            ResourceNotFoundException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Resource not found [{}]: {} - Type: {}, ID: {}", 
                correlationId, ex.getMessage(), ex.getResourceType(), ex.getResourceId());

        Map<String, Object> details = Map.of(
                "resourceType", ex.getResourceType(),
                "resourceId", ex.getResourceId()
        );

        ApiResponse<Map<String, Object>> response = ApiResponse.<Map<String, Object>>builder()
                .success(false)
                .message(ex.getMessage())
                .data(details)
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleDuplicateResource(
            DuplicateResourceException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Duplicate resource [{}]: {} - Type: {}, Field: {}, Value: {}", 
                correlationId, ex.getMessage(), ex.getResourceType(), ex.getConflictingField(), ex.getConflictingValue());

        Map<String, Object> details = Map.of(
                "resourceType", ex.getResourceType(),
                "conflictingField", ex.getConflictingField(),
                "conflictingValue", ex.getConflictingValue()
        );

        ApiResponse<Map<String, Object>> response = ApiResponse.<Map<String, Object>>builder()
                .success(false)
                .message(ex.getMessage())
                .data(details)
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    // ==================== AUTHENTICATION EXCEPTIONS ====================

    @ExceptionHandler({InvalidCredentialsException.class, TokenExpiredException.class, 
                      TokenRevokedException.class, AccountDisabledException.class, SessionExpiredException.class})
    public ResponseEntity<ApiResponse<Void>> handleAuthenticationExceptions(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Authentication exception [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    // ==================== AUTHORIZATION EXCEPTIONS ====================

    @ExceptionHandler({UnauthorizedAccessException.class, InsufficientPermissionException.class, 
                      OrderAuthorizationException.class, CourseAccessDeniedException.class})
    public ResponseEntity<ApiResponse<Void>> handleAuthorizationExceptions(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Authorization exception [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // ==================== COURSE EXCEPTIONS ====================

    @ExceptionHandler({CourseNotFoundException.class, LessonNotFoundException.class})
    public ResponseEntity<ApiResponse<Void>> handleCourseNotFound(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Course/Lesson not found [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({CourseNotPublishedException.class, InvalidCourseStateException.class})
    public ResponseEntity<ApiResponse<Void>> handleInvalidCourseState(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Invalid course state [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== ORDER EXCEPTIONS ====================

    @ExceptionHandler(OrderNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleOrderNotFound(
            OrderNotFoundException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Order not found [{}]: {} - OrderID: {}", correlationId, ex.getMessage(), ex.getOrderId());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({InvalidOrderStateException.class, OperationNotAllowedException.class})
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleInvalidOrderState(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Invalid order state [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        Map<String, Object> details = new HashMap<>();
        if (ex instanceof InvalidOrderStateException orderEx) {
            details.put("orderId", orderEx.getOrderId());
            details.put("currentState", orderEx.getCurrentState());
            details.put("requiredState", orderEx.getRequiredState());
            details.put("operation", orderEx.getOperation());
        }

        ApiResponse<Map<String, Object>> response = ApiResponse.<Map<String, Object>>builder()
                .success(false)
                .message(ex.getMessage())
                .data(details)
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({DuplicateTransactionException.class, InvalidPaymentMethodException.class, 
                      PaymentVerificationException.class})
    public ResponseEntity<ApiResponse<Void>> handlePaymentExceptions(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Payment exception [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== USER EXCEPTIONS ====================

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(
            UserNotFoundException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("User not found [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({EmailAlreadyExistsException.class, InvalidUserStateException.class, ProfileUpdateException.class})
    public ResponseEntity<ApiResponse<Void>> handleUserExceptions(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("User exception [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== SYSTEM EXCEPTIONS ====================

    @ExceptionHandler({ExternalServiceException.class, CacheException.class, SchedulerException.class})
    public ResponseEntity<ApiResponse<Void>> handleSystemExceptions(
            BusinessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.error("System exception [{}]: {} - Code: {}", correlationId, ex.getMessage(), ex.getErrorCode(), ex);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("A system error occurred. Please try again later.")
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(DatabaseException.class)
    public ResponseEntity<ApiResponse<Void>> handleDatabaseException(
            DatabaseException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.error("Database exception [{}]: {} - Operation: {}, Entity: {}", 
                correlationId, ex.getMessage(), ex.getOperation(), ex.getEntity(), ex);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("A database error occurred. Please try again later.")
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ==================== VALIDATION EXCEPTIONS ====================

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationException(
            ValidationException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Validation exception [{}]: {} - Field errors: {}", correlationId, ex.getMessage(), ex.getFieldErrors());

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .message(ex.getMessage())
                .data(ex.getFieldErrors())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        log.warn("Method argument validation error [{}]: {}", correlationId, errors);

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .message("Validation failed")
                .data(errors)
                .errorCode("VALIDATION_ERROR")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleConstraintViolation(
            ConstraintViolationException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        Map<String, String> violations = new HashMap<>();

        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            violations.put(violation.getPropertyPath().toString(), violation.getMessage());
        }

        log.warn("Constraint violation [{}]: {}", correlationId, violations);

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .message("Constraint validation failed")
                .data(violations)
                .errorCode("CONSTRAINT_VIOLATION")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== DATA ACCESS EXCEPTIONS ====================

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataIntegrityViolation(
            DataIntegrityViolationException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Data integrity violation [{}]: {}", correlationId, ex.getMessage());

        String message = "Data integrity constraint violated. Please check your input.";
        if (ex.getMessage() != null) {
            if (ex.getMessage().contains("duplicate key") || ex.getMessage().contains("Duplicate entry")) {
                message = "Duplicate entry. Resource already exists.";
            }
        }

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(message)
                .errorCode("DATA_INTEGRITY_VIOLATION")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataAccessException(
            DataAccessException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.error("Data access exception [{}]: {}", correlationId, ex.getMessage(), ex);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("Database operation failed. Please try again later.")
                .errorCode("DATA_ACCESS_ERROR")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ==================== SECURITY EXCEPTIONS ====================

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Access denied [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("Access denied")
                .errorCode("ACCESS_DENIED")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Authentication failed [{}]: Bad credentials", correlationId);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("Authentication failed")
                .errorCode("BAD_CREDENTIALS")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.warn("Authentication exception [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("Authentication failed")
                .errorCode("AUTHENTICATION_FAILED")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    // ==================== TYPE MISMATCH EXCEPTIONS ====================

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponse<Void>> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        String message = String.format("Invalid value '%s' for parameter '%s'", ex.getValue(), ex.getName());

        log.warn("Type mismatch [{}]: {}", correlationId, message);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(message)
                .errorCode("TYPE_MISMATCH")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== GENERIC EXCEPTION ====================

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(
            Exception ex, WebRequest request) {

        String correlationId = generateCorrelationId();
        log.error("Unexpected error [{}]: {}", correlationId, ex.getMessage(), ex);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("An internal server error occurred")
                .errorCode("INTERNAL_ERROR")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ==================== HELPER METHODS ====================

    private String generateCorrelationId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
```

---

## Implementation Guide

### Phase 1: Create New Exception Classes (Priority: High)
1. Create the exception hierarchy packages and classes as shown above
2. Test each exception class with unit tests

### Phase 2: Update Service Layer (Priority: High)
1. **UserServiceImpl.java**:
   - Replace `IllegalArgumentException` with `ValidationException`
   - Replace generic `UserNotFoundException` usage with proper error codes

2. **OrderServiceImpl.java**:
   - Replace `ValidationException("Order not found...")` with `OrderNotFoundException`
   - Replace authorization ValidationExceptions with `OrderAuthorizationException`
   - Replace state validation with `InvalidOrderStateException`
   - Replace transaction duplicate checks with `DuplicateTransactionException`

3. **CourseServiceImpl.java**:
   - Replace `ValidationException("Course not found...")` with `CourseNotFoundException`
   - Replace `ValidationException("Video lesson not found...")` with `LessonNotFoundException`
   - Replace `CourseCreationException` with appropriate course exceptions

4. **AuthService & Related Classes**:
   - Update `TokenRefreshException` to use auth exception hierarchy
   - Replace generic exceptions with specific auth exceptions

### Phase 3: Update Global Exception Handler (Priority: Medium)
1. Replace the existing `GlobalExceptionHandler` with the enhanced version
2. Test all exception mappings
3. Verify proper HTTP status codes and response formats

### Phase 4: Remove Manual Controller Exception Handling (Priority: Medium)
1. **OrderController.java**:
   - Remove try-catch blocks and let global handler manage exceptions
   - Keep only business logic in controllers

2. **AuthController.java**:
   - Remove manual exception handling
   - Let global handler manage all exception responses

3. **UserController.java**:
   - Similar cleanup of manual exception handling

### Phase 5: Update Exception Classes to Remove (Priority: Low)
1. Remove or refactor:
   - `DuplicateCourseException` → Use `DuplicateResourceException`
   - `CourseCreationException` → Use appropriate course exceptions
   - `TokenRefreshException` → Use auth exception hierarchy

### Phase 6: Testing & Validation (Priority: High)
1. **Unit Tests**: Create tests for each new exception class
2. **Integration Tests**: Test exception handling through controllers
3. **API Documentation**: Update API docs with new error codes and responses

### Example Service Layer Changes

#### Before (OrderServiceImpl.java):
```java
// CURRENT - PROBLEMATIC
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new ValidationException("Order not found with ID: " + orderId));

if (!order.getUserId().equals(userId)) {
    throw new ValidationException("You are not authorized to cancel this order");
}

if (order.getStatus() != OrderStatus.PENDING) {
    throw new ValidationException("Order cannot be cancelled. Current status: " + order.getStatus());
}
```

#### After (OrderServiceImpl.java):
```java
// IMPROVED - SPECIFIC EXCEPTIONS
if (orderId == null || orderId.trim().isEmpty()) {
    throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");
}

Order order = orderRepository.findById(orderId)
    .orElseThrow(() -> new OrderNotFoundException(orderId));

if (!order.getUserId().equals(userId)) {
    throw new OrderAuthorizationException(orderId, userId, "cancel");
}

if (order.getStatus() != OrderStatus.PENDING) {
    throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "PENDING", "cancel");
}
```

### Benefits of This Approach:

1. **Clear Error Categorization**: Each exception type has a specific purpose
2. **Better Client Handling**: Frontend can handle different error types appropriately
3. **Improved Debugging**: More specific error information for troubleshooting
4. **Consistent Error Responses**: Uniform error format across the entire application
5. **Better Logging**: More structured and searchable logs
6. **Scalable**: Easy to add new exception types as the application grows

### Migration Timeline:
- **Week 1**: Create new exception classes and test them
- **Week 2**: Update service layers (UserService, OrderService, CourseService)
- **Week 3**: Update global exception handler and remove controller try-catch blocks
- **Week 4**: Testing, documentation, and final cleanup

This comprehensive exception handling strategy will significantly improve your application's error handling, debugging capabilities, and overall code quality.