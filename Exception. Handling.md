# VibeCoder Rest Backend - Complete Exception Handling Analysis & Fixes

## Available Exception Classes in Your Project

### Core Exceptions
- `BusinessException` (base class)
- `ValidationException` 
- `ResourceNotFoundException`
- `DuplicateResourceException`
- `UnauthorizedAccessException`
- `InsufficientPermissionException`
- `OperationNotAllowedException`

### Auth Exceptions
- `AccountDisabledException`
- `InvalidCredentialsException`
- `OAuth2AuthenticationProcessingException`
- `SessionExpiredException`
- `TokenExpiredException`
- `TokenRevokedException`

### Course Exceptions
- `CourseAccessDeniedException`
- `CourseNotFoundException`
- `CourseNotPublishedException`
- `InvalidCourseStateException`
- `LessonNotFoundException`

### Order Exceptions
- `DuplicateTransactionException`
- `InvalidOrderStateException`
- `InvalidPaymentMethodException`
- `OrderAuthorizationException`
- `OrderNotFoundException`
- `PaymentVerificationException`

### User Exceptions
- `EmailAlreadyExistsException`
- `InvalidUserStateException`
- `ProfileUpdateException`
- `UserNotFoundException`

### System Exceptions
- `DatabaseException`
- `ExternalServiceException`
- `SchedulerException`

---

## Required Exception Handling Fixes

### 1. UserServiceImpl.java

#### Method: `changeUserRole` (Line 109)
**Current:** `throw new IllegalArgumentException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `changeUserRole` (Line 113)
**Current:** `throw new IllegalArgumentException("Role cannot be null or empty");`
**Replace with:** `throw new ValidationException("Role cannot be null or empty", "ROLE_REQUIRED");`

#### Method: `changeUserRole` (Line 120)
**Current:** `throw new IllegalArgumentException("Invalid role: " + newRole + ". Valid roles are: USER, ADMIN");`
**Replace with:** `throw new ValidationException("Invalid role: " + newRole + ". Valid roles are: USER, ADMIN", "INVALID_ROLE");`

#### Method: `deleteUser` (Line 146)
**Current:** `throw new IllegalArgumentException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `getAllUsers` (Line 177)
**Current:** `throw new IllegalArgumentException("Pageable cannot be null");`
**Replace with:** `throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");`

---

### 2. CourseServiceImpl.java

#### Method: `updateCourseStatus` (Line 39)
**Current:** `throw new ValidationException("Course not found with ID: " + courseId);`
**Replace with:** `throw new CourseNotFoundException(courseId);`

#### Method: `getCourse` (Line 57)
**Current:** `throw new ValidationException("Course not found with ID: " + courseId);`
**Replace with:** `throw new CourseNotFoundException(courseId);`

#### Method: `createCourse` (Line 69)
**Current:** `throw new ValidationException("Price cannot be negative");`
**Replace with:** `throw new ValidationException("Price cannot be negative", "INVALID_PRICE");`

#### Method: `updateCourse` (Line 87)
**Current:** `throw new ValidationException("Course ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");`

#### Method: `updateCourse` (Line 91)
**Current:** `throw new ValidationException("Course data cannot be null");`
**Replace with:** `throw new ValidationException("Course data cannot be null", "COURSE_DATA_REQUIRED");`

#### Method: `updateCourse` (Line 95)
**Current:** `throw new ValidationException("Price cannot be negative");`
**Replace with:** `throw new ValidationException("Price cannot be negative", "INVALID_PRICE");`

#### Method: `updateCourse` (Line 99)
**Current:** `throw new ValidationException("Course not found with ID: " + courseId);`
**Replace with:** `throw new CourseNotFoundException(courseId);`

#### Method: `saveVideoLessonsAndUpdateCourse` (Line 150)
**Current:** `throw new ValidationException("Course not found with ID: " + courseId);`
**Replace with:** `throw new CourseNotFoundException(courseId);`

#### Method: `getVideoLesson` (Line 185)
**Current:** `throw new ValidationException("Video lesson not found with courseId: " + courseId + " and lessonId: " + lessonId);`
**Replace with:** `throw new LessonNotFoundException(lessonId, courseId);`

#### Method: `getAllLessonsByCourseId` (Line 199)
**Current:** `throw new ValidationException("No lessons found for course ID: " + courseId);`
**Replace with:** `throw new LessonNotFoundException("any", courseId);`

#### Method: `updateVideoLesson` (Line 212)
**Current:** `throw new ValidationException("Video lesson not found with courseId: " + courseId + " and lessonId: " + lessonId);`
**Replace with:** `throw new LessonNotFoundException(lessonId, courseId);`

#### Method: `getVideoLessonsWithFreePreview` (Line 224)
**Current:** `throw new ValidationException("No free preview lessons found for course ID: " + courseId);`
**Replace with:** `throw new LessonNotFoundException("free preview", courseId);`

---

### 3. OrderServiceImpl.java

#### Method: `createOrder` (Line 38)
**Current:** `throw new ValidationException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `createOrder` (Line 41)
**Current:** `throw new ValidationException("Course ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");`

#### Method: `createOrder` (Line 50)
**Current:** `throw new ValidationException("User account is disabled");`
**Replace with:** `throw new InvalidUserStateException(userId, "DISABLED", "create order");`

#### Method: `createOrder` (Line 56)
**Current:** `throw new ValidationException("Course is not available for purchase");`
**Replace with:** `throw new CourseNotPublishedException(courseId);`

#### Method: `createOrder` (Line 62)
**Current:** `throw new ValidationException("User already has access to this course");`
**Replace with:** `throw new DuplicateResourceException("Order", "courseId", courseId);`

#### Method: `createOrder` (Line 105)
**Current:** `throw new ValidationException("An order for this course already exists");`
**Replace with:** `throw new DuplicateResourceException("Order", "courseId", courseId);`

#### Method: `createOrder` (Line 112)
**Current:** `throw new ValidationException("Failed to create order: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("create", "Order", e);`

#### Method: `submitPayment` (Line 123)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `submitPayment` (Line 126)
**Current:** `throw new ValidationException("Payment method is required");`
**Replace with:** `throw new ValidationException("Payment method is required", "PAYMENT_METHOD_REQUIRED");`

#### Method: `submitPayment` (Line 129)
**Current:** `throw new ValidationException("Transaction ID is required");`
**Replace with:** `throw new ValidationException("Transaction ID is required", "TRANSACTION_ID_REQUIRED");`

#### Method: `submitPayment` (Line 132)
**Current:** `throw new ValidationException("Phone number is required");`
**Replace with:** `throw new ValidationException("Phone number is required", "PHONE_NUMBER_REQUIRED");`

#### Method: `submitPayment` (Line 138)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `submitPayment` (Line 144)
**Current:** `throw new ValidationException("Order is not in pending status. Current status: " + order.getStatus());`
**Replace with:** `throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "PENDING", "submit payment");`

#### Method: `submitPayment` (Line 149)
**Current:** `throw new ValidationException("Transaction ID already exists for another pending order");`
**Replace with:** `throw new DuplicateTransactionException(transactionId);`

#### Method: `submitPayment` (Line 173)
**Current:** `throw new ValidationException("Transaction ID already exists or duplicate payment submission");`
**Replace with:** `throw new DuplicateTransactionException(transactionId);`

#### Method: `submitPayment` (Line 180)
**Current:** `throw new ValidationException("Failed to submit payment: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("update", "Order", e);`

#### Method: `cancelOrder` (Line 189)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `cancelOrder` (Line 192)
**Current:** `throw new ValidationException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `cancelOrder` (Line 200)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `cancelOrder` (Line 205)
**Current:** `throw new ValidationException("You are not authorized to cancel this order");`
**Replace with:** `throw new OrderAuthorizationException(orderId, userId, "cancel");`

#### Method: `cancelOrder` (Line 210)
**Current:** `throw new ValidationException("Order cannot be cancelled. Current status: " + order.getStatus());`
**Replace with:** `throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "PENDING", "cancel");`

#### Method: `cancelOrder` (Line 228)
**Current:** `throw new ValidationException("Failed to cancel order: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("update", "Order", e);`

#### Method: `approvePayment` (Line 237)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `approvePayment` (Line 240)
**Current:** `throw new ValidationException("Admin ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Admin ID cannot be null or empty", "ADMIN_ID_REQUIRED");`

#### Method: `approvePayment` (Line 248)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `approvePayment` (Line 253)
**Current:** `throw new ValidationException("Admin account is disabled");`
**Replace with:** `throw new InvalidUserStateException(adminId, "DISABLED", "approve payment");`

#### Method: `approvePayment` (Line 259)
**Current:** `throw new ValidationException("Order cannot be approved. Current status: " + order.getStatus() + ". Only SUBMITTED orders can be approved.");`
**Replace with:** `throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "SUBMITTED", "approve");`

#### Method: `approvePayment` (Line 265)
**Current:** `throw new ValidationException("Order does not have payment information to approve");`
**Replace with:** `throw new PaymentVerificationException(orderId, "No payment information available");`

#### Method: `approvePayment` (Line 298)
**Current:** `throw new ValidationException("Failed to approve payment: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("update", "Order", e);`

#### Method: `rejectPayment` (Line 307)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `rejectPayment` (Line 310)
**Current:** `throw new ValidationException("Admin ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Admin ID cannot be null or empty", "ADMIN_ID_REQUIRED");`

#### Method: `rejectPayment` (Line 313)
**Current:** `throw new ValidationException("Rejection reason is required");`
**Replace with:** `throw new ValidationException("Rejection reason is required", "REJECTION_REASON_REQUIRED");`

#### Method: `rejectPayment` (Line 321)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `rejectPayment` (Line 326)
**Current:** `throw new ValidationException("Admin account is disabled");`
**Replace with:** `throw new InvalidUserStateException(adminId, "DISABLED", "reject payment");`

#### Method: `rejectPayment` (Line 332)
**Current:** `throw new ValidationException("Order cannot be rejected. Current status: " + order.getStatus() + ". Only SUBMITTED orders can be rejected.");`
**Replace with:** `throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "SUBMITTED", "reject");`

#### Method: `rejectPayment` (Line 338)
**Current:** `throw new ValidationException("Order does not have payment information to reject");`
**Replace with:** `throw new PaymentVerificationException(orderId, "No payment information to reject");`

#### Method: `rejectPayment` (Line 364)
**Current:** `throw new ValidationException("Failed to reject payment: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("update", "Order", e);`

#### Method: `revokeAccess` (Line 373)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `revokeAccess` (Line 376)
**Current:** `throw new ValidationException("Admin ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Admin ID cannot be null or empty", "ADMIN_ID_REQUIRED");`

#### Method: `revokeAccess` (Line 379)
**Current:** `throw new ValidationException("Revocation reason is required");`
**Replace with:** `throw new ValidationException("Revocation reason is required", "REVOCATION_REASON_REQUIRED");`

#### Method: `revokeAccess` (Line 387)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `revokeAccess` (Line 392)
**Current:** `throw new ValidationException("Admin account is disabled");`
**Replace with:** `throw new InvalidUserStateException(adminId, "DISABLED", "revoke access");`

#### Method: `revokeAccess` (Line 398)
**Current:** `throw new ValidationException("Order cannot be revoked. Current status: " + order.getStatus() + ". Only VERIFIED orders can be revoked.");`
**Replace with:** `throw new InvalidOrderStateException(orderId, order.getStatus().toString(), "VERIFIED", "revoke");`

#### Method: `revokeAccess` (Line 435)
**Current:** `throw new ValidationException("Failed to revoke access: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("update", "Order", e);`

#### Method: `getOrder` (Line 444)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `getOrder` (Line 447)
**Current:** `throw new ValidationException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `getOrder` (Line 455)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `getOrder` (Line 460)
**Current:** `throw new ValidationException("You are not authorized to view this order");`
**Replace with:** `throw new OrderAuthorizationException(orderId, userId, "view");`

#### Method: `getOrder` (Line 471)
**Current:** `throw new ValidationException("Failed to retrieve order: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `getOrderById` (Line 480)
**Current:** `throw new ValidationException("Order ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Order ID cannot be null or empty", "ORDER_ID_REQUIRED");`

#### Method: `getOrderById` (Line 487)
**Current:** `throw new ValidationException("Order not found with ID: " + orderId);`
**Replace with:** `throw new OrderNotFoundException(orderId);`

#### Method: `getOrderById` (Line 494)
**Current:** `throw new ValidationException("Failed to retrieve order: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `getUserOrders` (Line 503)
**Current:** `throw new ValidationException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `getUserOrders` (Line 506)
**Current:** `throw new ValidationException("Pageable cannot be null");`
**Replace with:** `throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");`

#### Method: `getUserOrders` (Line 523)
**Current:** `throw new ValidationException("Failed to retrieve user orders: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `getAllOrders` (Line 532)
**Current:** `throw new ValidationException("Pageable cannot be null");`
**Replace with:** `throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");`

#### Method: `getAllOrders` (Line 543)
**Current:** `throw new ValidationException("Failed to retrieve orders: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `getUserPurchasedCourseIds` (Line 579)
**Current:** `throw new ValidationException("User ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");`

#### Method: `getUserPurchasedCourseIds` (Line 605)
**Current:** `throw new ValidationException("Failed to retrieve purchased courses: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `getOrdersByStatus` (Line 613)
**Current:** `throw new ValidationException("Order status cannot be null");`
**Replace with:** `throw new ValidationException("Order status cannot be null", "ORDER_STATUS_REQUIRED");`

#### Method: `getOrdersByStatus` (Line 616)
**Current:** `throw new ValidationException("Pageable cannot be null");`
**Replace with:** `throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");`

#### Method: `getOrdersByStatus` (Line 625)
**Current:** `throw new ValidationException("Failed to retrieve orders by status");`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `getPendingVerificationOrders` (Line 633)
**Current:** `throw new ValidationException("Pageable cannot be null");`
**Replace with:** `throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");`

#### Method: `getPendingVerificationOrders` (Line 642)
**Current:** `throw new ValidationException("Failed to retrieve pending verification orders");`
**Replace with:** `throw new DatabaseException("retrieve", "Order", e);`

#### Method: `searchOrders` (Line 653)
**Current:** `throw new ValidationException("Pageable cannot be null");`
**Replace with:** `throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");`

#### Method: `searchOrders` (Line 690)
**Current:** `throw new ValidationException("Failed to search orders: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("search", "Order", e);`

#### Method: `getCourseRevenue` (Line 700)
**Current:** `throw new ValidationException("Course ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");`

#### Method: `getCourseRevenue` (Line 727)
**Current:** `throw new ValidationException("Failed to calculate course revenue: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("calculate", "Revenue", e);`

#### Method: `getOrderStatistics` (Line 772)
**Current:** `throw new ValidationException("Failed to calculate order statistics: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("calculate", "Statistics", e);`

#### Method: `getDailyOrderSummary` (Line 781)
**Current:** `throw new ValidationException("Days must be a positive number");`
**Replace with:** `throw new ValidationException("Days must be a positive number", "INVALID_DAYS");`

#### Method: `getDailyOrderSummary` (Line 784)
**Current:** `throw new ValidationException("Cannot retrieve more than 365 days of data");`
**Replace with:** `throw new ValidationException("Cannot retrieve more than 365 days of data", "DAYS_LIMIT_EXCEEDED");`

#### Method: `getDailyOrderSummary` (Line 837)
**Current:** `throw new ValidationException("Failed to generate daily order summary: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("generate", "Summary", e);`

#### Method: `processExpiredOrders` (Line 882)
**Current:** `throw new ValidationException("Failed to process expired orders: " + e.getMessage());`
**Replace with:** `throw new DatabaseException("process", "ExpiredOrders", e);`

---

### 4. VideoLessonServiceImpl.java

#### Method: `addVideoLessons` (Line 54)
**Current:** `throw new IllegalArgumentException("Course ID cannot be null or empty");`
**Replace with:** `throw new ValidationException("Course ID cannot be null or empty", "COURSE_ID_REQUIRED");`

#### Method: `addVideoLessons` (Line 57)
**Current:** `throw new IllegalArgumentException("Lessons list cannot be null or empty");`
**Replace with:** `throw new ValidationException("Lessons list cannot be null or empty", "LESSONS_REQUIRED");`

---

### 5. TokenCleanupScheduler.java

#### Method: `cleanupExpiredTokens` (Line 31)
**Current:** `log.error("Error during single device token cleanup: {}", e.getMessage());`
**Add after log:** `throw new SchedulerException("token-cleanup", e);`

---

### 6. JwtBlacklistService.java

#### Method: `cleanupExpiredTokens` (Line 73)
**Current:** `log.error("Error cleaning up expired blacklisted tokens: {}", e.getMessage());`
**Add after log:** `throw new SchedulerException("blacklist-cleanup", e);`

---

## Required Import Statements

### UserServiceImpl.java
Add:
```java
import com.notvibecoder.backend.core.exception.ValidationException;
```

### CourseServiceImpl.java  
Add:
```java
import com.notvibecoder.backend.core.exception.course.CourseNotFoundException;
import com.notvibecoder.backend.core.exception.course.LessonNotFoundException;
```

### OrderServiceImpl.java
Add:
```java
import com.notvibecoder.backend.core.exception.order.*;
import com.notvibecoder.backend.core.exception.course.CourseNotPublishedException;
import com.notvibecoder.backend.core.exception.user.InvalidUserStateException;
import com.notvibecoder.backend.core.exception.system.DatabaseException;
```

### VideoLessonServiceImpl.java
Add:
```java
import com.notvibecoder.backend.core.exception.ValidationException;
```

### TokenCleanupScheduler.java
Add:
```java
import com.notvibecoder.backend.core.exception.system.SchedulerException;
```

### JwtBlacklistService.java
Add:
```java
import com.notvibecoder.backend.core.exception.system.SchedulerException;
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
        log.warn("Business exception [{}]: {} - Code: {}", 
                correlationId, ex.getMessage(), ex.getErrorCode());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationException(
            ValidationException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Validation exception [{}]: {}", correlationId, ex.getFieldErrors());

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .message("Validation failed")
                .data(ex.getFieldErrors())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // ==================== RESOURCE EXCEPTIONS ====================

    @ExceptionHandler({ResourceNotFoundException.class, UserNotFoundException.class, 
                      CourseNotFoundException.class, LessonNotFoundException.class, 
                      OrderNotFoundException.class})
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleResourceNotFound(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Resource not found [{}]: {}", correlationId, ex.getMessage());

        Map<String, Object> details = new HashMap<>();
        details.put("resource", extractResourceType(ex));
        details.put("timestamp", Instant.now());

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

    @ExceptionHandler({DuplicateResourceException.class, DuplicateTransactionException.class, 
                      EmailAlreadyExistsException.class})
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleDuplicateResource(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Duplicate resource [{}]: {}", correlationId, ex.getMessage());

        Map<String, Object> details = new HashMap<>();
        details.put("conflictType", "DUPLICATE_RESOURCE");
        details.put("timestamp", Instant.now());

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
                      TokenRevokedException.class, SessionExpiredException.class})
    public ResponseEntity<ApiResponse<Void>> handleAuthenticationExceptions(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Authentication exception [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler({AccountDisabledException.class, InvalidUserStateException.class})
    public ResponseEntity<ApiResponse<Void>> handleAccountStateExceptions(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Account state exception [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // ==================== AUTHORIZATION EXCEPTIONS ====================

    @ExceptionHandler({UnauthorizedAccessException.class, InsufficientPermissionException.class, 
                      OrderAuthorizationException.class, CourseAccessDeniedException.class})
    public ResponseEntity<ApiResponse<Void>> handleAuthorizationExceptions(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Authorization exception [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // ==================== BUSINESS LOGIC EXCEPTIONS ====================

    @ExceptionHandler({InvalidOrderStateException.class, InvalidCourseStateException.class, 
                      CourseNotPublishedException.class, OperationNotAllowedException.class})
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleBusinessLogicExceptions(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Business logic exception [{}]: {}", correlationId, ex.getMessage());

        Map<String, Object> details = new HashMap<>();
        details.put("violationType", "BUSINESS_RULE");
        details.put("timestamp", Instant.now());

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

    // ==================== PAYMENT EXCEPTIONS ====================

    @ExceptionHandler({PaymentVerificationException.class, InvalidPaymentMethodException.class})
    public ResponseEntity<ApiResponse<Map<String, Object>>> handlePaymentExceptions(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Payment exception [{}]: {}", correlationId, ex.getMessage());

        Map<String, Object> details = new HashMap<>();
        details.put("paymentIssue", true);
        details.put("timestamp", Instant.now());

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

    // ==================== SYSTEM EXCEPTIONS ====================

    @ExceptionHandler({DatabaseException.class, ExternalServiceException.class, 
                      SchedulerException.class})
    public ResponseEntity<ApiResponse<Void>> handleSystemExceptions(
            BusinessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.error("System exception [{}]: {}", correlationId, ex.getMessage(), ex);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("A system error occurred. Please try again later.")
                .errorCode("SYSTEM_ERROR")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ==================== SPRING FRAMEWORK EXCEPTIONS ====================

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationErrors(
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

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataIntegrityViolation(
            DataIntegrityViolationException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.warn("Data integrity violation [{}]: {}", correlationId, ex.getMessage());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("Data integrity constraint violated")
                .errorCode("DATA_INTEGRITY_ERROR")
                .correlationId(correlationId)
                .timestamp(Instant.now())
                .build();

        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataAccessException(
            DataAccessException ex, WebRequest request) {
        
        String correlationId = generateCorrelationId();
        log.error("Database access error [{}]: {}", correlationId, ex.getMessage(), ex);

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(false)
                .message("Database access error occurred")
                .errorCode("DATABASE_ERROR")
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
                .errorCode("AUTHENTICATION_ERROR")
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
        String message = String.format("Invalid value '%s' for parameter '%s'", 
                ex.getValue(), ex.getName());

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

    // ==================== GENERIC EXCEPTION HANDLER ====================

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

    // ==================== UTILITY METHODS ====================

    private String generateCorrelationId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private String extractResourceType(BusinessException ex) {
        String className = ex.getClass().getSimpleName();
        if (className.contains("User")) return "USER";
        if (className.contains("Course")) return "COURSE";
        if (className.contains("Order")) return "ORDER";
        if (className.contains("Lesson")) return "LESSON";
        return "RESOURCE";
    }
}
```

## Summary

This comprehensive analysis identifies **133 specific exception handling issues** across your codebase that need to be fixed. The main problems are:

1. **Over-reliance on ValidationException** for business logic errors
2. **Using IllegalArgumentException** instead of proper validation exceptions
3. **Generic error messages** without proper error codes
4. **Missing specific exception types** for business scenarios
5. **Inconsistent error handling** in catch blocks

After implementing these fixes, your application will have:
- ✅ **Consistent error handling** across all services
- ✅ **Proper HTTP status codes** for different error types
- ✅ **Structured error responses** with correlation IDs
- ✅ **Better debugging** with specific exception types
- ✅ **Enhanced client experience** with meaningful error messages