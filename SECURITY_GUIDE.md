# Centralized Security Configuration Guide

## 🏗️ Architecture Overview

This project implements a **layered security approach** with centralized configuration for consistent authorization
across all application layers.

## 📁 Security Components

### 1. **Method Security Configuration**

- **File**: `MethodSecurityConfig.java`
- **Purpose**: Enables method-level security annotations
- **Features**: @PreAuthorize, @PostAuthorize, @Secured, @RolesAllowed

### 2. **Security Service**

- **File**: `SecurityService.java`
- **Purpose**: Centralized security logic for complex authorization
- **Usage**: `@PreAuthorize("@securityService.isAdmin()")`

### 3. **Security Constants**

- **File**: `SecurityConstants.java`
- **Purpose**: Centralized security expressions and role definitions
- **Usage**: `@PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)`

## 🎯 Authorization Strategy by Layer

### **Controller Layer (Primary Authorization)**

```java
@RestController
@RequestMapping("/api/v1/courses")
public class CourseController {
    
    // Public access
    @GetMapping("/public")
    public ResponseEntity<List<Course>> getPublicCourses() { }
    
    // Authenticated users
    @GetMapping("/my-courses")
    @PreAuthorize(SecurityConstants.IS_AUTHENTICATED)
    public ResponseEntity<List<Course>> getMyCourses() { }
    
    // Role-based access
    @PostMapping
    @PreAuthorize(SecurityConstants.CAN_CREATE_COURSES)
    public ResponseEntity<Course> createCourse(@RequestBody Course course) { }
    
    // Resource ownership
    @PutMapping("/{courseId}")
    @PreAuthorize("@securityService.canManageCourse(#courseId, #course.instructorId)")
    public ResponseEntity<Course> updateCourse(@PathVariable String courseId, @RequestBody Course course) { }
    
    // Admin only
    @DeleteMapping("/{courseId}")
    @PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
    public ResponseEntity<Void> deleteCourse(@PathVariable String courseId) { }
}
```

### **Service Layer (Business Logic Protection)**

```java
@Service
public class PaymentService {
    
    // Admin-only operations
    @PreAuthorize(SecurityConstants.CAN_VERIFY_PAYMENTS)
    public PaymentRequest verifyPayment(String paymentId) { }
    
    // User data access with ownership check
    @PreAuthorize(SecurityConstants.CAN_ACCESS_USER_DATA)
    public List<Payment> getUserPayments(String userId) { }
    
    // Post-execution filtering
    @PostFilter("@securityService.isAdmin() or filterObject.userId == authentication.principal.id")
    public List<Payment> getAllPayments() { }
    
    // Complex authorization
    @PreAuthorize("@securityService.isAdmin() or @paymentService.isOwner(#paymentId, authentication.principal.id)")
    public void cancelPayment(String paymentId) { }
}
```

## 🔐 Security Expressions Reference

### **Basic Role Checks**

```java
@PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)           // Admin only
@PreAuthorize(SecurityConstants.HAS_ROLE_TEACHER)         // Teacher only  
@PreAuthorize(SecurityConstants.HAS_ADMIN_OR_TEACHER)     // Admin or Teacher
@PreAuthorize(SecurityConstants.IS_AUTHENTICATED)        // Any authenticated user
```

### **Custom Security Service**

```java
@PreAuthorize(SecurityConstants.IS_ADMIN)                // @securityService.isAdmin()
@PreAuthorize(SecurityConstants.CAN_CREATE_COURSES)      // @securityService.canCreateCourses()
@PreAuthorize(SecurityConstants.CAN_VERIFY_PAYMENTS)     // @securityService.canVerifyPayments()
@PreAuthorize(SecurityConstants.CAN_ACCESS_COURSE)       // @securityService.canAccessCourse(#courseId)
```

### **Dynamic Resource Access**

```java
// Current user or admin can access
@PreAuthorize("@securityService.isCurrentUserOrAdmin(#email)")

// Resource ownership check
@PreAuthorize("@securityService.isOwnerOrAdmin(#resourceOwnerId)")

// Course access check (purchased or admin)
@PreAuthorize("@securityService.canAccessCourse(#courseId)")

// Course management (instructor or admin)
@PreAuthorize("@securityService.canManageCourse(#courseId, #instructorId)")
```

## 🚀 Usage Examples

### **Course Management**

```java
// Anyone can browse public courses
@GetMapping("/courses/public")
public List<Course> getPublicCourses() { }

// Only authenticated users can see their courses
@GetMapping("/my-courses")
@PreAuthorize(SecurityConstants.IS_AUTHENTICATED)
public List<Course> getMyCourses() { }

// Only teachers/admins can create courses
@PostMapping("/courses")
@PreAuthorize(SecurityConstants.CAN_CREATE_COURSES)
public Course createCourse(@RequestBody Course course) { }

// Only course instructor or admin can update
@PutMapping("/courses/{courseId}")
@PreAuthorize("@securityService.canManageCourse(#courseId, #course.instructorId)")
public Course updateCourse(@PathVariable String courseId, @RequestBody Course course) { }
```

### **Payment Management**

```java
// Any authenticated user can submit payment
@PostMapping("/payments")
@PreAuthorize(SecurityConstants.IS_AUTHENTICATED)
public Payment submitPayment(@RequestBody Payment payment) { }

// Users can see their payments, admins can see any
@GetMapping("/payments/user/{userId}")
@PreAuthorize(SecurityConstants.CAN_ACCESS_USER_DATA)
public List<Payment> getUserPayments(@PathVariable String userId) { }

// Only admins can verify payments
@PostMapping("/payments/{paymentId}/verify")
@PreAuthorize(SecurityConstants.CAN_VERIFY_PAYMENTS)
public Payment verifyPayment(@PathVariable String paymentId) { }
```

### **User Management**

```java
// Users can update their own profile, admins can update any
@PutMapping("/users/{userId}")
@PreAuthorize("@securityService.canAccessUserData(#userId)")
public User updateUser(@PathVariable String userId, @RequestBody User user) { }

// Only admins can manage all users
@GetMapping("/admin/users")
@PreAuthorize(SecurityConstants.CAN_MANAGE_USERS)
public List<User> getAllUsers() { }
```

## 🛡️ Best Practices

### **1. Use Constants Instead of Hardcoding**

```java
// ❌ Bad
@PreAuthorize("hasRole('ADMIN')")

// ✅ Good  
@PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
```

### **2. Prefer Controller-Level Security**

```java
// ✅ Primary authorization at controller
@RestController
public class UserController {
    @PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
    public List<User> getAllUsers() {
        return userService.getAllUsers(); // No additional security needed
    }
}
```

### **3. Use Service-Level for Complex Business Logic**

```java
// ✅ Complex business rules at service level
@Service
public class CourseService {
    @PreAuthorize("@securityService.canManageCourse(#courseId, authentication.principal.id)")
    public void publishCourse(String courseId) {
        // Business logic here
    }
}
```

### **4. Combine Multiple Checks**

```java
// ✅ Multiple authorization conditions
@PreAuthorize("hasRole('ADMIN') or (hasRole('TEACHER') and @courseService.isInstructor(#courseId, authentication.principal.id))")
public Course updateCourse(String courseId, Course course) { }
```

## 🔍 Testing Security

### **Debug Endpoints**

```java
// Check current user's roles and permissions
GET /api/v1/admin/check

// Test admin-only access  
GET /api/v1/admin/test

// Verify configuration
GET /api/v1/debug/config
```

### **Common Issues**

1. **Role Prefix**: Spring Security adds `ROLE_` prefix automatically
2. **Method Parameters**: Use `#paramName` to access method parameters in expressions
3. **Authentication Object**: Access via `authentication.principal.id` or `authentication.name`
4. **SpEL Expressions**: Use `@serviceName.methodName()` for custom security services

This centralized approach ensures consistent security across your entire application while making it easy to maintain
and modify authorization rules.
