package com.notvibecoder.backend.modules.system.constants;

/**
 * Security Constants for VibeCoder Backend
 * <p>
 * This class centralizes all security-related constants used throughout the application.
 * Based on actual business requirements with USER and ADMIN roles only.
 */
public final class SecurityConstants {

    // ==================== ROLES ====================
    public static final String ROLE_USER = "USER";
    public static final String ROLE_ADMIN = "ADMIN";

    // ==================== SPRING SECURITY ROLES (with ROLE_ prefix) ====================
    public static final String SPRING_ROLE_USER = "ROLE_USER";
    public static final String SPRING_ROLE_ADMIN = "ROLE_ADMIN";

    // ==================== PREAUTHORIZE EXPRESSIONS ====================
    
    // Basic authentication check
    public static final String IS_AUTHENTICATED = "isAuthenticated()";
    
    // Role-based access control
    public static final String HAS_ROLE_USER = "hasRole('ROLE_USER')";
    public static final String HAS_ROLE_ADMIN = "hasRole('ROLE_ADMIN')";
    
    // Combined expressions for method security
    public static final String IS_USER_OR_ADMIN = "hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')";
    
    // Admin-specific operations
    public static final String ADMIN_ONLY = "hasRole('ROLE_ADMIN')";
    
    // User access with ownership validation
    public static final String USER_ACCESS_OWN_DATA = "hasRole('ROLE_USER') and #userId == authentication.principal.id";
    public static final String ADMIN_OR_OWNER = "hasRole('ROLE_ADMIN') or #userId == authentication.principal.id";

    // ==================== BUSINESS OPERATION CONSTANTS ====================
    
    // User Profile Operations (User can manage their own profile)
    public static final String USER_PROFILE_ACCESS = "isAuthenticated()";
    
    // Course Operations
    public static final String COURSE_CREATE = "hasRole('ROLE_ADMIN')";           // Only admin can create courses
    public static final String COURSE_UPDATE = "hasRole('ROLE_ADMIN')";           // Only admin can update courses  
    public static final String COURSE_DELETE = "hasRole('ROLE_ADMIN')";           // Only admin can delete courses
    public static final String COURSE_VIEW_CONTENT = "isAuthenticated()";    // Any authenticated user can view course content
    public static final String COURSE_ADMIN_VIEW = "hasRole('ROLE_ADMIN')";       // Admin can view all courses
    
    // Course Content Access - requires purchase verification or admin
    public static final String COURSE_CONTENT_ACCESS = "hasRole('ROLE_ADMIN') or (isAuthenticated() and @courseAccessService.hasAccess(authentication.principal.id, #courseId))";
    public static final String LESSON_ACCESS = "hasRole('ROLE_ADMIN') or (isAuthenticated() and @courseAccessService.hasAccess(authentication.principal.id, #courseId))";
    
    // Order Operations
    public static final String ORDER_CREATE = "hasRole('ROLE_USER')";             // Users create orders
    public static final String ORDER_VIEW_OWN = "hasRole('ROLE_ADMIN') or (hasRole('ROLE_USER') and @orderService.isOwner(authentication.principal.id, #orderId))";           // Users view their own orders
    public static final String ORDER_MANAGE_OWN = "hasRole('ROLE_ADMIN') or (hasRole('ROLE_USER') and @orderService.isOwner(authentication.principal.id, #orderId))";         // Users manage their own orders
    public static final String ORDER_ADMIN_VIEW = "hasRole('ROLE_ADMIN')";        // Admin can view all orders
    public static final String ORDER_ADMIN_MANAGE = "hasRole('ROLE_ADMIN')";      // Admin can approve/reject orders
    
    // User Management Operations
    public static final String USER_ADMIN_MANAGE = "hasRole('ROLE_ADMIN')";       // Admin manages users

    // ==================== ENDPOINT PATTERNS ====================
    
    // Public endpoints (no authentication required)
    public static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/auth/**",
            "/oauth2/**", 
            "/login/**",
            "/api/v1/debug/**",
            "/api/v1/users/exists",           // User existence check
            "/api/v1/courses/",               // Public course listing
            "/api/v1/courses/*/public/**"     // Public course details
    };
    
    // Admin-only endpoints
    public static final String[] ADMIN_ENDPOINTS = {
            "/api/v1/admin/**",               // All admin operations
            "/api/v1/orders/admin/**",        // Order management
            "/api/v1/courses/admin/**"        // Course management
    };

    private SecurityConstants() {
        // Utility class - prevent instantiation
    }
}
