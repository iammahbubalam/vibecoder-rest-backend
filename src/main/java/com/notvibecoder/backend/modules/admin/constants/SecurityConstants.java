package com.notvibecoder.backend.modules.admin.constants;

/**
 * Security Constants for Authorization
 * 
 * This class centralizes all security-related constants used throughout the application.
 * Use these constants instead of hardcoding role names and permissions.
 */
public final class SecurityConstants {

    private SecurityConstants() {
        // Utility class
    }

    // ==================== ROLES ====================
    public static final String ROLE_USER = "USER";
    public static final String ROLE_TEACHER = "TEACHER";
    public static final String ROLE_ADMIN = "ADMIN";

    // ==================== SPRING SECURITY ROLES (with ROLE_ prefix) ====================
    public static final String SPRING_ROLE_USER = "ROLE_USER";
    public static final String SPRING_ROLE_TEACHER = "ROLE_TEACHER";
    public static final String SPRING_ROLE_ADMIN = "ROLE_ADMIN";

    // ==================== PREAUTHORIZE EXPRESSIONS ====================
    
    // Basic role checks
    public static final String HAS_ROLE_USER = "hasRole('USER')";
    public static final String HAS_ROLE_TEACHER = "hasRole('TEACHER')";
    public static final String HAS_ROLE_ADMIN = "hasRole('ADMIN')";
    
    // Combined role checks
    public static final String HAS_ADMIN_OR_TEACHER = "hasRole('ADMIN') or hasRole('TEACHER')";
    public static final String HAS_ANY_ROLE = "hasRole('USER') or hasRole('TEACHER') or hasRole('ADMIN')";
    
    // Authentication checks
    public static final String IS_AUTHENTICATED = "isAuthenticated()";
    public static final String IS_ANONYMOUS = "isAnonymous()";
    
    // Custom security service expressions
    public static final String IS_ADMIN = "@securityService.isAdmin()";
    public static final String IS_TEACHER = "@securityService.isTeacher()";
    public static final String IS_ADMIN_OR_TEACHER = "@securityService.isAdminOrTeacher()";
    public static final String CAN_CREATE_COURSES = "@securityService.canCreateCourses()";
    public static final String CAN_VERIFY_PAYMENTS = "@securityService.canVerifyPayments()";
    public static final String CAN_MANAGE_USERS = "@securityService.canManageUsers()";
    public static final String CAN_ACCESS_ADMIN_PANEL = "@securityService.canAccessAdminPanel()";
    
    // Resource-based permissions (with parameters)
    public static final String CAN_ACCESS_COURSE = "@securityService.canAccessCourse(#courseId)";
    public static final String CAN_MANAGE_COURSE = "@securityService.canManageCourse(#courseId, #instructorId)";
    public static final String IS_OWNER_OR_ADMIN = "@securityService.isOwnerOrAdmin(#ownerId)";
    public static final String CAN_ACCESS_USER_DATA = "@securityService.canAccessUserData(#userId)";
    public static final String IS_CURRENT_USER_OR_ADMIN = "@securityService.isCurrentUserOrAdmin(#email)";
    public static final String HAS_PURCHASED_COURSE = "@securityService.hasPurchasedCourse(#courseId)";

    // ==================== ENDPOINTS PATTERNS ====================
    public static final String[] PUBLIC_ENDPOINTS = {
        "/api/v1/auth/**",
        "/oauth2/**", 
        "/login/**",
        "/api/v1/debug/**",
        "/api/v1/courses/public/**"
    };
    
    public static final String[] ADMIN_ENDPOINTS = {
        "/api/v1/admin/**",
        "/api/v1/users/admin/**",
        "/api/v1/payments/admin/**"
    };
    
    public static final String[] TEACHER_ENDPOINTS = {
        "/api/v1/courses/create",
        "/api/v1/courses/*/edit",
        "/api/v1/teacher/**"
    };
}
