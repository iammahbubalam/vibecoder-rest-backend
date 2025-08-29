package com.notvibecoder.backend.modules.admin.service;

import com.notvibecoder.backend.modules.user.entity.Role;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Centralized Security Service for complex authorization logic
 * 
 * This service provides reusable security checks that can be used across
 * different layers of the application with @PreAuthorize annotations.
 * 
 * Usage Examples:
 * - @PreAuthorize("@securityService.isAdmin()")
 * - @PreAuthorize("@securityService.canAccessCourse(#courseId)")
 * - @PreAuthorize("@securityService.isOwnerOrAdmin(#resourceOwnerId)")
 */
@Service("securityService")
@RequiredArgsConstructor
@Slf4j
public class SecurityService {

    private final UserRepository userRepository;

    /**
     * Get current authenticated user
     */
    public Optional<User> getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !auth.getPrincipal().equals("anonymousUser")) {
            String email = auth.getName();
            return userRepository.findByEmail(email);
        }
        return Optional.empty();
    }

    /**
     * Get current user ID
     */
    public Optional<String> getCurrentUserId() {
        return getCurrentUser().map(User::getId);
    }

    /**
     * Check if current user is admin
     */
    public boolean isAdmin() {
        return getCurrentUser()
                .map(user -> user.getRoles().contains(Role.ADMIN))
                .orElse(false);
    }




    /**
     * Check if current user is the owner of a resource or admin
     */
    public boolean isOwnerOrAdmin(String resourceOwnerId) {
        if (isAdmin()) {
            return true;
        }
        return getCurrentUserId()
                .map(currentUserId -> currentUserId.equals(resourceOwnerId))
                .orElse(false);
    }

    /**
     * Check if current user can access a specific course
     * (purchased, owns, or is admin)
     */
    public boolean canAccessCourse(String courseId) {
        return getCurrentUser()
                .map(user -> {
                    // Admin can access all courses
                    if (user.getRoles().contains(Role.ADMIN)) {
                        return true;
                    }
                    // Check if user purchased the course
                    return user.getPurchasedCourseIds().contains(courseId);
                })
                .orElse(false);
    }

    /**
     * Check if current user can manage a specific course
     * (instructor or admin)
     */
    public boolean canManageCourse(String courseId, String instructorId) {
        if (isAdmin()) {
            return true;
        }
        return getCurrentUserId()
                .map(currentUserId -> currentUserId.equals(instructorId))
                .orElse(false);
    }

    /**
     * Check if current user can verify payments
     * (only admins)
     */
    public boolean canVerifyPayments() {
        return isAdmin();
    }

    /**
     * Check if current user can access user management
     * (only admins)
     */
    public boolean canManageUsers() {
        return isAdmin();
    }

    /**
     * Check if current user can access their own data or admin can access any
     */
    public boolean canAccessUserData(String targetUserId) {
        if (isAdmin()) {
            return true;
        }
        return getCurrentUserId()
                .map(currentUserId -> currentUserId.equals(targetUserId))
                .orElse(false);
    }

    /**
     * Check if current user can create courses
     * (teachers and admins)
     */
    public boolean canCreateCourses() {
        return getCurrentUser()
                .map(user -> user.getRoles().contains(Role.ADMIN))
                .orElse(false);
    }

    /**
     * Check if current user has purchased a specific course
     */
    public boolean hasPurchasedCourse(String courseId) {
        return getCurrentUser()
                .map(user -> user.getPurchasedCourseIds().contains(courseId))
                .orElse(false);
    }

    /**
     * Check if current user can access admin panel
     */
    public boolean canAccessAdminPanel() {
        return isAdmin();
    }

    /**
     * Check if email belongs to current user or user is admin
     */
    public boolean isCurrentUserOrAdmin(String email) {
        if (isAdmin()) {
            return true;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getName().equals(email);
    }
}
