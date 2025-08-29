package com.notvibecoder.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import com.notvibecoder.backend.modules.admin.service.SecurityService;

/**
 * Centralized Method Security Configuration
 * 
 * This configuration enables method-level security across the application.
 * It supports @PreAuthorize, @PostAuthorize, @Secured annotations.
 * 
 * Usage Examples:
 * - @PreAuthorize("hasRole('ADMIN')")
 * - @PreAuthorize("hasRole('ADMIN') or hasRole('TEACHER')")
 * - @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
 * - @PostAuthorize("hasRole('ADMIN') or returnObject.userId == authentication.principal.id")
 */
@Configuration
@EnableMethodSecurity(
    prePostEnabled = true,      // Enable @PreAuthorize and @PostAuthorize
    securedEnabled = true,      // Enable @Secured annotation
    jsr250Enabled = true        // Enable @RolesAllowed annotation
)
public class SecurityAccessConfig {

    /**
     * Custom security expressions bean for complex authorization logic
     * Can be used like: @PreAuthorize("@customSecurityService.canAccess(#resourceId)")
     */
    @Bean("customSecurityService")
    public CustomSecurityService customSecurityService(SecurityService securityService) {
        return new CustomSecurityService(securityService);
    }

    /**
         * Custom Security Service for complex authorization logic
         */
        public record CustomSecurityService(SecurityService securityService) {

        /**
             * Check if current user can access a specific course
             * User can access if:
             * - is ADMIN
             * - has purchased the course
             */
            public boolean canAccessCourse(String courseId) {
                // Admin or purchased
                return securityService.canAccessCourse(courseId);
            }

            /**
             * Check if current user is the owner of a resource or admin
             */
            public boolean isOwnerOrAdmin(String resourceOwnerId) {
                return securityService.isOwnerOrAdmin(resourceOwnerId);
            }

            /**
             * Check if current user can manage payments (admin only)
             */
            public boolean canManagePayments() {
                return securityService.canAccessAdminPanel();
            }
        }
}
