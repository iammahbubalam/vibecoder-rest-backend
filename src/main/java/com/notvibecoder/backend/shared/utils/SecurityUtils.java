package com.notvibecoder.backend.shared.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

import java.util.Optional;

public final class SecurityUtils {

    private SecurityUtils() {
        // Utility class
    }

    public static Optional<String> getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && 
            !(authentication.getPrincipal() instanceof String)) {
            return Optional.of(authentication.getName());
        }
        return Optional.empty();
    }

    public static String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xRealIp)) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    public static String sanitizeUserAgent(String userAgent) {
        if (userAgent == null) {
            return "Unknown";
        }
        
        // Remove potentially dangerous characters and limit length
        return userAgent
            .replaceAll("[<>\"'&]", "")
            .substring(0, Math.min(200, userAgent.length()));
    }

    public static boolean isValidTokenFormat(String token) {
        return StringUtils.hasText(token) && 
               token.matches("^[A-Za-z0-9_-]{86}$");
    }
}