package com.notvibecoder.backend.shared.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.notvibecoder.backend.shared.config.RateLimitingConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Rate limiting filter that integrates with Spring Security filter chain
 * <p>
 * This filter applies rate limiting based on the endpoint type and client identifier.
 * It should be placed early in the filter chain, ideally before authentication.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingConfig.RateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String requestPath = request.getRequestURI();
        String method = request.getMethod();

        // Determine rate limit type based on the endpoint
        RateLimitingConfig.RateLimitType rateLimitType = determineRateLimitType(requestPath, method);

        // Skip rate limiting for certain paths if needed
        if (shouldSkipRateLimiting(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Generate unique key for the client (IP + User Agent for better tracking)
        String clientKey = generateClientKey(request, rateLimitType);

        // Check rate limit
        boolean allowed = rateLimitService.isAllowed(clientKey, rateLimitType);

        if (allowed) {
            // Request is allowed, continue the filter chain
            log.debug("Rate limit passed for key: {} on path: {}", clientKey, requestPath);
            filterChain.doFilter(request, response);
        } else {
            // Rate limit exceeded, return 429 Too Many Requests
            handleRateLimitExceeded(request, response, clientKey, rateLimitType);
        }
    }

    /**
     * Determine the rate limit type based on the request path and method
     */
    private RateLimitingConfig.RateLimitType determineRateLimitType(String path, String method) {
        // Authentication endpoints
        if (path.startsWith("/api/auth/")) {
            if (path.contains("/refresh")) {
                return RateLimitingConfig.RateLimitType.TOKEN_REFRESH;
            }
            return RateLimitingConfig.RateLimitType.AUTH_ENDPOINTS;
        }

        // User profile endpoints
        if (path.startsWith("/api/user/") || path.startsWith("/api/profile/")) {
            return RateLimitingConfig.RateLimitType.USER_PROFILE;
        }

        // Admin endpoints
        if (path.startsWith("/api/admin/")) {
            return RateLimitingConfig.RateLimitType.ADMIN_ENDPOINTS;
        }

        // Default to general API
        return RateLimitingConfig.RateLimitType.GENERAL_API;
    }

    /**
     * Generate a unique key for the client based on IP and endpoint type
     */
    private String generateClientKey(HttpServletRequest request, RateLimitingConfig.RateLimitType rateLimitType) {
        String clientIp = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Create a composite key: IP + UserAgent hash + endpoint type
        String userAgentHash = userAgent != null ? String.valueOf(userAgent.hashCode()) : "unknown";

        return String.format("%s_%s_%s", clientIp, userAgentHash, rateLimitType.name());
    }

    /**
     * Extract the real client IP address considering proxies and load balancers
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "CF-Connecting-IP", // Cloudflare
                "X-Cluster-Client-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // Handle comma-separated IPs (X-Forwarded-For can have multiple IPs)
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    /**
     * Check if rate limiting should be skipped for certain paths
     */
    private boolean shouldSkipRateLimiting(String path) {
        // Skip rate limiting for health checks, metrics, etc.
        return path.startsWith("/actuator/") ||
                path.startsWith("/health") ||
                path.startsWith("/metrics") ||
                path.startsWith("/favicon.ico") ||
                path.startsWith("/static/") ||
                path.startsWith("/css/") ||
                path.startsWith("/js/") ||
                path.startsWith("/images/");
    }

    /**
     * Handle rate limit exceeded scenario
     */
    private void handleRateLimitExceeded(HttpServletRequest request,
                                         HttpServletResponse response,
                                         String clientKey,
                                         RateLimitingConfig.RateLimitType rateLimitType) throws IOException {

        log.warn("Rate limit exceeded for client: {} on path: {} with type: {}",
                clientKey, request.getRequestURI(), rateLimitType);

        // Get rate limit information
        long availableTokens = rateLimitService.getAvailableTokens(clientKey, rateLimitType);
        Duration timeToRefill = rateLimitService.getTimeToRefill(clientKey, rateLimitType);
        long capacity = rateLimitService.getCapacity(rateLimitType);

        // Set response status and headers
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Add rate limit headers (following standard conventions)
        response.setHeader("X-RateLimit-Limit", String.valueOf(capacity));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(availableTokens));
        response.setHeader("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + timeToRefill.toMillis()));
        response.setHeader("Retry-After", String.valueOf(timeToRefill.getSeconds()));

        // Create error response body
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Rate limit exceeded");
        errorResponse.put("message", "Too many requests. Please try again later.");
        errorResponse.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("path", request.getRequestURI());

        // Rate limit details
        Map<String, Object> rateLimitInfo = new HashMap<>();
        rateLimitInfo.put("limit", capacity);
        rateLimitInfo.put("remaining", availableTokens);
        rateLimitInfo.put("resetTimeMs", System.currentTimeMillis() + timeToRefill.toMillis());
        rateLimitInfo.put("retryAfterSeconds", timeToRefill.getSeconds());
        rateLimitInfo.put("type", rateLimitType.getDescription());

        errorResponse.put("rateLimit", rateLimitInfo);

        // Write JSON response
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        response.getWriter().flush();
    }

    /**
     * Only apply this filter to API endpoints
     */
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();

        // Only apply to API endpoints
        return !path.startsWith("/api/") &&
                !path.startsWith("/oauth2/") &&
                !path.startsWith("/login/oauth2/");
    }
}
