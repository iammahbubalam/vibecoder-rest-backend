package com.notvibecoder.backend.shared.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.local.LocalBucket;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate Limiting Configuration using Bucket4j with in-memory cache
 * 
 * This provides rate limiting without Redis dependency.
 * For true distributed rate limiting across multiple instances, Redis would be needed.
 */
@Configuration
@Slf4j
public class RateLimitingConfig {

    @Bean
    public RateLimitService rateLimitService() {
        return new RateLimitService();
    }

    /**
     * Rate limiting service that manages buckets for different endpoint types
     */
    @Component
    public static class RateLimitService {
        
        // In-memory bucket storage - use Redis for distributed applications
        private final Map<String, LocalBucket> buckets = new ConcurrentHashMap<>();

        /**
         * Create or retrieve a bucket for the given key and rate limit type
         */
        public LocalBucket createBucket(String key, RateLimitType type) {
            return buckets.computeIfAbsent(key, k -> {
                Bandwidth bandwidth = getBandwidthForType(type);
                log.debug("Creating rate limit bucket for key: {} with type: {}", key, type);
                return Bucket.builder()
                    .addLimit(bandwidth)
                    .build();
            });
        }

        /**
         * Check if the request is allowed (consumes 1 token)
         */
        public boolean isAllowed(String key, RateLimitType type) {
            LocalBucket bucket = createBucket(key, type);
            boolean allowed = bucket.tryConsume(1);
            
            if (!allowed) {
                log.warn("Rate limit exceeded for key: {} with type: {}", key, type);
            }
            
            return allowed;
        }

        /**
         * Get remaining tokens in the bucket
         */
        public long getAvailableTokens(String key, RateLimitType type) {
            LocalBucket bucket = createBucket(key, type);
            return bucket.getAvailableTokens();
        }

        /**
         * Get time until bucket refills to allow next request
         */
        public Duration getTimeToRefill(String key, RateLimitType type) {
            LocalBucket bucket = createBucket(key, type);
            return Duration.ofNanos(bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill());
        }

        /**
         * Get the maximum capacity for a rate limit type
         */
        public long getCapacity(RateLimitType type) {
            return getBandwidthForType(type).getCapacity();
        }

        /**
         * Clear all buckets (useful for testing)
         */
        public void clearAllBuckets() {
            buckets.clear();
            log.info("All rate limit buckets cleared");
        }

        /**
         * Get current bucket count (for monitoring)
         */
        public int getBucketCount() {
            return buckets.size();
        }

        /**
         * Define bandwidth limits for different endpoint types using modern Bucket4j API
         */
        private Bandwidth getBandwidthForType(RateLimitType type) {
            return switch (type) {
                case AUTH_ENDPOINTS -> 
                    // 20 requests per minute for authentication endpoints
                    Bandwidth.builder()
                        .capacity(20)
                        .refillIntervally(20, Duration.ofMinutes(1))
                        .build();
                    
                case TOKEN_REFRESH -> 
                    // 10 token refresh requests per minute (more restrictive)
                    Bandwidth.builder()
                        .capacity(10)
                        .refillIntervally(10, Duration.ofMinutes(1))
                        .build();
                    
                case USER_PROFILE -> 
                    // 100 requests per minute for user profile operations
                    Bandwidth.builder()
                        .capacity(100)
                        .refillIntervally(100, Duration.ofMinutes(1))
                        .build();
                    
                case GENERAL_API -> 
                    // 200 requests per minute for general API calls
                    Bandwidth.builder()
                        .capacity(200)
                        .refillIntervally(200, Duration.ofMinutes(1))
                        .build();
                    
                case ADMIN_ENDPOINTS ->
                    // 50 requests per minute for admin operations
                    Bandwidth.builder()
                        .capacity(50)
                        .refillIntervally(50, Duration.ofMinutes(1))
                        .build();
            };
        }
    }

    /**
     * Rate limit types for different categories of endpoints
     */
    public enum RateLimitType {
        AUTH_ENDPOINTS("Authentication endpoints - login, logout, OAuth2"),
        TOKEN_REFRESH("Token refresh operations"),
        USER_PROFILE("User profile operations"),
        GENERAL_API("General API endpoints"),
        ADMIN_ENDPOINTS("Administrative endpoints");

        private final String description;

        RateLimitType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}
