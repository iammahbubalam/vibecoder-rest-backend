package com.notvibecoder.backend.shared.config;


import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.time.Duration;
import java.util.Arrays;

@Configuration
@EnableCaching
public class CacheConfig {

      @Bean
    @Primary
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(defaultCaffeineConfig());
        
        // Set ALL cache names with consistent configuration
        cacheManager.setCacheNames(Arrays.asList(
            "users-by-email", 
            "users-by-id", 
            "blacklist", 
            "tokens"
        ));
        return cacheManager;
    }

    private Caffeine<Object, Object> defaultCaffeineConfig() {
        return Caffeine.newBuilder()
                .maximumSize(5000)  // Increased for all caches
                .expireAfterWrite(Duration.ofMinutes(15))
                .expireAfterAccess(Duration.ofMinutes(5))
                .recordStats();
    }
}