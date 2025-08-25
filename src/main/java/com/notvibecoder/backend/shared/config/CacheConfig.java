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
        cacheManager.setCacheNames(Arrays.asList("users", "tokens", "blacklist"));
        return cacheManager;
    }

    @Bean("userCacheManager")
    public CacheManager userCacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager("users");
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(Duration.ofMinutes(15))
                .expireAfterAccess(Duration.ofMinutes(5))
                .recordStats()
        );
        return cacheManager;
    }

    @Bean("tokenCacheManager")
    public CacheManager tokenCacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager("tokens", "blacklist");
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(5000)
                .expireAfterWrite(Duration.ofMinutes(10))
                .recordStats()
        );
        return cacheManager;
    }

    private Caffeine<Object, Object> defaultCaffeineConfig() {
        return Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(Duration.ofMinutes(15))
                .expireAfterAccess(Duration.ofMinutes(5))
                .recordStats();
    }
}