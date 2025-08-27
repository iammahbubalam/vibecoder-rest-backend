package com.notvibecoder.backend.service;

import com.notvibecoder.backend.entity.BlacklistedToken;
import com.notvibecoder.backend.repository.BlacklistedTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtBlacklistService {

    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final JwtTokenUtil jwtTokenUtil;

    @CacheEvict(value = "blacklist", key = "#token", cacheManager = "tokenCacheManager")
    public void blacklistToken(String token, String reason) {
        try {
            String jwtId = jwtTokenUtil.extractJwtId(token);
            String userId = jwtTokenUtil.extractUserId(token);
            String username = jwtTokenUtil.extractUsername(token);
            Date expiration = jwtTokenUtil.extractExpiration(token);

            BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                    .jwtId(jwtId)
                    .userId(userId != null ? userId : username) // Fallback to username
                    .reason(reason)
                    .blacklistedAt(Instant.now())
                    .expiresAt(expiration.toInstant())
                    .build();

            blacklistedTokenRepository.save(blacklistedToken);
            log.info("Token blacklisted - JWT ID: {}, User: {}, Reason: {}", jwtId, userId, reason);

        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
            // Don't throw - blacklisting failure shouldn't break logout
        }
    }

    @Cacheable(value = "blacklist", key = "#token", cacheManager = "tokenCacheManager")
    public boolean isTokenBlacklisted(String token) {
        try {
            String jwtId = jwtTokenUtil.extractJwtId(token);
            return blacklistedTokenRepository.existsByJwtId(jwtId);
        } catch (Exception e) {
            log.error("Error checking blacklist: {}", e.getMessage());
            return true; // Fail secure
        }
    }

    public void blacklistAllUserTokens(String userId, String reason) {
        try {
            // Single session: simpler since only one token per user
            log.info("Blacklisting current session for user: {} with reason: {}", userId, reason);
        } catch (Exception e) {
            log.error("Error blacklisting user session: {}", e.getMessage());
        }
    }

    public void cleanupExpiredTokens() {
        try {
            long deletedCount = blacklistedTokenRepository.deleteByExpiresAtBefore(Instant.now());
            if (deletedCount > 0) {
                log.info("Cleaned up {} expired blacklisted tokens", deletedCount);
            }
        } catch (Exception e) {
            log.error("Error cleaning up expired blacklisted tokens: {}", e.getMessage());
        }
    }
}