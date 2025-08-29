package com.notvibecoder.backend.modules.admin.schedular;

import com.notvibecoder.backend.modules.auth.repository.RefreshTokenRepository;
import com.notvibecoder.backend.modules.auth.service.JwtBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtBlacklistService jwtBlacklistService;

    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupExpiredTokens() {
        try {
            Instant now = Instant.now();

            // ✅ Clean up expired refresh tokens (single device - should be minimal)
            refreshTokenRepository.deleteByExpiryDateBefore(now);
            jwtBlacklistService.cleanupExpiredTokens();
            // ✅ MongoDB TTL will handle blacklisted tokens automatically
            log.debug("Single device token cleanup completed successfully");

        } catch (Exception e) {
            log.error("Error during single device token cleanup: {}", e.getMessage());
        }
    }
}