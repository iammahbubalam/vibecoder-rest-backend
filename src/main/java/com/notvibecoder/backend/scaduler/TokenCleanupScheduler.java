package com.notvibecoder.backend.scaduler;

import com.notvibecoder.backend.repository.RefreshTokenRepository;
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

    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupExpiredTokens() {
        try {
            refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
            log.info("Cleaned up expired refresh tokens");
        } catch (Exception e) {
            log.error("Error during token cleanup", e);
        }
    }
}