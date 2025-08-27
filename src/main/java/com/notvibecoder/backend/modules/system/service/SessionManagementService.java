package com.notvibecoder.backend.service;

import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class SessionManagementService {

    private final RefreshTokenRepository refreshTokenRepository;

    public void revokeUserSessions(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenRepository.save(token);
        log.info("All sessions revoked for user: {}", token.getUserId());
    }

    public void revokeUserSessions(String userId) {
        Optional<RefreshToken> activeToken = refreshTokenRepository.findActiveTokenByUserId(userId);
        if (activeToken.isPresent()) {
            revokeUserSessions(activeToken.get());
        }
    }


    public boolean hasActiveSession(String userId) {
        return refreshTokenRepository.existsByUserId(userId);
    }

    public Optional<RefreshToken> getCurrentSession(String userId) {
        return refreshTokenRepository.findActiveTokenByUserId(userId);
    }

    public Instant getLastActivityTime(String userId) {
        return refreshTokenRepository.findActiveTokenByUserId(userId)
                .map(RefreshToken::getLastUsed)
                .orElse(null);
    }

    public Optional<RefreshToken> handleExistingSession(String userId) {
        Optional<RefreshToken> existingToken = refreshTokenRepository.findActiveTokenByUserId(userId);
        if (existingToken.isPresent()) {
            log.info("User {} logging in from new device. Previous session will be terminated.", userId);
            revokeUserSessions(existingToken.get());
        }
        return existingToken;
    }
}