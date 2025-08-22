package com.notvibecoder.backend.service;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.notvibecoder.backend.config.properties.JwtProperties;
import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.repository.RefreshTokenRepository;
import com.notvibecoder.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.notvibecoder.backend.exception.UserNotFoundException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    private static final String AUTH_PATH = "/api/v1/auth";

    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        if (StringUtils.isBlank(token)) {
            return Optional.empty();
        }
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(String userId) {
        validateUserId(userId);
        verifyUserExists(userId);

        // Revoke all existing tokens for single-session enforcement
        int revokedCount = refreshTokenRepository.revokeAllByUserId(userId);
        if (revokedCount > 0) {
            log.info("Revoked {} existing refresh tokens for user: {}", revokedCount, userId);
        }

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(generateSecureToken())
                .expiryDate(calculateExpiryDate())
                .createdAt(Instant.now())
                .revoked(false)
                .build();

        log.info("Created new refresh token for user id: {}", userId);
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        validateToken(oldToken);
        validateUserId(oldToken.getUserId());

        if (isTokenExpired(oldToken)) {
            throw new TokenRefreshException("Refresh token was expired. Please make a new signin request.");
        }

        if (oldToken.isRevoked()) {
            throw new TokenRefreshException("Refresh token was revoked. Please make a new signin request.");
        }

        // Revoke the old token instead of deleting
        refreshTokenRepository.revokeToken(oldToken.getId());
        log.info("Revoked old refresh token for user id: {}", oldToken.getUserId());

        return createRefreshToken(oldToken.getUserId());
    }

    public void verifyExpiration(RefreshToken token) {
        validateToken(token);

        if (isTokenExpired(token)) {
            throw new TokenRefreshException("Refresh token was expired. Please make a new signin request.");
        }

        if (token.isRevoked()) {
            throw new TokenRefreshException("Refresh token was revoked. Please make a new signin request.");
        }
    }

    @Transactional
    public void revokeToken(RefreshToken token) {
        validateToken(token);
        refreshTokenRepository.revokeToken(token.getId());
        log.info("Revoked refresh token for user id: {}", token.getUserId());
    }

    @Transactional
    public void revokeAllUserTokens(String userId) {
        validateUserId(userId);
        int revokedCount = refreshTokenRepository.revokeAllByUserId(userId);
        log.info("Revoked {} refresh tokens for user id: {}", revokedCount, userId);
    }

    private boolean isTokenExpired(RefreshToken token) {
        return token.getExpiryDate() != null && token.getExpiryDate().isBefore(Instant.now());
    }

    private void validateToken(RefreshToken token) {
        Objects.requireNonNull(token, "Token cannot be null");
        Objects.requireNonNull(token.getExpiryDate(), "Token expiry date cannot be null");
    }

    private void validateUserId(String userId) {
        if (StringUtils.isBlank(userId)) {
            throw new IllegalArgumentException("User ID cannot be null or empty");
        }
    }

    private void verifyUserExists(String userId) {
        userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
    }

    private String generateSecureToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private Instant calculateExpiryDate() {
        return Instant.now().plusMillis(jwtProperties.getRefreshToken().getExpirationMs());
    }

    public ResponseCookie createRefreshTokenCookie(String token, boolean isSecure) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, token)
                .httpOnly(true)
                .secure(isSecure)
                .path(AUTH_PATH)
                .maxAge(Duration.ofMillis(jwtProperties.getRefreshToken().getExpirationMs()))
                .sameSite("Strict")
                .build();
    }

    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .path(AUTH_PATH)
                .maxAge(Duration.ZERO)
                .sameSite("Strict")
                .build();
    }
}