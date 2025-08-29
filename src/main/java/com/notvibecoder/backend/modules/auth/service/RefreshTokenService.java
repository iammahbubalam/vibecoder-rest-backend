package com.notvibecoder.backend.modules.auth.service;

import com.notvibecoder.backend.core.exception.TokenRefreshException;
import com.notvibecoder.backend.modules.admin.service.SecurityAuditService;
import com.notvibecoder.backend.modules.admin.service.SessionManagementService;
import com.notvibecoder.backend.modules.auth.entity.RefreshToken;
import com.notvibecoder.backend.modules.auth.repository.RefreshTokenRepository;
import com.notvibecoder.backend.modules.user.security.DeviceSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    public final RefreshTokenCookieService refreshTokenCookieService;
    public final SessionManagementService sessionManagementService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenGeneratorService tokenGeneratorService;
    private final DeviceSecurityService deviceSecurityService;
    private final SecurityAuditService securityAuditService;
    private final RefreshTokenConfigurationService configurationService;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }


    @Transactional
    public ResponseCookie createRefreshTokenCookie(String userId, HttpServletRequest request) {
        var existingToken = sessionManagementService.handleExistingSession(userId);
        RefreshToken savedToken = refreshTokenRepository.save(buildRefreshToken(userId, request));

        securityAuditService.logTokenCreation(userId, request, existingToken.isPresent());

        log.info("Created secure refresh token for user: {} (Single session enforced)", userId);
        return refreshTokenCookieService.createRefreshTokenCookie(savedToken.getToken());
    }

    public ResponseCookie createLogoutCookie() {
        return refreshTokenCookieService.createLogoutCookie();
    }

    public RefreshToken verifyRefreshToken(RefreshToken token, HttpServletRequest request) {

        if (!isValidToken(token, request)) {
            String reason = isRevoked(token) ? "revoked" : isExpired(token) ? "expired" : "invalid_device";
            log.warn("Invalid refresh token for user {}: {}", token.getUserId(), reason);
            throw new TokenRefreshException("Refresh token is " + reason + ". Please log in again.");
        }

        updateTokenUsage(token);
        securityAuditService.logTokenUsage(token.getUserId(), request);

        return token;
    }


    private RefreshToken buildRefreshToken(String userId, HttpServletRequest request) {
        String secureToken = tokenGeneratorService.generateSecureToken();
        var deviceInfo = deviceSecurityService.extractDeviceInfo(request);

        return RefreshToken.builder()
                .userId(userId)
                .token(secureToken)
                .deviceFingerprint(deviceInfo.fingerprint())
                .ipAddress(deviceInfo.ipAddress())
                .userAgent(deviceInfo.userAgent())
                .expiryDate(configurationService.calculateExpiryDate())
                .createdAt(Instant.now())
                .isRevoked(false)
                .build();
    }

    private boolean isRevoked(RefreshToken token) {
        return token.isRevoked();
    }

    private boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }

    private boolean isValidDevice(RefreshToken token, HttpServletRequest request) {
        return deviceSecurityService.verifyDeviceBinding(token, request);
    }

    private boolean isValidToken(RefreshToken token, HttpServletRequest request) {
        return !isRevoked(token) && !isExpired(token) && isValidDevice(token, request);
    }

    private void updateTokenUsage(RefreshToken token) {
        token.setLastUsed(Instant.now());
        refreshTokenRepository.save(token);
    }
}