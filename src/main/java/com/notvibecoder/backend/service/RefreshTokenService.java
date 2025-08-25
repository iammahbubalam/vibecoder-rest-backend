package com.notvibecoder.backend.service;

import com.notvibecoder.backend.config.properties.JwtProperties;
import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.repository.RefreshTokenRepository;
import com.notvibecoder.backend.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int TOKEN_LENGTH = 64;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    @Value("${app.environment:dev}")
    private String environment;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(String userId) {
        return createRefreshToken(userId, null);
    }

    @Transactional
    public RefreshToken createRefreshToken(String userId, HttpServletRequest request) {

        // Verify user exists
        userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        // Single device: Check if user has existing session
        Optional<RefreshToken> existingToken = refreshTokenRepository.findActiveTokenByUserId(userId);
        if (existingToken.isPresent()) {
            log.info("User {} logging in from new device. Previous session will be terminated.", userId);
        }

        // Single device enforcement: Delete any existing tokens
        refreshTokenRepository.deleteByUserIdAndIsRevoked(userId, false);

        // Generate cryptographically secure token
        String secureToken = generateSecureToken();

        // Create device fingerprint for security tracking
        String deviceFingerprint = request != null ? createDeviceFingerprint(request) : null;
        String clientIp = request != null ? getClientIp(request) : null;
        String userAgent = request != null ? request.getHeader("User-Agent") : null;

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(secureToken)
                .deviceFingerprint(deviceFingerprint)
                .ipAddress(clientIp)
                .userAgent(userAgent)
                .expiryDate(Instant.now().plusMillis(jwtProperties.refreshToken().expirationMs()))
                .createdAt(Instant.now())
                .isRevoked(false)  // ✅ ADDED - Explicit default
                .build();

        log.info("Device fingerprint: {}", deviceFingerprint);
        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);

        // Security audit logging
        if (request != null) {
            logTokenCreation(userId, request, existingToken.isPresent());
        }

        log.info("Created secure refresh token for user: {} (Single session enforced)", userId);
        return savedToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        return verifyExpiration(token, null);
    }

    public RefreshToken verifyExpiration(RefreshToken token, HttpServletRequest request) {

        // Check if token is revoked
        if (token.isRevoked()) {
            log.warn("Revoked refresh token attempted for user: {}", token.getUserId());
            throw new TokenRefreshException("Token has been revoked. Please login again.");
        }

        // Check expiration
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.deleteById(token.getId());  // ✅ FIXED - Use ID instead of object
            log.warn("Expired refresh token deleted for user: {}", token.getUserId());
            throw new TokenRefreshException("Refresh token expired. Please login again.");
        }

        // Single device security: verify device binding if request available
        if (request != null && !verifyDeviceBinding(token, request)) {
            refreshTokenRepository.deleteById(token.getId());  // ✅ FIXED - Use ID instead of object
            log.error("Device fingerprint mismatch for user: {} - possible token theft or device change", token.getUserId());
            throw new TokenRefreshException("Session security violation detected. Please login again.");
        }

        // Update last used timestamp for monitoring
        token.setLastUsed(Instant.now());
        refreshTokenRepository.save(token);

        // Security audit logging
        if (request != null) {
            logTokenUsage(token.getUserId(), request);
        }

        return token;
    }

    @Transactional
    public void deleteByUserId(String userId) {
        refreshTokenRepository.deleteByUserIdAndIsRevoked(userId, false);
        log.info("Single session terminated for user: {}", userId);
    }

    public ResponseCookie createRefreshTokenCookie(String token) {
        return ResponseCookie.from("refreshToken", token)
                .httpOnly(true)
                .secure("prod".equals(environment)) // ✅ Environment-dependent
                .path("/api/v1/auth")
                .maxAge(jwtProperties.refreshToken().expirationMs() / 1000)
                .sameSite("Strict") // ✅ Enhanced CSRF protection
                .build();
    }

    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure("prod".equals(environment))
                .path("/api/v1/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }

    // ==================== SECURITY METHODS ====================

    private String generateSecureToken() {
        byte[] tokenBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    private String createDeviceFingerprint(HttpServletRequest request) {
        String fingerprint = request.getHeader("User-Agent") + "|" +
                request.getHeader("Accept-Language") + "|" +
                request.getHeader("Accept-Encoding") + "|" +
                getClientIp(request);

        return String.valueOf(fingerprint.hashCode());
    }

    private boolean verifyDeviceBinding(RefreshToken token, HttpServletRequest request) {
        if (token.getDeviceFingerprint() == null) {
            return true; // Skip verification for legacy tokens
        }

        String currentFingerprint = createDeviceFingerprint(request);
        boolean fingerprintMatch = currentFingerprint.equals(token.getDeviceFingerprint());

        if (!fingerprintMatch) {
            log.warn("Device fingerprint mismatch for user: {} - Expected: {}, Got: {}",
                    token.getUserId(), token.getDeviceFingerprint(), currentFingerprint);
        }

        return fingerprintMatch;
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xfHeader)) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void logTokenCreation(String userId, HttpServletRequest request, boolean hadExistingSession) {
        if (hadExistingSession) {
            log.warn("SECURITY_AUDIT: New device login terminated previous session - User: {}, IP: {}, UserAgent: {}",
                    userId, getClientIp(request), request.getHeader("User-Agent"));
        } else {
            log.info("SECURITY_AUDIT: Single session created - User: {}, IP: {}, UserAgent: {}",
                    userId, getClientIp(request), request.getHeader("User-Agent"));
        }
    }

    private void logTokenUsage(String userId, HttpServletRequest request) {
        log.info("SECURITY_AUDIT: Session token used - User: {}, IP: {}",
                userId, getClientIp(request));
    }

    // ==================== SINGLE SESSION MONITORING ====================

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
}