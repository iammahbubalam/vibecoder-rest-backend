package com.notvibecoder.backend.service;

import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.entity.User;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.repository.UserRepository;
import com.notvibecoder.backend.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Transactional
    public RotatedTokens refreshTokens(String requestRefreshToken) {
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(oldToken -> {
                    // ✅ Enhanced security: verify user is still active
                    User user = userRepository.findById(oldToken.getUserId())
                            .orElseThrow(() -> new TokenRefreshException("User not found for refresh token."));
                    
                    // ✅ Check if user account is still enabled
                    if (!user.getEnabled()) {
                        refreshTokenService.deleteByUserId(user.getId());
                        throw new TokenRefreshException("User account is disabled.");
                    }
                    
                    // ✅ Single device: Delete old refresh token (will be only one)
                    refreshTokenService.deleteByUserId(oldToken.getUserId());

                    // ✅ Single device: Create new refresh token (ensures only one exists)
                    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(oldToken.getUserId());

                    // Create new access token with enhanced claims
                    String newAccessToken = jwtService.generateToken(UserPrincipal.create(user, null));

                    log.info("Single session tokens refreshed successfully for user {}", user.getEmail());
                    return new RotatedTokens(newAccessToken, newRefreshToken.getToken());
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found in database."));
    }

    @Transactional
    public void logout(String requestRefreshToken) {
        logout(requestRefreshToken, null);
    }
    
    @Transactional
    public void logout(String requestRefreshToken, String accessToken) {
        // ✅ Enhanced: Blacklist the current access token immediately
        if (accessToken != null) {
            jwtService.blacklistToken(accessToken, "user_logout");
            log.info("Access token blacklisted on logout");
        }
        
        // ✅ Single device: Delete the single refresh token
        if (requestRefreshToken != null) {
            refreshTokenService.findByToken(requestRefreshToken)
                    .ifPresent(token -> {
                        refreshTokenService.deleteByUserId(token.getUserId());
                        log.info("Single session terminated for user: {}", token.getUserId());
                    });
        }
        
        log.info("User logged out successfully from single device");
    }

    public record RotatedTokens(String accessToken, String refreshToken) {}
}