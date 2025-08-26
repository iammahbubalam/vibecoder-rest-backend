package com.notvibecoder.backend.service;

import com.notvibecoder.backend.dto.RotatedTokens;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.repository.UserRepository;
import com.notvibecoder.backend.security.UserPrincipal;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final SessionManagementService sessionManagementService;

    @Transactional
    public RotatedTokens refreshUser(String requestRefreshToken, HttpServletRequest request) {
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(token -> refreshTokenService.verifyRefreshToken(token, request))
                .map(oldToken -> {
                    var user = userRepository.findById(oldToken.getUserId())
                            .orElseThrow(() -> new TokenRefreshException("User not found for refresh token."));
                    if (!user.getEnabled()) {
                        sessionManagementService.revokeUserSessions(oldToken);
                        throw new TokenRefreshException("User account is disabled.");
                    }
                    var cookie = refreshTokenService.createRefreshTokenCookie(oldToken.getUserId(), request);
                    String accessToken = jwtService.generateToken(UserPrincipal.create(user, null));

                    log.info("Single session tokens refreshed successfully for user {}", user.getEmail());
                    return new RotatedTokens(accessToken, cookie);
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found in database."));
    }

    @Transactional
    public ResponseCookie logout(String requestRefreshToken, String accessToken) {
        if (accessToken != null) {
            jwtService.blacklistToken(accessToken, "user_logout");
            log.info("Access token blacklisted on logout");
        }
        if (requestRefreshToken != null) {
            refreshTokenService.findByToken(requestRefreshToken)
                    .ifPresent(token -> {
                        sessionManagementService.revokeUserSessions(token);
                        log.info("Single session terminated for user: {}", token.getUserId());
                    });
        }
        log.info("User logged out successfully from single device");
        return refreshTokenService.createLogoutCookie();
    }


}