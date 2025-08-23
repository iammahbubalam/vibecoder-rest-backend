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
                    // Delete old token
                    refreshTokenService.deleteByUserId(oldToken.getUserId());

                    // Create new refresh token
                    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(oldToken.getUserId());

                    // Fetch user and create new access token
                    User user = userRepository.findById(oldToken.getUserId())
                            .orElseThrow(() -> new TokenRefreshException("User not found for refresh token."));
                    String newAccessToken = jwtService.generateToken(UserPrincipal.create(user, null));

                    log.info("Tokens refreshed successfully for user {}", user.getEmail());
                    return new RotatedTokens(newAccessToken, newRefreshToken.getToken());
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found in database."));
    }

    @Transactional
    public void logout(String requestRefreshToken) {
        if (requestRefreshToken != null) {
            refreshTokenService.findByToken(requestRefreshToken)
                    .ifPresent(token -> refreshTokenService.deleteByUserId(token.getUserId()));
        }
    }

    public record RotatedTokens(String accessToken, String refreshToken) {
    }
}