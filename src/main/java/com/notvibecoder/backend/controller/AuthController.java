package com.notvibecoder.backend.controller;

import com.notvibecoder.backend.dto.AccessTokenResponse;
import com.notvibecoder.backend.entity.User;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.repository.RefreshTokenRepository;
import com.notvibecoder.backend.repository.UserRepository;
import com.notvibecoder.backend.service.JwtService;
import com.notvibecoder.backend.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refreshToken(@CookieValue(name = "refreshToken", required = false) String requestRefreshToken) {
        if (requestRefreshToken == null) {
            throw new TokenRefreshException("Refresh token is missing.");
        }

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(oldToken -> {
                    User user = userRepository.findById(oldToken.getUserId())
                            .orElseThrow(() -> new TokenRefreshException("User not found for refresh token."));

                    var newRefreshToken = refreshTokenService.rotateRefreshToken(oldToken);
                    var newAccessToken = jwtService.generateToken(userDetailsService.loadUserByUsername(user.getEmail()));
                    var refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(newRefreshToken.getToken());

                    log.info("Tokens refreshed successfully for user {}", user.getEmail());
                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                            .body(new AccessTokenResponse(newAccessToken));
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found in database."));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@CookieValue(name = "refreshToken", required = false) String requestRefreshToken) {
        if (requestRefreshToken != null) {
            refreshTokenService.findByToken(requestRefreshToken)
                    .ifPresent(token -> refreshTokenRepository.deleteById(token.getId()));
        }

        ResponseCookie logoutCookie = refreshTokenService.createLogoutCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, logoutCookie.toString())
                .body("You've been signed out!");
    }
}
