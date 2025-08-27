package com.notvibecoder.backend.modules.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenCookieService {

    private final RefreshTokenConfigurationService configurationService;

    @Value("${app.environment:dev}")
    private String environment;

    public ResponseCookie createRefreshTokenCookie(String token) {
        return ResponseCookie.from("refreshToken", token)
                .httpOnly(true)
                .secure(isProductionEnvironment())
                .path("/api/v1/auth")
                .maxAge(configurationService.getExpirationTimeInSeconds())
                .sameSite("Strict")
                .build();
    }

    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(isProductionEnvironment())
                .path("/api/v1/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }

    private boolean isProductionEnvironment() {
        return "prod".equals(environment);
    }
}