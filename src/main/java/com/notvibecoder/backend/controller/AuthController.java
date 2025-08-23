package com.notvibecoder.backend.controller;


import com.notvibecoder.backend.dto.AuthResponse;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.service.AuthService;
import com.notvibecoder.backend.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    @GetMapping("/refresh")
    // @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(name = "refreshToken", required = false) String requestRefreshToken) {
        if (requestRefreshToken == null) {
            throw new TokenRefreshException("Refresh token is missing.");
        }

        AuthService.RotatedTokens rotatedTokens = authService.refreshTokens(requestRefreshToken);
        ResponseCookie refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(rotatedTokens.refreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(new AuthResponse(rotatedTokens.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@CookieValue(name = "refreshToken", required = false) String requestRefreshToken) {
        authService.logout(requestRefreshToken);
        ResponseCookie logoutCookie = refreshTokenService.createLogoutCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, logoutCookie.toString())
                .body("You've been signed out!");
    }
}