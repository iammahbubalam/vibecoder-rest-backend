package com.notvibecoder.backend.controller;

import com.notvibecoder.backend.dto.AuthResponse;
import com.notvibecoder.backend.exception.TokenRefreshException;
import com.notvibecoder.backend.service.AuthService;
import com.notvibecoder.backend.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    @GetMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String requestRefreshToken,
            HttpServletRequest request) {
        
        if (requestRefreshToken == null) {
            throw new TokenRefreshException("Refresh token is missing.");
        }

        try {
            AuthService.RotatedTokens rotatedTokens = authService.refreshTokens(requestRefreshToken);
            ResponseCookie refreshTokenCookie = refreshTokenService.createRefreshTokenCookie(rotatedTokens.refreshToken());

            // ✅ Enhanced logging for single device security monitoring
            log.info("Single session token refresh successful from IP: {}", getClientIp(request));

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                    .body(new AuthResponse(rotatedTokens.accessToken()));
                    
        } catch (Exception e) {
            log.error("Single session token refresh failed from IP: {} - Error: {}", getClientIp(request), e.getMessage());
            throw e;
        }
    }

    // @PostMapping("/logout")
    @GetMapping("/logout")
    public ResponseEntity<Map<String, String>> logoutUser(
            @CookieValue(name = "refreshToken", required = false) String requestRefreshToken,
            HttpServletRequest request) {
        
        try {
            // ✅ Extract current access token for blacklisting
            String accessToken = extractAccessTokenFromRequest(request);
            
            authService.logout(requestRefreshToken, accessToken);
            ResponseCookie logoutCookie = refreshTokenService.createLogoutCookie();
            
            log.info("Single device logout successful from IP: {}", getClientIp(request));
            
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, logoutCookie.toString())
                    .body(Map.of(
                            "message", "You've been signed out successfully!",
                            "sessionType", "single_device"
                    ));
                    
        } catch (Exception e) {
            log.error("Logout failed from IP: {} - Error: {}", getClientIp(request), e.getMessage());
            return ResponseEntity.ok()
                    .body(Map.of("message", "Logout completed"));
        }
    }
    
    @GetMapping("/validate")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> validateToken() {
        return ResponseEntity.ok(Map.of(
                "valid", true,
                "message", "Token is valid",
                "sessionType", "single_device"
        ));
    }
    
    @GetMapping("/session-info")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getSessionInfo(HttpServletRequest request) {
        // This endpoint can provide session information for the single device
        return ResponseEntity.ok(Map.of(
                "sessionType", "single_device",
                "ip", getClientIp(request),
                "userAgent", request.getHeader("User-Agent"),
                "timestamp", System.currentTimeMillis()
        ));
    }
    
    // ==================== HELPER METHODS ====================
    
    private String extractAccessTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}