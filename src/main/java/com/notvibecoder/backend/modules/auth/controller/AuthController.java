package com.notvibecoder.backend.modules.auth.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.core.exception.BusinessException;
import com.notvibecoder.backend.modules.auth.service.AuthService;
import com.notvibecoder.backend.core.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    @GetMapping("/refresh")
    public ResponseEntity<ApiResponse<Map<String, String>>> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String requestRefreshToken,
            HttpServletRequest request) {

        if (requestRefreshToken == null || requestRefreshToken.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Refresh token is required", "MISSING_REFRESH_TOKEN"));
        }

        try {
            String clientIp = SecurityUtils.getClientIpAddress(request);
            log.info("Token refresh attempt from IP: {}", clientIp);

            var rotatedTokens = authService.refreshUser(requestRefreshToken, request);

            return ResponseEntity.ok()
                    .header("Set-Cookie", rotatedTokens.cookie().toString())
                    .body(ApiResponse.success("Token refreshed successfully",
                            Map.of("accessToken", rotatedTokens.accessToken())));

        } catch (BusinessException e) {
            log.error("Token refresh failed from IP: {} - Error: {}",
                    SecurityUtils.getClientIpAddress(request), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error(e.getMessage(), e.getErrorCode()));
        } catch (Exception e) {
            log.error("Unexpected error during token refresh from IP: {} - Error: {}",
                    SecurityUtils.getClientIpAddress(request), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Token refresh failed", "TOKEN_REFRESH_ERROR"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Map<String, String>>> logout(
            @CookieValue(name = "refreshToken", required = false) String requestRefreshToken,
            HttpServletRequest request) {

        try {
            String accessToken = extractAccessTokenFromRequest(request);
            var logoutCookie = authService.logout(requestRefreshToken, accessToken);
            log.info("Logout attempt from IP: {}", SecurityUtils.getClientIpAddress(request));
            return ResponseEntity.ok()
                    .header("Set-Cookie", logoutCookie.toString())
                    .body(ApiResponse.success("Logged out successfully",
                            Map.of("sessionType", "single_device")));

        } catch (Exception e) {
            log.error("Logout error for IP: {} - {}",
                    SecurityUtils.getClientIpAddress(request), e.getMessage());
            return ResponseEntity.ok()
                    .body(ApiResponse.success("Logout completed", Map.of()));
        }
    }

    @GetMapping("/validate")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Map<String, Object>>> validateToken() {
        return ResponseEntity.ok(ApiResponse.success(Map.of(
                "valid", true,
                "user", SecurityUtils.getCurrentUsername().orElse("unknown"),
                "sessionType", "single_device",
                "timestamp", System.currentTimeMillis()
        )));
    }

    private String extractAccessTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return (String) request.getAttribute("jwt");
    }

    @GetMapping("/session-info")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getSessionInfo(HttpServletRequest request) {
        // This endpoint can provide session information for the single device
        return ResponseEntity.ok(Map.of(
                "sessionType", "single_device",
                "ip", SecurityUtils.getClientIpAddress(request),
                "userAgent", request.getHeader("User-Agent"),
                "timestamp", System.currentTimeMillis()
        ));
    }

}