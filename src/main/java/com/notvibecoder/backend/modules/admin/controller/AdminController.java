package com.notvibecoder.backend.modules.admin.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.admin.constants.SecurityConstants;
import com.notvibecoder.backend.modules.admin.service.AdminService;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/test")
    @PreAuthorize(SecurityConstants.HAS_ROLE_ADMIN)
    public ResponseEntity<ApiResponse<Map<String, Object>>> adminTest(
            @AuthenticationPrincipal UserPrincipal principal) {

        log.info("Admin endpoint accessed by: {}", principal.getEmail());

        return ResponseEntity.ok(ApiResponse.success("Admin access confirmed", Map.of(
                "message", "Welcome to admin panel!",
                "userEmail", principal.getEmail(),
                "userRoles", principal.getAuthorities(),
                "adminEmails", adminService.getAdminEmails()
        )));
    }

    @GetMapping("/check")
    @PreAuthorize(SecurityConstants.IS_AUTHENTICATED)
    public ResponseEntity<ApiResponse<Map<String, Object>>> checkAdminStatus(
            @AuthenticationPrincipal UserPrincipal principal) {

        boolean isAdmin = adminService.isAdminEmail(principal.getEmail());
        boolean hasAdminRole = principal.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        return ResponseEntity.ok(ApiResponse.success("Admin status checked", Map.of(
                "userEmail", principal.getEmail(),
                "isAdminEmail", isAdmin,
                "hasAdminRole", hasAdminRole,
                "userRoles", principal.getAuthorities()
        )));
    }
}
