package com.notvibecoder.backend.modules.admin.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.admin.service.AdminService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/debug")
@RequiredArgsConstructor
@Slf4j
public class DebugController {

    private final AdminService adminService;

    @GetMapping("/config")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getConfiguration() {
        log.info("Debug endpoint accessed - checking admin configuration");
        
        return ResponseEntity.ok(ApiResponse.success("Configuration retrieved", Map.of(
                "adminEmails", adminService.getAdminEmails(),
                "isAdminEmailTest", adminService.isAdminEmail("bubhamnojrin7196@gmail.com"),
                "timestamp", System.currentTimeMillis()
        )));
    }

    @GetMapping("/oauth2")
    public ResponseEntity<ApiResponse<String>> getOAuth2Info() {
        log.info("OAuth2 debug endpoint accessed");
        
        return ResponseEntity.ok(ApiResponse.success(
                "OAuth2 endpoints available", 
                "Try: http://localhost:8080/oauth2/authorize/google"
        ));
    }
}
