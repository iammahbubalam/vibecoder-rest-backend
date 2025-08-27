package com.notvibecoder.backend.modules.system.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.auth.security.UserPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping("/hello")
    public ResponseEntity<ApiResponse<Map<String, String>>> sayHello(@AuthenticationPrincipal UserPrincipal principal) {
        String message = "Hello from a secured endpoint, " + principal.getName() + "!";
        return ResponseEntity.ok(ApiResponse.success("Demo endpoint accessed successfully", 
                Map.of("message", message, "user", principal.getName())));
    }
}