package com.notvibecoder.backend.controller;

import com.notvibecoder.backend.security.UserPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping("/hello")
    public ResponseEntity<String> sayHello(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok("Hello from a secured endpoint, " + principal.getName() + "!");
    }
}