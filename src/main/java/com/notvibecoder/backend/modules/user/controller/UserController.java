package com.notvibecoder.backend.modules.user.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.user.dto.UserUpdateRequest;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<User>> getCurrentUserProfile(
            @AuthenticationPrincipal UserDetails userDetails) {

        User user = userService.findByEmail(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.success("Profile retrieved", user));
    }

    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<User>> updateProfile(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UserUpdateRequest updateRequest) {

        User updatedUser = userService.updateProfile(userDetails.getUsername(), updateRequest);
        return ResponseEntity.ok(ApiResponse.success("Profile updated", updatedUser));
    }
}