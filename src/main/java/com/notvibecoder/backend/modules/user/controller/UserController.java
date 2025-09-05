package com.notvibecoder.backend.modules.user.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.user.dto.*;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserResponseDto>> getCurrentUserProfile(
            @AuthenticationPrincipal UserDetails userDetails) {

        User user = userService.findByEmail(userDetails.getUsername());
        UserResponseDto userDto = UserResponseDto.from(user);
        return ResponseEntity.ok(ApiResponse.success("Profile retrieved", userDto));
    }

    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserResponseDto>> updateProfile(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UserUpdateRequest updateRequest) {

        User updatedUser = userService.updateProfile(userDetails.getUsername(), updateRequest);
        UserResponseDto userDto = UserResponseDto.from(updatedUser);
        return ResponseEntity.ok(ApiResponse.success("Profile updated", userDto));
    }

    @PostMapping("/exists")
    public ResponseEntity<ApiResponse<Boolean>> checkUserExists(
            @Valid @RequestBody UserExistsRequest request) {
        
        boolean exists = userService.existsByEmail(request.getEmail());
        return ResponseEntity.ok(ApiResponse.success("Email existence checked", exists));
    }

    @PostMapping("/profile/courses")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Void>> addPurchasedCourse(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CourseRequest request) {
        
        User user = userService.findByEmail(userDetails.getUsername());
        userService.addPurchasedCourse(user.getId(), request.getCourseId());
        return ResponseEntity.ok(ApiResponse.success("Course added to your purchased courses", null));
    }

    @DeleteMapping("/profile/courses/{courseId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Void>> removePurchasedCourse(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String courseId) {
        
        User user = userService.findByEmail(userDetails.getUsername());
        userService.removePurchasedCourse(user.getId(), courseId);
        return ResponseEntity.ok(ApiResponse.success("Course removed from your purchased courses", null));
    }
}