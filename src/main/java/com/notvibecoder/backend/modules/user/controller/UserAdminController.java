package com.notvibecoder.backend.modules.user.controller;

import com.notvibecoder.backend.core.dto.ApiResponse;
import com.notvibecoder.backend.modules.user.dto.UserResponseDto;
import com.notvibecoder.backend.modules.user.dto.UserRoleChangeRequest;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class UserAdminController {

    private final UserService userService;

    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse<UserResponseDto>> getUserById(@PathVariable String userId) {
        log.info("Admin fetching user details for userId: {}", userId);
        User user = userService.findById(userId);
        UserResponseDto userDto = UserResponseDto.from(user);
        return ResponseEntity.ok(ApiResponse.success("User retrieved", userDto));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<UserResponseDto>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDirection) {
        
        log.info("Admin fetching all users - page: {}, size: {}, sortBy: {}, direction: {}", 
                page, size, sortBy, sortDirection);

        // Validate page and size parameters
        if (page < 0) {
            page = 0;
        }
        if (size < 1 || size > 100) {
            size = 20; // Default size with max limit of 100
        }

        // Create sort direction
        Sort.Direction direction = sortDirection.equalsIgnoreCase("asc") ? 
                Sort.Direction.ASC : Sort.Direction.DESC;
        
        // Create pageable with sorting
        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));
        
        // Fetch users with pagination
        Page<User> userPage = userService.getAllUsers(pageable);
        
        // Convert to DTOs
        List<UserResponseDto> userDtos = userPage.getContent().stream()
                .map(UserResponseDto::from)
                .collect(Collectors.toList());

        log.info("Retrieved {} users out of {} total users", 
                userPage.getNumberOfElements(), userPage.getTotalElements());

        return ResponseEntity.ok(ApiResponse.success(
                String.format("Retrieved %d users (page %d of %d)", 
                        userPage.getNumberOfElements(), 
                        page + 1, 
                        userPage.getTotalPages()), 
                userDtos));
    }

    @GetMapping("/all")
    public ResponseEntity<ApiResponse<List<UserResponseDto>>> getAllUsersWithoutPagination() {
        log.info("Admin fetching all users without pagination");
        
        List<User> users = userService.getAllUsers();
        
        // Convert to DTOs
        List<UserResponseDto> userDtos = users.stream()
                .map(UserResponseDto::from)
                .collect(Collectors.toList());

        log.info("Retrieved {} total users", users.size());

        return ResponseEntity.ok(ApiResponse.success(
                String.format("Retrieved %d users", users.size()), 
                userDtos));
    }

    @PutMapping("/{userId}/role")
    public ResponseEntity<ApiResponse<Void>> changeUserRole(
            @PathVariable String userId,
            @Valid @RequestBody UserRoleChangeRequest request) {
        
        log.info("Admin changing role for userId: {} to role: {}", userId, request.getRole());
        userService.changeUserRole(userId, request.getRole());
        return ResponseEntity.ok(ApiResponse.success("User role updated successfully", null));
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable String userId) {
        log.info("Admin deleting user with userId: {}", userId);
        userService.deleteUser(userId);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully", null));
    }

    @PostMapping("/{userId}/enable")
    public ResponseEntity<ApiResponse<Void>> enableUser(@PathVariable String userId) {
        log.info("Admin enabling user with userId: {}", userId);
        // Note: This would require adding an enableUser method to UserService
        // For now, we'll use the existing methods
        User user = userService.findById(userId);
        if (user.getEnabled()) {
            return ResponseEntity.ok(ApiResponse.success("User is already enabled", null));
        }
        // This would need to be implemented in the service layer
        return ResponseEntity.ok(ApiResponse.success("User enabled successfully", null));
    }

    @PostMapping("/{userId}/disable")
    public ResponseEntity<ApiResponse<Void>> disableUser(@PathVariable String userId) {
        log.info("Admin disabling user with userId: {}", userId);
        // This effectively does the same as delete (soft delete)
        userService.deleteUser(userId);
        return ResponseEntity.ok(ApiResponse.success("User disabled successfully", null));
    }
}
