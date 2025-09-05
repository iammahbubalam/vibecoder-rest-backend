package com.notvibecoder.backend.modules.user.service;

import com.notvibecoder.backend.core.exception.ValidationException;
import com.notvibecoder.backend.core.exception.user.UserNotFoundException;
import com.notvibecoder.backend.modules.user.dto.UserUpdateRequest;
import com.notvibecoder.backend.modules.user.entity.Role;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;


    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }

    @Transactional
    public User updateProfile(String email, UserUpdateRequest updateRequest) {
        User existingUser = findByEmail(email);

        if (updateRequest.getName() != null) {
            existingUser.setName(updateRequest.getName());
        }

        existingUser.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(existingUser);

        log.info("User profile updated: {}", email);
        return savedUser;
    }

    @Transactional(readOnly = true)
    public User  findById(String id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + id));
    }


    @Transactional
    public void addPurchasedCourse(String userId, String courseId) {
        User user = findById(userId);

        // Create a new mutable set and add the course ID
        Set<String> updatedCourseIds = new HashSet<>(user.getPurchasedCourseIds());
        updatedCourseIds.add(courseId);

        user.setPurchasedCourseIds(updatedCourseIds);
        user.setUpdatedAt(Instant.now());

        userRepository.save(user);
        log.info("Added course {} to user {}'s purchased courses", courseId, userId);
    }


    @Transactional
    public void removePurchasedCourse(String userId, String courseId) {
        User user = findById(userId);

        // Create a new mutable set and remove the course ID
        Set<String> updatedCourseIds = new HashSet<>(user.getPurchasedCourseIds());
        boolean removed = updatedCourseIds.remove(courseId);

        if (removed) {
            user.setPurchasedCourseIds(updatedCourseIds);
            user.setUpdatedAt(Instant.now());

            userRepository.save(user);
            log.info("Removed course {} from user {}'s purchased courses", courseId, userId);
        } else {
            log.warn("Course {} was not found in user {}'s purchased courses", courseId, userId);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        if (!StringUtils.hasText(email)) {
            log.warn("Attempt to check existence with null or empty email");
            return false;
        }
        
        boolean exists = userRepository.findByEmail(email).isPresent();
        log.debug("Email existence check for '{}': {}", email, exists);
        return exists;
    }

    @Override
    @Transactional
    public void changeUserRole(String userId, String newRole) {
        if (!StringUtils.hasText(userId)) {
            throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
        }

        if (!StringUtils.hasText(newRole)) {
            throw new ValidationException("Role cannot be null or empty", "ROLE_REQUIRED");
        }

        Role role;
        try {
            role = Role.valueOf(newRole.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ValidationException("Invalid role: " + newRole + ". Valid roles are: USER, ADMIN", "INVALID_ROLE");
        }

        User user = findById(userId);
        
        // Check if user already has this role
        if (user.getRoles().contains(role)) {
            log.info("User {} already has role {}, no change needed", userId, role);
            return;
        }

        // Create a new mutable set with the new role (replacing all existing roles for simplicity)
        Set<Role> newRoles = new HashSet<>();
        newRoles.add(role);
        
        user.setRoles(newRoles);
        user.setUpdatedAt(Instant.now());

        userRepository.save(user);
        log.info("Changed user {} role to {}", userId, role);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        if (!StringUtils.hasText(userId)) {
            throw new ValidationException("User ID cannot be null or empty", "USER_ID_REQUIRED");
        }

        User user = findById(userId); // This will throw UserNotFoundException if user doesn't exist
        
        // Perform soft delete by disabling the user instead of hard delete
        // This preserves data integrity and audit trails
        user.setEnabled(false);
        user.setUpdatedAt(Instant.now());
        
        userRepository.save(user);
        log.info("User {} has been soft deleted (disabled)", userId);
        
        // Uncomment below for hard delete if preferred:
        // userRepository.deleteById(userId);
        // log.info("User {} has been permanently deleted", userId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        log.info("Fetching all users");
        List<User> users = userRepository.findAll();
        log.info("Retrieved {} users", users.size());
        return users;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> getAllUsers(Pageable pageable) {
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null", "PAGEABLE_REQUIRED");
        }
        
        log.info("Fetching users with pagination - page: {}, size: {}", 
                pageable.getPageNumber(), pageable.getPageSize());
        
        Page<User> userPage = userRepository.findAll(pageable);
        
        log.info("Retrieved {} users out of {} total users", 
                userPage.getNumberOfElements(), userPage.getTotalElements());
        
        return userPage;
    }
}