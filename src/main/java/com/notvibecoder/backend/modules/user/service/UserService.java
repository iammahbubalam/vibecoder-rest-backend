package com.notvibecoder.backend.modules.user.service;

import com.notvibecoder.backend.core.exception.UserNotFoundException;
import com.notvibecoder.backend.modules.user.dto.UserUpdateRequest;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;

    // ← UPDATED CACHE NAME
    @Cacheable(value = "users-by-email", key = "#email")
    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }

    // ← UPDATED CACHE NAME AND EVICTION
    @CacheEvict(value = {"users-by-email", "users-by-id"}, key = "#email")
    @Transactional
    public User updateProfile(String email, UserUpdateRequest updateRequest) {
        User existingUser = findByEmail(email);

        if (updateRequest.getName() != null) {
            existingUser.setName(updateRequest.getName());
        }
        if (updateRequest.getPictureUrl() != null) {
            existingUser.setPictureUrl(updateRequest.getPictureUrl());
        }

        existingUser.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(existingUser);

        log.info("User profile updated: {}", email);
        return savedUser;
    }

    // ← UPDATED CACHE NAME
    @Cacheable(value = "users-by-id", key = "#id")
    @Transactional(readOnly = true)
    public User findById(String id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + id));
    }
}