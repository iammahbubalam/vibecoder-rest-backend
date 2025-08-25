package com.notvibecoder.backend.service;

import com.notvibecoder.backend.entity.User;
import com.notvibecoder.backend.exception.UserNotFoundException;
import com.notvibecoder.backend.repository.UserRepository;
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

    @Cacheable(value = "users", key = "#email")
    @Transactional(readOnly = true)
    public com.notvibecoder.backend.entity.User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }

    @CacheEvict(value = "users", key = "#email")
    @Transactional
    public User updateProfile(String email, User updateRequest) {
        User existingUser = findByEmail(email);

        // Update allowed fields
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

    @Cacheable(value = "users", key = "#id")
    @Transactional(readOnly = true)
    public User findById(String id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + id));
    }
}