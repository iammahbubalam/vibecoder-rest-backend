package com.notvibecoder.backend.modules.user.service;

import com.notvibecoder.backend.core.exception.UserNotFoundException;
import com.notvibecoder.backend.modules.user.dto.UserUpdateRequest;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.modules.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

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
        if (updateRequest.getPictureUrl() != null) {
            existingUser.setPictureUrl(updateRequest.getPictureUrl());
        }

        existingUser.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(existingUser);

        log.info("User profile updated: {}", email);
        return savedUser;
    }

    @Transactional(readOnly = true)
    public User findById(String id) {
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

    @CacheEvict(value = {"users-by-email", "users-by-id"}, allEntries = true)
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
}