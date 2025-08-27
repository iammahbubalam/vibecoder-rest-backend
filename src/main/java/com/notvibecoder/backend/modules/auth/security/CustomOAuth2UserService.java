package com.notvibecoder.backend.modules.auth.security;

import com.notvibecoder.backend.modules.auth.entity.AuthProvider;
import com.notvibecoder.backend.modules.user.entity.Role;
import com.notvibecoder.backend.modules.user.entity.User;
import com.notvibecoder.backend.core.exception.OAuth2AuthenticationProcessingException;
import com.notvibecoder.backend.modules.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Collections;

/**
 * Custom OAuth2 User Service that processes OAuth2 users and creates UserPrincipal objects.
 * <p>
 * Flow:
 * 1. Load OAuth2 user from provider (Google, etc.)
 * 2. Extract user information using provider-specific extractors
 * 3. Find existing user or create new user in database
 * 4. Return UserPrincipal wrapping the user entity
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String providerId = userRequest.getClientRegistration().getRegistrationId();
        log.info("Starting OAuth2 authentication process for provider: {}", providerId);

        try {
            // Step 1: Load user from OAuth2 provider
            OAuth2User oAuth2User = super.loadUser(userRequest);
            log.debug("Successfully loaded OAuth2 user from provider");

            // Step 2: Process the OAuth2 user and return UserPrincipal
            UserPrincipal userPrincipal = processOAuth2User(userRequest, oAuth2User);

            log.info("OAuth2 authentication completed successfully for user: {}",
                    userPrincipal.getEmail());
            return userPrincipal;

        } catch (OAuth2AuthenticationProcessingException e) {
            log.error("OAuth2 processing failed for provider {}: {}", providerId, e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during OAuth2 authentication for provider: {}", providerId, e);
            throw new OAuth2AuthenticationProcessingException("OAuth2 authentication failed", e);
        }
    }

    /**
     * Processes OAuth2 user information and creates UserPrincipal.
     */
    private UserPrincipal processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // Extract user information using provider-specific logic
        OAuth2UserInfo userInfo = extractUserInfo(registrationId, oAuth2User);

        // Validate required information
        validateUserInfo(userInfo);

        // Find or create user in database
        User user = findOrCreateUser(userInfo, registrationId);

        // Create and return UserPrincipal
        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    /**
     * Extracts user information from OAuth2User using provider-specific extractors.
     */
    private OAuth2UserInfo extractUserInfo(String registrationId, OAuth2User oAuth2User) {
        try {
            OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());
            log.debug("Extracted user info for email: {}", userInfo.getEmail());
            return userInfo;
        } catch (Exception e) {
            log.error("Failed to extract user info for provider: {}", registrationId, e);
            throw new OAuth2AuthenticationProcessingException(
                    "Failed to extract user information from provider: " + registrationId, e);
        }
    }

    /**
     * Validates that required user information is present.
     */
    private void validateUserInfo(OAuth2UserInfo userInfo) {
        if (!StringUtils.hasText(userInfo.getEmail())) {
            log.error("Email not found in OAuth2 provider response");
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        if (!StringUtils.hasText(userInfo.getName())) {
            log.warn("Name not found in OAuth2 provider response for email: {}", userInfo.getEmail());
        }
    }

    /**
     * Finds existing user or creates new user in database.
     * Handles race conditions gracefully.
     */
    private User findOrCreateUser(OAuth2UserInfo userInfo, String registrationId) {
        String email = userInfo.getEmail();

        // Try to find existing user first
        return userRepository.findByEmail(email)
                .map(existingUser -> {
                    log.debug("Found existing user: {}", email);
                    return existingUser;
                })
                .orElseGet(() -> createNewUser(userInfo, registrationId));
    }

    /**
     * Creates a new user in the database.
     * Handles duplicate key exceptions from race conditions.
     */
    private User createNewUser(OAuth2UserInfo userInfo, String registrationId) {
        String email = userInfo.getEmail();
        log.info("Creating new user: {}", email);

        try {
            User newUser = buildNewUser(userInfo, registrationId);
            User savedUser = userRepository.save(newUser);

            log.info("Successfully created new user: {} with ID: {}",
                    savedUser.getEmail(), savedUser.getId());
            return savedUser;

        } catch (DuplicateKeyException e) {
            log.warn("Duplicate key detected for email: {}. Attempting to find existing user.", email);

            // Handle race condition: another thread created the user
            return userRepository.findByEmail(email)
                    .orElseThrow(() -> new OAuth2AuthenticationProcessingException(
                            "User creation failed due to race condition", e));

        } catch (Exception e) {
            log.error("Failed to create new user: {}", email, e);
            throw new OAuth2AuthenticationProcessingException("User creation failed", e);
        }
    }

    /**
     * Builds a new User entity from OAuth2 user information.
     */
    private User buildNewUser(OAuth2UserInfo userInfo, String registrationId) {
        Instant now = Instant.now();

        return User.builder()
                .email(userInfo.getEmail())
                .name(userInfo.getName())
                .pictureUrl(userInfo.getImageUrl())
                .provider(mapRegistrationIdToProvider(registrationId))
                .providerId(userInfo.getId())
                .roles(Collections.singleton(Role.STUDENT))
                .enabled(true)  // New OAuth2 users are enabled by default
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    /**
     * Maps OAuth2 registration ID to internal AuthProvider enum.
     */
    private AuthProvider mapRegistrationIdToProvider(String registrationId) {
        if (!StringUtils.hasText(registrationId)) {
            log.warn("Empty registration ID, defaulting to google");
            return AuthProvider.google;
        }

        return switch (registrationId.toLowerCase()) {
            case "google" -> AuthProvider.google;
            default -> {
                log.warn("Unknown registration ID: {}, defaulting to google", registrationId);
                yield AuthProvider.google;
            }
        };
    }
}