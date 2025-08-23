package com.notvibecoder.backend.security;

import com.notvibecoder.backend.entity.AuthProvider;
import com.notvibecoder.backend.entity.Role;
import com.notvibecoder.backend.entity.User;
import com.notvibecoder.backend.exception.OAuth2AuthenticationProcessingException;
import com.notvibecoder.backend.repository.UserRepository;
import com.notvibecoder.backend.security.oauth2.OAuth2UserInfo;
import com.notvibecoder.backend.security.oauth2.OAuth2UserInfoFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Collections;



@Service
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    // Add this constructor to see if the bean is being created
    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
        System.out.println("=== CustomOAuth2UserService CONSTRUCTOR CALLED ===");
        log.info("=== CustomOAuth2UserService CONSTRUCTOR CALLED ===");
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("=== CUSTOM OAUTH2 USER SERVICE CALLED ===");
        log.info("=== CUSTOM OAUTH2 USER SERVICE CALLED ===");
        log.info("Loading user from provider: {}", userRequest.getClientRegistration().getRegistrationId());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("OAuth2User loaded from provider: {}", oAuth2User.getAttributes());

        try {
            OAuth2User result = processOAuth2User(userRequest, oAuth2User);
            System.out.println("=== CUSTOM OAUTH2 USER SERVICE COMPLETED SUCCESSFULLY ===");
            log.info("=== CUSTOM OAUTH2 USER SERVICE COMPLETED SUCCESSFULLY ===");
            return result;
        } catch (Exception ex) {
            log.info("=== Error in CustomOAuth2UserService.loadUser() ===", ex);
            throw new OAuth2AuthenticationProcessingException("Error processing OAuth2 user", ex);
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        log.info("=== Processing OAuth2 user ===");
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        log.info("Registration ID: {}", registrationId);
        
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());
        log.info("OAuth2UserInfo created for email: {}", oAuth2UserInfo.getEmail());
        
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        log.info("Checking if user exists in database...");
        User user = userRepository.findByEmail(oAuth2UserInfo.getEmail())
                .map(existingUser -> {
                    log.info("Found existing user, updating...");
                    return updateExistingUser(existingUser, oAuth2UserInfo, registrationId);
                })
                .orElseGet(() -> {
                    log.info("User not found, registering new user...");
                    return registerNewUser(registrationId, oAuth2UserInfo);
                });

        log.info("Creating UserPrincipal for user: {}", user.getEmail());
        UserPrincipal principal = UserPrincipal.create(user, oAuth2User.getAttributes());
        log.info("=== OAuth2 user processing completed ===");
        return principal;
    }

    private User registerNewUser(String registrationId, OAuth2UserInfo oAuth2UserInfo) {
        log.info("=== Registering new user: {} ===", oAuth2UserInfo.getEmail());

        try {
            AuthProvider provider = AuthProvider.valueOf(registrationId.toLowerCase());

            User user = User.builder()
                    .provider(provider)
                    .providerId(oAuth2UserInfo.getId())
                    .name(oAuth2UserInfo.getName())
                    .email(oAuth2UserInfo.getEmail())
                    .pictureUrl(oAuth2UserInfo.getImageUrl())
                    .roles(Collections.singleton(Role.STUDENT))
                    .build();

            log.info("About to save user to database...");
            User savedUser = userRepository.save(user);
            log.info("=== New user registered successfully with ID: {} ===", savedUser.getId());

            return savedUser;
        } catch (Exception e) {
            log.info("=== Failed to register new user ===", e);
            throw new OAuth2AuthenticationProcessingException("Failed to register new user", e);
        }
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo, String registrationId) {
    log.info("Updating existing user: {}", existingUser.getEmail());

    try {
        // Convert to lowercase to match the enum
        AuthProvider provider = AuthProvider.valueOf(registrationId.toLowerCase());
        
        existingUser.setName(oAuth2UserInfo.getName());
        existingUser.setPictureUrl(oAuth2UserInfo.getImageUrl());
        
        if (!existingUser.getProvider().equals(provider)) {
            existingUser.setProvider(provider);
            existingUser.setProviderId(oAuth2UserInfo.getId());
        }
        
        User savedUser = userRepository.save(existingUser);
        log.info("Successfully updated user: {}", savedUser.getEmail());
        return savedUser;
    } catch (Exception e) {
        log.info("Failed to update existing user: {}", e.getMessage(), e);
        throw new OAuth2AuthenticationProcessingException("Failed to update existing user", e);
    }
}
}