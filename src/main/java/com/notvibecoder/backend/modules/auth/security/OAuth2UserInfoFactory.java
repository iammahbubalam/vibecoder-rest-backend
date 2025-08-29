package com.notvibecoder.backend.modules.auth.security;


import com.notvibecoder.backend.core.exception.OAuth2AuthenticationProcessingException;
import com.notvibecoder.backend.modules.auth.entity.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (AuthProvider.google.toString().equalsIgnoreCase(registrationId)) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
