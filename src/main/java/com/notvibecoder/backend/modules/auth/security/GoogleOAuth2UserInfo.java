 package com.notvibecoder.backend.modules.auth.security;

import java.util.Map;

public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        // Try 'sub' first (from OIDC token), then fall back to 'id'
        String id = (String) attributes.get("sub");
        if (id == null) {
            id = (String) attributes.get("id");
        }
        return id;
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}