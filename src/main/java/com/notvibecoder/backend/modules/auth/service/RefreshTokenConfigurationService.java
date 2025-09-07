package com.notvibecoder.backend.modules.auth.service;

import com.notvibecoder.backend.config.properties.JwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshTokenConfigurationService {

    private final JwtProperties jwtProperties;

    public Instant calculateExpiryDate() {
        return Instant.now().plusMillis(jwtProperties.getRefreshToken().getExpirationMs());
    }

    public long getExpirationTimeInSeconds() {
        return jwtProperties.getRefreshToken().getExpirationMs() / 1000;
    }
}