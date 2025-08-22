package com.notvibecoder.backend.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "jwt")
@Data
@Component
@Validated
public class JwtProperties {

    @NotBlank
    private String secret;

    @Valid
    private final AccessToken accessToken = new AccessToken();

    @Valid
    private final RefreshToken refreshToken = new RefreshToken();

    @Data
    public static class AccessToken {
        @Min(60000) // Minimum 1 minute
        private long expirationMs = 900000; // 15 minutes default
    }

    @Data
    public static class RefreshToken {
        @Min(3600000) // Minimum 1 hour
        private long expirationMs = 604800000; // 7 days default
    }
}
