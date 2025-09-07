package com.notvibecoder.backend.config.properties;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@ConfigurationProperties(prefix = "jwt")
@Validated
public class JwtProperties {
    
    @NotEmpty
    private String secret;
    
    @NotNull
    private AccessToken accessToken = new AccessToken();
    
    @NotNull
    private RefreshToken refreshToken = new RefreshToken();
    
    @Data
    public static class AccessToken {
        private long expirationMs = 900000; // 15 minutes default
    }
    
    @Data
    public static class RefreshToken {
        private long expirationMs = 604800000; // 7 days default
    }
}
