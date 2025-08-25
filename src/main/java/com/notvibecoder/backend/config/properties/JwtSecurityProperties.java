package com.notvibecoder.backend.config.properties;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "jwt.security")
@Validated
public record JwtSecurityProperties(
    @NotEmpty String issuer,
    @NotEmpty String audience,
    @NotNull @Min(512) Integer minimumKeyLength,
    @NotNull Boolean validateIssuer,
    @NotNull Boolean validateAudience
) {
    public JwtSecurityProperties() {
        this("vibecoder-backend", 
             "vibecoder-frontend", 
             512, 
             true, 
             true);
    }
}