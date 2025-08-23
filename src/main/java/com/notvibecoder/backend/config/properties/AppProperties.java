package com.notvibecoder.backend.config.properties;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "app")
@Validated
public record AppProperties(Oauth2 oauth2, Cors cors) {
    public record Oauth2(@NotEmpty String redirectUri) {
    }

    public record Cors(@NotEmpty String[] allowedOrigins) {
    }
}
