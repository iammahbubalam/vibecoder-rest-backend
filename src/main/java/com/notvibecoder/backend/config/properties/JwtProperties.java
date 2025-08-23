package com.notvibecoder.backend.config.properties;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;


@ConfigurationProperties(prefix = "jwt")
@Validated
public record JwtProperties(@NotEmpty String secret, @NotNull AccessToken accessToken,
                            @NotNull RefreshToken refreshToken) {
    public record AccessToken(long expirationMs) {
    }

    public record RefreshToken(long expirationMs) {
    }
}
