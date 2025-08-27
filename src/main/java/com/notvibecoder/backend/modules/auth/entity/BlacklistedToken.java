package com.notvibecoder.backend.modules.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Document(collection = "blacklisted_tokens")
public class BlacklistedToken {
    @Id
    private String id;

    @Indexed(unique = true)
    @Field("jwt_id")
    private String jwtId; // JWT ID from the 'jti' claim

    @Field("user_id")
    private String userId;

    @Field("reason")
    private String reason; // "logout", "security_breach", etc.

    @Field("blacklisted_at")
    private Instant blacklistedAt;

    @Indexed(name = "expires_at_ttl", expireAfter = "0s")
    @Field("expires_at")
    private Instant expiresAt;
}
