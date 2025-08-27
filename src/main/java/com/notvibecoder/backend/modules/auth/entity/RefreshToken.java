package com.notvibecoder.backend.modules.auth.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;

@Document(collection = "refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "userId_revoked_idx",
                def = "{'userId': 1, 'isRevoked': 1}"),
        @CompoundIndex(name = "userId_expiry_idx",
                def = "{'userId': 1, 'expiryDate': 1}"),
        @CompoundIndex(name = "ip_userAgent_idx",
                def = "{'ipAddress': 1, 'userAgent': 1}")
})
public class RefreshToken {

    @Id
    private String id;

    @Indexed(unique = true)
    @NotBlank(message = "Token is required")
    @Field("token")
    private String token;

    @Indexed  // ✅ REMOVED unique=true - users can have multiple sessions in some cases
    @NotBlank(message = "User ID is required")
    @Field("user_id")
    private String userId;

    @Builder.Default
    @Field("is_revoked")
    private boolean isRevoked = false;

    @Indexed(expireAfter = "0s")
    @NotNull(message = "Expiry date is required")
    @Field("expiry_date")
    private Instant expiryDate;

    @Field("created_at")
    private Instant createdAt;

    // ✅ ADDED - Missing field used in service
    @Field("last_used")
    private Instant lastUsed;

    @Field("device_fingerprint")
    private String deviceFingerprint;

    @Field("ip_address")
    private String ipAddress;

    @Field("user_agent")
    private String userAgent;
}