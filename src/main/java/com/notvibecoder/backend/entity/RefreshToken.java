package com.notvibecoder.backend.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;

@Document(collection = "refreshTokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    
    @Id
    private String id;
    
    @Indexed(unique = true)
    private String token;
    
    @Indexed(unique = true) // ✅ Single session: one token per user
    @Field("user_id")
    private String userId;
    
    @Field("is_revoked")
    @Builder.Default
    private boolean isRevoked = false;
    
    @Indexed(expireAfter = "0s")
    @Field("expiry_date")
    private Instant expiryDate;
    
    @Field("created_at")
    private Instant createdAt;
    
    // ✅ Single device security tracking
    @Field("device_fingerprint")
    private String deviceFingerprint;
    
    @Field("ip_address")
    private String ipAddress;
    
    @Field("user_agent")
    private String userAgent;
    
    @Field("last_used")
    private Instant lastUsed;
}
