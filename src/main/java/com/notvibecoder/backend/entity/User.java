package com.notvibecoder.backend.entity;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;
import java.util.Set;

@Document(collection = "users")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "email_provider_idx",
                def = "{'email': 1, 'provider': 1}",
                unique = true),
        @CompoundIndex(name = "provider_providerId_idx",
                def = "{'provider': 1, 'providerId': 1}",
                unique = true),
        @CompoundIndex(name = "roles_enabled_idx",
                def = "{'roles': 1, 'enabled': 1}"),
        @CompoundIndex(name = "created_updated_idx",
                def = "{'createdAt': -1, 'updatedAt': -1}")
})
public class User {

    @Id
    private String id;

    @Indexed(unique = true)
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    @Size(max = 254, message = "Email too long")
    @Field("email")
    private String email;

    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    @Field("name")
    private String name;

    @Size(max = 500, message = "Picture URL too long")
    @Field("picture_url")
    private String pictureUrl;

    @NotNull(message = "Provider is required")
    @Field("provider")
    private AuthProvider provider;

    @NotBlank(message = "Provider ID is required")
    @Field("provider_id")
    private String providerId;

    @NotNull(message = "Roles are required")
    @Field("roles")
    private Set<Role> roles;

    @Builder.Default
    @Field("enabled")
    private Boolean enabled = true;

    @CreatedDate
    @Field("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Field("updated_at")
    private Instant updatedAt;

    // Version field for optimistic locking
    @org.springframework.data.annotation.Version
    @Field("version")
    private Long version;
}
