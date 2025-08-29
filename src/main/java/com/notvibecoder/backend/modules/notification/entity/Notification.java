package com.notvibecoder.backend.modules.notification.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;
import java.util.Map;

@Document(collection = "notifications")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "user_read_created_idx",
                def = "{'userId': 1, 'read': 1, 'createdAt': -1}"),
        @CompoundIndex(name = "user_type_created_idx",
                def = "{'userId': 1, 'type': 1, 'createdAt': -1}"),
        @CompoundIndex(name = "type_created_idx",
                def = "{'type': 1, 'createdAt': -1}")
})
public class Notification {

    @Id
    private String id;

    @Indexed
    @NotBlank(message = "User ID is required")
    @Field("user_id")
    private String userId;

    @Indexed
    @NotNull(message = "Type is required")
    @Field("type")
    private NotificationType type;

    @NotBlank(message = "Title is required")
    @Field("title")
    private String title;

    @NotBlank(message = "Message is required")
    @Field("message")
    private String message;

    @Field("data")
    private Map<String, Object> data;

    @Indexed
    @Field("read")
    @Builder.Default
    private Boolean read = false;

    @Field("read_at")
    private Instant readAt;

    @Field("action_url")
    private String actionUrl;

    @Indexed
    @CreatedDate
    @Field("created_at")
    private Instant createdAt;

    @org.springframework.data.annotation.Version
    @Field("version")
    private Long version;
}