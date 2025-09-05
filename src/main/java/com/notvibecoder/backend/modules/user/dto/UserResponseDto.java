package com.notvibecoder.backend.modules.user.dto;

import com.notvibecoder.backend.modules.user.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {

    private String id;
    private String email;
    private String name;
    private String pictureUrl;
    private Set<Role> roles;
    private Boolean enabled;
    private Set<String> purchasedCourseIds;
    private Instant createdAt;
    private Instant updatedAt;

    public static UserResponseDto from(com.notvibecoder.backend.modules.user.entity.User user) {
        return UserResponseDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .pictureUrl(user.getPictureUrl())
                .roles(user.getRoles())
                .enabled(user.getEnabled())
                .purchasedCourseIds(user.getPurchasedCourseIds())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
