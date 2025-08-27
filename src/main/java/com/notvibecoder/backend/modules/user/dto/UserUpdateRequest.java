package com.notvibecoder.backend.modules.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserUpdateRequest {
    
    // Constants from User entity
    private static final int MIN_NAME_LENGTH = 2;
    private static final int MAX_NAME_LENGTH = 100;
    private static final int MAX_PICTURE_URL_LENGTH = 500;
    
    @NotBlank(message = "Name is required")
    @Size(min = MIN_NAME_LENGTH, max = MAX_NAME_LENGTH, message = "Name must be between 2 and 100 characters")
    private String name;
    
    @Size(max = MAX_PICTURE_URL_LENGTH, message = "Picture URL too long")
    private String pictureUrl;
}
