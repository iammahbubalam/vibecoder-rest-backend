package com.notvibecoder.backend.modules.order.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for creating a new order
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateOrderRequest {
    
    @NotBlank(message = "Course ID is required")
    @Pattern(regexp = "^[a-zA-Z0-9]{1,50}$", message = "Course ID must be alphanumeric and max 50 characters")
    private String courseId;
}
