package com.notvibecoder.backend.modules.order.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request DTO for revoking course access
 */
@Data
public class RevokeAccessRequest {

    @NotBlank(message = "Revocation reason is required")
    @Size(min = 10, max = 500, message = "Revocation reason must be between 10 and 500 characters")
    private String revocationReason;
}
