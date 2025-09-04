package com.notvibecoder.backend.modules.order.dto;

import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for approving payment by admin
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentApprovalRequest {
    
    @Size(max = 1000, message = "Admin note cannot exceed 1000 characters")
    private String adminNote;
}
