package com.notvibecoder.backend.modules.order.dto;

import com.notvibecoder.backend.modules.order.entity.PaymentMethod;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for submitting payment information
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentSubmissionRequest {
    
    @NotNull(message = "Payment method is required")
    private PaymentMethod paymentMethod;
    
    @NotBlank(message = "Transaction ID is required")
    @Size(max = 100, message = "Transaction ID cannot exceed 100 characters")
    private String transactionId;
    
    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^(\\+88)?01[3-9]\\d{8}$", message = "Invalid Bangladeshi phone number format")
    private String phoneNumber;
    
    @Size(max = 500, message = "Payment note cannot exceed 500 characters")
    private String paymentNote;
}
