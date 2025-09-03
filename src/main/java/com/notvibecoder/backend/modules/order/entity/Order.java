package com.notvibecoder.backend.modules.order.entity;

import jakarta.validation.constraints.*;
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

import java.math.BigDecimal;
import java.time.Instant;

@Document(collection = "orders")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "user_course_unique_idx", 
                def = "{'userId': 1, 'courseId': 1}", unique = true),
        @CompoundIndex(name = "status_created_idx", 
                def = "{'status': 1, 'createdAt': -1}"),
        @CompoundIndex(name = "payment_method_transaction_idx", 
                def = "{'paymentMethod': 1, 'transactionId': 1}"),
        @CompoundIndex(name = "user_status_amount_idx", 
                def = "{'userId': 1, 'status': 1, 'totalAmount': -1}"),
        @CompoundIndex(name = "admin_verification_idx", 
                def = "{'verifiedBy': 1, 'verifiedAt': -1}"),
        @CompoundIndex(name = "course_status_idx", 
                def = "{'courseId': 1, 'status': 1}"),
        @CompoundIndex(name = "phone_transaction_idx", 
                def = "{'phoneNumber': 1, 'transactionId': 1}")
})
public class Order {
    
    @Id
    private String id;
    
    // === CORE ORDER INFORMATION ===
    @Indexed
    @NotBlank(message = "User ID is required")
    @Field("user_id")
    private String userId;
    
    @Indexed
    @NotBlank(message = "Course ID is required")
    @Field("course_id")
    private String courseId;
    
    @Indexed
    @NotNull(message = "Order status is required")
    @Field("status")
    private OrderStatus status;
    
    // === PRICING INFORMATION ===
    @NotNull(message = "Course price is required")
    @DecimalMin(value = "0.0", message = "Course price cannot be negative")
    @Field("course_price")
    private BigDecimal coursePrice;
    
    @Builder.Default
    @DecimalMin(value = "0.0", message = "Discount amount cannot be negative")
    @Field("discount_amount")
    private BigDecimal discountAmount = BigDecimal.ZERO;
    
    
    @NotNull(message = "Total amount is required")
    @DecimalMin(value = "0.0", message = "Total amount cannot be negative")
    @Field("total_amount")
    private BigDecimal totalAmount; // coursePrice - discountAmount
    
    // === COURSE SNAPSHOT (for historical reference) ===
    @NotBlank(message = "Course title is required")
    @Field("course_title")
    private String courseTitle;
    
    @NotBlank(message = "Course instructor is required")
    @Field("course_instructor")
    private String courseInstructor;
    
    @Field("course_thumbnail_url")
    private String courseThumbnailUrl;
    
    @Field("course_category")
    private String courseCategory;
    
    // === USER SNAPSHOT (for admin reference) ===
    @NotBlank(message = "User name is required")
    @Field("user_name")
    private String userName;
    
    @Email(message = "Invalid user email format")
    @NotBlank(message = "User email is required")
    @Field("user_email")
    private String userEmail;
    
    // === PAYMENT INFORMATION ===
    @Field("payment_method")
    private PaymentMethod paymentMethod;
    
    @Indexed
    @Field("transaction_id")
    @Size(max = 100, message = "Transaction ID cannot exceed 100 characters")
    private String transactionId;
    
    @Field("phone_number")
    @Pattern(regexp = "^(\\+88)?01[3-9]\\d{8}$", message = "Invalid Bangladeshi phone number")
    private String phoneNumber;
    
    @Field("payment_screenshot_url")
    private String paymentScreenshotUrl; // Optional: if user uploads payment proof
    
    @Field("payment_reference_note")
    @Size(max = 500, message = "Payment reference note cannot exceed 500 characters")
    private String paymentReferenceNote; // User's additional payment info
    
    // === ADMIN VERIFICATION ===
    @Field("verified_by")
    private String verifiedBy; // Admin user ID
    
    @Field("verified_at")
    private Instant verifiedAt;
    
    @Field("admin_note")
    @Size(max = 1000, message = "Admin note cannot exceed 1000 characters")
    private String adminNote;
    
    @Field("rejection_reason")
    @Size(max = 500, message = "Rejection reason cannot exceed 500 characters")
    private String rejectionReason;
    
    // === ACCESS MANAGEMENT ===
    @Field("access_granted_at")
    private Instant accessGrantedAt; // When course access was granted
    
    @Field("access_expires_at")
    private Instant accessExpiresAt; // Optional: for time-limited access
    
    @Field("access_revoked_at")
    private Instant accessRevokedAt; // If access is revoked later
    
    @Field("revocation_reason")
    @Size(max = 500, message = "Revocation reason cannot exceed 500 characters")
    private String revocationReason;
     
    @Field("user_ip_address")
    private String userIpAddress; // For fraud detection
    
    @Field("currency")
    @Builder.Default
    private String currency = "BDT"; // Bangladeshi Taka
    

    
    @Field("last_payment_attempt_at")
    private Instant lastPaymentAttemptAt;
    
    
    // === AUDIT TRAIL ===
    @Indexed
    @CreatedDate
    @Field("created_at")
    private Instant createdAt;
    
    @LastModifiedDate
    @Field("updated_at")
    private Instant updatedAt;
    
    
    public boolean hasDiscount() {
        return discountAmount != null && discountAmount.compareTo(BigDecimal.ZERO) > 0;
    }
}