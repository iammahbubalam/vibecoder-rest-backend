package com.notvibecoder.backend.modules.payment.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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

@Document(collection = "payment_requests")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "user_course_status_idx",
                def = "{'userId': 1, 'courseId': 1, 'status': 1}"),
        @CompoundIndex(name = "status_created_idx",
                def = "{'status': 1, 'createdAt': -1}"),
        @CompoundIndex(name = "transaction_method_idx",
                def = "{'transactionId': 1, 'paymentMethod': 1}"),
        @CompoundIndex(name = "verified_by_date_idx",
                def = "{'verifiedBy': 1, 'verifiedAt': -1}"),
        @CompoundIndex(name = "course_amount_idx",
                def = "{'courseId': 1, 'amount': 1}")
})
public class PaymentRequest {

    @Id
    private String id;

    @Indexed
    @NotBlank(message = "User ID is required")
    @Field("user_id")
    private String userId;

    @Indexed
    @NotBlank(message = "Course ID is required")
    @Field("course_id")
    private String courseId;

    @NotNull(message = "Amount is required")
    @Field("amount")
    private BigDecimal amount;

    @Indexed
    @NotNull(message = "Payment method is required")
    @Field("payment_method")
    private PaymentMethod paymentMethod;

    @Indexed(unique = true)
    @NotBlank(message = "Transaction ID is required")
    @Field("transaction_id")
    private String transactionId;

    @Field("phone_number")
    private String phoneNumber;

    @Indexed
    @NotNull(message = "Status is required")
    @Field("status")
    private PaymentStatus status;

    @Field("admin_note")
    private String adminNote;

    @Indexed
    @Field("verified_by")
    private String verifiedBy;

    @Field("verified_at")
    private Instant verifiedAt;

    @Field("rejected_reason")
    private String rejectedReason;

    @Indexed
    @CreatedDate
    @Field("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Field("updated_at")
    private Instant updatedAt;

    @org.springframework.data.annotation.Version
    @Field("version")
    private Long version;
}