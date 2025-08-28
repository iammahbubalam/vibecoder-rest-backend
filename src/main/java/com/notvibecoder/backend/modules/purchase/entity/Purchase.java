package com.notvibecoder.backend.modules.purchase.entity;

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

import java.math.BigDecimal;
import java.time.Instant;

@Document(collection = "purchases")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@CompoundIndexes({
        @CompoundIndex(name = "user_course_unique_idx",
                def = "{'userId': 1, 'courseId': 1}",
                unique = true),
        @CompoundIndex(name = "user_status_purchased_idx",
                def = "{'userId': 1, 'status': 1, 'purchasedAt': -1}"),
        @CompoundIndex(name = "course_status_purchased_idx",
                def = "{'courseId': 1, 'status': 1, 'purchasedAt': -1}"),
        @CompoundIndex(name = "payment_request_idx",
                def = "{'paymentRequestId': 1}"),
        @CompoundIndex(name = "status_amount_idx",
                def = "{'status': 1, 'purchaseAmount': -1}")
})
public class Purchase {
    
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

    @Indexed
    @NotBlank(message = "Payment request ID is required")
    @Field("payment_request_id")
    private String paymentRequestId;

    @NotNull(message = "Purchase amount is required")
    @Field("purchase_amount")
    private BigDecimal purchaseAmount;

    @Indexed
    @NotNull(message = "Status is required")
    @Field("status")
    private PurchaseStatus status;

    @Field("course_title")
    private String courseTitle;

    @Field("course_instructor")
    private String courseInstructor;

    @Field("course_thumbnail_url")
    private String courseThumbnailUrl;

    @Indexed
    @CreatedDate
    @Field("purchased_at")
    private Instant purchasedAt;

    @Field("access_granted_at")
    private Instant accessGrantedAt;

    @Field("access_revoked_at")
    private Instant accessRevokedAt;

    @org.springframework.data.annotation.Version
    @Field("version")
    private Long version;
}