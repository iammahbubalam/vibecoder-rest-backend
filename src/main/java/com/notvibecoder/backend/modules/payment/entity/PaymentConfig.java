package com.notvibecoder.backend.modules.payment.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.Instant;
import java.util.Map;

@Document(collection = "payment_config")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PaymentConfig {

    @Id
    private String id;

    @Field("payment_numbers")
    private Map<String, String> paymentNumbers;

    @Field("payment_instructions")
    private Map<String, String> paymentInstructions;

    @Indexed
    @Builder.Default
    @Field("active")
    private Boolean active = true;

    @LastModifiedDate
    @Field("updated_at")
    private Instant updatedAt;
}