package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class PaymentVerificationException extends BusinessException {
    private final String orderId;
    private final String reason;

    public PaymentVerificationException(String orderId, String reason) {
        super(String.format("Payment verification failed for order %s: %s", orderId, reason), 
              "PAYMENT_VERIFICATION_FAILED");
        this.orderId = orderId;
        this.reason = reason;
    }
}
