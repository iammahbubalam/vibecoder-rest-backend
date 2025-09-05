package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class InvalidPaymentMethodException extends BusinessException {
    private final String paymentMethod;

    public InvalidPaymentMethodException(String paymentMethod) {
        super(String.format("Invalid payment method: %s", paymentMethod), "INVALID_PAYMENT_METHOD");
        this.paymentMethod = paymentMethod;
    }
}