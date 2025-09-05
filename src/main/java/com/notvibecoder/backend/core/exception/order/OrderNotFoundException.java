package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class OrderNotFoundException extends BusinessException {
    private final String orderId;

    public OrderNotFoundException(String orderId) {
        super(String.format("Order not found with ID: %s", orderId), "ORDER_NOT_FOUND");
        this.orderId = orderId;
    }
}