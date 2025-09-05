package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class OrderAuthorizationException extends BusinessException {
    private final String orderId;
    private final String userId;
    private final String action;

    public OrderAuthorizationException(String orderId, String userId, String action) {
        super(String.format("User %s is not authorized to %s order %s", userId, action, orderId), 
              "ORDER_AUTHORIZATION_FAILED");
        this.orderId = orderId;
        this.userId = userId;
        this.action = action;
    }
}
