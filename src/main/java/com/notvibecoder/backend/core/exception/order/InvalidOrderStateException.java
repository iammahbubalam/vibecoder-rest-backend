package com.notvibecoder.backend.core.exception.order;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class InvalidOrderStateException extends BusinessException {
    private final String orderId;
    private final String currentState;
    private final String requiredState;
    private final String operation;

    public InvalidOrderStateException(String orderId, String currentState, String requiredState, String operation) {
        super(String.format("Cannot %s order %s. Current state: %s, Required: %s", 
              operation, orderId, currentState, requiredState), "INVALID_ORDER_STATE");
        this.orderId = orderId;
        this.currentState = currentState;
        this.requiredState = requiredState;
        this.operation = operation;
    }
}
