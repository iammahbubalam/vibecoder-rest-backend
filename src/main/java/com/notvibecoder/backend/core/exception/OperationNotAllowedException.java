package com.notvibecoder.backend.core.exception;

import lombok.Getter;

@Getter
public class OperationNotAllowedException extends BusinessException {
    private final String operation;
    private final String currentState;
    private final String reason;

    public OperationNotAllowedException(String operation, String currentState, String reason) {
        super(String.format("Operation '%s' not allowed in current state '%s': %s", operation, currentState, reason), 
              "OPERATION_NOT_ALLOWED");
        this.operation = operation;
        this.currentState = currentState;
        this.reason = reason;
    }
}