package com.notvibecoder.backend.core.exception.user;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class InvalidUserStateException extends BusinessException {
    private final String userId;
    private final String currentState;
    private final String operation;

    public InvalidUserStateException(String userId, String currentState, String operation) {
        super(String.format("Cannot %s user %s. Current state: %s", operation, userId, currentState), 
              "INVALID_USER_STATE");
        this.userId = userId;
        this.currentState = currentState;
        this.operation = operation;
    }
}
