package com.notvibecoder.backend.core.exception;

import lombok.Getter;

@Getter
public class UnauthorizedAccessException extends BusinessException {
    private final String resource;
    private final String action;
    private final String userId;

    public UnauthorizedAccessException(String resource, String action, String userId) {
        super(String.format("User %s is not authorized to %s resource: %s", userId, action, resource), 
              "UNAUTHORIZED_ACCESS");
        this.resource = resource;
        this.action = action;
        this.userId = userId;
    }
}