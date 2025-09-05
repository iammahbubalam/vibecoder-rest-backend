package com.notvibecoder.backend.core.exception.auth;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

// Invalid Credentials Exception
@Getter
public class InvalidCredentialsException extends BusinessException {
    private final String identifier;

    public InvalidCredentialsException(String identifier) {
        super("Invalid credentials provided", "INVALID_CREDENTIALS");
        this.identifier = identifier;
    }
}