package com.notvibecoder.backend.core.exception.auth;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class TokenRevokedException extends BusinessException {
    private final String tokenType;
    private final String reason;

    public TokenRevokedException(String tokenType, String reason) {
        super(String.format("%s token has been revoked: %s", tokenType, reason), "TOKEN_REVOKED");
        this.tokenType = tokenType;
        this.reason = reason;
    }
}