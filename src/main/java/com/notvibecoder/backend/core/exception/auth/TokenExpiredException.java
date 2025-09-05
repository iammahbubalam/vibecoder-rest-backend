package com.notvibecoder.backend.core.exception.auth;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class TokenExpiredException extends BusinessException {
    private final String tokenType;

    public TokenExpiredException(String tokenType) {
        super(String.format("%s token has expired", tokenType), "TOKEN_EXPIRED");
        this.tokenType = tokenType;
    }
}