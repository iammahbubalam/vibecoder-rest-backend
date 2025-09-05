package com.notvibecoder.backend.core.exception.auth;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class AccountDisabledException extends BusinessException {
    private final String userId;

    public AccountDisabledException(String userId) {
        super("Account is disabled", "ACCOUNT_DISABLED");
        this.userId = userId;
    }
}