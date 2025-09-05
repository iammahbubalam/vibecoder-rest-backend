package com.notvibecoder.backend.core.exception.user;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class ProfileUpdateException extends BusinessException {
    private final String userId;
    private final String field;

    public ProfileUpdateException(String userId, String field, String reason) {
        super(String.format("Failed to update %s for user %s: %s", field, userId, reason), "PROFILE_UPDATE_FAILED");
        this.userId = userId;
        this.field = field;
    }
}