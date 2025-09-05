package com.notvibecoder.backend.core.exception.user;

import com.notvibecoder.backend.core.exception.BusinessException;

public class UserNotFoundException extends BusinessException {
    public UserNotFoundException(String message) {
        super(message, "USER_NOT_FOUND");
    }

    public UserNotFoundException(String message, String userId) {
        super(message, "USER_NOT_FOUND", userId);
    }
}