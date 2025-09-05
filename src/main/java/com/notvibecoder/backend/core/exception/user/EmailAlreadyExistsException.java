package com.notvibecoder.backend.core.exception.user;

import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

// Email Already Exists Exception
@Getter
public class EmailAlreadyExistsException extends BusinessException {
    private final String email;

    public EmailAlreadyExistsException(String email) {
        super(String.format("Email already exists: %s", email), "EMAIL_ALREADY_EXISTS");
        this.email = email;
    }
}