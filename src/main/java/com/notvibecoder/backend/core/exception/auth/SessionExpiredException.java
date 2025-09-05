package com.notvibecoder.backend.core.exception.auth;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class SessionExpiredException extends BusinessException {
    private final String sessionId;

    public SessionExpiredException(String sessionId) {
        super("Session has expired. Please login again", "SESSION_EXPIRED");
        this.sessionId = sessionId;
    }
}
