package com.notvibecoder.backend.exception;
import lombok.Getter;

import java.util.Map;

@Getter
public class ValidationException extends BusinessException {
    private final Map<String, String> fieldErrors;

    public ValidationException(String message, Map<String, String> fieldErrors) {
        super(message, "VALIDATION_ERROR");
        this.fieldErrors = fieldErrors;
    }
}