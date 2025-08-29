package com.notvibecoder.backend.core.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class CourseCreationException extends RuntimeException {
    public CourseCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
