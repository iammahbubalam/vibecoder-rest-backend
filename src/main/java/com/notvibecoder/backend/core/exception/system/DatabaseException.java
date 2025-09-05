package com.notvibecoder.backend.core.exception.system;
import com.notvibecoder.backend.core.exception.BusinessException;
import lombok.Getter;

@Getter
public class DatabaseException extends BusinessException {
    private final String operation;
    private final String entity;

    public DatabaseException(String operation, String entity, String message) {
        super(String.format("Database operation %s failed for %s: %s", operation, entity, message), 
              "DATABASE_ERROR");
        this.operation = operation;
        this.entity = entity;
    }

    public DatabaseException(String operation, String entity, Throwable cause) {
        super(String.format("Database operation %s failed for %s", operation, entity), 
              "DATABASE_ERROR", cause);
        this.operation = operation;
        this.entity = entity;
    }
}