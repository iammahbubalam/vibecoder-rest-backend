package com.notvibecoder.backend.core.exception.system;

import com.notvibecoder.backend.core.exception.BusinessException;

import lombok.Getter;

@Getter
public class ExternalServiceException extends BusinessException {
    private final String serviceName;
    private final String operation;

    public ExternalServiceException(String serviceName, String operation, String message) {
        super(String.format("External service %s failed during %s: %s", serviceName, operation, message), 
              "EXTERNAL_SERVICE_ERROR");
        this.serviceName = serviceName;
        this.operation = operation;
    }

    public ExternalServiceException(String serviceName, String operation, Throwable cause) {
        super(String.format("External service %s failed during %s", serviceName, operation), 
              "EXTERNAL_SERVICE_ERROR", cause);
        this.serviceName = serviceName;
        this.operation = operation;
    }
}
