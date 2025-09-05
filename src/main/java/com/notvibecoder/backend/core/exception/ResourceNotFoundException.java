package com.notvibecoder.backend.core.exception;

import lombok.Getter;

// Resource Not Found Exception
@Getter
public class ResourceNotFoundException extends BusinessException {
    private final String resourceType;
    private final String resourceId;

    public ResourceNotFoundException(String resourceType, String resourceId) {
        super(String.format("%s not found with ID: %s", resourceType, resourceId), "RESOURCE_NOT_FOUND");
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }

    public ResourceNotFoundException(String resourceType, String resourceId, String message) {
        super(message, "RESOURCE_NOT_FOUND", resourceType, resourceId);
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }
}