package com.notvibecoder.backend.core.exception;

import lombok.Getter;

@Getter
public class DuplicateResourceException extends BusinessException {
    private final String resourceType;
    private final String conflictingField;
    private final String conflictingValue;

    public DuplicateResourceException(String resourceType, String conflictingField, String conflictingValue) {
        super(String.format("%s already exists with %s: %s", resourceType, conflictingField, conflictingValue), 
              "DUPLICATE_RESOURCE");
        this.resourceType = resourceType;
        this.conflictingField = conflictingField;
        this.conflictingValue = conflictingValue;
    }
}
