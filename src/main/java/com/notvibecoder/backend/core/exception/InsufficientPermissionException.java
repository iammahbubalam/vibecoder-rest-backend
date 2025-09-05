package com.notvibecoder.backend.core.exception;

import lombok.Getter;

@Getter
public class InsufficientPermissionException extends BusinessException {
    private final String requiredPermission;
    private final String currentPermission;

    public InsufficientPermissionException(String requiredPermission, String currentPermission) {
        super(String.format("Insufficient permission. Required: %s, Current: %s", requiredPermission, currentPermission), 
              "INSUFFICIENT_PERMISSION");
        this.requiredPermission = requiredPermission;
        this.currentPermission = currentPermission;
    }
}