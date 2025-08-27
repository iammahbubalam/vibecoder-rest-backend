package com.notvibecoder.backend.core.dto;

public record DeviceInfo(
        String fingerprint,
        String ipAddress,
        String userAgent
) {
}