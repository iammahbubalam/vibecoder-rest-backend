package com.notvibecoder.backend.service.dto;

public record DeviceInfo(
        String fingerprint,
        String ipAddress,
        String userAgent
) {
}