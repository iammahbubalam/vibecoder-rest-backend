package com.notvibecoder.backend.dto;

public record DeviceInfo(
        String fingerprint,
        String ipAddress,
        String userAgent
) {
}