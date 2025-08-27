package com.notvibecoder.backend.dto;

import java.time.Instant;

public record ErrorResponse(int statusCode, Instant timestamp, String message, String description) {
}