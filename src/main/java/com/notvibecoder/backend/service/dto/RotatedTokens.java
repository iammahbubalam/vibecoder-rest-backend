package com.notvibecoder.backend.service.dto;

import org.springframework.http.ResponseCookie;

public record RotatedTokens(String accessToken, ResponseCookie cookie) {
}
