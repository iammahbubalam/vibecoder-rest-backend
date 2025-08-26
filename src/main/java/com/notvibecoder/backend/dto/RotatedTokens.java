package com.notvibecoder.backend.dto;

import org.springframework.http.ResponseCookie;

public record RotatedTokens(String accessToken, ResponseCookie cookie) {
}
