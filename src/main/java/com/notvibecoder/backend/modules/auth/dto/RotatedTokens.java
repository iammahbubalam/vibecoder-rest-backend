package com.notvibecoder.backend.modules.auth.dto;

import org.springframework.http.ResponseCookie;

public record RotatedTokens(String accessToken, ResponseCookie cookie) {
}
