package com.notvibecoder.backend.service;

import com.notvibecoder.backend.entity.RefreshToken;
import com.notvibecoder.backend.service.dto.DeviceInfo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@Slf4j
public class DeviceSecurityService {

    public DeviceInfo extractDeviceInfo(HttpServletRequest request) {
        if (request == null) {
            return new DeviceInfo(null, null, null);
        }

        String userAgent = request.getHeader("User-Agent");
        String clientIp = getClientIp(request);
        String fingerprint = createDeviceFingerprint(request);

        return new DeviceInfo(fingerprint, clientIp, userAgent);
    }

    public boolean verifyDeviceBinding(RefreshToken token, HttpServletRequest request) {
        if (token.getDeviceFingerprint() == null) {
            return true; // Skip verification for legacy tokens
        }

        String currentFingerprint = createDeviceFingerprint(request);
        boolean fingerprintMatch = currentFingerprint.equals(token.getDeviceFingerprint());

        if (!fingerprintMatch) {
            log.warn("Device fingerprint mismatch for user: {} - Expected: {}, Got: {}",
                    token.getUserId(), token.getDeviceFingerprint(), currentFingerprint);
        }

        return fingerprintMatch;
    }

    private String createDeviceFingerprint(HttpServletRequest request) {
        String fingerprint = request.getHeader("User-Agent") + "|" +
                request.getHeader("Accept-Language") + "|" +
                request.getHeader("Accept-Encoding") + "|" +
                getClientIp(request);

        return String.valueOf(fingerprint.hashCode());
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xfHeader)) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}